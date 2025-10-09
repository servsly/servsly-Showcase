### What is servsly
>Servsly Homebase acts as the control plane, packaging and validating sites before securely deploying them to Servsly Edge Nodes (our VPS delivery layer) via SSH.
>Edge Nodes >serve content directly from disk, enforcing runtime directives like suspensions or maintenance triggers.

### Advanced: Hosting Lifecycle (Validate → Preview → Publish)

This appendix outlines the high-level pipeline that processes uploaded site bundles:
1) **Validate** an archive and record stats  
2) **Promote Preview** with a short-lived token/expiry  
3) **Publish** a validated revision atomically and idempotently

The showcase uses DB-centric stubs to illustrate flow without exposing filesystem
paths, IP addresses, or production markers.
##

> ### hosting/models.py  
> These models define the **core data structure** behind Servsly’s site-hosting platform.  
>  
> The `Site` model represents an individual hosted website, tracking its state (live, maintenance, or suspended)  
> and linking it to one or more `Domain` entries. Each `Domain` includes built-in validation to ensure that  
> only properly formatted hostnames and verified subdomains are used.  
>  
> The `SiteRevision` model introduces a versioning system that creates a new revision each time a site is  
> uploaded or updated. This allows safe previewing, validation, and publishing without overwriting live content.  
>  
> Together, these models outline the **foundation of Servsly’s hosting architecture**—  
> connecting sites, revisions, and domains in a secure, auditable, and scalable structure.
##
```python
from __future__ import annotations
import secrets
import uuid
from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models, transaction
from django.db.models import Max
from django.utils import timezone


# ---- Simple helpers (safe) ---------------------------------------------------

ROOT_DOMAIN = getattr(settings, "DEMO_ROOT_DOMAIN", "example.test")

def generate_verification_token() -> str:
    # Short, URL-safe token used for domain ownership checks
    return secrets.token_urlsafe(16)

def _is_valid_hostname(host: str) -> bool:
    """Basic ASCII FQDN check (subdomains allowed)."""
    if not host or len(host) > 253:
        return False
    labels = host.split(".")
    if len(labels) < 2:
        return False
    for label in labels:
        if not (0 < len(label) <= 63):
            return False
        if label[0] == "-" or label[-1] == "-":
            return False
        for ch in label:
            if not (ch.isalnum() or ch == "-"):
                return False
    return True


# ---- Core models (minimal) ---------------------------------------------------

class ServingState(models.TextChoices):
    LIVE = "live", "Live"
    MAINTENANCE = "maintenance", "Maintenance"
    SUSPENDED = "suspended", "Suspended"


class DomainType(models.TextChoices):
    SERVSLY = "servsly_subdomain", "Platform Subdomain"
    CUSTOM = "custom", "Custom Domain"


class VerificationStatus(models.TextChoices):
    PENDING = "pending", "Pending"
    VERIFIED = "verified", "Verified"
    FAILED = "failed", "Failed"


class Site(models.Model):
    """
    A hosted site owned by a business/user (owner details omitted in showcase).
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    display_name = models.CharField(max_length=160)
    serving_state = models.CharField(
        max_length=20,
        choices=ServingState.choices,
        default=ServingState.LIVE,
    )

    # Optional: which domain is considered canonical for this site
    primary_domain = models.ForeignKey(
        "hosting.Domain",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="primary_for_sites",
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["display_name"]

    def __str__(self) -> str:
        return self.display_name


class SiteRevision(models.Model):
    """
    A numbered, immutable snapshot of a site's content/config that can be previewed or published.
    """
    STATUS = [
        ("uploaded", "Uploaded"),
        ("validated", "Validated"),
        ("in_preview", "In Preview"),
        ("published", "Published"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    site = models.ForeignKey("hosting.Site", on_delete=models.CASCADE, related_name="revisions")
    status = models.CharField(max_length=20, choices=STATUS, default="uploaded")

    # Monotonic per-site integer (e.g., r1, r2, r3...). Calculated on save.
    rev_no = models.PositiveIntegerField(editable=False, db_index=True)

    # Preview/publish metadata (kept minimal)
    preview_token = models.CharField(max_length=64, blank=True, null=True, unique=True, db_index=True)
    preview_expires_at = models.DateTimeField(blank=True, null=True)
    published_at = models.DateTimeField(blank=True, null=True)

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-rev_no", "-created_at"]
        constraints = [
            models.UniqueConstraint(fields=["site", "rev_no"], name="uniq_site_revno"),
        ]

    def __str__(self):
        return f"{self.site_id}@r{self.rev_no}"

    def save(self, *args, **kwargs):
        # Assign next rev_no atomically per site
        if self.rev_no is None:
            with transaction.atomic():
                row = (
                    type(self)
                    .objects.select_for_update()
                    .filter(site=self.site)
                    .aggregate(m=Max("rev_no"))
                )
                self.rev_no = (row["m"] or 0) + 1
        super().save(*args, **kwargs)


class Domain(models.Model):
    """
    A DNS hostname associated with a Site (one row per host).
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    site = models.ForeignKey(Site, on_delete=models.PROTECT, related_name="domains")

    host = models.CharField(
        max_length=253,
        unique=True,
        help_text="FQDN, e.g. example.com or sub.example.com",
    )
    type = models.CharField(max_length=32, choices=DomainType.choices)

    is_primary = models.BooleanField(
        default=False,
        help_text="At most one primary domain per site.",
    )

    verification_status = models.CharField(
        max_length=16,
        choices=VerificationStatus.choices,
        default=VerificationStatus.PENDING,
    )
    verification_token = models.CharField(
        max_length=64,
        default=generate_verification_token,
        help_text="Used for DNS/HTTP ownership checks.",
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["host"]
        indexes = [
            models.Index(fields=["site", "is_primary"], name="idx_domain_site_primary"),
            models.Index(fields=["type"], name="idx_domain_type"),
        ]

    def __str__(self) -> str:
        return self.host

    def clean(self):
        # Normalize & validate host
        host = (self.host or "").strip().lower()
        if not _is_valid_hostname(host):
            raise ValidationError({"host": "Enter a valid domain/hostname."})

        # Platform subdomain rule: must end with ROOT_DOMAIN and include a sublabel
        if self.type == DomainType.SERVSLY:
            if not host.endswith(f".{ROOT_DOMAIN}"):
                raise ValidationError({"host": f"Platform subdomains must end with .{ROOT_DOMAIN}"})
            if host.count(".") < 2:
                raise ValidationError({"host": f"Subdomain must be like <label>.{ROOT_DOMAIN}"})

        # Enforce single primary per site at the application layer
        if self.is_primary:
            qs = Domain.objects.filter(site=self.site, is_primary=True)
            if self.pk:
                qs = qs.exclude(pk=self.pk)
            if qs.exists():
                raise ValidationError({"is_primary": "Only one primary domain is allowed per site."})

        self.host = host

    def save(self, *args, **kwargs):
        self.full_clean()
        super().save(*args, **kwargs)
        # Keep Site.primary_domain in sync (optional convenience)
        if self.is_primary and self.site.primary_domain_id != self.pk:
            Site.objects.filter(pk=self.site_id).update(primary_domain=self)
```
##

> ### pipeline.py (showcase)
> Implements the **validate → extract → mark status** step for a site revision.
> This version omits real filesystem layout and quarantine paths; it keeps
> the high-level control flow and atomic DB updates that a reviewer cares about.

##
```python
from __future__ import annotations
from pathlib import Path
from django.db import transaction
from django.utils import timezone
from hosting.models import SiteRevision, SiteRevisionValidation

# Placeholder: your real validator returns object with ok/errors/files/bytes/hash.
class _ValidatorResult:
    def __init__(self, ok, errors=None, files=0, total_uncompressed=0, sha256="", has_index_html=False):
        self.ok = ok
        self.errors = errors or []
        self.files = files
        self.total_uncompressed = total_uncompressed
        self.sha256 = sha256
        self.has_index_html = has_index_html

def _run_validator(zip_path: Path) -> _ValidatorResult:
    """
    Showcase-only stub for a ZIP validator.
    In production this would parse the archive and compute stats.
    """
    if not zip_path or not zip_path.exists():
        return _ValidatorResult(False, ["No ZIP found"])
    # Pretend success with minimal stats for the demo
    return _ValidatorResult(True, files=12, total_uncompressed=42_000, sha256="demo", has_index_html=True)

def _valobj(revision: SiteRevision) -> SiteRevisionValidation:
    return getattr(revision, "validation", None) or SiteRevisionValidation.objects.create(revision=revision)

@transaction.atomic
def validate_and_extract(revision: SiteRevision, *, zip_path: Path) -> dict:
    """
    Validate a ZIP for a revision and update DB state.
    Filesystem extraction is intentionally omitted in the showcase.
    """
    vr = _run_validator(zip_path)

    report = {
        "ok": vr.ok,
        "errors": vr.errors,
        "stats": {
            "files": vr.files,
            "total_uncompressed": vr.total_uncompressed,
            "has_index_html": vr.has_index_html,
        },
        "sha256": vr.sha256,
    }

    # Update revision summary/status
    revision.report = report
    revision.files = vr.files
    revision.total_bytes = vr.total_uncompressed
    revision.sha256 = vr.sha256 or ""

    if vr.ok:
        revision.status = "validated"
        revision.validated_at = timezone.now()
    else:
        revision.status = "uploaded"
        revision.validated_at = None

    revision.save(update_fields=["report", "files", "total_bytes", "sha256", "status", "validated_at"])

    # Update one-to-one validation row
    v = _valobj(revision)
    v.ok = vr.ok
    v.sha256 = vr.sha256 or ""
    v.files = vr.files
    v.total_uncompressed = vr.total_uncompressed
    v.has_index_html = vr.has_index_html
    v.report = report
    v.validated_at = revision.validated_at
    v.save(update_fields=["ok", "sha256", "files", "total_uncompressed", "has_index_html", "report", "validated_at"])

    return report
```
##

> ### services.py (showcase)
> Provides **preview/publish lifecycle** helpers with safe, DB-centric operations.
> Real symlink flips, directory normalization, audit sinks, and marker files are
> removed. The goal is to show **race-safe updates** and **clean invariants**
> (one primary domain, monotonic revision numbers, idempotent publishes).

##
```python
from __future__ import annotations
from datetime import timedelta
from typing import Optional
from django.db import transaction
from django.utils import timezone
from hosting.models import Site, SiteRevision

def assign_next_rev_no(revision: SiteRevision) -> None:
    """
    Showcase helper: set next rev_no if missing.
    (Production version can live on the model.save() override.)
    """
    from django.db.models import Max
    if getattr(revision, "rev_no", None):
        return
    with transaction.atomic():
        row = (
            type(revision)
            .objects.select_for_update()
            .filter(site=revision.site)
            .aggregate(m=Max("rev_no"))
        )
        revision.rev_no = (row["m"] or 0) + 1

@transaction.atomic
def publish_revision(*, site: Site, revision: SiteRevision) -> SiteRevision:
    """
    Idempotent, race-safe: if already published to this revision, no-op.
    (Real filesystem swaps intentionally omitted in the showcase.)
    """
    site = Site.objects.select_for_update().get(pk=site.pk)
    if revision.site_id != site.id:
        raise ValueError("Revision does not belong to site")

    if getattr(site, "current_published_revision_id", None) == revision.id:
        return revision

    # In production, flip a symlink to validated assets here.
    site.current_published_revision = revision
    site.save(update_fields=["current_published_revision"])

    # Mark revision state for clarity
    if hasattr(revision, "published_at"):
        revision.published_at = timezone.now()
        revision.save(update_fields=["published_at"])
    if hasattr(revision, "status"):
        revision.status = "published"
        revision.save(update_fields=["status"])

    return revision

@transaction.atomic
def promote_preview(
    *, site: Site, revision: SiteRevision, ttl: timedelta = timedelta(hours=24), token: Optional[str] = None
) -> SiteRevision:
    """
    Make `revision` the current preview.
    In production, you'd point a preview symlink at the build dir.
    """
    site = Site.objects.select_for_update().get(pk=site.pk)
    if revision.site_id != site.id:
        raise ValueError("Revision does not belong to site")

    site.current_preview_revision = revision
    site.save(update_fields=["current_preview_revision"])

    updates = []
    expiry = timezone.now() + ttl
    if hasattr(revision, "preview_expires_at"):
        revision.preview_expires_at = expiry
        updates.append("preview_expires_at")
    if hasattr(revision, "preview_token") and token:
        revision.preview_token = token
        updates.append("preview_token")
    if updates:
        revision.save(update_fields=updates)
    return revision

def guard_preview_access(revision: SiteRevision, *, require_auth: bool, is_authenticated: bool):
    """
    Minimal preview guard for the showcase:
    - optionally requires auth (no user/IP logging here)
    - returns None if OK, or a dict with a simple 'error' key
    """
    if require_auth and not is_authenticated:
        return {"error": "forbidden"}

    if revision.preview_expires_at and revision.preview_expires_at <= timezone.now():
        # In production, you'd also revoke any preview pointer here.
        return {"error": "expired"}

    return None
    ```
