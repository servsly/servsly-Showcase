```python
from __future__ import annotations
import secrets
from datetime import timedelta
from django.contrib.auth.base_user import AbstractBaseUser, BaseUserManager
from django.contrib.auth.models import PermissionsMixin
from django.db import models, transaction
from django.utils import timezone


class UserManager(BaseUserManager):
    use_in_migrations = True

    def _create_user(self, email, password, **extra_fields):
        if not email:
            raise ValueError("Email is required")
        email = self.normalize_email(email)
        if not password:
            raise ValueError("Password is required")
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.full_clean()
        user.save(using=self._db)
        return user

    def create_user(self, email, password=None, **extra_fields):
        extra_fields.setdefault("is_staff", False)
        extra_fields.setdefault("is_superuser", False)
        extra_fields.setdefault("is_active", True)
        return self._create_user(email, password, **extra_fields)

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        extra_fields.setdefault("is_active", True)
        if not extra_fields.get("is_staff"):
            raise ValueError("Superuser must have is_staff=True.")
        if not extra_fields.get("is_superuser"):
            raise ValueError("Superuser must have is_superuser=True.")
        return self._create_user(email, password, **extra_fields)


class User(AbstractBaseUser, PermissionsMixin):
    email       = models.EmailField(unique=True, db_index=True)
    first_name  = models.CharField(max_length=150, blank=True)
    last_name   = models.CharField(max_length=150, blank=True)

    is_active   = models.BooleanField(default=True)
    is_staff    = models.BooleanField(default=False)
    is_verified = models.BooleanField(default=False)

    date_joined = models.DateTimeField(default=timezone.now)
    updated_at  = models.DateTimeField(auto_now=True)

    objects = UserManager()

    USERNAME_FIELD  = "email"
    REQUIRED_FIELDS = ()

    def __str__(self):
        return self.email


class EmailVerification(models.Model):
    PURPOSE_VERIFY = "verify"

    user       = models.ForeignKey("User", on_delete=models.CASCADE, related_name="email_tokens")
    token      = models.CharField(max_length=64, unique=True, db_index=True)
    purpose    = models.CharField(max_length=20, default=PURPOSE_VERIFY)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    used_at    = models.DateTimeField(null=True, blank=True)

    class Meta:
        indexes = [models.Index(fields=["user", "purpose", "expires_at"])]

    @classmethod
    @transaction.atomic
    def issue(cls, user: User, *, ttl_minutes: int = 60 * 24, throttle_minutes: int = 2):
        """
        Create a new token unless a recent valid one exists (basic throttle).
        """
        now = timezone.now()
        recent = (
            cls.objects.select_for_update()
            .filter(user=user, purpose=cls.PURPOSE_VERIFY, used_at__isnull=True, expires_at__gt=now)
            .order_by("-created_at")
            .first()
        )
        if recent and (now - recent.created_at).total_seconds() < throttle_minutes * 60:
            return recent

        token = secrets.token_urlsafe(32)
        return cls.objects.create(
            user=user,
            token=token,
            purpose=cls.PURPOSE_VERIFY,
            expires_at=now + timedelta(minutes=ttl_minutes),
        )

    def is_valid(self) -> bool:
        return self.used_at is None and self.expires_at > timezone.now()
```
