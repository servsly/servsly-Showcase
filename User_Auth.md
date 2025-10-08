## Models

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
##

## Forms
```python
# accounts/forms.py (showcase)

from django import forms
from django.contrib.auth.forms import AuthenticationForm, UserCreationForm
from django.core.validators import validate_email
from django.utils.translation import gettext_lazy as _
from .models import User


class HoneypotMixin(forms.Form):
    hp = forms.CharField(required=False)  # hidden via CSS

    def clean(self):
        cleaned = super().clean()
        if cleaned.get("hp"):
            raise forms.ValidationError("Invalid submission.")
        return cleaned


class SignUpForm(HoneypotMixin, UserCreationForm):
    email      = forms.EmailField(max_length=254)
    first_name = forms.CharField(max_length=150, required=False)
    last_name  = forms.CharField(max_length=150, required=False)

    class Meta:
        model  = User
        fields = ("email", "first_name", "last_name")

    def clean_email(self):
        email = self.cleaned_data["email"].strip().lower()
        validate_email(email)
        if User.objects.filter(email=email).exists():
            raise forms.ValidationError("This email is already registered.")
        return email


class EmailAuthenticationForm(HoneypotMixin, AuthenticationForm):
    username = forms.EmailField(label=_("Email"))
    password = forms.CharField(label=_("Password"), strip=False, widget=forms.PasswordInput)
    remember_me = forms.BooleanField(required=False, initial=False)

    def confirm_login_allowed(self, user):
        if not getattr(user, "is_verified", False):
            raise forms.ValidationError(_("Please verify your email before logging in."), code="unverified")
        if not user.is_active:
            raise forms.ValidationError(_("This account is inactive."), code="inactive")
```
##

## Views
```python
from django.contrib import messages
from django.contrib.auth import login as auth_login, logout as auth_logout
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.views import LoginView, PasswordResetView, PasswordResetConfirmView
from django.shortcuts import redirect, render
from django.urls import reverse, reverse_lazy
from django.utils import timezone
from django.views import View
from django.views.generic import FormView

from .forms import EmailAuthenticationForm, SignUpForm
from .models import EmailVerification, User


class PostLoginRedirectView(LoginRequiredMixin, View):
    def get(self, request):
        return redirect(reverse("dashboard:home"))


class SignUpView(FormView):
    template_name = "accounts/signup.html"
    form_class    = SignUpForm
    success_url   = reverse_lazy("accounts:check_email")

    def form_valid(self, form):
        user = form.save()
        token = EmailVerification.issue(user)
        # TODO: send verification email with token.token
        messages.success(self.request, "We sent a verification link to your email.")
        return super().form_valid(form)


class EmailLoginView(LoginView):
    template_name = "accounts/login.html"
    authentication_form = EmailAuthenticationForm
    redirect_authenticated_user = True

    def form_valid(self, form):
        response = super().form_valid(form)
        remember = form.cleaned_data.get("remember_me")
        self.request.session.set_expiry(0 if not remember else 60 * 60 * 24 * 14)
        return response


class VerifyEmailView(View):
    def get(self, request, token: str):
        try:
            rec = EmailVerification.objects.select_related("user").get(token=token)
        except EmailVerification.DoesNotExist:
            messages.error(request, "Invalid or expired link.")
            return redirect("accounts:login")

        if not rec.is_valid():
            messages.error(request, "Invalid or expired link.")
            return redirect("accounts:login")

        rec.used_at = timezone.now()
        rec.save(update_fields=["used_at"])

        user = rec.user
        if not user.is_verified:
            user.is_verified = True
            user.save(update_fields=["is_verified"])

        auth_login(request, user, backend="django.contrib.auth.backends.ModelBackend")
        messages.success(request, "Email verified. Welcome!")
        return redirect("accounts:post_login")


class CheckEmailView(View):
    template_name = "accounts/check_email.html"

    def get(self, request):
        return render(request, self.template_name)

    def post(self, request):
        email = (request.POST.get("email") or "").strip().lower()
        user = User.objects.filter(email__iexact=email).first() if email else None
        if user and not user.is_verified:
            token = EmailVerification.issue(user)
            # TODO: resend verification email
        messages.success(request, "If an account needs verification, we’ve sent a new link.")
        return redirect("accounts:check_email")


def logout_view(request):
    auth_logout(request)
    return redirect("home")


class ResetPasswordView(PasswordResetView):
    template_name = "accounts/password_reset/password_reset_form.html"


class ResetPasswordConfirmView(PasswordResetConfirmView):
    form_class = None
    post_reset_login = False
    post_reset_login_backend = None
```

