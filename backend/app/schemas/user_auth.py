"""User authentication and OIDC schemas for VulnForge single-user auth."""

import re

from pydantic import BaseModel, EmailStr, Field, field_validator


class SetupRequest(BaseModel):
    """Schema for initial admin account setup."""

    username: str = Field(..., min_length=3, max_length=100)
    email: EmailStr = Field(..., max_length=255)
    password: str = Field(..., min_length=8, max_length=100)
    full_name: str | None = Field(None, max_length=255)

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        """Validate username format."""
        if not re.match(r"^[a-zA-Z0-9_-]+$", v):
            raise ValueError("Username can only contain letters, numbers, underscores, and hyphens")
        return v

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        """Validate password strength."""
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters long")
        if not re.search(r"[A-Z]", v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not re.search(r"[a-z]", v):
            raise ValueError("Password must contain at least one lowercase letter")
        if not re.search(r"\d", v):
            raise ValueError("Password must contain at least one digit")
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", v):
            raise ValueError("Password must contain at least one special character")
        return v


class SetupResponse(BaseModel):
    """Response after successful setup."""

    username: str
    email: str
    full_name: str | None
    message: str = "Admin account created successfully"


class LoginRequest(BaseModel):
    """Login request schema."""

    username: str = Field(..., min_length=1, max_length=100)
    password: str = Field(..., min_length=1, max_length=100)


class TokenResponse(BaseModel):
    """Token response schema."""

    access_token: str
    token_type: str = "bearer"
    expires_in: int
    csrf_token: str | None = None


class UserProfile(BaseModel):
    """Admin user profile schema."""

    username: str
    email: str
    full_name: str | None
    auth_method: str  # "local" or "oidc"
    oidc_provider: str | None = None
    created_at: str | None = None  # ISO timestamp string
    last_login: str | None = None  # ISO timestamp string


class UpdateProfileRequest(BaseModel):
    """Schema for updating admin profile."""

    email: EmailStr | None = Field(None, max_length=255)
    full_name: str | None = Field(None, max_length=255)


class ChangePasswordRequest(BaseModel):
    """Schema for changing password."""

    current_password: str = Field(..., min_length=1, max_length=100)
    new_password: str = Field(..., min_length=8, max_length=100)

    @field_validator("new_password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        """Validate password strength."""
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters long")
        if not re.search(r"[A-Z]", v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not re.search(r"[a-z]", v):
            raise ValueError("Password must contain at least one lowercase letter")
        if not re.search(r"\d", v):
            raise ValueError("Password must contain at least one digit")
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", v):
            raise ValueError("Password must contain at least one special character")
        return v


class UserAuthStatusResponse(BaseModel):
    """User authentication status response."""

    setup_complete: bool
    auth_mode: str  # "none", "local", "oidc"
    oidc_enabled: bool


# ============================================================================
# OIDC Schemas
# ============================================================================


class OIDCConfig(BaseModel):
    """OIDC configuration schema."""

    enabled: bool = False
    issuer_url: str = Field("", max_length=512)
    client_id: str = Field("", max_length=255)
    client_secret: str = Field("", max_length=255)  # Will be masked in responses
    provider_name: str = Field("", max_length=100)
    scopes: str = Field("openid profile email", max_length=255)
    redirect_uri: str = Field("", max_length=512)
    username_claim: str = Field("preferred_username", max_length=100)
    email_claim: str = Field("email", max_length=100)
    link_token_expire_minutes: int = Field(5, ge=1, le=60)
    link_max_password_attempts: int = Field(3, ge=1, le=10)


class OIDCConfigUpdate(BaseModel):
    """Schema for updating OIDC configuration."""

    enabled: bool | None = None
    issuer_url: str | None = Field(None, max_length=512)
    client_id: str | None = Field(None, max_length=255)
    client_secret: str | None = Field(None, max_length=255)
    provider_name: str | None = Field(None, max_length=100)
    scopes: str | None = Field(None, max_length=255)
    redirect_uri: str | None = Field(None, max_length=512)
    username_claim: str | None = Field(None, max_length=100)
    email_claim: str | None = Field(None, max_length=100)
    link_token_expire_minutes: int | None = Field(None, ge=1, le=60)
    link_max_password_attempts: int | None = Field(None, ge=1, le=10)


class OIDCLinkRequest(BaseModel):
    """Request to link OIDC account with password verification."""

    token: str = Field(..., min_length=1, max_length=128)
    password: str = Field(..., min_length=1, max_length=100)


class OIDCTestResult(BaseModel):
    """Result of OIDC connection test."""

    success: bool
    provider_reachable: bool = False
    metadata_valid: bool = False
    endpoints_found: bool = False
    errors: list[str] = Field(default_factory=list)
    metadata: dict | None = None


class OIDCProviderMetadata(BaseModel):
    """OIDC provider metadata from discovery."""

    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    userinfo_endpoint: str | None = None
    jwks_uri: str
    scopes_supported: list[str] | None = None
    response_types_supported: list[str] | None = None
    subject_types_supported: list[str] | None = None
    id_token_signing_alg_values_supported: list[str] | None = None


class OIDCPendingLinkResponse(BaseModel):
    """Response when OIDC account linking requires password verification."""

    link_required: bool = True
    token: str
    username: str
    provider_name: str
    expires_in_seconds: int
    message: str = "Password verification required to link OIDC account"
