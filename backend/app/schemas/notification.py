"""Notification schemas."""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class NotificationLogBase(BaseModel):
    """Base notification log schema."""

    notification_type: str
    channel: str
    title: str | None = None
    message: str
    status: str
    error_message: str | None = None
    priority: int | None = None
    tags: str | None = None


class NotificationLogCreate(NotificationLogBase):
    """Schema for creating notification log."""

    scan_id: int | None = None


class NotificationLog(NotificationLogBase):
    """Notification log schema with all fields."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    scan_id: int | None
    created_at: datetime
    sent_at: datetime | None


class NotificationRuleBase(BaseModel):
    """Base notification rule schema."""

    name: str
    description: str | None = None
    enabled: bool = True
    event_type: str
    min_critical: int | None = None
    min_high: int | None = None
    min_medium: int | None = None
    min_total: int | None = None
    title_template: str | None = None
    message_template: str
    priority: int = 3
    tags: str | None = None
    send_to_ntfy: bool = Field(default=True, deprecated=True)


class NotificationRuleCreate(NotificationRuleBase):
    """Schema for creating notification rule."""

    pass


class NotificationRuleUpdate(BaseModel):
    """Schema for updating notification rule."""

    description: str | None = None
    enabled: bool | None = None
    event_type: str | None = None
    min_critical: int | None = None
    min_high: int | None = None
    min_medium: int | None = None
    min_total: int | None = None
    title_template: str | None = None
    message_template: str | None = None
    priority: int | None = None
    tags: str | None = None
    send_to_ntfy: bool | None = Field(default=None, deprecated=True)


class NotificationRule(NotificationRuleBase):
    """Notification rule schema with all fields."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    created_at: datetime
    updated_at: datetime


class NotificationStatsResponse(BaseModel):
    """Notification delivery statistics."""

    total_notifications: int
    sent: int
    failed: int
    success_rate: float
    by_type: dict[str, int]


class OidcTestResponse(BaseModel):
    """OIDC provider connectivity test result (canonical envelope per plan §5.4(4))."""

    ok: bool
    error: str | None = None
    detail: str | None = None
    issuer: str | None = None
    algorithms_supported: list[str] | None = None


class OidcAdminConfig(BaseModel):
    """Full admin OIDC configuration (homelab canonical OIDC settings contract).

    `client_secret` follows §5.4(3): admin GET returns "********" when stored,
    "" otherwise. Admin PUT with empty string OR the placeholder preserves the value.
    """

    enabled: bool = False
    provider_name: str = ""
    issuer_url: str = ""
    client_id: str = ""
    client_secret: str = ""
    scopes: str = "openid profile email"
    username_claim: str = "preferred_username"
    email_claim: str = "email"
    # When true on PUT, clears the bound admin OIDC subject (re-arms TOFU). The
    # GET response always serializes this as false; it is a write-only signal.
    reset_subject: bool = False
