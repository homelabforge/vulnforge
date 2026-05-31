"""Settings API endpoints."""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings as app_settings
from app.database import get_db
from app.dependencies.auth import require_admin
from app.models import Setting
from app.models.user import User
from app.schemas import Setting as SettingSchema
from app.schemas import SettingUpdate
from app.schemas.setting import SettingUpdateResponse
from app.services.oidc import display_mask_secret, is_masked_secret
from app.services.settings_manager import SettingsManager

router = APIRouter()


def _is_sensitive(setting: Setting) -> bool:
    """A setting is sensitive if its DB flag is set OR its key classifies as one.

    Classification-driven (plan §6): masking holds even if migration 012 never
    backfilled the column, because ``_is_sensitive_key`` now covers ``webhook``.
    """
    return bool(setting.is_sensitive) or SettingsManager._is_sensitive_key(setting.key)


def _serialize(setting: Setting) -> SettingSchema:
    """Serialize a setting, masking the value when it is sensitive."""
    schema = SettingSchema.model_validate(setting)
    if _is_sensitive(setting):
        schema.value = display_mask_secret(schema.value)
    return schema


def _should_preserve(setting: Setting, incoming_value: str) -> bool:
    """True when a sensitive setting receives an empty/masked value.

    Mirrors the OIDC client-secret contract: an empty string or the mask
    placeholder means "keep the stored secret" rather than overwrite it.
    """
    return _is_sensitive(setting) and (not incoming_value or is_masked_secret(incoming_value))


class BulkSettingsUpdate(BaseModel):
    """Schema for bulk settings update."""

    settings: dict[str, str]


class TestConnectionResult(BaseModel):
    """Schema for test-connection responses."""

    success: bool
    message: str
    details: dict[str, str] | None = None


@router.get("/", response_model=list[SettingSchema])
async def list_settings(db: AsyncSession = Depends(get_db), user: User = Depends(require_admin)):
    """List all settings. Requires admin privileges."""
    result = await db.execute(select(Setting))
    settings = result.scalars().all()
    return [_serialize(s) for s in settings]


@router.get("/{key}", response_model=SettingSchema)
async def get_setting(
    key: str, db: AsyncSession = Depends(get_db), user: User = Depends(require_admin)
):
    """Get setting by key. Requires admin privileges."""
    result = await db.execute(select(Setting).where(Setting.key == key))
    setting = result.scalar_one_or_none()

    if not setting:
        raise HTTPException(status_code=404, detail="Setting not found")

    return _serialize(setting)


@router.put("/{key}", response_model=SettingUpdateResponse)
async def update_setting(
    key: str,
    update: SettingUpdate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_admin),
):
    """Update setting value with validation. Requires admin privileges.

    Returns the updated setting plus a ``restart_required`` flag for
    boot-time settings (parallel_scans, scan_schedule, etc.).
    """
    settings_manager = SettingsManager(db)

    # Preserve-on-placeholder: an empty/masked value for a sensitive setting must
    # not overwrite the stored secret (plan §6 / D2 — keeps the masked frontend
    # round-trip from clearing credentials).
    existing = await db.execute(select(Setting).where(Setting.key == key))
    cur = existing.scalar_one_or_none()
    if cur is not None and _should_preserve(cur, update.value):
        setting = cur
    else:
        # Use SettingsManager.set() which includes validation
        setting = await settings_manager.set(key, update.value)

        # Timezone is an in-process runtime value — mutate app_settings directly.
        # This works because VulnForge runs as a single Granian worker (see main.py).
        if key == "timezone":
            app_settings.timezone = update.value

    return SettingUpdateResponse(
        setting=_serialize(setting),
        restart_required=key in SettingsManager.BOOT_SETTINGS,
    )


@router.post("/bulk", response_model=list[SettingUpdateResponse])
async def bulk_update_settings(
    bulk_update: BulkSettingsUpdate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_admin),
):
    """
    Bulk update multiple settings at once with validation.
    Requires admin privileges.

    Each response item includes ``restart_required`` if the setting is boot-time.
    """
    settings_manager = SettingsManager(db)
    results: list[SettingUpdateResponse] = []

    for key, value in bulk_update.settings.items():
        existing = await db.execute(select(Setting).where(Setting.key == key))
        cur = existing.scalar_one_or_none()
        if cur is not None and _should_preserve(cur, value):
            setting = cur
        else:
            setting = await settings_manager.set(key, value)

            # Timezone is an in-process runtime value (single-worker pattern)
            if key == "timezone":
                app_settings.timezone = value

        results.append(
            SettingUpdateResponse(
                setting=_serialize(setting),
                restart_required=key in SettingsManager.BOOT_SETTINGS,
            )
        )

    return results


@router.post("/test/docker", response_model=TestConnectionResult)
async def test_docker_connection(
    user: User = Depends(require_admin),
):
    """
    Test Docker connection using DOCKER_HOST environment variable.

    Returns:
        Success flag, message, and basic details about the connection.
    """
    import os
    from urllib.parse import urlparse

    from docker import DockerClient
    from docker.errors import DockerException

    from app.config import settings as app_settings

    # Use DOCKER_HOST env variable (from compose) with fallbacks
    socket_value = (
        os.getenv("DOCKER_HOST")
        or app_settings.docker_socket_proxy
        or "unix:///var/run/docker.sock"
    )

    # Normalize plain paths to unix:// URLs for docker-py
    parsed = urlparse(socket_value)
    if not parsed.scheme or socket_value.startswith("/"):
        base_url = f"unix://{socket_value}"
    else:
        base_url = socket_value

    try:
        client = DockerClient(base_url=base_url, timeout=5)
        ping_result = client.ping()
        info = client.info()
        client.close()

        if ping_result:
            return TestConnectionResult(
                success=True,
                message="Successfully connected to Docker daemon",
                details={
                    "docker_host": base_url,
                    "server_version": str(info.get("ServerVersion", "")),
                    "os": str(info.get("OperatingSystem", "")),
                },
            )

        return TestConnectionResult(
            success=False,
            message="Ping to Docker daemon failed",
            details={"docker_host": base_url},
        )
    except DockerException as exc:
        return TestConnectionResult(
            success=False,
            message="Failed to connect to Docker daemon",
            details={"docker_host": base_url, "error": str(exc)},
        )
