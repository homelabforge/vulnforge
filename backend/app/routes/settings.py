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

router = APIRouter()


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
    return [SettingSchema.model_validate(s) for s in settings]


@router.get("/{key}", response_model=SettingSchema)
async def get_setting(
    key: str, db: AsyncSession = Depends(get_db), user: User = Depends(require_admin)
):
    """Get setting by key. Requires admin privileges."""
    result = await db.execute(select(Setting).where(Setting.key == key))
    setting = result.scalar_one_or_none()

    if not setting:
        raise HTTPException(status_code=404, detail="Setting not found")

    return SettingSchema.model_validate(setting)


@router.put("/{key}", response_model=SettingSchema)
async def update_setting(
    key: str,
    update: SettingUpdate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_admin),
):
    """Update setting value with validation. Requires admin privileges."""
    from app.services.settings_manager import SettingsManager

    settings_manager = SettingsManager(db)

    # Use SettingsManager.set() which includes validation
    setting = await settings_manager.set(key, update.value)

    # Keep runtime config in sync for timezone setting
    if key == "timezone":
        app_settings.timezone = update.value

    return SettingSchema.model_validate(setting)


@router.post("/bulk", response_model=list[SettingSchema])
async def bulk_update_settings(
    bulk_update: BulkSettingsUpdate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_admin),
):
    """
    Bulk update multiple settings at once with validation.
    Requires admin privileges.

    All settings are validated before being saved to ensure data integrity.
    """
    from app.services.settings_manager import SettingsManager

    settings_manager = SettingsManager(db)
    updated_settings = []

    for key, value in bulk_update.settings.items():
        # Use SettingsManager.set() which includes validation
        setting = await settings_manager.set(key, value)
        updated_settings.append(setting)

        # Keep runtime config in sync for timezone setting
        if key == "timezone":
            app_settings.timezone = value

    return [SettingSchema.model_validate(s) for s in updated_settings]


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
