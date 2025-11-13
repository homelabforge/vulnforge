"""Settings API endpoints."""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_db
from app.dependencies.auth import require_admin
from app.models import Setting
from app.models.user import User
from app.schemas import Setting as SettingSchema, SettingUpdate

router = APIRouter()


class BulkSettingsUpdate(BaseModel):
    """Schema for bulk settings update."""

    settings: dict[str, str]


@router.get("/", response_model=list[SettingSchema])
async def list_settings(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_admin)
):
    """List all settings. Requires admin privileges."""
    result = await db.execute(select(Setting))
    settings = result.scalars().all()
    return [SettingSchema.model_validate(s) for s in settings]


@router.get("/{key}", response_model=SettingSchema)
async def get_setting(
    key: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_admin)
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
    user: User = Depends(require_admin)
):
    """Update setting value with validation. Requires admin privileges."""
    from app.services.settings_manager import SettingsManager

    settings_manager = SettingsManager(db)

    # Use SettingsManager.set() which includes validation
    setting = await settings_manager.set(key, update.value)

    return SettingSchema.model_validate(setting)


@router.post("/bulk", response_model=list[SettingSchema])
async def bulk_update_settings(
    bulk_update: BulkSettingsUpdate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_admin)
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

    return [SettingSchema.model_validate(s) for s in updated_settings]
