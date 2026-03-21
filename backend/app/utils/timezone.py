"""Timezone utilities for VulnForge.

Reads timezone from ``app.config.settings.timezone`` synchronously. This value
is mutated in-process by the settings route when the user changes timezone.
This pattern is intentional — VulnForge runs as a single Granian worker (see
``main.py`` docstring), so ``settings`` is a shared in-process object.

Do NOT route this through SettingsManager — ``get_now()`` is synchronous and
used in ORM model defaults (``container.py``, ``scan.py``).
"""

from datetime import datetime
from zoneinfo import ZoneInfo

from app.config import settings


def get_now() -> datetime:
    """
    Get current datetime in the configured timezone.

    Returns:
        Timezone-aware datetime in the configured timezone
    """
    try:
        tz = ZoneInfo(settings.timezone)
        return datetime.now(tz)
    except Exception:
        # Fallback to UTC if timezone is invalid
        return datetime.now(ZoneInfo("UTC"))


def get_timezone() -> ZoneInfo:
    """
    Get the configured timezone.

    Returns:
        ZoneInfo object for the configured timezone
    """
    try:
        return ZoneInfo(settings.timezone)
    except Exception:
        # Fallback to UTC if timezone is invalid
        return ZoneInfo("UTC")


def to_local(dt: datetime) -> datetime:
    """
    Convert a datetime to the configured timezone.

    Args:
        dt: Datetime to convert (can be naive or aware)

    Returns:
        Timezone-aware datetime in the configured timezone
    """
    tz = get_timezone()

    # If naive, assume UTC
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=ZoneInfo("UTC"))

    # Convert to local timezone
    return dt.astimezone(tz)
