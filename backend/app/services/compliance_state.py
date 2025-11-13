"""Global compliance scan state manager for tracking progress."""

import logging
from datetime import datetime
from typing import Optional
from app.utils.timezone import get_now

logger = logging.getLogger(__name__)


# Global state variables (module-level to ensure true global access)
_is_scanning: bool = False
_current_check: str = ""
_current_check_id: str = ""
_progress_current: int = 0
_progress_total: int = 0
_started_at: Optional[datetime] = None


class ComplianceState:
    """Global compliance scan state manager."""

    def __init__(self):
        """Initialize state manager."""
        pass

    def start_scan(self, total_checks: int = 150):
        """Start a new compliance scan."""
        global _is_scanning, _progress_current, _progress_total, _current_check, _current_check_id, _started_at
        _is_scanning = True
        _progress_current = 0
        _progress_total = total_checks
        _current_check = "Initializing Docker Bench scan..."
        _current_check_id = ""
        _started_at = get_now()
        logger.info(f"DEBUG start_scan: Set _is_scanning={_is_scanning}, total={total_checks}")

    def update_progress(self, check_id: str, check_title: str, completed: int):
        """Update scan progress with current check."""
        global _current_check_id, _current_check, _progress_current
        _current_check_id = check_id
        _current_check = check_title
        _progress_current = completed

    def finish_scan(self):
        """Mark scan as finished."""
        global _is_scanning, _current_check, _current_check_id, _progress_current, _progress_total, _started_at
        _is_scanning = False
        _current_check = ""
        _current_check_id = ""
        _progress_current = 0
        _progress_total = 0
        _started_at = None

    def get_status(self) -> dict:
        """Get current compliance scan status."""
        global _is_scanning, _current_check, _current_check_id, _progress_current, _progress_total, _started_at

        # DEBUG: Log the actual global variable values
        logger.info(f"DEBUG get_status: _is_scanning={_is_scanning}, progress={_progress_current}/{_progress_total}, check_id={_current_check_id}")

        if not _is_scanning:
            return {"status": "idle"}

        return {
            "status": "scanning",
            "current_check": _current_check,
            "current_check_id": _current_check_id,
            "progress_current": _progress_current,
            "progress_total": _progress_total,
            "started_at": _started_at.isoformat() if _started_at else None,
        }

    @property
    def is_scanning(self) -> bool:
        """Check if a compliance scan is currently running."""
        global _is_scanning
        return _is_scanning


# Global instance
compliance_state = ComplianceState()
