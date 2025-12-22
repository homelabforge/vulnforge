"""Global scan state manager for tracking progress."""

from __future__ import annotations

from datetime import datetime

from app.utils.timezone import get_now


class ScanState:
    """Singleton to track current scan state."""

    _instance: ScanState | None = None
    _is_scanning: bool = False
    _current_container: str = ""
    _progress_current: int = 0
    _progress_total: int = 0
    _started_at: datetime | None = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def start_scan(self, total: int):
        """Start a new scan batch."""
        self._is_scanning = True
        self._progress_current = 0
        self._progress_total = total
        self._current_container = ""
        self._started_at = get_now()

    def update_progress(self, container_name: str, current: int):
        """Update scan progress."""
        self._current_container = container_name
        self._progress_current = current

    def finish_scan(self):
        """Mark scan as finished."""
        self._is_scanning = False
        self._current_container = ""
        self._progress_current = 0
        self._progress_total = 0
        self._started_at = None

    def get_status(self) -> dict:
        """Get current scan status."""
        if not self._is_scanning:
            return {"status": "idle", "scan": None}

        return {
            "status": "scanning",
            "current_container": self._current_container,
            "progress_current": self._progress_current,
            "progress_total": self._progress_total,
            "started_at": self._started_at.isoformat() if self._started_at else None,
        }

    @property
    def is_scanning(self) -> bool:
        """Check if a scan is currently running."""
        return self._is_scanning


# Global instance
scan_state = ScanState()
