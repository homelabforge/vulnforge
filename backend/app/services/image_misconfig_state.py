"""Global state manager for image misconfiguration (Trivy) scans."""

from __future__ import annotations

import logging
from typing import Optional, Sequence

from app.utils.timezone import get_now

logger = logging.getLogger(__name__)


class ImageMisconfigState:
    """Track progress for Trivy image misconfiguration scans."""

    def __init__(self):
        self._is_scanning: bool = False
        self._mode: str = "single"
        self._targets: list[str] = []
        self._current_image: Optional[str] = None
        self._progress_current: int = 0
        self._progress_total: int = 0
        self._started_at = None
        self._last_result: Optional[dict] = None

    def start_scan(self, *, total_images: int, mode: str, targets: Sequence[str]):
        """Initialize scan state before launching Trivy misconfiguration jobs."""
        self._is_scanning = True
        self._mode = mode
        self._targets = list(targets)
        self._progress_current = 0
        self._progress_total = max(total_images, 0)
        self._current_image = None
        self._started_at = get_now()
        self._last_result = None
        logger.info(
            "Image misconfiguration scan started (mode=%s, total=%d)",
            mode,
            self._progress_total,
        )

    def update_current_image(self, image_name: str):
        """Record the image currently being processed."""
        if not self._is_scanning:
            # Defensive fallback – treat as single-image scan
            self.start_scan(total_images=1, mode="single", targets=[image_name])
        self._current_image = image_name

    def record_result(self, *, image_name: str, success: bool, error_message: Optional[str]):
        """Store the result for the image that just finished."""
        if self._progress_current < self._progress_total:
            self._progress_current += 1

        self._last_result = {
            "image_name": image_name,
            "success": success,
            "error": error_message,
            "finished_at": get_now().isoformat(),
        }

        if success:
            logger.info("Image misconfiguration scan finished for %s", image_name)
        else:
            logger.warning(
                "Image misconfiguration scan failed for %s: %s",
                image_name,
                error_message or "unknown error",
            )

    def finish_scan(self):
        """Reset state when all scans complete or a task aborts."""
        logger.info("Image misconfiguration scan finished (mode=%s)", self._mode)
        self._is_scanning = False
        self._mode = "single"
        self._targets = []
        self._current_image = None
        self._progress_current = 0
        self._progress_total = 0
        self._started_at = None

    def get_status(self) -> dict:
        """Expose state for polling endpoints."""
        if not self._is_scanning:
            return {"status": "idle", "last_result": self._last_result}

        return {
            "status": "scanning",
            "mode": self._mode,
            "current_image": self._current_image,
            "progress_current": self._progress_current,
            "progress_total": self._progress_total,
            "started_at": self._started_at.isoformat() if self._started_at else None,
            "targets": self._targets,
            "last_result": self._last_result,
        }

    @property
    def is_scanning(self) -> bool:
        """Return True if a scan is currently active."""
        return self._is_scanning


# Shared instance
image_misconfig_state = ImageMisconfigState()
