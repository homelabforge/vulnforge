"""Scanner error classification and handling."""

import logging
import re
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class ScanErrorType(Enum):
    """Types of scan errors with specific handling."""

    NETWORK = "network"  # Network connectivity issues
    DB_UPDATE = "db_update"  # Database update failures
    DB_STALE = "db_stale"  # Database too old
    SCANNER_CRASH = "scanner_crash"  # Scanner process crash
    TIMEOUT = "timeout"  # Scan timeout
    IMAGE_NOT_FOUND = "image_not_found"  # Container image not available
    PERMISSION = "permission"  # Permission denied
    RESOURCE = "resource"  # Resource exhaustion (memory, disk)
    UNKNOWN = "unknown"  # Unclassified error


@dataclass
class ScanError:
    """Classified scan error with actionable suggestions."""

    error_type: ScanErrorType
    scanner_name: str
    original_error: str
    user_message: str
    suggestions: list[str]
    is_retryable: bool
    requires_user_action: bool

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "error_type": self.error_type.value,
            "scanner": self.scanner_name,
            "message": self.user_message,
            "suggestions": self.suggestions,
            "is_retryable": self.is_retryable,
            "requires_user_action": self.requires_user_action,
            "original_error": self.original_error,
        }


class ScanErrorClassifier:
    """
    Classify scan errors and provide actionable suggestions.

    Analyzes error messages from scanners to determine the root cause
    and provide user-friendly explanations with recovery steps.
    """

    # Error patterns for classification
    NETWORK_PATTERNS = [
        r"network.*unreachable",
        r"connection.*refused",
        r"connection.*timed out",
        r"no route to host",
        r"temporary failure.*name resolution",
        r"could not resolve host",
        r"dial tcp.*i/o timeout",
        r"EOF.*connection",
    ]

    DB_UPDATE_PATTERNS = [
        r"failed to download vulnerability db",
        r"db update failed",
        r"unable to download.*database",
        r"failed to fetch.*metadata",
        r"error downloading.*db",
    ]

    TIMEOUT_PATTERNS = [
        r"timeout.*exceeded",
        r"operation.*timed out",
        r"deadline exceeded",
        r"context deadline exceeded",
    ]

    IMAGE_NOT_FOUND_PATTERNS = [
        r"image.*not found",
        r"manifest.*not found",
        r"no such image",
        r"failed to pull image",
    ]

    PERMISSION_PATTERNS = [
        r"permission denied",
        r"access denied",
        r"unauthorized",
        r"forbidden",
    ]

    RESOURCE_PATTERNS = [
        r"out of memory",
        r"no space left",
        r"disk quota exceeded",
        r"resource temporarily unavailable",
    ]

    def classify_error(
        self, scanner_name: str, error_message: str, db_age_hours: int | None = None
    ) -> ScanError:
        """
        Classify a scanner error and provide suggestions.

        Args:
            scanner_name: Name of the scanner that failed
            error_message: Error message from scanner
            db_age_hours: Age of scanner database in hours (if known)

        Returns:
            ScanError with classification and suggestions
        """
        error_lower = error_message.lower()

        # Check network errors
        if self._matches_patterns(error_lower, self.NETWORK_PATTERNS):
            return ScanError(
                error_type=ScanErrorType.NETWORK,
                scanner_name=scanner_name,
                original_error=error_message,
                user_message=f"{scanner_name} cannot reach vulnerability databases due to network connectivity issues",
                suggestions=[
                    "Check internet connectivity to ghcr.io and github.com",
                    "Verify firewall rules allow outbound HTTPS connections",
                    "Enable offline mode to scan with cached databases",
                    "Check if proxy settings are required",
                ],
                is_retryable=True,
                requires_user_action=True,
            )

        # Check DB update errors
        if self._matches_patterns(error_lower, self.DB_UPDATE_PATTERNS):
            return ScanError(
                error_type=ScanErrorType.DB_UPDATE,
                scanner_name=scanner_name,
                original_error=error_message,
                user_message=f"{scanner_name} failed to update vulnerability database",
                suggestions=[
                    "Check network connectivity",
                    "Enable 'Skip DB update when fresh' in scanner settings",
                    "Manually update database: docker exec trivy trivy image --download-db-only",
                    "Check if database mirrors are accessible",
                ],
                is_retryable=True,
                requires_user_action=True,
            )

        # Check timeout errors
        if self._matches_patterns(error_lower, self.TIMEOUT_PATTERNS):
            return ScanError(
                error_type=ScanErrorType.TIMEOUT,
                scanner_name=scanner_name,
                original_error=error_message,
                user_message=f"{scanner_name} scan exceeded timeout threshold",
                suggestions=[
                    "Increase scan timeout in Settings (current: 5 minutes)",
                    "Large images may require longer timeouts",
                    "Check if database update is causing delays",
                    "Consider disabling Grype for faster scans",
                ],
                is_retryable=True,
                requires_user_action=False,
            )

        # Check image errors
        if self._matches_patterns(error_lower, self.IMAGE_NOT_FOUND_PATTERNS):
            return ScanError(
                error_type=ScanErrorType.IMAGE_NOT_FOUND,
                scanner_name=scanner_name,
                original_error=error_message,
                user_message="Container image not found or cannot be pulled",
                suggestions=[
                    "Verify container is running: docker ps",
                    "Check if image has been deleted from registry",
                    "Re-discover containers to update image list",
                    "Check registry authentication if using private images",
                ],
                is_retryable=False,
                requires_user_action=True,
            )

        # Check permission errors
        if self._matches_patterns(error_lower, self.PERMISSION_PATTERNS):
            return ScanError(
                error_type=ScanErrorType.PERMISSION,
                scanner_name=scanner_name,
                original_error=error_message,
                user_message=f"{scanner_name} does not have sufficient permissions",
                suggestions=[
                    "Check Docker socket permissions",
                    "Verify VulnForge has access to Docker API",
                    "Check registry authentication for private images",
                    "Review Docker socket proxy configuration",
                ],
                is_retryable=False,
                requires_user_action=True,
            )

        # Check resource errors
        if self._matches_patterns(error_lower, self.RESOURCE_PATTERNS):
            return ScanError(
                error_type=ScanErrorType.RESOURCE,
                scanner_name=scanner_name,
                original_error=error_message,
                user_message="Insufficient system resources (memory/disk)",
                suggestions=[
                    "Check available disk space: df -h",
                    "Check memory usage: free -h",
                    "Clean up old scan data in Maintenance",
                    "Reduce parallel scan count in Settings",
                ],
                is_retryable=True,
                requires_user_action=True,
            )

        # Check stale database
        if db_age_hours and db_age_hours > 168:  # 7 days
            return ScanError(
                error_type=ScanErrorType.DB_STALE,
                scanner_name=scanner_name,
                original_error=error_message,
                user_message=f"{scanner_name} database is very old ({db_age_hours} hours) and may have outdated CVE data",
                suggestions=[
                    f"Database last updated: {db_age_hours} hours ago",
                    "Update database: docker exec trivy trivy image --download-db-only",
                    "Check internet connectivity for automatic updates",
                    "Consider reducing 'Max DB age' threshold in settings",
                ],
                is_retryable=True,
                requires_user_action=True,
            )

        # Default: unclassified error
        return ScanError(
            error_type=ScanErrorType.UNKNOWN,
            scanner_name=scanner_name,
            original_error=error_message,
            user_message=f"{scanner_name} scan failed with an unclassified error",
            suggestions=[
                "Check scanner logs for details",
                "Retry the scan - transient issues may resolve",
                "Report issue if error persists",
                "Check GitHub issues: github.com/yourusername/vulnforge/issues",
            ],
            is_retryable=True,
            requires_user_action=False,
        )

    def _matches_patterns(self, text: str, patterns: list[str]) -> bool:
        """Check if text matches any of the given patterns."""
        return any(re.search(pattern, text, re.IGNORECASE) for pattern in patterns)


# Singleton instance
_error_classifier: ScanErrorClassifier | None = None


def get_error_classifier() -> ScanErrorClassifier:
    """Get or create the global error classifier instance."""
    global _error_classifier
    if _error_classifier is None:
        _error_classifier = ScanErrorClassifier()
    return _error_classifier
