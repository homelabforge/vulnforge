"""Database models for VulnForge."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.models.activity_log import ActivityLog
    from app.models.api_key import APIKey
    from app.models.compliance_finding import ComplianceFinding
    from app.models.compliance_scan import ComplianceScan
    from app.models.container import Container
    from app.models.false_positive_pattern import FalsePositivePattern
    from app.models.image_compliance_finding import ImageComplianceFinding
    from app.models.image_compliance_scan import ImageComplianceScan
    from app.models.notification_log import NotificationLog
    from app.models.notification_rule import NotificationRule
    from app.models.scan import Scan
    from app.models.secret import Secret
    from app.models.setting import Setting
    from app.models.user import User
    from app.models.vulnerability import Vulnerability

    # Legacy alias for backward compatibility
    ScanResult = Scan

__all__ = [
    "ActivityLog",
    "APIKey",
    "ComplianceFinding",
    "ComplianceScan",
    "Container",
    "FalsePositivePattern",
    "ImageComplianceFinding",
    "ImageComplianceScan",
    "NotificationLog",
    "NotificationRule",
    "Scan",
    "ScanResult",  # Legacy alias
    "Secret",
    "Setting",
    "User",
    "Vulnerability",
]


def __getattr__(name: str):
    """Lazy-load models to avoid circular imports."""
    if name == "ActivityLog":
        from app.models.activity_log import ActivityLog

        return ActivityLog
    if name == "APIKey":
        from app.models.api_key import APIKey

        return APIKey
    if name == "ComplianceFinding":
        from app.models.compliance_finding import ComplianceFinding

        return ComplianceFinding
    if name == "ComplianceScan":
        from app.models.compliance_scan import ComplianceScan

        return ComplianceScan
    if name == "Container":
        from app.models.container import Container

        return Container
    if name == "FalsePositivePattern":
        from app.models.false_positive_pattern import FalsePositivePattern

        return FalsePositivePattern
    if name == "ImageComplianceFinding":
        from app.models.image_compliance_finding import ImageComplianceFinding

        return ImageComplianceFinding
    if name == "ImageComplianceScan":
        from app.models.image_compliance_scan import ImageComplianceScan

        return ImageComplianceScan
    if name == "NotificationLog":
        from app.models.notification_log import NotificationLog

        return NotificationLog
    if name == "NotificationRule":
        from app.models.notification_rule import NotificationRule

        return NotificationRule
    if name == "Scan":
        from app.models.scan import Scan

        return Scan
    if name == "ScanResult":
        # Compatibility alias: ScanResult is now Scan
        from app.models.scan import Scan

        return Scan
    if name == "Secret":
        from app.models.secret import Secret

        return Secret
    if name == "Setting":
        from app.models.setting import Setting

        return Setting
    if name == "User":
        from app.models.user import User

        return User
    if name == "Vulnerability":
        from app.models.vulnerability import Vulnerability

        return Vulnerability
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
