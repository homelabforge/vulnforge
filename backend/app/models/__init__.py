"""Database models for VulnForge."""

from app.models.activity_log import ActivityLog
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
from app.models.vulnerability import Vulnerability

# Compatibility alias: ScanResult is now Scan
# This maintains backward compatibility with older tests
ScanResult = Scan

__all__ = [
    "ActivityLog",
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
    "Vulnerability",
]
