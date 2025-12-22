"""Enhanced notification service with templates and rules."""

import logging
from string import Template
from typing import Any

from sqlalchemy import select

from app.db import db_session
from app.models import NotificationLog, NotificationRule
from app.services.notifications import NotificationDispatcher
from app.utils.timezone import get_now

logger = logging.getLogger(__name__)

# Priority mapping from int (1-5) to string
PRIORITY_INT_TO_STR = {
    1: "min",
    2: "low",
    3: "default",
    4: "high",
    5: "urgent",
}


class EnhancedNotificationService:
    """Enhanced notification service with rule-based templates and logging."""

    def __init__(self):
        """Initialize enhanced notification service."""
        pass  # No longer needs base_notifier - uses dispatcher per-request

    async def send_notification_with_logging(
        self,
        notification_type: str,
        message: str,
        title: str | None = None,
        priority: int = 3,
        tags: list[str] | None = None,
        scan_id: int | None = None,
    ) -> bool:
        """
        Send notification and log it to database.

        Args:
            notification_type: Type of notification (e.g., "scan_complete")
            message: Notification message
            title: Optional title
            priority: Priority level (1-5)
            tags: Optional tags
            scan_id: Associated scan ID

        Returns:
            True if sent successfully
        """
        async with db_session() as db:
            try:
                # Send notification using multi-service dispatcher
                dispatcher = NotificationDispatcher(db)
                priority_str = PRIORITY_INT_TO_STR.get(priority, "default")

                results = await dispatcher.dispatch(
                    event_type=notification_type,
                    title=title or "VulnForge Notification",
                    message=message,
                    priority=priority_str,
                    tags=tags,
                )

                # Check if any service succeeded
                sent = any(results.values()) if results else False
                channels = ",".join(k for k, v in results.items() if v) if results else "none"

                # Log notification
                log_entry = NotificationLog(
                    scan_id=scan_id,
                    notification_type=notification_type,
                    channel=channels if channels else "none",
                    title=title,
                    message=message,
                    status="sent" if sent else "failed",
                    priority=priority,
                    tags=",".join(tags) if tags else None,
                    sent_at=get_now() if sent else None,
                )
                db.add(log_entry)
                await db.commit()

                return sent

            except Exception as e:
                logger.error(f"Error sending/logging notification: {e}")
                # Try to log the failure
                try:
                    log_entry = NotificationLog(
                        scan_id=scan_id,
                        notification_type=notification_type,
                        channel="error",
                        title=title,
                        message=message,
                        status="failed",
                        error_message=str(e),
                        priority=priority,
                        tags=",".join(tags) if tags else None,
                    )
                    db.add(log_entry)
                    await db.commit()
                except Exception as log_error:
                    logger.error(f"Failed to log notification error: {log_error}")

                return False

    def render_template(self, template: str, context: dict[str, Any]) -> str:
        """
        Render a notification template with context variables using safe substitution.

        Security: Uses string.Template.safe_substitute() to prevent code injection.
        Template syntax: $variable or ${variable} (no arbitrary code execution).

        Args:
            template: Template string with $variable placeholders
            context: Dictionary of variables to substitute

        Returns:
            Rendered message with safe substitution
        """
        try:
            # Use safe_substitute to prevent format string attacks and code injection
            # This only allows simple variable substitution, no attribute access or code execution
            return Template(template).safe_substitute(context)
        except Exception as e:
            logger.error(f"Template rendering error: {e}")
            return template

    async def evaluate_rule(self, rule: NotificationRule, context: dict[str, Any]) -> bool:
        """
        Evaluate if a notification rule should trigger.

        Args:
            rule: Notification rule to evaluate
            context: Scan/event context data

        Returns:
            True if rule conditions are met
        """
        if not rule.enabled:
            return False

        # Check thresholds
        if rule.min_critical is not None:
            if context.get("critical_count", 0) < rule.min_critical:
                return False

        if rule.min_high is not None:
            if context.get("high_count", 0) < rule.min_high:
                return False

        if rule.min_medium is not None:
            if context.get("medium_count", 0) < rule.min_medium:
                return False

        if rule.min_total is not None:
            if context.get("total_vulns", 0) < rule.min_total:
                return False

        return True

    async def process_rules(
        self,
        event_type: str,
        context: dict[str, Any],
        scan_id: int | None = None,
    ) -> int:
        """
        Process all notification rules for an event.

        Args:
            event_type: Type of event (e.g., "scan_complete")
            context: Event context data
            scan_id: Associated scan ID

        Returns:
            Number of notifications sent
        """
        sent_count = 0

        async with db_session() as db:
            # Get all matching rules
            result = await db.execute(
                select(NotificationRule).where(
                    NotificationRule.event_type == event_type,
                    NotificationRule.enabled,
                )
            )
            rules = result.scalars().all()

            for rule in rules:
                # Evaluate rule conditions
                if not await self.evaluate_rule(rule, context):
                    logger.debug(f"Rule {rule.name} conditions not met, skipping")
                    continue

                # Render templates
                title = None
                if rule.title_template:
                    title = self.render_template(rule.title_template, context)

                message = self.render_template(rule.message_template, context)

                # Parse tags
                tags = None
                if rule.tags:
                    tags = [tag.strip() for tag in rule.tags.split(",")]

                # Send notification
                sent = await self.send_notification_with_logging(
                    notification_type=f"{event_type}_{rule.name}",
                    message=message,
                    title=title,
                    priority=rule.priority,
                    tags=tags,
                    scan_id=scan_id,
                )

                if sent:
                    sent_count += 1
                    logger.info(f"Sent notification for rule: {rule.name}")

            return sent_count

    async def create_default_rules(self):
        """Create default notification rules if none exist."""
        async with db_session() as db:
            # Check if any rules exist
            result = await db.execute(select(NotificationRule))
            existing_rules = result.scalars().all()

            if len(existing_rules) > 0:
                logger.info(f"Found {len(existing_rules)} notification rules, skipping defaults")
                return

            # Create default rules
            default_rules = [
                NotificationRule(
                    name="critical_vulnerabilities",
                    description="Alert on containers with critical vulnerabilities",
                    event_type="scan_complete",
                    min_critical=1,
                    title_template="VulnForge: Critical Vulnerabilities",
                    message_template="{container_name}: {critical_count} critical vulnerabilities ({fixable_count} fixable)",
                    priority=5,
                    tags="warning,rotating_light,VulnForge",
                ),
                NotificationRule(
                    name="high_risk_container",
                    description="Alert on containers with many high-severity issues",
                    event_type="scan_complete",
                    min_high=10,
                    title_template="VulnForge: High Risk Container",
                    message_template="{container_name}: {total_vulns} total vulnerabilities ({high_count} high, {critical_count} critical)",
                    priority=4,
                    tags="warning,VulnForge",
                ),
                NotificationRule(
                    name="scan_complete_summary",
                    description="Summary notification for all scan completions",
                    event_type="scan_batch_complete",
                    title_template="VulnForge: Scan Complete",
                    message_template="Scanned {total_containers} containers: {total_vulns} vulnerabilities ({critical_count} critical, {high_count} high)",
                    priority=3,
                    tags="shield,VulnForge",
                ),
                NotificationRule(
                    name="scan_failed",
                    description="Alert when container scan fails",
                    event_type="scan_failed",
                    title_template="VulnForge: Scan Failed",
                    message_template="Failed to scan {container_name}: {error}",
                    priority=4,
                    tags="x,VulnForge",
                ),
            ]

            for rule in default_rules:
                db.add(rule)

            await db.commit()
            logger.info(f"Created {len(default_rules)} default notification rules")


# Global enhanced notifier instance
_enhanced_notifier: EnhancedNotificationService | None = None


def get_enhanced_notifier() -> EnhancedNotificationService:
    """Get or create the global enhanced notifier instance."""
    global _enhanced_notifier
    if _enhanced_notifier is None:
        _enhanced_notifier = EnhancedNotificationService()
    return _enhanced_notifier
