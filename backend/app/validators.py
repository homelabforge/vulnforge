"""Input validation utilities for security hardening."""

import re
from typing import Any
from urllib.parse import urlparse

from croniter import croniter
from fastapi import HTTPException


class ValidationError(HTTPException):
    """Custom validation error exception."""

    def __init__(self, detail: str):
        super().__init__(status_code=400, detail=detail)


def validate_cron_expression(cron_expr: str) -> str:
    """
    Validate cron expression format.

    Args:
        cron_expr: Cron expression to validate

    Returns:
        Validated cron expression

    Raises:
        ValidationError: If cron expression is invalid
    """
    if not cron_expr or not isinstance(cron_expr, str):
        raise ValidationError("Cron expression must be a non-empty string")

    try:
        croniter(cron_expr)
    except Exception as e:
        raise ValidationError(f"Invalid cron expression: {str(e)}")

    return cron_expr


def validate_url(url: str, allowed_schemes: list[str] | None = None) -> str:
    """
    Validate URL format and scheme.

    Args:
        url: URL to validate
        allowed_schemes: List of allowed URL schemes (default: http, https)

    Returns:
        Validated URL

    Raises:
        ValidationError: If URL is invalid
    """
    if not url or not isinstance(url, str):
        raise ValidationError("URL must be a non-empty string")

    if allowed_schemes is None:
        allowed_schemes = ["http", "https"]

    try:
        parsed = urlparse(url)
        if not parsed.scheme:
            raise ValidationError("URL must include a scheme (http:// or https://)")
        if parsed.scheme not in allowed_schemes:
            raise ValidationError(f"URL scheme must be one of: {', '.join(allowed_schemes)}")
        if not parsed.netloc:
            raise ValidationError("URL must include a host")
    except ValidationError:
        raise
    except Exception as e:
        raise ValidationError(f"Invalid URL format: {str(e)}")

    return url


def validate_severity(severity: str) -> str:
    """
    Validate vulnerability severity level.

    Args:
        severity: Severity level to validate

    Returns:
        Validated severity (uppercase)

    Raises:
        ValidationError: If severity is invalid
    """
    valid_severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]

    if not severity or not isinstance(severity, str):
        raise ValidationError("Severity must be a non-empty string")

    severity_upper = severity.upper()
    if severity_upper not in valid_severities:
        raise ValidationError(
            f"Invalid severity level. Must be one of: {', '.join(valid_severities)}"
        )

    return severity_upper


def validate_log_level(log_level: str) -> str:
    """
    Validate logging level.

    Args:
        log_level: Log level to validate

    Returns:
        Validated log level (uppercase)

    Raises:
        ValidationError: If log level is invalid
    """
    valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]

    if not log_level or not isinstance(log_level, str):
        raise ValidationError("Log level must be a non-empty string")

    log_level_upper = log_level.upper()
    if log_level_upper not in valid_levels:
        raise ValidationError(
            f"Invalid log level. Must be one of: {', '.join(valid_levels)}"
        )

    return log_level_upper


def validate_positive_integer(value: Any, name: str, min_value: int = 1, max_value: int | None = None) -> int:
    """
    Validate that a value is a positive integer within range.

    Args:
        value: Value to validate
        name: Name of the field (for error messages)
        min_value: Minimum allowed value (default: 1)
        max_value: Maximum allowed value (optional)

    Returns:
        Validated integer

    Raises:
        ValidationError: If value is invalid
    """
    try:
        int_value = int(value)
    except (ValueError, TypeError):
        raise ValidationError(f"{name} must be an integer")

    if int_value < min_value:
        raise ValidationError(f"{name} must be at least {min_value}")

    if max_value is not None and int_value > max_value:
        raise ValidationError(f"{name} must be at most {max_value}")

    return int_value


def validate_boolean(value: Any, name: str) -> bool:
    """
    Validate and convert value to boolean.

    Args:
        value: Value to validate
        name: Name of the field (for error messages)

    Returns:
        Validated boolean

    Raises:
        ValidationError: If value cannot be converted to boolean
    """
    if isinstance(value, bool):
        return value

    if isinstance(value, str):
        if value.lower() in ("true", "1", "yes", "on"):
            return True
        if value.lower() in ("false", "0", "no", "off"):
            return False

    raise ValidationError(f"{name} must be a boolean value (true/false)")


def validate_topic_name(topic: str) -> str:
    """
    Validate ntfy topic name.

    Args:
        topic: Topic name to validate

    Returns:
        Validated topic name

    Raises:
        ValidationError: If topic name is invalid
    """
    if not topic or not isinstance(topic, str):
        raise ValidationError("Topic name must be a non-empty string")

    # Topic names should be alphanumeric with hyphens/underscores
    if not re.match(r"^[a-zA-Z0-9_-]+$", topic):
        raise ValidationError(
            "Topic name can only contain letters, numbers, hyphens, and underscores"
        )

    if len(topic) < 1 or len(topic) > 64:
        raise ValidationError("Topic name must be between 1 and 64 characters")

    return topic


def validate_priority(priority: Any) -> int:
    """
    Validate notification priority (1-5).

    Args:
        priority: Priority value to validate

    Returns:
        Validated priority integer

    Raises:
        ValidationError: If priority is invalid
    """
    return validate_positive_integer(priority, "Priority", min_value=1, max_value=5)


def sanitize_string(value: str, max_length: int = 1000) -> str:
    """
    Sanitize string input by trimming whitespace and limiting length.

    Args:
        value: String to sanitize
        max_length: Maximum allowed length

    Returns:
        Sanitized string

    Raises:
        ValidationError: If string is too long
    """
    if not isinstance(value, str):
        raise ValidationError("Value must be a string")

    sanitized = value.strip()

    if len(sanitized) > max_length:
        raise ValidationError(f"Value exceeds maximum length of {max_length} characters")

    return sanitized
