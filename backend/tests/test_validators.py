"""Tests for validator utility functions."""

import pytest

from app.validators import (
    ValidationError,
    sanitize_string,
    validate_boolean,
    validate_cron_expression,
    validate_log_level,
    validate_positive_integer,
    validate_priority,
    validate_severity,
    validate_topic_name,
    validate_url,
)


class TestCronExpression:
    """Cron expression validation behaviour."""

    def test_accepts_valid_cron(self):
        valid_values = [
            "0 2 * * *",
            "*/15 * * * *",
            "0 */6 * * *",
            "30 3 1 * *",
        ]
        for cron in valid_values:
            assert validate_cron_expression(cron) == cron

    @pytest.mark.parametrize(
        "cron",
        ["", "invalid", "* * * *", "60 * * * *"],
    )
    def test_rejects_invalid_cron(self, cron):
        with pytest.raises(ValidationError):
            validate_cron_expression(cron)


class TestURLValidation:
    """URL validation behaviour."""

    @pytest.mark.parametrize(
        "url",
        ["https://example.com", "http://localhost:8080", "https://api.example.com/path"],
    )
    def test_accepts_valid_urls(self, url):
        assert validate_url(url) == url

    @pytest.mark.parametrize(
        "url",
        ["", "ftp://example.com", "file:///etc/passwd", "not a url"],
    )
    def test_rejects_invalid_urls(self, url):
        with pytest.raises(ValidationError):
            validate_url(url)


class TestSeverityValidation:
    """Severity validation rules."""

    def test_valid_severities(self):
        for severity in ["critical", "HIGH", "Medium", "low", "UNKNOWN"]:
            assert validate_severity(severity) == severity.upper()

    @pytest.mark.parametrize("severity", ["", "urgent", "medium-high"])
    def test_invalid_severities(self, severity):
        with pytest.raises(ValidationError):
            validate_severity(severity)


class TestLogLevelValidation:
    """Logging level validation."""

    def test_valid_log_levels(self):
        for level in ["debug", "INFO", "Warning", "ERROR", "critical"]:
            assert validate_log_level(level) == level.upper()

    @pytest.mark.parametrize("level", ["", "Verbose", "notice"])
    def test_invalid_log_levels(self, level):
        with pytest.raises(ValidationError):
            validate_log_level(level)


class TestPositiveIntegerValidation:
    """Integer range validation."""

    def test_accepts_values_within_range(self):
        assert validate_positive_integer(5, "test", min_value=1, max_value=10) == 5
        assert validate_positive_integer("3", "test", min_value=1, max_value=5) == 3

    def test_rejects_out_of_range(self):
        with pytest.raises(ValidationError):
            validate_positive_integer(0, "test", min_value=1)
        with pytest.raises(ValidationError):
            validate_positive_integer(11, "test", min_value=1, max_value=10)


class TestBooleanValidation:
    """Boolean parsing validation."""

    @pytest.mark.parametrize("value", [True, "true", "1", "Yes", "ON"])
    def test_truthy_values(self, value):
        assert validate_boolean(value, "flag") is True

    @pytest.mark.parametrize("value", [False, "false", "0", "No", "off"])
    def test_falsy_values(self, value):
        assert validate_boolean(value, "flag") is False

    def test_invalid_boolean(self):
        with pytest.raises(ValidationError):
            validate_boolean("maybe", "flag")


class TestTopicValidation:
    """Topic name validation."""

    def test_valid_topics(self):
        for topic in ["vulnforge", "topic-123", "Another_topic"]:
            assert validate_topic_name(topic) == topic

    @pytest.mark.parametrize(
        "topic",
        ["", "topic with spaces", "topic/slash", "!" * 5, "a" * 70],
    )
    def test_invalid_topics(self, topic):
        with pytest.raises(ValidationError):
            validate_topic_name(topic)


class TestPriorityValidation:
    """Notification priority validation."""

    def test_priority_bounds(self):
        assert validate_priority(3) == 3
        with pytest.raises(ValidationError):
            validate_priority(0)
        with pytest.raises(ValidationError):
            validate_priority(6)


class TestSanitizeString:
    """String sanitisation rules."""

    def test_trims_and_limits_length(self):
        assert sanitize_string("  hello  ") == "hello"
        with pytest.raises(ValidationError):
            sanitize_string("a" * 300, max_length=100)
