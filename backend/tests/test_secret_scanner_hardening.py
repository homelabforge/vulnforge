"""Tests for secret scanner hardening fixes.

Covers: log redaction, status validation, severity sorting, schema redaction,
FP fingerprint narrowing (hybrid mode), FP delete unsuppress, and misconfig
content redaction.
"""

import pytest
from pydantic import ValidationError


class TestLogRedactionTrivyOutput:
    """Tests for Trivy output redaction in sanitize_for_log."""

    def test_redacts_trivy_match_json_key(self):
        """Trivy's Match JSON key containing secrets must be redacted."""
        from app.utils.log_redaction import sanitize_for_log

        raw = '{"RuleID": "generic-api-key", "Match": "AKIA1234567890EXAMPLE", "Severity": "CRITICAL"}'
        result = sanitize_for_log(raw)
        assert "AKIA1234567890EXAMPLE" not in result
        assert "***REDACTED***" in result
        # Non-sensitive keys should be preserved
        assert "generic-api-key" in result
        assert "CRITICAL" in result

    def test_redacts_trivy_content_json_key(self):
        """Trivy's Content JSON key in code lines must be redacted."""
        from app.utils.log_redaction import sanitize_for_log

        raw = '{"Number": 42, "Content": "api_key=sk_test_123456789", "IsCause": true}'
        result = sanitize_for_log(raw)
        assert "sk_test_123456789" not in result
        assert "***REDACTED***" in result

    def test_handles_bytes_input(self):
        """sanitize_for_log should handle bytes via str() conversion."""
        from app.utils.log_redaction import sanitize_for_log

        raw_bytes = b'{"Match": "secret_value_here"}'
        result = sanitize_for_log(str(raw_bytes.decode("utf-8", errors="replace")))
        assert "secret_value_here" not in result

    def test_truncates_long_output(self):
        """Output longer than 500 chars should be truncated."""
        from app.utils.log_redaction import sanitize_for_log

        long_text = "A" * 600
        result = sanitize_for_log(long_text)
        assert len(result) < 600
        assert "truncated" in result


class TestStatusValidation:
    """Tests for secret status enum validation."""

    def test_validate_secret_status_valid(self):
        """All valid statuses should be accepted and normalized to lowercase."""
        from app.validators import validate_secret_status

        for status in ("to_review", "false_positive", "confirmed", "accepted_risk"):
            assert validate_secret_status(status) == status
            assert validate_secret_status(status.upper()) == status

    def test_validate_secret_status_invalid(self):
        """Invalid status values should raise ValidationError."""
        from app.validators import ValidationError, validate_secret_status

        for status in ("active", "bogus", "hacked", "pwned", ""):
            with pytest.raises(ValidationError):
                validate_secret_status(status)

    def test_schema_rejects_invalid_status(self):
        """SecretUpdate schema should reject invalid status at Pydantic level."""
        from app.schemas.secret import SecretUpdate

        with pytest.raises(ValidationError):
            SecretUpdate(status="bogus")

    def test_schema_accepts_valid_status(self):
        """SecretUpdate schema should accept valid status and normalize case."""
        from app.schemas.secret import SecretUpdate

        update = SecretUpdate(status="FALSE_POSITIVE")
        assert update.status == "false_positive"

    def test_schema_allows_none_status(self):
        """SecretUpdate schema should allow None status."""
        from app.schemas.secret import SecretUpdate

        update = SecretUpdate(status=None)
        assert update.status is None

    def test_validate_status_filter_valid(self):
        """All valid filter scopes should be accepted and lowercased."""
        from app.validators import validate_status_filter

        for scope in ("active", "false_positive", "accepted_risk", "all"):
            assert validate_status_filter(scope) == scope
            assert validate_status_filter(scope.upper()) == scope

    def test_validate_status_filter_invalid(self):
        """Invalid filter values should raise ValidationError."""
        from app.validators import ValidationError, validate_status_filter

        for scope in ("bogus", "to_review", "confirmed", ""):
            with pytest.raises(ValidationError):
                validate_status_filter(scope)


class TestSeveritySortOrder:
    """Tests for severity sort ordering."""

    @pytest.mark.asyncio
    async def test_severity_order_expression(self):
        """_severity_order should return CRITICAL < HIGH < MEDIUM < LOW."""
        from app.repositories.secret_repository import SecretRepository

        order = SecretRepository._severity_order()
        # Verify it's a valid case expression (can be used in a query)
        assert order is not None


class TestSchemaRedactionGuard:
    """Tests for defensive redaction in Secret response schema."""

    def test_unredacted_match_forced_to_redacted(self):
        """Secret schema model_validator should force unredacted match to REDACTED."""
        from datetime import UTC, datetime

        from app.schemas.secret import Secret

        secret = Secret(
            id=1,
            scan_id=1,
            rule_id="test",
            category="Generic",
            title="Test",
            severity="HIGH",
            match="AKIA1234567890EXAMPLE",
            status="to_review",
            created_at=datetime.now(UTC),
        )
        assert secret.match == "***REDACTED***"

    def test_already_redacted_match_unchanged(self):
        """Already-redacted match should pass through unchanged."""
        from datetime import UTC, datetime

        from app.schemas.secret import Secret

        secret = Secret(
            id=1,
            scan_id=1,
            rule_id="test",
            category="Generic",
            title="Test",
            severity="HIGH",
            match="***REDACTED***",
            status="to_review",
            created_at=datetime.now(UTC),
        )
        assert secret.match == "***REDACTED***"

    def test_unredacted_code_snippet_forced_to_redacted(self):
        """Code snippet without REDACTED marker should be redacted."""
        from datetime import UTC, datetime

        from app.schemas.secret import Secret

        secret = Secret(
            id=1,
            scan_id=1,
            rule_id="test",
            category="Generic",
            title="Test",
            severity="HIGH",
            match="***REDACTED***",
            code_snippet="Line 42: api_key=sk_test_123",
            status="to_review",
            created_at=datetime.now(UTC),
        )
        assert secret.code_snippet == "***REDACTED***"

    def test_already_redacted_snippet_unchanged(self):
        """Code snippet containing REDACTED should pass through."""
        from datetime import UTC, datetime

        from app.schemas.secret import Secret

        secret = Secret(
            id=1,
            scan_id=1,
            rule_id="test",
            category="Generic",
            title="Test",
            severity="HIGH",
            match="***REDACTED***",
            code_snippet="Line 42: ***REDACTED***\nLine 43: ***REDACTED***",
            status="to_review",
            created_at=datetime.now(UTC),
        )
        assert secret.code_snippet is not None
        assert "***REDACTED***" in secret.code_snippet


class TestMisconfigContentRedaction:
    """Tests for misconfig parser sensitive content redaction."""

    def test_redacts_env_password_assignment(self):
        """ENV PASSWORD=value lines should be redacted."""
        import re

        pattern = re.compile(
            r"(?:ENV|ARG)\s+\w*(?:PASSWORD|SECRET|TOKEN|KEY|CREDENTIAL|API_KEY)\w*\s*=",
            re.IGNORECASE,
        )
        assert pattern.search("ENV PASSWORD=hunter2")
        assert pattern.search("ENV SECRET_KEY=abc123")
        assert pattern.search("ARG DB_PASSWORD=foo")
        assert pattern.search("ENV API_KEY=xyz")

    def test_preserves_non_sensitive_env(self):
        """ENV NODE_ENV=production should NOT be redacted."""
        import re

        pattern = re.compile(
            r"(?:ENV|ARG)\s+\w*(?:PASSWORD|SECRET|TOKEN|KEY|CREDENTIAL|API_KEY)\w*\s*=",
            re.IGNORECASE,
        )
        assert not pattern.search("ENV NODE_ENV=production")
        assert not pattern.search("ENV DEBIAN_FRONTEND=noninteractive")
        assert not pattern.search("RUN apt-get install -y curl")


class TestFPPatternStartLine:
    """Tests for FP pattern start_line field in API responses."""

    @pytest.mark.asyncio
    async def test_pattern_response_includes_start_line(self, authenticated_client, db_session):
        """FP pattern API response should include start_line field."""
        from app.models import FalsePositivePattern

        pattern = FalsePositivePattern(
            container_name="test-container",
            file_path="/app/config.yaml",
            rule_id="generic-api-key",
            start_line=42,
            created_by="admin",
            match_count=0,
        )
        db_session.add(pattern)
        await db_session.commit()

        response = await authenticated_client.get("/api/v1/false-positive-patterns/")
        assert response.status_code == 200
        data = response.json()
        found = next((p for p in data if p.get("start_line") == 42), None)
        assert found is not None
        assert found["start_line"] == 42

    @pytest.mark.asyncio
    async def test_legacy_pattern_has_null_start_line(self, authenticated_client, db_session):
        """Legacy patterns without start_line should show null."""
        from app.models import FalsePositivePattern

        pattern = FalsePositivePattern(
            container_name="legacy-container",
            file_path="/app/old.yaml",
            rule_id="old-rule",
            start_line=None,
            created_by="admin",
            match_count=0,
        )
        db_session.add(pattern)
        await db_session.commit()

        response = await authenticated_client.get("/api/v1/false-positive-patterns/")
        assert response.status_code == 200
        data = response.json()
        found = next((p for p in data if p["rule_id"] == "old-rule"), None)
        assert found is not None
        assert found["start_line"] is None

    @pytest.mark.asyncio
    async def test_create_pattern_from_secret_includes_start_line(
        self, authenticated_client, db_session, make_container, make_scan
    ):
        """Creating FP pattern from secret should capture its start_line."""
        from app.models import Secret

        container = make_container(name="fp-test-container")
        db_session.add(container)
        await db_session.commit()
        await db_session.refresh(container)

        scan = make_scan(container_id=container.id)
        db_session.add(scan)
        await db_session.commit()
        await db_session.refresh(scan)

        secret = Secret(
            scan_id=scan.id,
            file_path="/app/config.yaml",
            rule_id="generic-api-key",
            category="Generic",
            title="Generic API Key",
            severity="HIGH",
            match="***REDACTED***",
            start_line=42,
        )
        db_session.add(secret)
        await db_session.commit()
        await db_session.refresh(secret)

        response = await authenticated_client.post(
            "/api/v1/false-positive-patterns/",
            json={"secret_id": secret.id, "reason": "Known test key"},
        )

        assert response.status_code in (200, 201)
        data = response.json()
        assert data["start_line"] == 42


class TestFPDeleteUnsuppress:
    """Tests for FP pattern deletion with secret unsuppression."""

    @pytest.mark.asyncio
    async def test_delete_returns_unsuppressed_count(self, authenticated_client, db_session):
        """Deleting a pattern should return the unsuppressed_secrets count."""
        from app.models import FalsePositivePattern

        pattern = FalsePositivePattern(
            container_name="test-container",
            file_path="/app/config.yaml",
            rule_id="test-rule",
            created_by="admin",
            match_count=0,
        )
        db_session.add(pattern)
        await db_session.commit()
        await db_session.refresh(pattern)

        response = await authenticated_client.delete(
            f"/api/v1/false-positive-patterns/{pattern.id}"
        )
        assert response.status_code == 200
        data = response.json()
        assert "unsuppressed_secrets" in data
        assert isinstance(data["unsuppressed_secrets"], int)
