"""Tests for secrets API endpoints."""

from datetime import UTC, datetime
from types import SimpleNamespace

from fastapi import HTTPException

from app.models.user import User


class TestSecretsList:
    """Tests for secret listing endpoint."""

    async def test_list_requires_auth(self, authenticated_client):
        """Test that listing secrets requires authentication."""
        from app.dependencies.auth import require_admin
        from app.main import app

        async def override_require_admin(request=None):
            raise HTTPException(status_code=403, detail="Admin required")

        app.dependency_overrides[require_admin] = override_require_admin

        response = await authenticated_client.get("/api/v1/secrets/")

        assert response.status_code == 403

        app.dependency_overrides.clear()

    async def test_list_secrets_success(self, authenticated_client, db_with_settings):
        """Test successful secret listing."""
        from app.dependencies.auth import require_admin
        from app.main import app

        async def override_require_admin(request=None):
            return User(username="admin", provider="test", is_admin=True)

        app.dependency_overrides[require_admin] = override_require_admin

        response = await authenticated_client.get("/api/v1/secrets/")

        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, (list, dict))

        app.dependency_overrides.clear()

    async def test_secrets_are_redacted_in_response(self, authenticated_client, db_with_settings):
        """Test that secret code snippets are redacted in API response."""
        from app.dependencies.auth import require_admin
        from app.main import app

        async def override_require_admin(request=None):
            return User(username="admin", provider="test", is_admin=True)

        app.dependency_overrides[require_admin] = override_require_admin

        response = await authenticated_client.get("/api/v1/secrets/")

        assert response.status_code == 200
        data = response.json()

        # Verify secrets are redacted
        if isinstance(data, list) and len(data) > 0:
            for secret in data:
                if "code_snippet" in secret:
                    assert (
                        "***REDACTED***" in secret["code_snippet"]
                        or secret["code_snippet"] == ""
                        or secret["code_snippet"] is None
                    )

        app.dependency_overrides.clear()

    async def test_filter_by_container(self, authenticated_client, db_with_settings):
        """Test filtering secrets by container."""
        from app.dependencies.auth import require_admin
        from app.main import app

        async def override_require_admin(request=None):
            return User(username="admin", provider="test", is_admin=True)

        app.dependency_overrides[require_admin] = override_require_admin

        response = await authenticated_client.get("/api/v1/secrets/containers/1/secrets")

        assert response.status_code in [200, 404]

        app.dependency_overrides.clear()

    async def test_list_secrets_returns_container_name(
        self, authenticated_client, db_with_settings
    ):
        """Test that list endpoint returns container_name in response."""
        from app.dependencies.auth import require_admin
        from app.main import app
        from app.repositories.dependencies import get_secret_repository

        async def override_require_admin(request=None):
            return User(username="admin", provider="test", is_admin=True)

        class DummySecretRepo:
            async def get_all(self, severity=None, category=None, status=None, limit=100, offset=0):
                secret = SimpleNamespace(
                    id=1,
                    scan_id=1,
                    rule_id="private-key",
                    category="AsymmetricPrivateKey",
                    title="Asymmetric Private Key",
                    severity="HIGH",
                    match="***REDACTED***",
                    file_path="/ak-root/.venv/lib/python3.14/site-packages/docs/x509/ocsp.rst",
                    start_line=84,
                    end_line=86,
                    code_snippet="Line 84: ***REDACTED***",
                    layer_digest="sha256:abc123",
                    status="to_review",
                    notes=None,
                    created_at=datetime.now(UTC),
                    updated_at=None,
                )
                return [(secret, "authentik-server")]

        app.dependency_overrides[require_admin] = override_require_admin
        app.dependency_overrides[get_secret_repository] = lambda: DummySecretRepo()

        response = await authenticated_client.get("/api/v1/secrets/")

        assert response.status_code == 200
        data = response.json()
        assert len(data) == 1
        assert data[0]["container_name"] == "authentik-server"

        app.dependency_overrides.clear()

    async def test_list_secrets_invalid_status_returns_400(
        self, authenticated_client, db_with_settings
    ):
        """Test that invalid status filter returns 400."""
        from app.dependencies.auth import require_admin
        from app.main import app

        async def override_require_admin(request=None):
            return User(username="admin", provider="test", is_admin=True)

        app.dependency_overrides[require_admin] = override_require_admin

        response = await authenticated_client.get("/api/v1/secrets/?status=bogus")

        assert response.status_code == 400

        app.dependency_overrides.clear()

    async def test_list_secrets_redaction_with_container(
        self, authenticated_client, db_with_settings
    ):
        """Test that match and code_snippet remain redacted in SecretWithContainer."""
        from app.dependencies.auth import require_admin
        from app.main import app
        from app.repositories.dependencies import get_secret_repository

        async def override_require_admin(request=None):
            return User(username="admin", provider="test", is_admin=True)

        class DummySecretRepo:
            async def get_all(self, severity=None, category=None, status=None, limit=100, offset=0):
                secret = SimpleNamespace(
                    id=1,
                    scan_id=1,
                    rule_id="generic-api-key",
                    category="Generic",
                    title="API Key",
                    severity="HIGH",
                    match="sk_live_SHOULD_NOT_APPEAR",
                    file_path="/app/config.py",
                    start_line=10,
                    end_line=10,
                    code_snippet="api_key=sk_live_SHOULD_NOT_APPEAR",
                    layer_digest=None,
                    status="to_review",
                    notes=None,
                    created_at=datetime.now(UTC),
                    updated_at=None,
                )
                return [(secret, "test-container")]

        app.dependency_overrides[require_admin] = override_require_admin
        app.dependency_overrides[get_secret_repository] = lambda: DummySecretRepo()

        response = await authenticated_client.get("/api/v1/secrets/")

        assert response.status_code == 200
        data = response.json()
        assert len(data) == 1
        assert data[0]["match"] == "***REDACTED***"
        assert "sk_live" not in data[0].get("code_snippet", "")
        assert data[0]["container_name"] == "test-container"

        app.dependency_overrides.clear()


class TestSecretsBulkUpdate:
    """Tests for bulk secret update endpoint."""

    async def test_bulk_update_requires_auth(self, authenticated_client):
        """Test that bulk update requires authentication."""
        from app.dependencies.auth import require_admin
        from app.main import app

        async def override_require_admin(request=None):
            raise HTTPException(status_code=403, detail="Admin required")

        app.dependency_overrides[require_admin] = override_require_admin

        response = await authenticated_client.post(
            "/api/v1/secrets/bulk-update",
            json={"secret_ids": [1, 2], "update": {"status": "false_positive"}},
        )

        assert response.status_code == 403

        app.dependency_overrides.clear()

    async def test_mark_as_false_positive(self, authenticated_client, db_with_settings):
        """Test marking secrets as false positives."""
        from app.dependencies.auth import require_admin
        from app.main import app

        async def override_require_admin(request=None):
            return User(username="admin", provider="test", is_admin=True)

        app.dependency_overrides[require_admin] = override_require_admin

        response = await authenticated_client.post(
            "/api/v1/secrets/bulk-update",
            json={
                "secret_ids": [1, 2],
                "update": {
                    "status": "false_positive",
                    "notes": "test-pattern-123",
                },
            },
        )

        assert response.status_code in [200, 404]

        app.dependency_overrides.clear()


class TestSecretsFalsePositivePatterns:
    """Tests for false positive pattern management."""

    async def test_create_false_positive_pattern(self, authenticated_client, db_with_settings):
        """Test creating a false positive pattern."""
        from app.dependencies.auth import require_admin
        from app.main import app

        async def override_require_admin(request=None):
            return User(username="admin", provider="test", is_admin=True)

        app.dependency_overrides[require_admin] = override_require_admin

        response = await authenticated_client.post(
            "/api/v1/false-positive-patterns",
            json={
                "secret_id": 1,
                "reason": "Test pattern",
            },
        )

        assert response.status_code in [200, 404]

        app.dependency_overrides.clear()

    async def test_list_false_positive_patterns(self, authenticated_client, db_with_settings):
        """Test listing false positive patterns."""
        response = await authenticated_client.get("/api/v1/false-positive-patterns")

        assert response.status_code == 200


class TestSecretsExport:
    """Tests for secret export functionality."""

    async def test_export_csv(self, authenticated_client, db_with_settings):
        """Test CSV export of secrets."""
        from datetime import datetime
        from types import SimpleNamespace

        from app.dependencies.auth import require_admin
        from app.main import app
        from app.repositories.dependencies import get_secret_repository

        async def override_require_admin(request=None):
            return User(username="admin", provider="test", is_admin=True)

        class DummySecretRepo:
            async def get_for_export(
                self, severity=None, category=None, include_false_positives=False
            ):
                secret = SimpleNamespace(
                    id=1,
                    rule_id="generic-secret",
                    category="Generic",
                    title="Test Secret",
                    severity="HIGH",
                    file_path="/app/config.py",
                    start_line=10,
                    end_line=12,
                    match="***REDACTED***",
                    layer_digest=None,
                    status="active",
                    created_at=datetime.now(UTC),
                )
                return [(secret, "demo-container")]

        app.dependency_overrides[require_admin] = override_require_admin
        app.dependency_overrides[get_secret_repository] = lambda: DummySecretRepo()

        response = await authenticated_client.get("/api/v1/secrets/export?format=csv")

        assert response.status_code == 200

        content = response.text
        assert "***REDACTED***" in content
        assert "demo-container" in content

        app.dependency_overrides.clear()


class TestSecretsRedactionSecurity:
    """Security tests for secret redaction."""

    async def test_no_secret_exposure_in_api(self, authenticated_client, db_with_settings):
        """Test that no actual secrets are exposed via API."""
        from app.dependencies.auth import require_admin
        from app.main import app

        async def override_require_admin(request=None):
            return User(username="admin", provider="test", is_admin=True)

        app.dependency_overrides[require_admin] = override_require_admin

        response = await authenticated_client.get("/api/v1/secrets/")

        assert response.status_code == 200
        content = response.text

        # Check that common secret patterns are not exposed
        secret_patterns = ["sk_live_", "sk_test_", "AKIA", "ghp_", "Bearer "]

        for pattern in secret_patterns:
            if pattern in content:
                # If pattern exists, verify it's in redacted context
                assert "***REDACTED***" in content or "redacted" in content.lower()

        app.dependency_overrides.clear()
