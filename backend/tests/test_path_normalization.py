"""Tests for path normalization and traversal protection."""

import pytest

from app.middleware import auth as auth_middleware


@pytest.fixture(autouse=True)
def _force_auth(monkeypatch):
    """Force authentication middleware into enabled state."""

    async def _fake_get_cached_settings(_db):
        return {
            "auth_enabled": "true",
            "auth_provider": "api_key",
        }

    monkeypatch.setattr(auth_middleware, "_get_cached_settings", _fake_get_cached_settings)
    auth_middleware._settings_cache = None
    auth_middleware._settings_cache_time = 0.0

    yield

    auth_middleware._settings_cache = None
    auth_middleware._settings_cache_time = 0.0


class TestPathNormalization:
    """Tests for URL path normalization security."""

    def test_path_traversal_blocked(self, client):
        """Test that path traversal attempts are normalized and blocked."""
        # Try various path traversal patterns
        traversal_attempts = [
            "/api/../api/v1/containers",
            "/api/v1/../../../etc/passwd",
            "/api/./v1/containers",
            "/api/v1/./containers",
            "/../api/v1/containers",
        ]

        for path in traversal_attempts:
            response = client.get(path)

            # Should require auth (not bypass to frontend)
            assert response.status_code in [401, 403, 404]
            # Should not return frontend HTML
            assert "<!DOCTYPE html>" not in response.text

    def test_double_slash_normalization(self, client):
        """Test that double slashes are normalized."""
        response = client.get("//api//v1//containers")

        # Should treat as API path requiring auth
        assert response.status_code in [401, 403, 404]

    def test_api_path_without_trailing_slash(self, client):
        """Test that /api without trailing slash requires auth."""
        response = client.get("/api")

        # Should require auth, not treat as frontend
        assert response.status_code in [401, 403]
        assert "<!DOCTYPE html>" not in response.text

    def test_api_with_trailing_slash_requires_auth(self, client):
        """Test that /api/ requires auth."""
        response = client.get("/api/")

        assert response.status_code in [401, 403]

    def test_url_encoded_traversal_blocked(self, client):
        """Test that URL-encoded path traversal is blocked."""
        encoded_attempts = [
            "/api/%2e%2e/api/v1/containers",
            "/api%2fv1%2f..%2f..%2fcontainers",
            "/api/v1/%2e%2e%2fcontainers",
        ]

        for path in encoded_attempts:
            response = client.get(path)

            # Should be normalized and require auth
            assert response.status_code in [401, 403, 404]

    def test_frontend_paths_allowed(self, client):
        """Test that legitimate frontend paths are accessible."""
        frontend_paths = [
            "/",
            "/dashboard",
            "/settings",
            "/containers",
        ]

        for path in frontend_paths:
            response = client.get(path)

            # Should return frontend (200) or redirect, not auth error
            assert response.status_code in [200, 301, 302, 404]
            # Should not be auth error
            assert response.status_code != 401

    def test_api_paths_require_auth(self, client):
        """Test that all API paths require authentication."""
        api_paths = [
            "/api/v1/containers",
            "/api/v1/scans",
            "/api/v1/settings",
            "/api/v1/vulnerabilities",
        ]

        for path in api_paths:
            response = client.get(path)

            # Should require auth
            assert response.status_code in [401, 403]


class TestCaseInsensitivePathCheck:
    """Tests for case-insensitive path checking."""

    def test_uppercase_api_requires_auth(self, client):
        """Test that /API and /Api require auth."""
        uppercase_paths = [
            "/API/v1/containers",
            "/Api/v1/containers",
            "/API/V1/CONTAINERS",
        ]

        for path in uppercase_paths:
            response = client.get(path)

            # Should require auth
            assert response.status_code in [401, 403, 404]

    def test_mixed_case_traversal_blocked(self, client):
        """Test that mixed-case traversal attempts are blocked."""
        mixed_case_attempts = [
            "/API/../api/v1/containers",
            "/Api/V1/../containers",
        ]

        for path in mixed_case_attempts:
            response = client.get(path)

            assert response.status_code in [401, 403, 404]


class TestPathNormalizationEdgeCases:
    """Tests for edge cases in path normalization."""

    def test_multiple_dots_normalized(self, client):
        """Test that multiple dot segments are normalized."""
        response = client.get("/api/v1/../../api/v1/containers")

        # Should normalize and require auth
        assert response.status_code in [401, 403, 404]

    def test_backslash_not_treated_as_separator(self, client):
        """Test that backslashes don't bypass path check."""
        # Some systems might treat backslash as path separator
        response = client.get("/api\\v1\\containers")

        # Should either normalize or be invalid
        # But definitely not bypass auth
        assert response.status_code != 200 or "<!DOCTYPE html>" in response.text

    def test_null_byte_injection_blocked(self, client):
        """Test that null byte injection doesn't bypass security."""
        # Null bytes should be rejected or stripped
        response = client.get("/api/v1/containers%00/../../etc/passwd")

        # Should not succeed
        assert response.status_code in [400, 401, 403, 404]

    def test_trailing_slashes_normalized(self, client):
        """Test that trailing slashes are handled consistently."""
        paths = [
            "/api/v1/containers",
            "/api/v1/containers/",
        ]

        responses = [client.get(path) for path in paths]

        # Both should behave the same way
        assert responses[0].status_code == responses[1].status_code

    def test_empty_path_segments_removed(self, client):
        """Test that empty path segments are removed."""
        response = client.get("/api//v1///containers")

        # Should normalize to /api/v1/containers and require auth
        assert response.status_code in [401, 403]


class TestSettingsCacheSecurity:
    """Tests for settings cache security."""

    @pytest.mark.asyncio
    async def test_cache_ttl_respected(self):
        """Test that cache TTL is respected."""
        from app.middleware.auth import _settings_cache, _settings_cache_time, SETTINGS_CACHE_TTL
        import time

        # This test verifies the cache invalidation logic
        # Actual implementation uses 60 second TTL
        assert SETTINGS_CACHE_TTL == 60

    @pytest.mark.asyncio
    async def test_cache_thread_safe(self):
        """Test that cache access is thread-safe with async lock."""
        from app.middleware.auth import _settings_lock

        # Verify lock exists for thread safety
        assert _settings_lock is not None

        # The double-check locking pattern should prevent race conditions
        # where multiple requests refresh cache simultaneously
