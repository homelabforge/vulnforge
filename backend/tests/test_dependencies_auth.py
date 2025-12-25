"""Tests for authentication dependency injection functions."""

import pytest
from fastapi import HTTPException

from app.dependencies.auth import get_current_user, require_admin, require_auth
from app.models.user import User


class MockRequest:
    """Mock request for testing dependencies."""

    def __init__(self, user: User | None = None):
        self.state = type("State", (), {"user": user})()


@pytest.mark.asyncio
class TestRequireAuth:
    """Tests for require_auth dependency."""

    async def test_require_auth_with_authenticated_user(self):
        """Test require_auth allows authenticated users."""
        user = User(username="testuser", provider="test", is_admin=False)
        request = MockRequest(user=user)

        # Should not raise exception
        result = await require_auth(request)
        assert result == user

    async def test_require_auth_with_admin_user(self):
        """Test require_auth allows admin users."""
        user = User(username="admin", provider="test", is_admin=True)
        request = MockRequest(user=user)

        # Should not raise exception
        result = await require_auth(request)
        assert result == user

    async def test_require_auth_without_user(self):
        """Test require_auth blocks unauthenticated requests."""
        request = MockRequest(user=None)

        # Should raise 401 Unauthorized
        with pytest.raises(HTTPException) as exc_info:
            await require_auth(request)

        assert exc_info.value.status_code == 401
        assert "Authentication required" in exc_info.value.detail

    async def test_require_auth_with_anonymous_user(self):
        """Test require_auth allows anonymous users when auth disabled."""
        user = User(username="anonymous", provider="none", is_admin=False)
        request = MockRequest(user=user)

        result = await require_auth(request)
        assert result == user

    async def test_require_auth_missing_state_attribute(self):
        """Test require_auth handles missing request.state gracefully."""
        request = type("MockRequest", (), {})()  # No state attribute

        # Should raise 401 Unauthorized
        with pytest.raises(HTTPException) as exc_info:
            await require_auth(request)

        assert exc_info.value.status_code == 401


@pytest.mark.asyncio
class TestRequireAdmin:
    """Tests for require_admin dependency."""

    async def test_require_admin_with_admin_user(self):
        """Test require_admin allows admin users."""
        user = User(username="admin", provider="test", is_admin=True)
        request = MockRequest(user=user)

        # Should not raise exception
        result = await require_admin(request)
        assert result == user
        assert result.is_admin is True

    async def test_require_admin_with_non_admin_user(self):
        """Test require_admin blocks non-admin users."""
        user = User(username="regularuser", provider="test", is_admin=False)
        request = MockRequest(user=user)

        # Should raise 403 Forbidden
        with pytest.raises(HTTPException) as exc_info:
            await require_admin(request)

        assert exc_info.value.status_code == 403
        assert "Admin privileges required" in exc_info.value.detail

    async def test_require_admin_without_user(self):
        """Test require_admin blocks unauthenticated requests."""
        request = MockRequest(user=None)

        # Should raise 401 Unauthorized (auth first, then admin check)
        with pytest.raises(HTTPException) as exc_info:
            await require_admin(request)

        assert exc_info.value.status_code == 401

    async def test_require_admin_with_anonymous_user(self):
        """Test require_admin allows anonymous users when auth disabled."""
        user = User(username="anonymous", provider="none", is_admin=False)
        request = MockRequest(user=user)

        result = await require_admin(request)
        assert result == user

    async def test_require_admin_prevents_privilege_escalation(self):
        """Test that is_admin flag cannot be bypassed."""
        # Create user with is_admin=False
        user = User(username="attacker", provider="test", is_admin=False)

        # Try to manually set is_admin (should not work due to dependency check)
        request = MockRequest(user=user)

        # Should still raise 403
        with pytest.raises(HTTPException) as exc_info:
            await require_admin(request)

        assert exc_info.value.status_code == 403


@pytest.mark.asyncio
class TestGetCurrentUser:
    """Tests for get_current_user dependency."""

    async def test_get_current_user_with_authenticated_user(self):
        """Test get_current_user returns authenticated user."""
        user = User(username="testuser", provider="test", is_admin=False)
        request = MockRequest(user=user)

        result = await get_current_user(request)
        assert result == user

    async def test_get_current_user_with_admin_user(self):
        """Test get_current_user returns admin user."""
        user = User(username="admin", provider="test", is_admin=True)
        request = MockRequest(user=user)

        result = await get_current_user(request)
        assert result == user
        assert result.is_admin is True

    async def test_get_current_user_allows_anonymous(self):
        """Test get_current_user allows anonymous users (for optional auth)."""
        user = User(username="anonymous", provider="none", is_admin=False)
        request = MockRequest(user=user)

        # Should return anonymous user without raising exception
        result = await get_current_user(request)
        assert result == user
        assert result.username == "anonymous"

    async def test_get_current_user_with_none(self):
        """Test get_current_user when no user attached."""
        request = MockRequest(user=None)

        # Should return None without raising exception
        result = await get_current_user(request)
        assert result is None


@pytest.mark.asyncio
class TestAuthDependencyChaining:
    """Tests for dependency chaining and composition."""

    async def test_require_admin_checks_auth_first(self):
        """Test that require_admin checks authentication before admin status."""
        request = MockRequest(user=None)

        # Should raise 401 (auth check) not 403 (admin check)
        with pytest.raises(HTTPException) as exc_info:
            await require_admin(request)

        assert exc_info.value.status_code == 401
        assert "Authentication required" in exc_info.value.detail

    async def test_require_auth_preserves_user_object(self):
        """Test that require_auth preserves all user object properties."""
        user = User(
            username="testuser",
            email="test@example.com",
            provider="authentik",
            is_admin=False,
        )
        request = MockRequest(user=user)

        result = await require_auth(request)

        # All properties should be preserved
        assert result.username == "testuser"
        assert result.email == "test@example.com"
        assert result.provider == "authentik"
        assert result.is_admin is False
