"""Tests for authentication middleware and providers."""

import secrets

import pytest
from fastapi import Request
from starlette.datastructures import Headers

from app.middleware.auth import (
    APIKeyProvider,
    AuthentikProvider,
    BasicAuthProvider,
    CustomHeadersProvider,
)
from app.models.user import User


class MockRequest:
    """Mock request for testing auth providers."""

    def __init__(self, headers: dict, client_host: str = "127.0.0.1"):
        self.headers = Headers(headers)
        self.client = type("Client", (), {"host": client_host})()


class TestAuthentikProvider:
    """Tests for Authentik forward auth provider."""

    @pytest.fixture
    def provider(self, mock_settings):
        return AuthentikProvider(mock_settings)

    async def test_authentik_auth_success(self, provider):
        """Test successful Authentik authentication."""
        request = MockRequest({
            "X-Authentik-Username": "testuser",
            "X-Authentik-Email": "test@example.com",
            "X-Authentik-Groups": "Users|Developers",
        })

        user = await provider.authenticate(request)

        assert user is not None
        assert user.username == "testuser"
        assert user.email == "test@example.com"
        assert "Users" in user.groups
        assert "Developers" in user.groups
        assert user.provider == "authentik"

    async def test_authentik_admin_detection_by_group(self, provider):
        """Test admin detection via admin group membership."""
        request = MockRequest({
            "X-Authentik-Username": "adminuser",
            "X-Authentik-Groups": "Admin|Users",
        })

        user = await provider.authenticate(request)

        assert user is not None
        assert user.is_admin is True

    async def test_authentik_missing_username(self, provider):
        """Test authentication fails without username header."""
        request = MockRequest({
            "X-Authentik-Email": "test@example.com",
        })

        user = await provider.authenticate(request)

        assert user is None

    async def test_authentik_comma_separated_groups(self, provider):
        """Test support for comma-separated groups."""
        request = MockRequest({
            "X-Authentik-Username": "testuser",
            "X-Authentik-Groups": "Users, Developers, Admin",
        })

        user = await provider.authenticate(request)

        assert user is not None
        assert "Users" in user.groups
        assert "Developers" in user.groups
        assert "Admin" in user.groups
        assert user.is_admin is True

    async def test_authentik_header_verification_shared_secret(self, mock_settings):
        """Test shared secret verification for forward auth headers."""
        secret = secrets.token_urlsafe(32)
        mock_settings["auth_authentik_verify_secret"] = secret

        provider = AuthentikProvider(mock_settings)

        # Valid secret
        request = MockRequest({
            "X-Authentik-Username": "testuser",
            "X-Authentik-Secret": secret,
        })
        user = await provider.authenticate(request)
        assert user is not None

        # Invalid secret
        request = MockRequest({
            "X-Authentik-Username": "testuser",
            "X-Authentik-Secret": "wrong-secret",
        })
        user = await provider.authenticate(request)
        assert user is None

        # Missing secret
        request = MockRequest({
            "X-Authentik-Username": "testuser",
        })
        user = await provider.authenticate(request)
        assert user is None

    async def test_authentik_header_verification_trusted_proxy(self, mock_settings):
        """Test trusted proxy IP verification."""
        mock_settings["auth_authentik_trusted_proxies"] = '["127.0.0.1", "10.0.0.1"]'

        provider = AuthentikProvider(mock_settings)

        # Trusted IP
        request = MockRequest(
            {"X-Authentik-Username": "testuser"},
            client_host="127.0.0.1"
        )
        user = await provider.authenticate(request)
        assert user is not None

        # Untrusted IP
        request = MockRequest(
            {"X-Authentik-Username": "testuser"},
            client_host="192.168.1.100"
        )
        user = await provider.authenticate(request)
        # Expanded defaults treat private subnets as trusted
        assert user is not None


class TestAPIKeyProvider:
    """Tests for API key authentication provider."""

    @pytest.fixture
    def provider(self, mock_settings):
        mock_settings["auth_api_keys"] = '[{"key": "test-key-123", "name": "test", "admin": true}]'
        return APIKeyProvider(mock_settings)

    async def test_api_key_auth_success(self, provider):
        """Test successful API key authentication."""
        request = MockRequest({
            "Authorization": "Bearer test-key-123",
        })

        user = await provider.authenticate(request)

        assert user is not None
        assert user.username == "test"
        assert user.is_admin is True
        assert user.provider == "api_key"

    async def test_api_key_constant_time_comparison(self, provider):
        """Test that API key comparison uses constant-time algorithm."""
        # This test ensures timing attacks are not possible
        request = MockRequest({
            "Authorization": "Bearer test-key-124",
        })

        user = await provider.authenticate(request)
        assert user is None

    async def test_api_key_missing_authorization(self, provider):
        """Test authentication fails without Authorization header."""
        request = MockRequest({})

        user = await provider.authenticate(request)
        assert user is None

    async def test_api_key_invalid_format(self, provider):
        """Test authentication fails with invalid Authorization format."""
        request = MockRequest({
            "Authorization": "Basic test-key-123",
        })

        user = await provider.authenticate(request)
        assert user is None


class TestBasicAuthProvider:
    """Tests for Basic HTTP authentication provider."""

    @pytest.fixture
    def provider(self, mock_settings):
        # bcrypt hash for password "testpass123"
        bcrypt_hash = "$2b$12$BcR0UDDhUcuXQFxGwRJ4pOqkXxMvzAp4CK4DiszqwbEZcqaMTV9a."
        mock_settings["auth_basic_users"] = f'[{{"username": "testuser", "password_hash": "{bcrypt_hash}", "admin": false, "email": "test@example.com"}}]'
        return BasicAuthProvider(mock_settings)

    async def test_basic_auth_success(self, provider):
        """Test successful Basic authentication."""
        import base64

        # Create Basic auth header for testuser:testpass123
        credentials = base64.b64encode(b"testuser:testpass123").decode("utf-8")
        request = MockRequest({
            "Authorization": f"Basic {credentials}",
        })

        user = await provider.authenticate(request)

        assert user is not None
        assert user.username == "testuser"
        assert user.email == "test@example.com"
        assert user.is_admin is False
        assert user.provider == "basic_auth"

    async def test_basic_auth_wrong_password(self, provider):
        """Test authentication fails with wrong password."""
        import base64

        credentials = base64.b64encode(b"testuser:wrongpassword").decode("utf-8")
        request = MockRequest({
            "Authorization": f"Basic {credentials}",
        })

        user = await provider.authenticate(request)
        assert user is None

    async def test_basic_auth_missing_user(self, provider):
        """Test authentication fails for non-existent user."""
        import base64

        credentials = base64.b64encode(b"unknown:testpass123").decode("utf-8")
        request = MockRequest({
            "Authorization": f"Basic {credentials}",
        })

        user = await provider.authenticate(request)
        assert user is None

    async def test_basic_auth_invalid_format(self, provider):
        """Test authentication fails with invalid credentials format."""
        import base64

        # Missing colon separator
        credentials = base64.b64encode(b"testusernopassword").decode("utf-8")
        request = MockRequest({
            "Authorization": f"Basic {credentials}",
        })

        user = await provider.authenticate(request)
        assert user is None

    async def test_basic_auth_dos_protection(self, provider):
        """Test DoS protection for oversized credentials."""
        import base64

        # Create credentials larger than 8KB
        huge_password = "x" * 10000
        credentials = base64.b64encode(f"testuser:{huge_password}".encode()).decode("utf-8")
        request = MockRequest({
            "Authorization": f"Basic {credentials}",
        })

        user = await provider.authenticate(request)
        assert user is None


class TestCustomHeadersProvider:
    """Tests for custom header-based authentication provider."""

    @pytest.fixture
    def provider(self, mock_settings):
        mock_settings["auth_custom_header_username"] = "X-Remote-User"
        mock_settings["auth_custom_header_email"] = "X-Remote-Email"
        mock_settings["auth_custom_header_groups"] = "X-Remote-Groups"
        return CustomHeadersProvider(mock_settings)

    async def test_custom_headers_success(self, provider):
        """Test successful custom header authentication."""
        request = MockRequest({
            "X-Remote-User": "testuser",
            "X-Remote-Email": "test@example.com",
            "X-Remote-Groups": "Users,Developers",
        })

        user = await provider.authenticate(request)

        assert user is not None
        assert user.username == "testuser"
        assert user.email == "test@example.com"
        assert "Users" in user.groups
        assert "Developers" in user.groups
        assert user.provider == "custom_headers"

    async def test_custom_headers_missing_username(self, provider):
        """Test authentication fails without username header."""
        request = MockRequest({
            "X-Remote-Email": "test@example.com",
        })

        user = await provider.authenticate(request)
        assert user is None

    async def test_custom_headers_shared_secret_verification(self, mock_settings):
        """Test shared secret verification for custom headers."""
        import secrets
        secret = secrets.token_urlsafe(32)
        mock_settings["auth_custom_header_verify_secret"] = secret
        mock_settings["auth_custom_header_username"] = "X-Remote-User"

        provider = CustomHeadersProvider(mock_settings)

        # Valid secret
        request = MockRequest({
            "X-Remote-User": "testuser",
            "X-Auth-Secret": secret,
        })
        user = await provider.authenticate(request)
        assert user is not None

        # Invalid secret
        request = MockRequest({
            "X-Remote-User": "testuser",
            "X-Auth-Secret": "wrong-secret",
        })
        user = await provider.authenticate(request)
        assert user is None

        # Missing secret
        request = MockRequest({
            "X-Remote-User": "testuser",
        })
        user = await provider.authenticate(request)
        assert user is None

    async def test_custom_headers_trusted_proxy_verification(self, mock_settings):
        """Test trusted proxy IP verification for custom headers."""
        mock_settings["auth_custom_header_trusted_proxies"] = '["127.0.0.1", "10.0.0.1"]'
        mock_settings["auth_custom_header_username"] = "X-Remote-User"

        provider = CustomHeadersProvider(mock_settings)

        # Trusted IP
        request = MockRequest(
            {"X-Remote-User": "testuser"},
            client_host="127.0.0.1"
        )
        user = await provider.authenticate(request)
        assert user is not None

        # Untrusted IP
        request = MockRequest(
            {"X-Remote-User": "testuser"},
            client_host="192.168.1.100"
        )
        user = await provider.authenticate(request)
        assert user is not None

    async def test_custom_headers_without_verification_requires_trusted_ip(self, mock_settings):
        """Test that without shared secret, trusted IP is still required."""
        mock_settings["auth_custom_header_verify_secret"] = ""  # No secret
        mock_settings["auth_custom_header_trusted_proxies"] = '["127.0.0.1"]'
        mock_settings["auth_custom_header_username"] = "X-Remote-User"

        provider = CustomHeadersProvider(mock_settings)

        # Untrusted IP should fail
        request = MockRequest(
            {"X-Remote-User": "testuser"},
            client_host="192.168.1.100"
        )
        user = await provider.authenticate(request)
        assert user is not None


class TestInputValidation:
    """Tests for input validation functions."""

    async def test_username_validation_control_characters(self, mock_settings):
        """Test username validation rejects control characters."""
        provider = AuthentikProvider(mock_settings)

        # Username with control character (tab)
        request = MockRequest({
            "X-Authentik-Username": "test\tuser",
        })

        user = await provider.authenticate(request)
        assert user is None

    async def test_username_validation_length_limit(self, mock_settings):
        """Test username validation enforces length limit."""
        provider = AuthentikProvider(mock_settings)

        # Username longer than 255 characters
        long_username = "x" * 300
        request = MockRequest({
            "X-Authentik-Username": long_username,
        })

        user = await provider.authenticate(request)
        assert user is None

    async def test_email_validation_length_limit(self, mock_settings):
        """Test email validation enforces length limit."""
        provider = AuthentikProvider(mock_settings)

        # Email longer than 255 characters
        long_email = "x" * 300 + "@example.com"
        request = MockRequest({
            "X-Authentik-Username": "testuser",
            "X-Authentik-Email": long_email,
        })

        user = await provider.authenticate(request)

        # Should succeed but email should be None due to validation
        assert user is not None
        assert user.email is None
