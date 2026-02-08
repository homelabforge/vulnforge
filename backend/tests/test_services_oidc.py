"""Tests for OIDC service functions.

This module tests the OIDC (OpenID Connect) service layer:
- Log sanitization (log injection prevention)
- SSRF URL validation
- State token generation and lifecycle
- OIDC configuration retrieval
"""

import socket
from unittest.mock import patch

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.services.oidc import (
    SSRFProtectionError,
    generate_state,
    get_oidc_config,
    store_oidc_state,
    validate_and_consume_state,
    validate_oidc_url,
)
from app.utils.log_redaction import sanitize_for_log


class TestSanitizeForLog:
    """Test sanitize_for_log helper for log injection prevention."""

    def test_sanitize_for_log_strips_newlines(self):
        """Verify newline characters are neutralized to prevent log injection."""
        result = sanitize_for_log("normal\ninjected line")
        assert "\n" not in result
        assert result == "normal injected line"

    def test_sanitize_for_log_strips_tabs(self):
        """Verify tab characters are neutralized to prevent log injection."""
        result = sanitize_for_log("before\tafter")
        assert "\t" not in result
        assert result == "before after"

    def test_sanitize_for_log_strips_carriage_return(self):
        """Verify carriage return characters are also neutralized."""
        result = sanitize_for_log("line1\r\nline2")
        assert "\r" not in result
        assert "\n" not in result
        assert result == "line1 line2"


class TestValidateOidcUrl:
    """Test validate_oidc_url SSRF protection."""

    @patch("socket.gethostbyname", return_value="8.8.8.8")
    def test_validate_oidc_url_valid_https(self, mock_dns):
        """No exception for a public HTTPS URL."""
        # Should not raise
        validate_oidc_url("https://auth.example.com/.well-known/openid-configuration")

    @patch("socket.gethostbyname", return_value="8.8.8.8")
    def test_validate_oidc_url_valid_http(self, mock_dns):
        """No exception for a public HTTP URL."""
        # HTTP is allowed (scheme check passes for http/https)
        validate_oidc_url("http://auth.example.com/callback")

    def test_validate_oidc_url_empty(self):
        """Raises ValueError for empty URL."""
        with pytest.raises(ValueError, match="URL cannot be empty"):
            validate_oidc_url("")

    def test_validate_oidc_url_no_hostname(self):
        """Raises ValueError for URL with no hostname."""
        with pytest.raises(ValueError, match="no hostname"):
            validate_oidc_url("https://")

    @patch("socket.gethostbyname", return_value="192.168.1.1")
    def test_validate_oidc_url_private_ip(self, mock_dns):
        """Raises SSRFProtectionError for private IP 192.168.x.x."""
        with pytest.raises(SSRFProtectionError, match="Private/local IP blocked"):
            validate_oidc_url("https://internal.corp.local/oidc")

    @patch("socket.gethostbyname", return_value="127.0.0.1")
    def test_validate_oidc_url_localhost(self, mock_dns):
        """Raises SSRFProtectionError for loopback address 127.0.0.1."""
        with pytest.raises(SSRFProtectionError, match="Private/local IP blocked"):
            validate_oidc_url("https://localhost/oidc")

    def test_validate_oidc_url_ftp_scheme(self):
        """Raises SSRFProtectionError for non-HTTP scheme (ftp)."""
        with pytest.raises(SSRFProtectionError, match="Unsupported scheme"):
            validate_oidc_url("ftp://files.example.com/data")

    @patch("socket.gethostbyname", return_value="10.0.0.5")
    def test_validate_oidc_url_private_10_network(self, mock_dns):
        """Raises SSRFProtectionError for 10.x.x.x private range."""
        with pytest.raises(SSRFProtectionError, match="Private/local IP blocked"):
            validate_oidc_url("https://internal.example.com/oidc")

    @patch("socket.gethostbyname", side_effect=socket.gaierror("Name resolution failed"))
    def test_validate_oidc_url_unresolvable_passes(self, mock_dns):
        """Unresolvable hostnames are allowed (will fail at HTTP layer)."""
        # Should not raise -- DNS failure is a pass-through
        validate_oidc_url("https://nonexistent.example.com/oidc")


class TestGenerateState:
    """Test generate_state token generation."""

    def test_generate_state_length(self):
        """Verify state token has reasonable length (32 bytes base64 ~ 43 chars)."""
        state = generate_state()
        # token_urlsafe(32) produces ~43 characters
        assert len(state) >= 32

    def test_generate_state_uniqueness(self):
        """Two calls must produce different values."""
        state1 = generate_state()
        state2 = generate_state()
        assert state1 != state2


class TestStateLifecycle:
    """Test store/validate/consume state workflow using the database."""

    @pytest.mark.asyncio
    async def test_store_and_validate_state(self, db_session: AsyncSession):
        """Store a state token, then validate and consume it."""
        state = generate_state()
        nonce = "test-nonce-value"
        redirect_uri = "https://app.example.com/callback"

        # Store
        await store_oidc_state(db_session, state, redirect_uri, nonce)

        # Validate + consume
        result = await validate_and_consume_state(db_session, state)
        assert result is not None
        assert result["redirect_uri"] == redirect_uri
        assert result["nonce"] == nonce

    @pytest.mark.asyncio
    async def test_validate_state_invalid(self, db_session: AsyncSession):
        """Validating a non-existent state returns None."""
        result = await validate_and_consume_state(db_session, "totally-bogus-state")
        assert result is None

    @pytest.mark.asyncio
    async def test_validate_state_consumed_once(self, db_session: AsyncSession):
        """After first validate, second validate returns None (one-time use)."""
        state = generate_state()
        await store_oidc_state(db_session, state, "https://app.example.com/cb", "nonce-abc")

        # First consume succeeds
        first = await validate_and_consume_state(db_session, state)
        assert first is not None

        # Second consume fails (state already deleted)
        second = await validate_and_consume_state(db_session, state)
        assert second is None


class TestGetOidcConfig:
    """Test get_oidc_config settings retrieval."""

    @pytest.mark.asyncio
    async def test_get_oidc_config(self, db_session: AsyncSession):
        """Test config retrieval returns expected keys from settings."""
        from app.services.settings_manager import SettingsManager

        # Arrange - set OIDC settings
        settings = SettingsManager(db_session)
        await settings.set("user_auth_oidc_enabled", "true")
        await settings.set("user_auth_oidc_issuer_url", "https://auth.example.com")
        await settings.set("user_auth_oidc_client_id", "my-client")
        await settings.set("user_auth_oidc_client_secret", "secret-value")
        await settings.set("user_auth_oidc_provider_name", "Authentik")
        await settings.set("user_auth_oidc_scopes", "openid profile email")
        await settings.set("user_auth_oidc_username_claim", "preferred_username")
        await settings.set("user_auth_oidc_email_claim", "email")
        await db_session.commit()

        # Act
        config = await get_oidc_config(db_session)

        # Assert - keys should have the oidc_ prefix stripped
        assert config["enabled"] == "true"
        assert config["issuer_url"] == "https://auth.example.com"
        assert config["client_id"] == "my-client"
        assert config["client_secret"] == "secret-value"
        assert config["provider_name"] == "Authentik"
        assert config["scopes"] == "openid profile email"
        assert config["username_claim"] == "preferred_username"
        assert config["email_claim"] == "email"
