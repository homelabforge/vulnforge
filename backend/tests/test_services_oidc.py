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

    @staticmethod
    def _gai(*ips: str):
        """Build a socket.getaddrinfo-style return for the given IP strings."""
        infos = []
        for ip in ips:
            family = socket.AF_INET6 if ":" in ip else socket.AF_INET
            sockaddr = (ip, 0, 0, 0) if family == socket.AF_INET6 else (ip, 0)
            infos.append((family, socket.SOCK_STREAM, 6, "", sockaddr))
        return infos

    @patch("socket.getaddrinfo")
    def test_validate_oidc_url_valid_https(self, mock_gai):
        """No exception for a public HTTPS URL."""
        mock_gai.return_value = self._gai("8.8.8.8")
        validate_oidc_url("https://auth.example.com/.well-known/openid-configuration")

    @patch("socket.getaddrinfo")
    def test_validate_oidc_url_valid_http(self, mock_gai):
        """No exception for a public HTTP URL."""
        mock_gai.return_value = self._gai("8.8.8.8")
        validate_oidc_url("http://auth.example.com/callback")

    @patch("socket.getaddrinfo")
    def test_validate_oidc_url_valid_ipv6_public(self, mock_gai):
        """A public IPv6 address (e.g. Google DNS) is allowed."""
        mock_gai.return_value = self._gai("2001:4860:4860::8888")
        validate_oidc_url("https://auth.example.com/oidc")

    def test_validate_oidc_url_empty(self):
        """Raises ValueError for empty URL."""
        with pytest.raises(ValueError, match="URL cannot be empty"):
            validate_oidc_url("")

    def test_validate_oidc_url_no_hostname(self):
        """Raises ValueError for URL with no hostname."""
        with pytest.raises(ValueError, match="no hostname"):
            validate_oidc_url("https://")

    @patch("socket.getaddrinfo")
    def test_validate_oidc_url_private_ip(self, mock_gai):
        """Raises SSRFProtectionError for private IP 192.168.x.x."""
        mock_gai.return_value = self._gai("192.168.1.1")
        with pytest.raises(SSRFProtectionError, match="Private/local IP blocked"):
            validate_oidc_url("https://internal.corp.local/oidc")

    @patch("socket.getaddrinfo")
    def test_validate_oidc_url_localhost(self, mock_gai):
        """Raises SSRFProtectionError for loopback address 127.0.0.1."""
        mock_gai.return_value = self._gai("127.0.0.1")
        with pytest.raises(SSRFProtectionError, match="Private/local IP blocked"):
            validate_oidc_url("https://localhost/oidc")

    @patch("socket.getaddrinfo")
    def test_validate_oidc_url_ipv6_loopback(self, mock_gai):
        """Raises SSRFProtectionError for an AAAA-only host resolving to ::1."""
        mock_gai.return_value = self._gai("::1")
        with pytest.raises(SSRFProtectionError, match="Private/local IP blocked"):
            validate_oidc_url("https://ipv6.internal/oidc")

    @patch("socket.getaddrinfo")
    def test_validate_oidc_url_ipv6_ula(self, mock_gai):
        """Raises SSRFProtectionError for an IPv6 ULA (fc00::/7) host."""
        mock_gai.return_value = self._gai("fd00::1")
        with pytest.raises(SSRFProtectionError, match="Private/local IP blocked"):
            validate_oidc_url("https://ula.internal/oidc")

    @patch("socket.getaddrinfo")
    def test_validate_oidc_url_unspecified(self, mock_gai):
        """Raises SSRFProtectionError for the unspecified address 0.0.0.0."""
        mock_gai.return_value = self._gai("0.0.0.0")
        with pytest.raises(SSRFProtectionError, match="Private/local IP blocked"):
            validate_oidc_url("https://zero.internal/oidc")

    @patch("socket.getaddrinfo")
    def test_validate_oidc_url_reserved(self, mock_gai):
        """Raises SSRFProtectionError for a reserved range (240.0.0.0/4)."""
        mock_gai.return_value = self._gai("240.0.0.1")
        with pytest.raises(SSRFProtectionError, match="Private/local IP blocked"):
            validate_oidc_url("https://reserved.internal/oidc")

    @patch("socket.getaddrinfo")
    def test_validate_oidc_url_metadata_endpoint(self, mock_gai):
        """Raises SSRFProtectionError for the cloud metadata IP 169.254.169.254."""
        mock_gai.return_value = self._gai("169.254.169.254")
        with pytest.raises(SSRFProtectionError):
            validate_oidc_url("https://metadata.internal/oidc")

    @patch("socket.getaddrinfo")
    def test_validate_oidc_url_mixed_families_blocks_any_private(self, mock_gai):
        """A host resolving to one public + one private address is rejected."""
        mock_gai.return_value = self._gai("8.8.8.8", "10.0.0.5")
        with pytest.raises(SSRFProtectionError, match="Private/local IP blocked"):
            validate_oidc_url("https://dual.example.com/oidc")

    def test_validate_oidc_url_ftp_scheme(self):
        """Raises SSRFProtectionError for non-HTTP scheme (ftp)."""
        with pytest.raises(SSRFProtectionError, match="Unsupported scheme"):
            validate_oidc_url("ftp://files.example.com/data")

    @patch("socket.getaddrinfo")
    def test_validate_oidc_url_private_10_network(self, mock_gai):
        """Raises SSRFProtectionError for 10.x.x.x private range."""
        mock_gai.return_value = self._gai("10.0.0.5")
        with pytest.raises(SSRFProtectionError, match="Private/local IP blocked"):
            validate_oidc_url("https://internal.example.com/oidc")

    @patch("socket.getaddrinfo", side_effect=socket.gaierror("Name resolution failed"))
    def test_validate_oidc_url_unresolvable_passes(self, mock_gai):
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
