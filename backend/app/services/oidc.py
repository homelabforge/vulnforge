"""OIDC service for OAuth2/OpenID Connect authentication."""

import logging
import secrets
from datetime import UTC, datetime
from typing import Any

import httpx
from authlib.jose import JsonWebKey, jwt
from authlib.jose.errors import JoseError
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.oidc_state import OIDCState
from app.utils.log_redaction import sanitize_for_log

logger = logging.getLogger(__name__)


class SSRFProtectionError(Exception):
    """SSRF protection blocked the request."""

    pass


def validate_oidc_url(url: str) -> None:
    """Validate OIDC URL against SSRF attacks (CWE-918).

    Blocks:
    - Private IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
    - Localhost (127.0.0.0/8, ::1)
    - Link-local addresses (169.254.0.0/16)
    - Metadata endpoints (169.254.169.254)

    Args:
        url: URL to validate

    Raises:
        SSRFProtectionError: If URL targets private/internal resources
    """
    import ipaddress
    from urllib.parse import urlparse

    if not url:
        raise ValueError("URL cannot be empty")

    parsed = urlparse(url)
    hostname = parsed.hostname

    if not hostname:
        raise ValueError("Invalid URL: no hostname")

    # Block non-HTTP(S) schemes
    if parsed.scheme not in ("http", "https"):
        raise SSRFProtectionError(f"Unsupported scheme: {parsed.scheme}")

    # Try to resolve hostname to IP
    import socket

    try:
        ip_str = socket.gethostbyname(hostname)
        ip = ipaddress.ip_address(ip_str)

        # Block private/local addresses
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            raise SSRFProtectionError(f"Private/local IP blocked: {ip}")

        # Specifically block cloud metadata endpoints
        if str(ip) == "169.254.169.254":
            raise SSRFProtectionError("Cloud metadata endpoint blocked")

    except socket.gaierror:
        # Hostname couldn't be resolved - allow (will fail at HTTP layer)
        pass
    except ValueError:
        # Invalid IP - allow (might be valid hostname)
        pass


def generate_state() -> str:
    """Generate cryptographically secure state token (256-bit)."""
    return secrets.token_urlsafe(32)


async def get_oidc_config(db: AsyncSession) -> dict[str, str]:
    """Get OIDC configuration from database settings.

    Returns:
        Dict with keys: enabled, issuer_url, client_id, client_secret,
                       provider_name, scopes, redirect_uri, username_claim, email_claim
    """
    from app.services.settings_manager import SettingsManager

    settings_manager = SettingsManager(db)

    config = {}
    keys = [
        "user_auth_oidc_enabled",
        "user_auth_oidc_issuer_url",
        "user_auth_oidc_client_id",
        "user_auth_oidc_client_secret",
        "user_auth_oidc_provider_name",
        "user_auth_oidc_scopes",
        "user_auth_oidc_username_claim",
        "user_auth_oidc_email_claim",
    ]

    for key in keys:
        value = await settings_manager.get(key, default="")
        # Remove user_auth_oidc_ prefix for cleaner keys
        clean_key = key.replace("user_auth_oidc_", "")
        config[clean_key] = value

    return config


async def get_provider_metadata(issuer_url: str) -> dict[str, Any] | None:
    """Fetch OIDC provider metadata from well-known endpoint.

    Args:
        issuer_url: OIDC issuer URL (e.g., https://auth.example.com)

    Returns:
        Provider metadata dict with endpoints (authorization_endpoint, token_endpoint, etc.)

    Raises:
        SSRFProtectionError: If URL targets private/internal resources
    """
    issuer_url = issuer_url.rstrip("/")

    # SECURITY: Validate issuer URL against SSRF attacks (CWE-918)
    try:
        validate_oidc_url(issuer_url)
    except (SSRFProtectionError, ValueError) as e:
        logger.error(f"SSRF protection blocked OIDC issuer URL: {e}")
        raise SSRFProtectionError(f"Invalid OIDC issuer URL: {e}")

    # Construct discovery endpoint
    discovery_url = f"{issuer_url}/.well-known/openid-configuration"

    # SECURITY: Validate discovery URL as well (defense in depth)
    try:
        validate_oidc_url(discovery_url)
    except (SSRFProtectionError, ValueError) as e:
        logger.error(f"SSRF protection blocked OIDC discovery URL: {e}")
        raise SSRFProtectionError(f"Invalid OIDC discovery URL: {e}")

    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(discovery_url, timeout=10.0)
            response.raise_for_status()
            metadata = response.json()

            logger.info(f"Successfully fetched OIDC metadata from {issuer_url}")
            return metadata

    except httpx.TimeoutException:
        logger.error("OIDC metadata request timeout")
        return None
    except httpx.ConnectError as e:
        logger.error(f"Cannot connect to OIDC provider: {e}")
        return None
    except httpx.HTTPStatusError as e:
        logger.error(f"OIDC provider returned error: {e}")
        return None


async def store_oidc_state(
    db: AsyncSession,
    state: str,
    redirect_uri: str,
    nonce: str,
) -> None:
    """Store OIDC state in database for CSRF protection.

    Args:
        db: Database session
        state: CSRF state token
        redirect_uri: OAuth callback URI
        nonce: Nonce for ID token validation
    """
    oidc_state = OIDCState(
        state=state,
        nonce=nonce,
        redirect_uri=redirect_uri,
        created_at=datetime.now(UTC),
        expires_at=OIDCState.get_expiry_time(minutes=10),
    )

    db.add(oidc_state)
    await db.commit()
    logger.debug("Stored OIDC state: %s...", sanitize_for_log(state[:8]))


async def _cleanup_expired_states(db: AsyncSession) -> None:
    """Delete expired OIDC states from database."""
    now = datetime.now(UTC)
    stmt = delete(OIDCState).where(OIDCState.expires_at < now)
    result = await db.execute(stmt)
    await db.commit()

    deleted = result.rowcount or 0  # type: ignore[union-attr]
    if deleted > 0:
        logger.info(f"Cleaned up {deleted} expired OIDC states")


async def validate_and_consume_state(
    db: AsyncSession,
    state: str,
) -> dict[str, Any] | None:
    """Validate and consume OIDC state from database (one-time use).

    Args:
        db: Database session
        state: State token to validate

    Returns:
        State data dict with redirect_uri and nonce, or None if invalid/expired
    """
    # Clean up expired states
    await _cleanup_expired_states(db)

    # Find state in database
    result = await db.execute(select(OIDCState).where(OIDCState.state == state))
    oidc_state = result.scalar_one_or_none()

    if not oidc_state:
        logger.warning("Invalid or expired OIDC state")
        return None

    # Check if expired
    if oidc_state.is_expired():
        logger.warning("OIDC state expired")
        await db.delete(oidc_state)
        await db.commit()
        return None

    # Convert to dict for compatibility
    state_data = {
        "redirect_uri": oidc_state.redirect_uri,
        "nonce": oidc_state.nonce,
        "created_at": oidc_state.created_at,
    }

    # Delete state (one-time use - CSRF protection)
    await db.delete(oidc_state)
    await db.commit()

    logger.debug("Validated and consumed OIDC state: %s...", sanitize_for_log(state[:8]))
    return state_data


async def create_authorization_url(
    db: AsyncSession,
    config: dict[str, str],
    metadata: dict[str, Any],
    base_url: str,
) -> tuple[str, str]:
    """Create OIDC authorization URL with state and nonce.

    Args:
        db: Database session
        config: OIDC configuration from database
        metadata: Provider metadata
        base_url: Application base URL

    Returns:
        Tuple of (authorization_url, state)
    """
    # Generate cryptographically secure state and nonce
    state = generate_state()
    nonce = secrets.token_urlsafe(32)

    # Determine redirect URI
    redirect_uri = f"{base_url.rstrip('/')}/api/v1/user-auth/oidc/callback"

    logger.info(f"OIDC redirect URI: {redirect_uri} (base_url: {base_url})")

    # Store state in database for validation in callback (CSRF protection)
    await store_oidc_state(db, state, redirect_uri, nonce)

    # Build authorization URL
    auth_endpoint = metadata.get("authorization_endpoint")
    scopes = config.get("scopes", "openid profile email")

    from urllib.parse import urlencode

    params = {
        "client_id": config.get("client_id", ""),
        "response_type": "code",
        "scope": scopes,
        "redirect_uri": redirect_uri,
        "state": state,
        "nonce": nonce,
    }

    auth_url = f"{auth_endpoint}?{urlencode(params)}"

    logger.info(f"Created authorization URL for provider: {config.get('provider_name', 'OIDC')}")
    return auth_url, state


async def exchange_code_for_tokens(
    code: str,
    config: dict[str, str],
    metadata: dict[str, Any],
    redirect_uri: str,
) -> dict[str, Any] | None:
    """Exchange authorization code for tokens.

    Args:
        code: Authorization code from callback
        config: OIDC configuration
        metadata: Provider metadata
        redirect_uri: Redirect URI used in authorization

    Returns:
        Tokens dict with access_token, refresh_token, id_token, etc.
    """
    token_endpoint = metadata.get("token_endpoint")
    if not token_endpoint:
        logger.error("Token endpoint not found in provider metadata")
        return None

    # SECURITY: Validate token endpoint against SSRF attacks
    try:
        validate_oidc_url(token_endpoint)
    except (SSRFProtectionError, ValueError) as e:
        logger.error(f"SSRF protection blocked token endpoint: {e}")
        return None

    # Prepare token request
    client_secret = config.get("client_secret", "")
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "client_id": config.get("client_id", ""),
        "client_secret": client_secret,
    }

    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                token_endpoint,
                data=data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=10.0,
            )

            response.raise_for_status()
            tokens = response.json()

            logger.info("Successfully exchanged code for tokens")
            return tokens

    except httpx.HTTPStatusError as e:
        logger.error(f"HTTP error during token exchange: {e.response.status_code}")
        try:
            error_detail = e.response.json()
            logger.error(f"Token endpoint error: {error_detail}")
        except Exception:
            # Ignore JSON parsing errors - error already logged above
            pass
        return None
    except httpx.TimeoutException:
        logger.error("Token exchange request timeout")
        return None
    except Exception as e:
        logger.error(f"Unexpected error during token exchange: {e}")
        return None


async def verify_id_token(
    id_token: str,
    config: dict[str, str],
    metadata: dict[str, Any],
    nonce: str,
) -> dict[str, Any] | None:
    """Verify and decode ID token from OIDC provider.

    Args:
        id_token: JWT ID token
        config: OIDC configuration
        metadata: Provider metadata
        nonce: Expected nonce value

    Returns:
        Verified claims dict, or None if verification fails
    """
    jwks_uri = metadata.get("jwks_uri")
    if not jwks_uri:
        logger.error("JWKS URI not found in provider metadata")
        return None

    # SECURITY: Validate JWKS URI against SSRF
    try:
        validate_oidc_url(jwks_uri)
    except (SSRFProtectionError, ValueError) as e:
        logger.error(f"SSRF protection blocked JWKS URI: {e}")
        return None

    try:
        # Fetch JSON Web Key Set
        async with httpx.AsyncClient() as client:
            response = await client.get(jwks_uri, timeout=10.0)
            response.raise_for_status()
            jwks = response.json()

        # Import key set using Authlib
        key_set = JsonWebKey.import_key_set(jwks)

        # Decode and verify ID token with issuer, audience, nonce validation
        issuer = config.get("issuer_url") or metadata.get("issuer", "")
        claims = jwt.decode(
            id_token,
            key_set,
            claims_options={
                "iss": {"essential": True, "value": issuer},
                "aud": {"essential": True, "value": config.get("client_id", "")},
                "nonce": {"essential": True, "value": nonce},
            },
        )
        claims.validate()

        logger.info(f"Successfully verified ID token for subject: {claims.get('sub')}")
        return dict(claims)

    except JoseError as e:
        logger.error(f"ID token verification failed: {e}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error verifying ID token: {e}")
        return None


async def get_userinfo(
    access_token: str,
    metadata: dict[str, Any],
) -> dict[str, Any] | None:
    """Fetch user info from OIDC provider's userinfo endpoint.

    Args:
        access_token: OAuth2 access token
        metadata: Provider metadata

    Returns:
        Userinfo dict with claims (sub, email, name, etc.)
    """
    userinfo_endpoint = metadata.get("userinfo_endpoint")
    if not userinfo_endpoint:
        logger.error("Userinfo endpoint not found in provider metadata")
        return None

    # SECURITY: Validate userinfo endpoint against SSRF
    try:
        validate_oidc_url(userinfo_endpoint)
    except (SSRFProtectionError, ValueError) as e:
        logger.error(f"SSRF protection blocked userinfo endpoint: {e}")
        return None

    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                userinfo_endpoint,
                headers={"Authorization": f"Bearer {access_token}"},
                timeout=10.0,
            )
            response.raise_for_status()
            userinfo = response.json()

            logger.info("Successfully fetched userinfo")
            return userinfo

    except httpx.HTTPStatusError as e:
        logger.error(f"HTTP error fetching userinfo: {e.response.status_code}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error fetching userinfo: {e}")
        return None
