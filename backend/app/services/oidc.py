"""OIDC service for OAuth2/OpenID Connect authentication."""

import base64
import hashlib
import ipaddress
import logging
import os
import secrets
import socket
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlencode, urlparse

import httpx
from joserfc import jwt
from joserfc.errors import JoseError
from joserfc.jwk import KeySet
from joserfc.jwt import JWTClaimsRegistry
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.oidc_state import OIDCState
from app.utils.log_redaction import sanitize_for_log

logger = logging.getLogger(__name__)


def generate_pkce_pair() -> tuple[str, str]:
    """Generate a PKCE code_verifier and its S256 code_challenge (RFC 7636)."""
    verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


class SSRFProtectionError(Exception):
    """SSRF protection blocked the request."""

    pass


def _get_trusted_hosts() -> set[str]:
    """Get trusted hosts from VULNFORGE_TRUSTED_HOSTS env var.

    Returns:
        Set of trusted hostnames, IPs, or CIDR ranges.
    """
    raw = os.environ.get("VULNFORGE_TRUSTED_HOSTS", "")
    return {h.strip() for h in raw.split(",") if h.strip()} if raw else set()


def _is_trusted(hostname: str, trusted_hosts: set[str]) -> bool:
    """Check if a hostname matches any trusted host entry.

    Supports exact hostname match, exact IP match, and CIDR range match.
    Also resolves hostnames via DNS to check if resolved IPs match.

    Args:
        hostname: Hostname or IP to check.
        trusted_hosts: Set of trusted hostnames, IPs, or CIDR strings.

    Returns:
        True if the hostname is trusted.
    """
    if not trusted_hosts:
        return False

    # Exact hostname/IP match
    if hostname in trusted_hosts:
        return True

    # Check if hostname is an IP in a trusted CIDR
    try:
        ip = ipaddress.ip_address(hostname)
        for trusted in trusted_hosts:
            if "/" in trusted:
                try:
                    if ip in ipaddress.ip_network(trusted, strict=False):
                        return True
                except ValueError:
                    continue
    except ValueError:
        pass

    # DNS resolution — check if resolved IPs match trusted entries
    try:
        for _, _, _, _, addr in socket.getaddrinfo(hostname, None):
            resolved_ip = ipaddress.ip_address(addr[0])
            if str(resolved_ip) in trusted_hosts:
                return True
            for trusted in trusted_hosts:
                if "/" in trusted:
                    try:
                        if resolved_ip in ipaddress.ip_network(trusted, strict=False):
                            return True
                    except ValueError:
                        continue
    except socket.gaierror, ValueError, OSError:
        pass

    return False


def validate_oidc_url(url: str, trusted_hosts: set[str] | None = None) -> None:
    """Validate OIDC URL against SSRF attacks (CWE-918).

    Resolves the hostname across ALL address families (A + AAAA) and rejects the
    URL if ANY resolved address is non-public — so an AAAA-only / IPv6 host can't
    slip past an IPv4-only check.

    Blocks (v4 and v6):
    - Private ranges (10/8, 172.16/12, 192.168/16, IPv6 ULA fc00::/7)
    - Loopback (127.0.0.0/8, ::1)
    - Link-local (169.254.0.0/16, fe80::/10) incl. the 169.254.169.254 metadata IP
    - Reserved, unspecified (0.0.0.0, ::), and multicast ranges

    A self-hosted OIDC issuer (e.g. Rauthy behind split-horizon DNS) may resolve
    to a private LAN IP. Such hosts can be allowlisted via the
    VULNFORGE_TRUSTED_HOSTS env var (comma-separated hostnames, IPs, or CIDR
    ranges), which relaxes the private-IP block for matching hosts only. The
    issuer URL is admin-only, so this allowlist is not attacker-controllable.

    Residual (accepted, §10/D4): DNS-rebinding TOCTOU between this check and the
    actual fetch is not closed by pinning the validated IP into the transport.
    The issuer URL is admin-only (set via authenticated PUT /oidc/config/admin),
    so this is an accepted residual for a single-admin homelab.

    Args:
        url: URL to validate
        trusted_hosts: Override for trusted hosts (defaults to env var)

    Raises:
        SSRFProtectionError: If URL targets private/internal resources.
        ValueError: If the URL is empty or has no hostname.
    """

    if not url:
        raise ValueError("URL cannot be empty")

    parsed = urlparse(url)
    hostname = parsed.hostname

    if not hostname:
        raise ValueError("Invalid URL: no hostname")

    # Block non-HTTP(S) schemes
    if parsed.scheme not in ("http", "https"):
        raise SSRFProtectionError(f"Unsupported scheme: {parsed.scheme}")

    # Allowlisted issuer (e.g. self-hosted Rauthy on a private LAN IP): accept
    # without the private-IP block. Scheme is still enforced above.
    if trusted_hosts is None:
        trusted_hosts = _get_trusted_hosts()
    if _is_trusted(hostname, trusted_hosts):
        return

    # Resolve across every address family. A genuine resolution failure is
    # fail-open (the HTTP fetch will fail anyway); a resolved-but-unparseable
    # address is treated as hostile and rejected (it must not slip through).
    try:
        addrinfos = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return

    for info in addrinfos:
        ip_str = info[4][0]
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError as exc:
            logger.warning("SSRF check: unparseable resolved address %r", ip_str)
            raise SSRFProtectionError(f"Unresolvable/invalid address for host: {hostname}") from exc

        # Normalize IPv4-mapped IPv6 (::ffff:a.b.c.d) so v4 ranges are checked.
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped

        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_unspecified
            or ip.is_multicast
        ):
            raise SSRFProtectionError(f"Private/local IP blocked: {ip}")

        # Explicit cloud metadata endpoint guard (also covered by is_link_local).
        if str(ip) == "169.254.169.254":
            raise SSRFProtectionError("Cloud metadata endpoint blocked")


def generate_state() -> str:
    """Generate cryptographically secure state token (256-bit)."""
    return secrets.token_urlsafe(32)


# Canonical placeholder per plan §5.4(3): admin GET returns this when a
# client_secret is stored.
MASKED_SECRET_PLACEHOLDER = "********"


def display_mask_secret(secret: str) -> str:
    """Return the canonical mask used in admin GET responses."""
    return MASKED_SECRET_PLACEHOLDER if secret else ""


def is_masked_secret(secret: str) -> bool:
    """Detect whether a value is a recognized mask placeholder."""
    if not secret:
        return False
    if secret == MASKED_SECRET_PLACEHOLDER:
        return True
    return secret.startswith("***") or "****...****" in secret


async def write_oidc_config(db: AsyncSession, payload: dict[str, str]) -> None:
    """Atomically persist OIDC settings.

    Caller passes prefix-stripped keys (e.g. "issuer_url"); we restore the
    `user_auth_oidc_` prefix used in the generic settings table.
    """
    from app.services.settings_manager import SettingsManager

    settings_manager = SettingsManager(db)
    for clean_key, value in payload.items():
        await settings_manager.set(f"user_auth_oidc_{clean_key}", value)


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
    code_verifier: str | None = None,
) -> None:
    """Store OIDC state in database for CSRF protection.

    Args:
        db: Database session
        state: CSRF state token
        redirect_uri: OAuth callback URI
        nonce: Nonce for ID token validation
        code_verifier: PKCE code_verifier to be sent in token exchange
    """
    oidc_state = OIDCState(
        state=state,
        nonce=nonce,
        code_verifier=code_verifier,
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
        "code_verifier": oidc_state.code_verifier,
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
    # Generate cryptographically secure state, nonce, and PKCE pair (RFC 7636 S256)
    state = generate_state()
    nonce = secrets.token_urlsafe(32)
    code_verifier, code_challenge = generate_pkce_pair()

    # Determine redirect URI
    redirect_uri = f"{base_url.rstrip('/')}/api/v1/user-auth/oidc/callback"

    logger.info(f"OIDC redirect URI: {redirect_uri} (base_url: {base_url})")

    # Store state in database for validation in callback (CSRF protection)
    await store_oidc_state(db, state, redirect_uri, nonce, code_verifier=code_verifier)

    # Build authorization URL
    auth_endpoint = metadata.get("authorization_endpoint")
    scopes = config.get("scopes", "openid profile email")

    params = {
        "client_id": config.get("client_id", ""),
        "response_type": "code",
        "scope": scopes,
        "redirect_uri": redirect_uri,
        "state": state,
        "nonce": nonce,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }

    auth_url = f"{auth_endpoint}?{urlencode(params)}"

    logger.info(f"Created authorization URL for provider: {config.get('provider_name', 'OIDC')}")
    return auth_url, state


async def exchange_code_for_tokens(
    code: str,
    config: dict[str, str],
    metadata: dict[str, Any],
    redirect_uri: str,
    code_verifier: str | None = None,
) -> dict[str, Any] | None:
    """Exchange authorization code for tokens.

    Args:
        code: Authorization code from callback
        config: OIDC configuration
        metadata: Provider metadata
        redirect_uri: Redirect URI used in authorization
        code_verifier: PKCE code_verifier matching the code_challenge sent
            in the authorization request

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
    if code_verifier:
        data["code_verifier"] = code_verifier

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

        # Import key set
        key_set = KeySet.import_key_set(jwks)

        # Decode (verifies signature) then validate iss/aud/nonce + default exp/nbf/iat.
        # Explicit allowlist accepts EdDSA (Rauthy default) and RS256
        # (Authentik/Keycloak/etc.) — rejects anything else.
        issuer = config.get("issuer_url") or metadata.get("issuer", "")
        decoded = jwt.decode(id_token, key_set, algorithms=["EdDSA", "RS256"])
        claims_registry = JWTClaimsRegistry(
            iss={"essential": True, "value": issuer},
            aud={"essential": True, "value": config.get("client_id", "")},
            nonce={"essential": True, "value": nonce},
        )
        claims_registry.validate(decoded.claims)

        logger.info(f"Successfully verified ID token for subject: {decoded.claims.get('sub')}")
        return dict(decoded.claims)

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
