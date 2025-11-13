"""Authentication middleware and providers for VulnForge."""

import ipaddress
import json
import logging
import os
import secrets
import socket
from abc import ABC, abstractmethod
from typing import Optional

import bcrypt
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from app.db import get_db
from app.models.user import User
from app.services.settings_manager import SettingsManager

logger = logging.getLogger(__name__)

# Settings cache for performance optimization
import asyncio
_settings_cache: dict[str, str] | None = None
_settings_cache_time: float = 0
_settings_lock = asyncio.Lock()
SETTINGS_CACHE_TTL = 60  # seconds


async def _get_cached_settings(db) -> dict[str, str]:
    """
    Get settings with caching to avoid database queries on every request.
    Thread-safe with async lock to prevent race conditions.

    Args:
        db: Database session

    Returns:
        Dict of all settings
    """
    import time
    global _settings_cache, _settings_cache_time

    # Fast path: check without lock
    now = time.time()
    if _settings_cache is not None and (now - _settings_cache_time) <= SETTINGS_CACHE_TTL:
        # Return shallow copy to prevent mutations of cached dict
        return _settings_cache.copy()

    # Slow path: acquire lock and refresh
    async with _settings_lock:
        # Double-check after acquiring lock
        now = time.time()
        if _settings_cache is None or (now - _settings_cache_time) > SETTINGS_CACHE_TTL:
            settings_manager = SettingsManager(db)
            _settings_cache = await settings_manager.get_all()
            _settings_cache_time = now
            logger.debug(f"Settings cache refreshed ({len(_settings_cache)} settings)")

    # Return shallow copy to prevent mutations of cached dict
    return _settings_cache.copy()


def _normalize_trusted_entries(raw_entries: list) -> list[str]:
    """Normalize trusted proxy entries to non-empty strings."""
    normalized: list[str] = []
    for entry in raw_entries:
        if entry is None:
            continue
        value = str(entry).strip()
        if value:
            normalized.append(value)

    # Merge in default hints and environment-provided proxy ranges
    default_hints = [
        "socket-proxy-ro",
        "host.docker.internal",
        "172.16.0.0/12",  # Docker default bridge networks
        "10.0.0.0/8",     # Common private ranges for reverse proxies
        "192.168.0.0/16",
    ]
    env_ranges: list[str] = []
    for env_var in ("TRUSTED_PROXY_CIDRS", "DOCKER_TUNNEL_SUBNETS", "CLOUDFLARE_TRUSTED_IPS"):
        value = os.getenv(env_var, "")
        if value:
            env_ranges.extend(v.strip() for v in value.split(",") if v.strip())

    for extra in default_hints + env_ranges:
        if extra and extra not in normalized:
            normalized.append(extra)

    return normalized


def _parse_trusted_proxy_values(raw_value: str | list | None) -> list[str]:
    """
    Parse trusted proxy configuration from JSON/CSV/string values.

    Accepts JSON arrays, single JSON strings, or comma-separated lists.
    """
    if raw_value is None:
        return _normalize_trusted_entries([])

    if isinstance(raw_value, list):
        return _normalize_trusted_entries(raw_value)

    text = str(raw_value).strip()
    if not text:
        return _normalize_trusted_entries([])

    parsed = None
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        parsed = None

    if isinstance(parsed, list):
        return _normalize_trusted_entries(parsed)

    if isinstance(parsed, str):
        return _normalize_trusted_entries([parsed])

    # Fallback: treat as comma-separated list
    csv_text = text.replace("[", "").replace("]", "")
    candidates = [
        part.strip().strip('"').strip("'")
        for part in csv_text.split(",")
        if part.strip()
    ]
    return _normalize_trusted_entries(candidates)


def _expand_trusted_entries(entries: list[str]):
    """
    Expand trusted proxy entries into explicit IPs and networks.

    Supports single IPs, CIDR ranges, and hostnames (resolved at runtime).
    """
    ip_set: set[ipaddress._BaseAddress] = set()
    network_set: set[ipaddress._BaseNetwork] = set()

    for entry in entries:
        # CIDR or single IP handling
        try:
            network = ipaddress.ip_network(entry, strict=False)
            if network.prefixlen == network.max_prefixlen:
                ip_set.add(network.network_address)
            else:
                network_set.add(network)
            continue
        except ValueError:
            pass

        try:
            ip_set.add(ipaddress.ip_address(entry))
            continue
        except ValueError:
            pass

        # Hostname resolution (covers dynamic Docker container IPs)
        try:
            resolved_addresses = {info[4][0] for info in socket.getaddrinfo(entry, None)}
        except socket.gaierror as err:
            logger.warning(f"Trusted proxy hostname '{entry}' could not be resolved: {err}")
            continue

        for addr in resolved_addresses:
            try:
                ip_set.add(ipaddress.ip_address(addr))
            except ValueError:
                logger.debug(f"Ignoring unparseable address '{addr}' resolved from '{entry}'")

    return ip_set, network_set


def _is_trusted_proxy_ip(client_ip: str | None, entries: list[str]) -> bool:
    """Check if the client IP is within the trusted proxy entries."""
    if not client_ip:
        return False

    try:
        client_ip_obj = ipaddress.ip_address(client_ip)
    except ValueError:
        logger.warning(f"Header verification failed: invalid client IP '{client_ip}'")
        return False

    ip_set, network_set = _expand_trusted_entries(entries)

    if client_ip_obj in ip_set:
        return True

    for network in network_set:
        if client_ip_obj in network:
            return True

    return False


def _validate_username(username: str | None) -> str | None:
    """
    Validate username from headers.

    Args:
        username: Username string from header

    Returns:
        Validated username or None if invalid
    """
    if not username:
        return None

    username = username.strip()

    # Length check (prevent DoS via huge usernames)
    if len(username) > 255:
        logger.warning(f"Username too long: {len(username)} characters")
        return None

    # Empty after strip
    if not username:
        return None

    # Check for control characters (prevent injection attacks)
    if any(ord(c) < 32 for c in username):
        logger.warning("Username contains control characters")
        return None

    return username


def _validate_email(email: str | None) -> str | None:
    """
    Validate email from headers.

    Args:
        email: Email string from header

    Returns:
        Validated email or None if invalid
    """
    if not email:
        return None

    email = email.strip()

    # Length check
    if len(email) > 255:
        logger.warning(f"Email too long: {len(email)} characters")
        return None

    # Empty after strip
    if not email:
        return None

    # Check for control characters
    if any(ord(c) < 32 for c in email):
        logger.warning("Email contains control characters")
        return None

    return email


class AuthProvider(ABC):
    """Abstract base class for authentication providers."""

    def __init__(self, settings: dict[str, str]):
        """
        Initialize provider with settings.

        Args:
            settings: Dictionary of all settings from SettingsManager
        """
        self.settings = settings

    @abstractmethod
    async def authenticate(self, request: Request) -> Optional[User]:
        """
        Authenticate the request and return User if successful.

        Args:
            request: FastAPI request object

        Returns:
            User object if authenticated, None otherwise
        """
        pass

    def _is_admin(self, user: User) -> bool:
        """
        Determine if user has admin privileges.

        Checks:
        1. User has is_admin flag set (for API keys, basic auth)
        2. Username in auth_admin_usernames list
        3. User belongs to auth_admin_group (for header-based auth)

        Args:
            user: User to check

        Returns:
            True if user is admin, False otherwise
        """
        # Check 1: Provider-specific admin flag
        if user.is_admin:
            return True

        # Check 2: Username in admin list
        try:
            admin_usernames = json.loads(self.settings.get("auth_admin_usernames", "[]"))
            if user.username in admin_usernames:
                return True
        except (json.JSONDecodeError, TypeError):
            pass

        # Check 3: Member of admin group (for header-based providers)
        admin_group = self.settings.get("auth_admin_group", "vulnforge-admins")
        if admin_group in user.groups:
            return True

        return False


class NoneProvider(AuthProvider):
    """No authentication - allows all requests."""

    async def authenticate(self, request: Request) -> Optional[User]:
        """Always return anonymous user (auth disabled)."""
        return User(username="anonymous", provider="none", is_admin=False)


class AuthentikProvider(AuthProvider):
    """Authentik ForwardAuth provider - reads headers set by Authentik outpost."""

    def _verify_forward_auth_headers(self, request: Request) -> bool:
        """
        Verify that forward auth headers are from a trusted source.

        Implements two verification methods:
        1. Shared secret verification - check for matching secret in header
        2. Trusted proxy IP verification - check if request comes from allowed IP

        Args:
            request: FastAPI request object

        Returns:
            True if verification passes, False otherwise
        """
        import secrets

        # Method 1: Shared secret verification (most secure)
        verify_secret = self.settings.get("auth_authentik_verify_secret", "").strip()
        if verify_secret:
            secret_header = self.settings.get("auth_authentik_secret_header", "X-Authentik-Secret")
            provided_secret = request.headers.get(secret_header, "").strip()

            if not provided_secret:
                logger.debug("Header verification failed: no secret provided")
                return False

            # Constant-time comparison to prevent timing attacks
            if not secrets.compare_digest(verify_secret, provided_secret):
                logger.warning("Header verification failed: secret mismatch")
                return False

            logger.debug("Header verification passed: shared secret validated")
            return True

        # Method 2: Trusted proxy IP verification (defense-in-depth)
        try:
            trusted_proxies_value = self.settings.get(
                "auth_authentik_trusted_proxies",
                '["127.0.0.1", "::1"]',
            )
            trusted_proxies = _parse_trusted_proxy_values(trusted_proxies_value)
            logger.info(
                "Authentik trusted proxies resolved to: %s",
                trusted_proxies,
            )

            client_ip = request.client.host if request.client else None
            if not client_ip:
                forwarded_for = request.headers.get("X-Forwarded-For", "")
                if forwarded_for:
                    client_ip = forwarded_for.split(",")[-1].strip() or None

            if _is_trusted_proxy_ip(client_ip, trusted_proxies):
                logger.debug(f"Header verification passed: trusted proxy IP {client_ip}")
                return True

            logger.warning(f"Header verification failed: untrusted IP {client_ip}")
            return False

        except Exception as e:
            logger.error(f"Header verification failed: invalid trusted_proxies config - {e}")
            return False

    async def authenticate(self, request: Request) -> Optional[User]:
        """
        Authenticate using Authentik headers.

        Expected headers (configurable):
        - X-Authentik-Username: User's username
        - X-Authentik-Email: User's email address
        - X-Authentik-Groups: Comma-separated list of groups

        Returns:
            User if X-Authentik-Username present, None otherwise
        """
        # Get header names from settings
        username_header = self.settings.get("auth_authentik_header_username", "X-Authentik-Username")
        email_header = self.settings.get("auth_authentik_header_email", "X-Authentik-Email")
        groups_header = self.settings.get("auth_authentik_header_groups", "X-Authentik-Groups")

        # Verify request authenticity using shared secret and/or trusted proxy check
        if not self._verify_forward_auth_headers(request):
            logger.warning("Authentik auth failed: header verification failed (untrusted source)")
            return None

        # Extract and validate username (required)
        username = _validate_username(request.headers.get(username_header))
        if not username:
            logger.debug(f"Authentik auth failed: missing or invalid {username_header} header")
            return None

        # Extract and validate optional fields
        email = _validate_email(request.headers.get(email_header))
        groups_str = request.headers.get(groups_header, "")
        # Authentik uses pipe separator (|), but also support comma for compatibility
        separator = "|" if "|" in groups_str else ","
        groups = [g.strip() for g in groups_str.split(separator) if g.strip()]

        # Debug logging for troubleshooting
        logger.debug(f"Authentik headers - username: {username}, email: {email}, groups_str: '{groups_str}', groups: {groups}")

        # Create user
        user = User(
            username=username,
            email=email,
            groups=groups,
            provider="authentik"
        )

        # Check admin status
        user.is_admin = self._is_admin(user)

        logger.debug(f"Authentik auth successful: {user.username} (admin={user.is_admin}, groups={user.groups})")
        return user


class CustomHeadersProvider(AuthProvider):
    """Custom header-based auth for reverse proxies like Authelia, nginx, etc."""

    def _verify_forward_auth_headers(self, request: Request) -> bool:
        """
        Verify that forward auth headers are from a trusted source.

        Implements two verification methods:
        1. Shared secret verification - check for matching secret in header
        2. Trusted proxy IP verification - check if request comes from allowed IP

        Args:
            request: FastAPI request object

        Returns:
            True if verification passes, False otherwise
        """
        import secrets

        # Method 1: Shared secret verification (most secure)
        verify_secret = self.settings.get("auth_custom_header_verify_secret", "").strip()
        if verify_secret:
            secret_header = self.settings.get("auth_custom_header_secret_header", "X-Auth-Secret")
            provided_secret = request.headers.get(secret_header, "").strip()

            if not provided_secret:
                logger.debug("Custom header verification failed: no secret provided")
                return False

            # Constant-time comparison to prevent timing attacks
            if not secrets.compare_digest(verify_secret, provided_secret):
                logger.warning("Custom header verification failed: secret mismatch")
                return False

            logger.debug("Custom header verification passed: shared secret validated")
            return True

        # Method 2: Trusted proxy IP verification (defense-in-depth)
        try:
            trusted_proxies_value = self.settings.get(
                "auth_custom_header_trusted_proxies",
                '["127.0.0.1", "::1"]',
            )
            trusted_proxies = _parse_trusted_proxy_values(trusted_proxies_value)
            logger.info(
                "Custom header trusted proxies resolved to: %s",
                trusted_proxies,
            )

            client_ip = request.client.host if request.client else None
            if not client_ip:
                forwarded_for = request.headers.get("X-Forwarded-For", "")
                if forwarded_for:
                    client_ip = forwarded_for.split(",")[-1].strip() or None

            if _is_trusted_proxy_ip(client_ip, trusted_proxies):
                logger.debug(f"Custom header verification passed: trusted proxy IP {client_ip}")
                return True

            logger.warning(f"Custom header verification failed: untrusted IP {client_ip}")
            return False

        except Exception as e:
            logger.error(f"Custom header verification failed: invalid trusted_proxies config - {e}")
            return False

    async def authenticate(self, request: Request) -> Optional[User]:
        """
        Authenticate using custom headers.

        Configurable headers:
        - auth_custom_header_username: Username header (default: X-Remote-User)
        - auth_custom_header_email: Email header
        - auth_custom_header_groups: Groups header

        Returns:
            User if username header present, None otherwise
        """
        # Get header names from settings
        username_header = self.settings.get("auth_custom_header_username", "X-Remote-User")
        email_header = self.settings.get("auth_custom_header_email", "X-Remote-Email")
        groups_header = self.settings.get("auth_custom_header_groups", "X-Remote-Groups")

        # Verify request authenticity using shared secret and/or trusted proxy check
        if not self._verify_forward_auth_headers(request):
            logger.warning("Custom header auth failed: header verification failed (untrusted source)")
            return None

        # Extract and validate username (required)
        username = _validate_username(request.headers.get(username_header))
        if not username:
            logger.debug(f"Custom headers auth failed: missing or invalid {username_header} header")
            return None

        # Extract and validate optional fields
        email = _validate_email(request.headers.get(email_header))
        groups_str = request.headers.get(groups_header, "")
        # Support both pipe and comma separators for compatibility
        separator = "|" if "|" in groups_str else ","
        groups = [g.strip() for g in groups_str.split(separator) if g.strip()]

        # Create user
        user = User(
            username=username,
            email=email,
            groups=groups,
            provider="custom_headers"
        )

        # Check admin status
        user.is_admin = self._is_admin(user)

        logger.debug(f"Custom headers auth successful: {user.username} (admin={user.is_admin})")
        return user


class ApiKeyProvider(AuthProvider):
    """API key-based authentication using Bearer tokens."""

    async def authenticate(self, request: Request) -> Optional[User]:
        """
        Authenticate using API key in Authorization header.

        Expected format:
        Authorization: Bearer <api-key>

        API keys stored in settings as JSON:
        [{"key": "abc123", "name": "my-script", "admin": true}]

        Returns:
            User if valid API key found, None otherwise
        """
        # Extract Authorization header
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            logger.debug("API key auth failed: missing or invalid Authorization header")
            return None

        # Extract token
        token = auth_header[7:]  # Remove "Bearer " prefix

        # Load API keys from settings
        try:
            api_keys = json.loads(self.settings.get("auth_api_keys", "[]"))
        except (json.JSONDecodeError, TypeError):
            logger.error("Failed to parse auth_api_keys setting")
            return None

        # Search for matching key using constant-time comparison
        for key_config in api_keys:
            if not isinstance(key_config, dict):
                continue

            stored_key = key_config.get("key", "")
            if secrets.compare_digest(stored_key, token):
                # Valid key found
                user = User(
                    username=key_config.get("name", "api-key-user"),
                    email=key_config.get("email"),
                    is_admin=key_config.get("admin", False),
                    provider="api_key"
                )
                logger.info(f"API key auth successful: {user.username} (admin={user.is_admin})")
                return user

        logger.debug("API key auth failed: invalid token")
        return None


class BasicAuthProvider(AuthProvider):
    """Basic HTTP authentication with bcrypt password hashing."""

    async def authenticate(self, request: Request) -> Optional[User]:
        """
        Authenticate using HTTP Basic Auth.

        Expected format:
        Authorization: Basic <base64(username:password)>

        Users stored in settings as JSON:
        [{"username": "admin", "password_hash": "bcrypt...", "admin": true}]

        Returns:
            User if credentials valid, None otherwise
        """
        import base64

        # Extract Authorization header
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Basic "):
            logger.debug("Basic auth failed: missing or invalid Authorization header")
            return None

        # Decode credentials
        try:
            encoded_credentials = auth_header[6:]  # Remove "Basic " prefix

            # Length check to prevent DoS via huge credentials
            if len(encoded_credentials) > 8192:  # ~6KB decoded
                logger.debug("Basic auth failed: credentials too long")
                return None

            decoded_bytes = base64.b64decode(encoded_credentials)
            decoded_str = decoded_bytes.decode("utf-8")

            if ":" not in decoded_str:
                logger.debug("Basic auth failed: invalid credentials format")
                return None

            username, password = decoded_str.split(":", 1)
        except Exception as e:
            logger.debug(f"Basic auth failed: decode error - {e}")
            return None

        # Load users from settings
        try:
            users = json.loads(self.settings.get("auth_basic_users", "[]"))
        except (json.JSONDecodeError, TypeError):
            logger.error("Failed to parse auth_basic_users setting")
            return None

        # Search for user and verify password
        for user_config in users:
            if not isinstance(user_config, dict):
                continue

            if user_config.get("username") != username:
                continue

            # Found user, check password
            password_hash = user_config.get("password_hash", "")
            try:
                # Move bcrypt to thread pool to avoid blocking event loop
                import asyncio
                password_valid = await asyncio.to_thread(
                    bcrypt.checkpw,
                    password.encode("utf-8"),
                    password_hash.encode("utf-8")
                )
                if password_valid:
                    # Valid password
                    user = User(
                        username=username,
                        email=user_config.get("email"),
                        is_admin=user_config.get("admin", False),
                        provider="basic_auth"
                    )
                    logger.info(f"Basic auth successful: {user.username} (admin={user.is_admin})")
                    return user
            except Exception as e:
                logger.error(f"Basic auth password check failed: {e}")

        logger.debug("Basic auth failed: invalid credentials")
        return None


class AuthProviderFactory:
    """Factory for creating auth provider instances."""

    _providers = {
        "none": NoneProvider,
        "authentik": AuthentikProvider,
        "custom_headers": CustomHeadersProvider,
        "api_key": ApiKeyProvider,
        "basic_auth": BasicAuthProvider,
    }

    @classmethod
    def get(cls, provider_name: str, settings: dict[str, str]) -> AuthProvider:
        """
        Get auth provider instance by name.

        Args:
            provider_name: Name of provider (none, authentik, custom_headers, api_key, basic_auth)
            settings: Dictionary of all settings

        Returns:
            AuthProvider instance

        Raises:
            ValueError: If provider_name is unknown
        """
        provider_class = cls._providers.get(provider_name)
        if not provider_class:
            raise ValueError(
                f"Unknown auth provider: {provider_name}. "
                f"Valid options: {', '.join(cls._providers.keys())}"
            )

        return provider_class(settings)


class AuthenticationMiddleware(BaseHTTPMiddleware):
    """FastAPI middleware for authentication."""

    async def dispatch(self, request: Request, call_next):
        """
        Process request through authentication.

        Flow:
        1. Check if auth is enabled
        2. If disabled, allow all requests
        3. If enabled, get configured provider
        4. Attempt authentication
        5. Attach user to request.state.user
        6. If auth fails and required, return 401

        Args:
            request: FastAPI request
            call_next: Next middleware/endpoint handler

        Returns:
            Response from next handler or 401 error
        """
        # Load settings from database
        # Manually create session for middleware usage
        from app.db import async_session_maker

        async with async_session_maker() as db:
            # Use cached settings for better performance
            settings_dict = await _get_cached_settings(db)
            auth_enabled = settings_dict.get("auth_enabled", "false").lower() == "true"

            # If auth is disabled, allow all requests
            if not auth_enabled:
                # Still attach anonymous user for consistency
                request.state.user = User(username="anonymous", provider="none", is_admin=False)
                return await call_next(request)

            # Allow unauthenticated access to frontend (non-API routes)
            # Only protect /api/* endpoints with authentication
            # Normalize path to prevent bypass via encoding or path manipulation
            import urllib.parse
            import posixpath

            # Decode URL encoding
            normalized_path = urllib.parse.unquote(request.url.path)
            # Remove double slashes
            while "//" in normalized_path:
                normalized_path = normalized_path.replace("//", "/")
            # Resolve relative path components (. and ..)
            normalized_path = posixpath.normpath(normalized_path)
            # Ensure path is absolute
            if not normalized_path.startswith("/"):
                normalized_path = "/" + normalized_path
            # Case-insensitive check for defense-in-depth
            # Check without trailing slash to catch /api, /api/, /api/v1, etc.
            normalized_path_lower = normalized_path.lower()
            if not (normalized_path_lower.startswith("/api/") or normalized_path_lower == "/api"):
                # Frontend routes - allow access so users can see login page
                request.state.user = User(username="anonymous", provider="none", is_admin=False)
                return await call_next(request)

            # Get configured provider
            provider_name = settings_dict.get("auth_provider", "none")

            # Create provider instance
            try:
                provider = AuthProviderFactory.get(provider_name, settings_dict)
            except ValueError as e:
                logger.error(f"Invalid auth provider configuration: {e}")
                return JSONResponse(
                    status_code=500,
                    content={"detail": "Invalid authentication configuration"}
                )

            # Attempt authentication
            user = await provider.authenticate(request)

            if user is None:
                # Authentication failed - don't disclose auth provider for security
                return JSONResponse(
                    status_code=401,
                    content={"detail": "Authentication required"}
                )

            # Authentication successful - attach user to request
            request.state.user = user

        # Continue to next handler (session is now closed)
        return await call_next(request)


# Compatibility alias: Tests may reference APIKeyProvider (capital letters)
# while the actual class uses PEP8 naming (ApiKeyProvider)
APIKeyProvider = ApiKeyProvider
