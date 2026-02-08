"""User authentication service for VulnForge - single-user, settings-based JWT auth.

This module provides single-user authentication capabilities adapted from TideWatch,
working alongside VulnForge's existing API authentication middleware.

Key features:
- Argon2id password hashing
- JWT tokens in httpOnly cookies
- Settings-based admin account storage
- Optional OIDC/SSO integration
- Auth mode toggle (none/local/oidc)
"""

import logging
import secrets
from datetime import UTC, datetime, timedelta
from pathlib import Path

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from authlib.jose import JoseError, jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.services.settings_manager import SettingsManager

logger = logging.getLogger(__name__)

# HTTP Bearer token
security = HTTPBearer(auto_error=False)

# JWT Configuration
JWT_SECRET_KEY_FILE = Path("/data/user_auth_secret.key")
JWT_ALGORITHM = "HS256"
JWT_ACCESS_TOKEN_EXPIRE_MINUTES = 24 * 60  # 24 hours
JWT_COOKIE_NAME = "vulnforge_token"
JWT_COOKIE_MAX_AGE = 86400  # 24 hours in seconds

# Initialize Argon2 password hasher with recommended parameters
# time_cost=2, memory_cost=102400 (100MB), parallelism=8
ph = PasswordHasher(time_cost=2, memory_cost=102400, parallelism=8)


# ============================================================================
# Secret Key Management
# ============================================================================


def sanitize_path(user_path: Path, base_dir: str, allow_symlinks: bool = False) -> Path:
    """Safely resolve user-provided paths within a base directory.

    Simple version for internal use - prevents path traversal.
    """
    base = Path(base_dir).resolve()
    if not base.exists():
        base.mkdir(parents=True, exist_ok=True)

    target = (base / user_path.name).resolve()

    # Ensure the resolved path is within base_dir
    try:
        target.relative_to(base)
    except ValueError:
        raise ValueError(
            f"Path traversal detected: {user_path} resolves to {target}, "
            f"which is outside base directory {base}"
        )

    return target


def get_or_create_secret_key(key_file: Path = JWT_SECRET_KEY_FILE) -> str:
    """Get existing or create new secret key.

    If the secret key file exists, reads and returns it.
    If not, generates a new cryptographically secure key and saves it.

    Args:
        key_file: Path to the secret key file (default: /data/user_auth_secret.key)

    Returns:
        The secret key as a string

    Note:
        Falls back to in-memory key generation if file operations fail.
        This means the key will change on restart, logging out all users.
    """
    try:
        # Validate key file path to prevent path traversal
        # JWT secret key must be in /data directory
        validated_key_file = sanitize_path(key_file, "/data", allow_symlinks=False)

        # Check if key file already exists
        if validated_key_file.exists():
            secret_key = validated_key_file.read_text().strip()
            if secret_key:
                logger.debug("Loaded existing user auth secret key from %s", validated_key_file)
                return secret_key
            else:
                logger.warning(
                    "User auth secret key file at %s is empty, generating new key",
                    validated_key_file,
                )

        # Generate cryptographically secure key (32 bytes = 256 bits)
        secret_key = secrets.token_urlsafe(32)

        # Ensure parent directory exists
        validated_key_file.parent.mkdir(parents=True, exist_ok=True)

        # Write key to file
        # nosec: intentional storage of JWT signing key for session persistence
        validated_key_file.write_text(secret_key)  # noqa: S105

        # Set restrictive permissions (owner read/write only)
        validated_key_file.chmod(0o600)

        logger.info("Generated new user auth secret key and saved to %s", validated_key_file)
        logger.info("User auth secret key will persist across container restarts")

        return secret_key

    except (ValueError, FileNotFoundError) as e:
        logger.error("Invalid user auth secret key file path: %s", str(e))
        logger.warning("Using temporary in-memory secret key (will change on restart)")
        return secrets.token_urlsafe(32)

    except PermissionError as e:
        logger.error("Permission denied when accessing user auth secret key file: %s", str(e))
        logger.warning("Using temporary in-memory secret key (will change on restart)")
        return secrets.token_urlsafe(32)

    except Exception as e:
        logger.error("Failed to handle user auth secret key file: %s", str(e), exc_info=True)
        logger.warning("Using temporary in-memory secret key (will change on restart)")
        return secrets.token_urlsafe(32)


# Load secret key on module import
_SECRET_KEY = get_or_create_secret_key()


# ============================================================================
# Password Operations
# ============================================================================


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against an Argon2 hash.

    Note: VulnForge user auth uses Argon2 (new system).
    The existing bcrypt is for API authentication providers only.
    """
    try:
        ph.verify(hashed_password, plain_password)
        return True
    except (VerifyMismatchError, InvalidHashError):
        return False


def hash_password(password: str) -> str:
    """Hash a password using Argon2id.

    Uses Argon2id with recommended parameters:
    - time_cost=2
    - memory_cost=102400 (100MB)
    - parallelism=8

    Note: Argon2 has no password length limitation (unlike bcrypt's 72 bytes).
    """
    return ph.hash(password)


# ============================================================================
# JWT Operations
# ============================================================================


def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    """Create a JWT access token."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(UTC) + expires_delta
    else:
        expire = datetime.now(UTC) + timedelta(minutes=JWT_ACCESS_TOKEN_EXPIRE_MINUTES)

    to_encode.update({"exp": expire, "iat": datetime.now(UTC)})
    header = {"alg": JWT_ALGORITHM}
    encoded_jwt = jwt.encode(header, to_encode, _SECRET_KEY)
    return encoded_jwt.decode("utf-8") if isinstance(encoded_jwt, bytes) else encoded_jwt


def get_token_from_request(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(security),
) -> str | None:
    """Extract JWT token from cookie or Authorization header.

    Priority:
    1. Cookie (primary method)
    2. Authorization header (backward compatibility)
    """
    # Try cookie first
    token = request.cookies.get(JWT_COOKIE_NAME)
    if token:
        return token

    # Fall back to Authorization header
    if credentials:
        return credentials.credentials

    return None


def decode_token(token: str) -> dict:
    """Decode and validate JWT token.

    Returns:
        Decoded token payload

    Raises:
        HTTPException: If token is invalid or expired
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(token, _SECRET_KEY)

        # Manually validate expiration (authlib doesn't do this automatically)
        import time

        if "exp" in payload:
            if payload["exp"] < time.time():
                logger.error("JWT token has expired")
                raise credentials_exception

        return payload
    except JoseError as e:
        logger.error("JWT decode error: %s", e)
        raise credentials_exception


# ============================================================================
# Admin Profile Management (Settings-based)
# ============================================================================


async def is_user_auth_setup_complete(db: AsyncSession) -> bool:
    """Check if user auth admin account has been created.

    Returns:
        True if user_auth_mode is "none" (no setup required) or admin account exists
    """
    # If auth is disabled, setup is considered complete (no account needed)
    auth_mode = await get_user_auth_mode(db)
    if auth_mode == "none":
        return True

    # For local/OIDC auth, check if admin account exists
    settings_manager = SettingsManager(db)
    admin_username = await settings_manager.get("user_auth_admin_username")
    return bool(admin_username and admin_username.strip())


async def get_user_admin_profile(db: AsyncSession) -> dict | None:
    """Get user auth admin profile from settings.

    Returns:
        Dict with admin profile data, or None if setup not complete
    """
    if not await is_user_auth_setup_complete(db):
        return None

    settings_manager = SettingsManager(db)
    return {
        "username": await settings_manager.get("user_auth_admin_username", default=""),
        "email": await settings_manager.get("user_auth_admin_email", default=""),
        "full_name": await settings_manager.get("user_auth_admin_full_name", default=""),
        "auth_method": await settings_manager.get("user_auth_admin_auth_method", default="local"),
        "oidc_provider": await settings_manager.get("user_auth_admin_oidc_provider", default=""),
        "created_at": await settings_manager.get("user_auth_admin_created_at", default=""),
        "last_login": await settings_manager.get("user_auth_admin_last_login", default=""),
    }


async def update_user_admin_profile(
    db: AsyncSession, email: str | None = None, full_name: str | None = None
) -> None:
    """Update user auth admin profile in settings."""
    settings_manager = SettingsManager(db)
    if email is not None:
        await settings_manager.set("user_auth_admin_email", email)
    if full_name is not None:
        await settings_manager.set("user_auth_admin_full_name", full_name)


async def update_user_admin_password(db: AsyncSession, new_hash: str) -> None:
    """Update user auth admin password hash in settings."""
    settings_manager = SettingsManager(db)
    await settings_manager.set("user_auth_admin_password_hash", new_hash)


async def update_user_admin_oidc_link(db: AsyncSession, oidc_subject: str, provider: str) -> None:
    """Link OIDC identity to user auth admin account."""
    settings_manager = SettingsManager(db)
    await settings_manager.set("user_auth_admin_oidc_subject", oidc_subject)
    await settings_manager.set("user_auth_admin_oidc_provider", provider)
    await settings_manager.set("user_auth_admin_auth_method", "oidc")


async def update_user_admin_last_login(db: AsyncSession) -> None:
    """Update user auth admin last login timestamp."""
    now = datetime.now(UTC).isoformat()
    settings_manager = SettingsManager(db)
    await settings_manager.set("user_auth_admin_last_login", now)


# ============================================================================
# Authentication
# ============================================================================


async def authenticate_user_admin(db: AsyncSession, username: str, password: str) -> dict | None:
    """Authenticate user auth admin by username and password.

    Returns:
        Admin profile dict if authenticated, None otherwise
    """
    # Get admin profile
    profile = await get_user_admin_profile(db)
    if not profile:
        return None

    # Check username matches
    if profile["username"] != username:
        return None

    # Get password hash
    settings_manager = SettingsManager(db)
    password_hash = await settings_manager.get("user_auth_admin_password_hash", default="")
    if not password_hash:
        logger.warning("Password login attempted but no password hash set")
        return None

    # Check auth method - reject password login for OIDC-only users
    if profile["auth_method"] == "oidc":
        logger.warning("Password login attempted for OIDC-linked admin account")
        return None

    # Verify password
    if not verify_password(password, password_hash):
        return None

    # Update last login
    await update_user_admin_last_login(db)

    return profile


async def get_current_user_admin(
    request: Request,
    db: AsyncSession = Depends(get_db),
    token: str | None = Depends(get_token_from_request),
) -> dict:
    """Get the current authenticated user admin from JWT token.

    Returns:
        Admin profile dict

    Raises:
        HTTPException 401: If token is invalid or missing
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    if not token:
        logger.error("No credentials provided - %s %s", request.method, request.url.path)
        raise credentials_exception

    logger.debug("Processing user authentication token")

    # Decode token
    payload = decode_token(token)

    # Validate token structure
    sub = payload.get("sub")
    username = payload.get("username")

    if sub is None or username is None:
        logger.error("Token missing sub or username")
        raise credentials_exception

    # For single-user VulnForge, sub should be "admin"
    if sub != "admin":
        logger.error("Invalid token subject: %s", sub)
        raise credentials_exception

    # Get admin profile from settings
    profile = await get_user_admin_profile(db)
    if not profile:
        logger.error("Admin profile not found")
        raise credentials_exception

    # Verify username matches
    if profile["username"] != username:
        logger.error("Token username mismatch")
        raise credentials_exception

    logger.debug("Token validated successfully for user admin")
    return profile


async def require_user_auth(
    request: Request,
    db: AsyncSession = Depends(get_db),
    token: str | None = Depends(get_token_from_request),
) -> dict | None:
    """Require user authentication - checks user_auth_mode setting.

    Returns:
        Admin profile dict if authenticated.
        None if user_auth_mode='none' (authentication disabled).

    Raises:
        HTTPException 401: If auth is enabled but user is not authenticated.
    """
    auth_mode = await get_user_auth_mode(db)

    # If auth is disabled, return None
    if auth_mode == "none":
        return None

    # Auth is enabled - enforce authentication
    return await get_current_user_admin(request, db, token)


async def optional_user_auth(
    request: Request,
    db: AsyncSession = Depends(get_db),
    token: str | None = Depends(get_token_from_request),
) -> dict | None:
    """Optional user authentication based on user_auth_mode setting.

    Returns:
        Admin profile dict if authenticated.
        None if user_auth_mode='none' or no credentials provided.
    """
    auth_mode = await get_user_auth_mode(db)

    if auth_mode == "none":
        return None

    # Auth optional - try to get current user, but don't raise if missing
    if not token:
        return None

    try:
        return await get_current_user_admin(request, db, token)
    except HTTPException:
        return None


# ============================================================================
# Auth Mode Management
# ============================================================================


async def get_user_auth_mode(db: AsyncSession) -> str:
    """Get the current user authentication mode from settings.

    Returns:
        "none", "local", or "oidc"
    """
    settings_manager = SettingsManager(db)
    auth_mode = await settings_manager.get("user_auth_mode", default="none")
    # Handle None case (fallback if SettingsManager returns None)
    if auth_mode is None:
        return "none"
    return auth_mode.lower()
