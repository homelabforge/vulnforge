"""User authentication API endpoints for VulnForge single-user auth."""

import logging
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Body, Depends, HTTPException, Request, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_db
from app.schemas.user_auth import (
    ChangePasswordRequest,
    LoginRequest,
    SetupRequest,
    SetupResponse,
    TokenResponse,
    UpdateProfileRequest,
    UserAuthStatusResponse,
    UserProfile,
)
from app.services.settings_manager import SettingsManager
from app.services.user_auth import (
    JWT_COOKIE_MAX_AGE,
    JWT_COOKIE_NAME,
    authenticate_user_admin,
    create_access_token,
    get_user_admin_profile,
    get_user_auth_mode,
    hash_password,
    is_user_auth_setup_complete,
    require_user_auth,
    update_user_admin_password,
    update_user_admin_profile,
    verify_password,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/user-auth", tags=["User Authentication"])


# ============================================================================
# Public Endpoints (No Auth Required)
# ============================================================================


@router.get("/status", response_model=UserAuthStatusResponse)
async def get_user_auth_status(
    db: AsyncSession = Depends(get_db),
):
    """Get user authentication status (public endpoint).

    Returns setup completion status, auth mode, and OIDC enablement.
    """
    setup_complete = await is_user_auth_setup_complete(db)
    auth_mode = await get_user_auth_mode(db)
    settings_manager = SettingsManager(db)
    oidc_enabled_str = await settings_manager.get("user_auth_oidc_enabled", default="false")
    oidc_enabled = oidc_enabled_str.lower() == "true"

    return {
        "setup_complete": setup_complete,
        "auth_mode": auth_mode,
        "oidc_enabled": oidc_enabled,
    }


@router.post("/setup", response_model=SetupResponse, status_code=status.HTTP_201_CREATED)
async def setup_admin_account(
    request: Request,
    setup_data: SetupRequest,
    db: AsyncSession = Depends(get_db),
):
    """Create initial admin account (first-time setup).

    Only works if no admin account exists yet.
    Automatically enables user_auth_mode='local' after setup.
    """
    # Check if admin account already exists
    settings_manager = SettingsManager(db)
    admin_username = await settings_manager.get("user_auth_admin_username")
    if admin_username and admin_username.strip():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Setup already complete. Admin account exists.",
        )

    # Hash password
    password_hash = hash_password(setup_data.password)

    # Create admin account in settings
    now = datetime.now(UTC).isoformat()
    await settings_manager.set("user_auth_admin_username", setup_data.username)
    await settings_manager.set("user_auth_admin_email", setup_data.email)
    await settings_manager.set("user_auth_admin_password_hash", password_hash)
    await settings_manager.set("user_auth_admin_full_name", setup_data.full_name or "")
    await settings_manager.set("user_auth_admin_auth_method", "local")
    await settings_manager.set("user_auth_admin_created_at", now)
    await settings_manager.set("user_auth_admin_last_login", now)

    # Enable local authentication
    await settings_manager.set("user_auth_mode", "local")

    logger.info("User auth admin account created: %s", setup_data.username)
    logger.info("User authentication mode set to: local")

    return {
        "username": setup_data.username,
        "email": setup_data.email,
        "full_name": setup_data.full_name or "",
        "message": "Admin account created successfully",
    }


@router.post("/cancel-setup")
async def cancel_setup(db: AsyncSession = Depends(get_db)):
    """Cancel setup and disable user authentication (only during initial setup).

    This endpoint allows users to cancel the setup process from the setup page.
    It can only be called before setup is complete to prevent unauthorized
    auth mode changes.
    """
    # Only allow canceling if setup is not complete yet
    setup_complete = await is_user_auth_setup_complete(db)
    if setup_complete:
        raise HTTPException(
            status_code=403, detail="Cannot cancel setup after it has been completed"
        )

    # Set user_auth_mode to none
    settings_manager = SettingsManager(db)
    await settings_manager.set("user_auth_mode", "none")

    logger.info("User auth setup cancelled - authentication disabled")

    return {"message": "Setup cancelled, authentication disabled"}


@router.post("/login", response_model=TokenResponse)
async def login(
    request: Request,
    response: Response,
    login_data: LoginRequest,
    db: AsyncSession = Depends(get_db),
):
    """Authenticate admin user and set JWT token in httpOnly cookie."""
    # Check if setup complete
    if not await is_user_auth_setup_complete(db):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Setup not complete. Please create admin account first.",
        )

    # Authenticate
    profile = await authenticate_user_admin(db, login_data.username, login_data.password)

    if not profile:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Create JWT token
    access_token_expires = timedelta(minutes=24 * 60)  # 24 hours
    access_token = create_access_token(
        data={"sub": "admin", "username": profile["username"]}, expires_delta=access_token_expires
    )

    # Set httpOnly cookie
    # secure=True for HTTPS (production), secure=False for HTTP (local dev)
    # Check X-Forwarded-Proto header (set by reverse proxy like Traefik)
    scheme = request.headers.get("x-forwarded-proto", request.url.scheme)
    is_secure = scheme == "https"
    response.set_cookie(
        key=JWT_COOKIE_NAME,
        value=access_token,
        httponly=True,
        secure=is_secure,
        samesite="lax",
        max_age=JWT_COOKIE_MAX_AGE,
    )

    logger.info("User auth admin user logged in: %s", profile["username"])

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": JWT_COOKIE_MAX_AGE,
    }


# ============================================================================
# Protected Endpoints (Auth Required)
# ============================================================================


@router.post("/logout")
async def logout(
    response: Response,
    admin: dict = Depends(require_user_auth),
    db: AsyncSession = Depends(get_db),
):
    """Logout admin user by clearing JWT cookie."""
    if not admin:
        # user_auth_mode is "none", no cookie to clear
        return {"message": "Authentication is disabled"}

    # Clear JWT cookie
    response.delete_cookie(key=JWT_COOKIE_NAME)

    logger.info("User auth admin user logged out")
    return {"message": "Logged out successfully"}


@router.get("/me", response_model=UserProfile)
async def get_current_admin_profile(
    admin: dict = Depends(require_user_auth),
    db: AsyncSession = Depends(get_db),
):
    """Get current admin user profile."""
    if not admin:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )

    return {
        "username": admin["username"],
        "email": admin["email"],
        "full_name": admin["full_name"],
        "auth_method": admin["auth_method"],
        "oidc_provider": admin["oidc_provider"] or None,
        "created_at": admin["created_at"] or None,
        "last_login": admin["last_login"] or None,
    }


@router.put("/me", response_model=UserProfile)
async def update_admin_profile_endpoint(
    profile_data: UpdateProfileRequest,
    admin: dict = Depends(require_user_auth),
    db: AsyncSession = Depends(get_db),
):
    """Update admin profile (email and full name only)."""
    if not admin:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )

    # Update profile
    await update_user_admin_profile(
        db,
        email=profile_data.email,
        full_name=profile_data.full_name,
    )

    # Get updated profile
    updated_profile = await get_user_admin_profile(db)

    logger.info("User auth admin profile updated")

    return {
        "username": updated_profile["username"],
        "email": updated_profile["email"],
        "full_name": updated_profile["full_name"],
        "auth_method": updated_profile["auth_method"],
        "oidc_provider": updated_profile["oidc_provider"] or None,
        "created_at": updated_profile["created_at"] or None,
        "last_login": updated_profile["last_login"] or None,
    }


@router.put("/password")
async def change_password(
    password_data: ChangePasswordRequest,
    admin: dict = Depends(require_user_auth),
    db: AsyncSession = Depends(get_db),
):
    """Change admin password (local auth only)."""
    if not admin:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )

    # Check if admin uses local authentication
    if admin["auth_method"] != "local":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Password change not allowed for {admin['auth_method']} authentication. "
            "Please use your identity provider to change your password.",
        )

    # Verify current password
    settings_manager = SettingsManager(db)
    current_hash = await settings_manager.get("user_auth_admin_password_hash", default="")
    if not current_hash:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Password hash not found",
        )

    if not verify_password(password_data.current_password, current_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Current password is incorrect",
        )

    # Hash new password
    new_hash = hash_password(password_data.new_password)

    # Update password
    await update_user_admin_password(db, new_hash)

    logger.info("User auth admin password changed")

    return {"message": "Password changed successfully"}


# ============================================================================
# OIDC Endpoints
# ============================================================================


@router.get("/oidc/login")
async def oidc_login(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Initiate OIDC authentication flow (public endpoint).

    Redirects user to OIDC provider for authentication.
    """
    from starlette.responses import RedirectResponse

    from app.services import oidc as oidc_service

    # Validate setup is complete
    if not await is_user_auth_setup_complete(db):
        raise HTTPException(
            status_code=400,
            detail="User authentication setup not complete. Complete setup first.",
        )

    # Get OIDC configuration from database
    config = await oidc_service.get_oidc_config(db)

    # Check if OIDC is enabled
    if config.get("enabled", "false").lower() != "true":
        raise HTTPException(
            status_code=400,
            detail="OIDC authentication is not enabled",
        )

    # Validate required config fields
    issuer_url = config.get("issuer_url", "").strip()
    client_id = config.get("client_id", "").strip()

    if not issuer_url or not client_id:
        raise HTTPException(
            status_code=500,
            detail="OIDC not properly configured. Check issuer URL and client ID in settings.",
        )

    try:
        # Fetch provider metadata (discovery endpoint)
        metadata = await oidc_service.get_provider_metadata(issuer_url)

        if not metadata:
            raise HTTPException(
                status_code=503,
                detail="Cannot connect to OIDC provider. Check issuer URL.",
            )

    except oidc_service.SSRFProtectionError as e:
        logger.error(f"SSRF protection blocked OIDC issuer URL: {e}")
        raise HTTPException(
            status_code=400,
            detail="Invalid OIDC issuer URL (SSRF protection)",
        )

    # Determine base URL (handles reverse proxy headers from Traefik)
    base_url = str(request.base_url).rstrip("/")
    if request.headers.get("x-forwarded-proto"):
        scheme = request.headers.get("x-forwarded-proto")
        host = request.headers.get("x-forwarded-host", request.headers.get("host"))
        base_url = f"{scheme}://{host}"

    # Create authorization URL with state/nonce
    auth_url, state = await oidc_service.create_authorization_url(db, config, metadata, base_url)

    logger.info(f"Initiating OIDC login flow (state: {state[:8]}...)")

    # Redirect to OIDC provider
    return RedirectResponse(url=auth_url, status_code=302)


@router.get("/oidc/callback")
async def oidc_callback(
    code: str,
    state: str,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
):
    """Handle OIDC callback from provider (public endpoint).

    Receives authorization code, exchanges for tokens, validates ID token,
    and creates admin account link or JWT session.
    """
    from starlette.responses import RedirectResponse

    from app.services import oidc as oidc_service

    logger.info(f"OIDC callback received (state: {state[:8]}...)")

    # VALIDATE STATE (CSRF Protection)
    state_data = await oidc_service.validate_and_consume_state(db, state)
    if not state_data:
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired state parameter",
        )

    # GET OIDC CONFIGURATION
    config = await oidc_service.get_oidc_config(db)
    issuer_url = config.get("issuer_url", "").strip()

    try:
        # FETCH PROVIDER METADATA
        metadata = await oidc_service.get_provider_metadata(issuer_url)

        if not metadata:
            raise HTTPException(
                status_code=503,
                detail="Cannot connect to OIDC provider",
            )

        # EXCHANGE CODE FOR TOKENS
        redirect_uri = state_data["redirect_uri"]
        tokens = await oidc_service.exchange_code_for_tokens(code, config, metadata, redirect_uri)

        if not tokens:
            raise HTTPException(
                status_code=502,
                detail="Failed to exchange code for tokens",
            )

        # VERIFY ID TOKEN
        id_token = tokens.get("id_token")
        nonce = state_data["nonce"]

        if not id_token:
            raise HTTPException(
                status_code=502,
                detail="No ID token received from provider",
            )

        claims = await oidc_service.verify_id_token(id_token, config, metadata, nonce)

        if not claims:
            raise HTTPException(
                status_code=401,
                detail="Failed to verify ID token",
            )

        # FETCH USERINFO (Optional)
        access_token = tokens.get("access_token")
        userinfo = None
        if access_token:
            userinfo = await oidc_service.get_userinfo(access_token, metadata)

        # EXTRACT USERNAME AND EMAIL FROM CLAIMS
        username_claim = config.get("username_claim", "preferred_username")
        email_claim = config.get("email_claim", "email")

        username = claims.get(username_claim)
        if not username and userinfo:
            username = userinfo.get(username_claim)
        if not username:
            username = claims.get("preferred_username") or claims.get("sub")

        email = claims.get(email_claim)
        if not email and userinfo:
            email = userinfo.get(email_claim)

        # LINK OIDC TO ADMIN ACCOUNT
        settings_manager = SettingsManager(db)
        oidc_sub = claims.get("sub")
        provider_name = config.get("provider_name", "OIDC Provider")

        await settings_manager.set("user_auth_admin_oidc_subject", oidc_sub)
        await settings_manager.set("user_auth_admin_oidc_provider", provider_name)

        # Update admin profile if we got username/email from OIDC
        admin_profile = await get_user_admin_profile(db)
        if username and username != admin_profile.get("username"):
            await settings_manager.set("user_auth_admin_username", username)
        if email and email != admin_profile.get("email"):
            await settings_manager.set("user_auth_admin_email", email or "")

        # Update last login
        await settings_manager.set(
            "user_auth_admin_last_login",
            datetime.now(UTC).isoformat(),
        )

        logger.info(f"OIDC login successful for admin: {username} (sub: {oidc_sub})")

        # GET UPDATED ADMIN PROFILE
        admin_profile = await get_user_admin_profile(db)

        # CREATE JWT TOKEN
        access_token_expires = timedelta(minutes=24 * 60)  # 24 hours
        jwt_token = create_access_token(
            data={"sub": "admin", "username": admin_profile["username"]},
            expires_delta=access_token_expires,
        )

        # SET HTTPONLY COOKIE AND REDIRECT
        scheme = request.headers.get("x-forwarded-proto", "http")
        host = request.headers.get("x-forwarded-host", request.headers.get("host", "localhost"))

        redirect_response = RedirectResponse(
            url=f"{scheme}://{host}/",
            status_code=302,
        )
        redirect_response.set_cookie(
            key=JWT_COOKIE_NAME,
            value=jwt_token,
            httponly=True,
            secure=(scheme == "https"),
            samesite="lax",
            max_age=JWT_COOKIE_MAX_AGE,
        )

        logger.info("Set JWT cookie and redirecting to dashboard")
        return redirect_response

    except oidc_service.SSRFProtectionError as e:
        logger.error(f"SSRF protection error: {e}")
        raise HTTPException(
            status_code=400,
            detail="Invalid OIDC provider URL (SSRF protection)",
        )
    except Exception as e:
        logger.error(f"OIDC callback error: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"OIDC authentication failed: {str(e)}",
        )


@router.post("/oidc/test")
async def test_oidc_connection(
    issuer_url: str = Body(...),
    client_id: str = Body(...),
    client_secret: str = Body(...),
    _current_user: str = Depends(require_user_auth),
):
    """Test OIDC configuration by fetching discovery document.

    Requires authentication. Tests connectivity to the OIDC provider
    and validates that required endpoints are present.
    """
    import httpx

    from app.services import oidc as oidc_service

    try:
        # Build discovery URL
        discovery_url = issuer_url.rstrip("/") + "/.well-known/openid-configuration"

        # Check for SSRF
        try:
            oidc_service.check_ssrf(discovery_url)
        except oidc_service.SSRFProtectionError as e:
            return {
                "success": False,
                "provider_reachable": False,
                "metadata_valid": False,
                "endpoints_found": False,
                "errors": [f"SSRF protection: {str(e)}"],
            }

        # Fetch discovery document
        async with httpx.AsyncClient(timeout=10.0) as client:
            try:
                response = await client.get(discovery_url)
                response.raise_for_status()
                metadata = response.json()
            except httpx.TimeoutException:
                return {
                    "success": False,
                    "provider_reachable": False,
                    "metadata_valid": False,
                    "endpoints_found": False,
                    "errors": ["Connection timeout - provider not reachable"],
                }
            except httpx.HTTPStatusError as e:
                return {
                    "success": False,
                    "provider_reachable": True,
                    "metadata_valid": False,
                    "endpoints_found": False,
                    "errors": [f"HTTP {e.response.status_code}: {e.response.text[:200]}"],
                }
            except Exception as e:
                return {
                    "success": False,
                    "provider_reachable": False,
                    "metadata_valid": False,
                    "endpoints_found": False,
                    "errors": [f"Connection error: {str(e)}"],
                }

        # Validate metadata structure
        if not isinstance(metadata, dict):
            return {
                "success": False,
                "provider_reachable": True,
                "metadata_valid": False,
                "endpoints_found": False,
                "errors": ["Invalid metadata format (not a JSON object)"],
            }

        # Check for required endpoints
        required_endpoints = [
            "authorization_endpoint",
            "token_endpoint",
            "userinfo_endpoint",
            "jwks_uri",
        ]
        missing = [ep for ep in required_endpoints if ep not in metadata]

        if missing:
            return {
                "success": False,
                "provider_reachable": True,
                "metadata_valid": True,
                "endpoints_found": False,
                "errors": [f"Missing required endpoints: {', '.join(missing)}"],
            }

        # All checks passed
        return {
            "success": True,
            "provider_reachable": True,
            "metadata_valid": True,
            "endpoints_found": True,
            "errors": [],
        }

    except Exception as e:
        logger.error(f"OIDC test connection error: {e}", exc_info=True)
        return {
            "success": False,
            "provider_reachable": False,
            "metadata_valid": False,
            "endpoints_found": False,
            "errors": [f"Unexpected error: {str(e)}"],
        }
