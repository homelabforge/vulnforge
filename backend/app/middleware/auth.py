"""Authentication middleware for VulnForge - Dual authentication (User Auth + API Keys)."""

import logging

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from app.models.user import User
from app.services.api_key_service import APIKeyService
from app.services.user_auth import JWT_COOKIE_NAME, decode_token

logger = logging.getLogger(__name__)


class AuthenticationMiddleware(BaseHTTPMiddleware):
    """FastAPI middleware for dual authentication (JWT + API keys)."""

    async def dispatch(self, request: Request, call_next):
        """
        Process request through dual authentication.

        Flow:
        1. Check if request is exempt (health checks, user auth endpoints)
        2. Try JWT cookie authentication (browser users)
        3. Fall back to API key authentication (external tools)
        4. Attach user to request.state.user
        5. Return 401 if both auth methods fail on protected endpoints

        Args:
            request: FastAPI request
            call_next: Next middleware/endpoint handler

        Returns:
            Response from next handler or 401 error
        """
        # Normalize path to prevent bypass via encoding or path manipulation
        import posixpath
        import urllib.parse

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
        normalized_path_lower = normalized_path.lower()

        # Exempt user authentication endpoints from API authentication
        # These endpoints handle browser-based login and must be publicly accessible
        if normalized_path_lower.startswith("/api/v1/user-auth/"):
            request.state.user = User(username="anonymous", provider="none", is_admin=False)
            return await call_next(request)

        # Exempt health check endpoint
        if normalized_path_lower == "/health":
            request.state.user = User(username="anonymous", provider="none", is_admin=False)
            return await call_next(request)

        # Allow unauthenticated access to frontend (non-API routes)
        # Only protect /api/* endpoints with authentication
        if not (normalized_path_lower.startswith("/api/") or normalized_path_lower == "/api"):
            # Frontend routes - allow access so users can see login page
            request.state.user = User(username="anonymous", provider="none", is_admin=False)
            return await call_next(request)

        # Try JWT cookie authentication first (browser users)
        jwt_token = request.cookies.get(JWT_COOKIE_NAME)
        logger.info(f"JWT cookie present: {bool(jwt_token)} for {normalized_path}")
        if jwt_token:
            try:
                payload = decode_token(jwt_token)
                username = payload.get("username")
                if username:
                    # Successful JWT authentication
                    user = User(
                        username=username,
                        email=payload.get("email"),
                        is_admin=True,  # User auth admin is always admin
                        provider="user_auth",
                    )
                    request.state.user = user
                    logger.info(f"JWT auth successful: {username} for {normalized_path}")
                    return await call_next(request)
            except Exception as e:
                # JWT validation failed - fall through to API key check
                logger.warning(f"JWT validation failed for {normalized_path}: {e}")

        # Special case: API key management endpoints require JWT auth only
        # Browser users can manage API keys, but API keys cannot manage themselves
        if normalized_path_lower.startswith("/api/v1/api-keys"):
            logger.warning(
                f"API key management endpoint requires JWT authentication: {normalized_path}"
            )
            return JSONResponse(
                status_code=401,
                content={"detail": "API key management requires browser login (JWT cookie)"},
            )

        # Try API key authentication (external tools)
        api_key = request.headers.get("X-API-Key", "").strip()
        if api_key:
            from app.db import async_session_maker

            async with async_session_maker() as db:
                try:
                    api_key_record = await APIKeyService.verify_api_key(db, api_key)
                except Exception as e:
                    logger.error(f"API key verification failed: {e}")
                    return JSONResponse(
                        status_code=500, content={"detail": "Authentication service unavailable"}
                    )

                if api_key_record is not None:
                    # Successful API key authentication
                    user = User(
                        username=api_key_record.name,
                        email=None,
                        is_admin=True,  # All API keys have admin access for now
                        provider="api_key",
                    )
                    request.state.user = user
                    logger.debug(
                        f"API key auth successful: {user.username} (key_id={api_key_record.id})"
                    )
                    return await call_next(request)

        # Both authentication methods failed
        logger.debug("Authentication failed: no valid JWT cookie or API key")
        return JSONResponse(
            status_code=401,
            content={"detail": "Authentication required (JWT cookie or X-API-Key header)"},
        )
