"""Authentication middleware for VulnForge — dual authentication (User Auth + API Keys).

Pure ASGI middleware rather than Starlette's `BaseHTTPMiddleware`: the latter
buffers the entire response body through an internal asyncio queue, which is
fine for small JSON but throttles streaming responses (SSE, large file
downloads). Pure ASGI wraps `send` directly so the body streams through
unchanged.
"""

import json
import logging
import posixpath
import urllib.parse

from starlette.types import ASGIApp, Receive, Scope, Send

from app.models.user import User
from app.services.api_key_service import APIKeyService
from app.services.user_auth import JWT_COOKIE_NAME, decode_token

logger = logging.getLogger(__name__)


class AuthenticationMiddleware:
    """Dual authentication (JWT cookie + API key) as pure ASGI middleware."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # Normalize path to prevent bypass via encoding or path manipulation.
        raw_path = scope.get("path", "")
        normalized_path = urllib.parse.unquote(raw_path)
        while "//" in normalized_path:
            normalized_path = normalized_path.replace("//", "/")
        normalized_path = posixpath.normpath(normalized_path)
        if not normalized_path.startswith("/"):
            normalized_path = "/" + normalized_path
        normalized_path_lower = normalized_path.lower()

        anonymous = User(username="anonymous", provider="none", is_admin=False)

        # Exempt user authentication endpoints — they handle browser login.
        if normalized_path_lower.startswith("/api/v1/user-auth/"):
            _attach_user(scope, anonymous)
            await self.app(scope, receive, send)
            return

        # Exempt health check.
        if normalized_path_lower == "/health":
            _attach_user(scope, anonymous)
            await self.app(scope, receive, send)
            return

        # Frontend routes (non-API) — allow access so users can see the login page.
        if not (normalized_path_lower.startswith("/api/") or normalized_path_lower == "/api"):
            _attach_user(scope, anonymous)
            await self.app(scope, receive, send)
            return

        # Try JWT cookie authentication first (browser users).
        jwt_token = _get_cookie(scope, JWT_COOKIE_NAME)
        if jwt_token:
            try:
                payload = decode_token(jwt_token)
                username = payload.get("username")
                if username:
                    token_sv = payload.get("sv")
                    sv_valid = False
                    if token_sv is not None:
                        from app.database import async_session_maker
                        from app.services.user_auth import get_session_version

                        async with async_session_maker() as sv_db:
                            current_sv = await get_session_version(sv_db)
                        sv_valid = token_sv == current_sv

                    if sv_valid:
                        user = User(
                            username=username,
                            email=payload.get("email"),
                            is_admin=True,
                            provider="user_auth",
                        )
                        _attach_user(scope, user)
                        logger.info(f"JWT auth successful: {username} for {normalized_path}")
                        await self.app(scope, receive, send)
                        return
                    else:
                        logger.warning(
                            "JWT rejected: missing or stale session version for %s",
                            normalized_path,
                        )
            except Exception as e:
                logger.warning(f"JWT validation failed for {normalized_path}: {e}")

        # API key management endpoints require JWT (browser-only).
        if normalized_path_lower.startswith("/api/v1/api-keys"):
            logger.warning(
                f"API key management endpoint requires JWT authentication: {normalized_path}"
            )
            await _send_json(
                send,
                status=401,
                payload={"detail": "API key management requires browser login (JWT cookie)"},
            )
            return

        # Try API key authentication (external tools).
        api_key = (_get_header(scope, b"x-api-key") or "").strip()
        if api_key:
            from app.database import async_session_maker

            async with async_session_maker() as db:
                try:
                    api_key_record = await APIKeyService.verify_api_key(db, api_key)
                except Exception as e:
                    logger.error(f"API key verification failed: {e}")
                    await _send_json(
                        send,
                        status=500,
                        payload={"detail": "Authentication service unavailable"},
                    )
                    return

                if api_key_record is not None:
                    user = User(
                        username=api_key_record.name,
                        email=None,
                        is_admin=True,
                        provider="api_key",
                    )
                    _attach_user(scope, user)
                    logger.debug(
                        f"API key auth successful: {user.username} (key_id={api_key_record.id})"
                    )
                    await self.app(scope, receive, send)
                    return

        # No credentials. Check if auth is globally disabled.
        # SettingsManager has a 60s class-level TTL cache so this is a memory lookup
        # on the hot path after the first unauthenticated request within each TTL window.
        from app.database import async_session_maker
        from app.services.settings_manager import SettingsManager

        async with async_session_maker() as db:
            auth_mode_value = await SettingsManager(db).get("user_auth_mode", default="none")

        if (auth_mode_value or "none") == "none":
            _attach_user(scope, anonymous)
            await self.app(scope, receive, send)
            return

        logger.debug("Authentication failed: no valid JWT cookie or API key")
        await _send_json(
            send,
            status=401,
            payload={"detail": "Authentication required (JWT cookie or X-API-Key header)"},
        )


def _attach_user(scope: Scope, user: User) -> None:
    """Attach the user to scope['state'] so `request.state.user` resolves in routes."""
    state = scope.get("state")
    if state is None:
        state = {}
        scope["state"] = state
    state["user"] = user


def _get_header(scope: Scope, name: bytes) -> str | None:
    """Case-insensitive header lookup from the ASGI scope."""
    name_lower = name.lower()
    for key, value in scope.get("headers", []):
        if key.lower() == name_lower:
            return value.decode("latin-1")
    return None


def _get_cookie(scope: Scope, name: str) -> str | None:
    """Pull a single cookie value out of the Cookie header without instantiating Request."""
    cookie_header = _get_header(scope, b"cookie")
    if not cookie_header:
        return None
    for part in cookie_header.split(";"):
        if "=" not in part:
            continue
        k, _, v = part.strip().partition("=")
        if k == name:
            return v
    return None


async def _send_json(send: Send, *, status: int, payload: dict) -> None:
    """Emit a JSON response from inside ASGI middleware."""
    body = json.dumps(payload).encode("utf-8")
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode("ascii")),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})
