"""Authentication API endpoints."""

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel

from app.dependencies.auth import get_current_user
from app.models.user import User

router = APIRouter()


class UserResponse(BaseModel):
    """Response model for user information."""

    username: str
    email: str | None = None
    is_admin: bool = False
    provider: str = "unknown"
    is_authenticated: bool = True


@router.get("/me", response_model=UserResponse)
async def get_current_user_info(
    user: User = Depends(get_current_user),
) -> UserResponse:
    """
    Get information about the currently authenticated user.

    Returns user details from the authentication provider.
    """
    return UserResponse(
        username=user.username,
        email=user.email,
        is_admin=user.is_admin,
        provider=user.provider,
        is_authenticated=user.provider != "none",
    )


@router.get("/status")
async def get_auth_status(request: Request) -> dict[str, bool]:
    """
    Get authentication system status.

    Returns whether authentication is enabled and working.
    """
    has_user = hasattr(request.state, "user")
    is_authenticated = False

    if has_user:
        user = request.state.user
        is_authenticated = user.provider != "none"

    return {
        "enabled": has_user and is_authenticated,
        "configured": has_user,
    }
