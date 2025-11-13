"""Authentication and authorization dependencies for FastAPI endpoints."""

from fastapi import HTTPException, Request, status

from app.models.user import User


async def require_auth(request: Request) -> User:
    """
    Dependency that requires authentication.

    Checks if request.state.user exists and is authenticated.
    If authentication is disabled, returns anonymous user.
    If authentication is enabled but user is not authenticated, raises 401.

    Args:
        request: FastAPI request with user attached by auth middleware

    Returns:
        User object

    Raises:
        HTTPException: 401 if user not authenticated when auth is enabled
    """
    user = getattr(getattr(request, "state", None), "user", None)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required but user not attached to request"
        )

    # Check if user is actually authenticated (not anonymous)
    if user.provider == "none" and user.username == "anonymous":
        # This means auth middleware allowed request through (auth disabled)
        return user

    # User is authenticated
    return user


async def require_admin(request: Request) -> User:
    """
    Dependency that requires admin privileges.

    First ensures user is authenticated, then checks if they have admin rights.
    Admin status determined by:
    1. User has is_admin flag set (API keys, basic auth)
    2. User belongs to configured admin group (header-based auth)
    3. Username in admin usernames list

    Args:
        request: FastAPI request with user attached by auth middleware

    Returns:
        User object with admin privileges

    Raises:
        HTTPException: 401 if not authenticated, 403 if authenticated but not admin
    """
    # First ensure user is authenticated
    user = await require_auth(request)

    # If auth is disabled (anonymous user), allow access
    if user.provider == "none" and user.username == "anonymous":
        return user

    # Check if user has admin privileges
    if not user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Admin privileges required. User '{user.username}' is not an admin."
        )

    # User is authenticated and has admin privileges
    return user


async def get_current_user(request: Request) -> User:
    """
    Dependency that returns current user without requiring authentication.

    If auth is disabled or user not authenticated, returns anonymous user.
    Useful for endpoints that want to know who the user is but don't require auth.

    Args:
        request: FastAPI request

    Returns:
        User object (anonymous if not authenticated)
    """
    if not hasattr(request.state, "user"):
        # No user attached - return anonymous
        return User(username="anonymous", provider="none", is_admin=False)

    return request.state.user
