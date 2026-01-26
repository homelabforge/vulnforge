"""User model for authentication."""

from dataclasses import dataclass


@dataclass
class User:
    """Represents an authenticated user."""

    username: str
    email: str | None = None
    is_admin: bool = False
    provider: str = "unknown"

    def __str__(self) -> str:
        """String representation of user."""
        return f"User(username='{self.username}', provider='{self.provider}', is_admin={self.is_admin})"
