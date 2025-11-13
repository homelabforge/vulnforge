"""User model for authentication."""

from dataclasses import dataclass, field


@dataclass
class User:
    """Represents an authenticated user."""

    username: str
    email: str | None = None
    groups: list[str] = field(default_factory=list)
    is_admin: bool = False
    provider: str = "unknown"

    def __str__(self) -> str:
        """String representation of user."""
        return f"User(username='{self.username}', provider='{self.provider}', is_admin={self.is_admin})"
