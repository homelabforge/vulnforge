"""API Key service for secure token generation and validation."""

import hashlib
import secrets
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.api_key import APIKey


class APIKeyService:
    """Service for managing API keys."""

    KEY_PREFIX = "vf_"
    KEY_LENGTH = 32  # 32 bytes = 256 bits of entropy

    @classmethod
    def generate_key(cls) -> str:
        """
        Generate a cryptographically secure API key.

        Format: vf_<32 bytes of URL-safe base64>
        Example: vf_abc123...xyz789 (total ~48 characters)
        """
        token = secrets.token_urlsafe(cls.KEY_LENGTH)
        return f"{cls.KEY_PREFIX}{token}"

    @classmethod
    def hash_key(cls, key: str) -> str:
        """
        Hash an API key using SHA256.

        Args:
            key: The plaintext API key

        Returns:
            Hexadecimal SHA256 hash of the key

        Note:
            SHA256 is appropriate for API keys (not passwords).
            API keys are cryptographically random tokens, not user-chosen passwords.
            They have high entropy and are not vulnerable to dictionary attacks.
        """
        return hashlib.sha256(key.encode()).hexdigest()

    @classmethod
    def get_key_prefix(cls, key: str) -> str:
        """
        Extract the display prefix from a key.

        Args:
            key: The plaintext API key

        Returns:
            First 12 characters for display (e.g., "vf_abc12345")
        """
        return key[:12] if len(key) >= 12 else key

    @classmethod
    async def create_api_key(
        cls,
        db: AsyncSession,
        name: str,
        description: str | None = None,
        created_by: str = "admin",
    ) -> tuple[APIKey, str]:
        """
        Create a new API key.

        Args:
            db: Database session
            name: Human-readable key name
            description: Optional description
            created_by: Username of creator

        Returns:
            Tuple of (APIKey model, plaintext key)
            WARNING: Plaintext key is returned ONLY here - never stored!
        """
        # Generate secure key
        plaintext_key = cls.generate_key()
        key_hash = cls.hash_key(plaintext_key)
        key_prefix = cls.get_key_prefix(plaintext_key)

        # Create database record
        api_key = APIKey(
            name=name,
            description=description,
            key_hash=key_hash,
            key_prefix=key_prefix,
            created_at=datetime.now(UTC),
            created_by=created_by,
        )

        db.add(api_key)
        await db.commit()
        await db.refresh(api_key)

        return api_key, plaintext_key

    @classmethod
    async def verify_api_key(cls, db: AsyncSession, key: str) -> APIKey | None:
        """
        Verify an API key and return the associated record if valid.

        Args:
            db: Database session
            key: Plaintext API key from request

        Returns:
            APIKey model if valid and active, None otherwise
        """
        key_hash = cls.hash_key(key)

        result = await db.execute(
            select(APIKey).where(
                APIKey.key_hash == key_hash,
                APIKey.revoked_at.is_(None),  # Only active keys
            )
        )
        api_key = result.scalar_one_or_none()

        if api_key:
            # Update last_used_at timestamp
            api_key.last_used_at = datetime.now(UTC)
            await db.commit()

        return api_key

    @classmethod
    async def list_api_keys(
        cls,
        db: AsyncSession,
        include_revoked: bool = False,
    ) -> list[APIKey]:
        """
        List all API keys.

        Args:
            db: Database session
            include_revoked: Include revoked keys in results

        Returns:
            List of APIKey models
        """
        query = select(APIKey).order_by(APIKey.created_at.desc())

        if not include_revoked:
            query = query.where(APIKey.revoked_at.is_(None))

        result = await db.execute(query)
        return list(result.scalars().all())

    @classmethod
    async def revoke_api_key(cls, db: AsyncSession, key_id: int) -> APIKey | None:
        """
        Revoke an API key (soft delete).

        Args:
            db: Database session
            key_id: ID of the key to revoke

        Returns:
            Updated APIKey model if found, None otherwise
        """
        result = await db.execute(select(APIKey).where(APIKey.id == key_id))
        api_key = result.scalar_one_or_none()

        if api_key and api_key.revoked_at is None:
            api_key.revoked_at = datetime.now(UTC)
            await db.commit()
            await db.refresh(api_key)

        return api_key

    @classmethod
    async def get_api_key(cls, db: AsyncSession, key_id: int) -> APIKey | None:
        """
        Get an API key by ID.

        Args:
            db: Database session
            key_id: ID of the key

        Returns:
            APIKey model if found, None otherwise
        """
        result = await db.execute(select(APIKey).where(APIKey.id == key_id))
        return result.scalar_one_or_none()
