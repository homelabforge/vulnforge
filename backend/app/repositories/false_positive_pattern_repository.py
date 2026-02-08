"""Repository for managing persistent false positive patterns."""

from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Container, FalsePositivePattern, Scan, Secret
from app.utils.timezone import get_now


class FalsePositivePatternRepository:
    """Repository for FalsePositivePattern model."""

    def __init__(self, db: AsyncSession):
        """
        Initialize the repository.

        Args:
            db: AsyncSession database session
        """
        self.db = db

    async def create_from_secret(
        self, secret_id: int, reason: str | None = None, created_by: str = "user"
    ) -> FalsePositivePattern | None:
        """
        Create a false positive pattern from an existing secret.

        Args:
            secret_id: Secret ID to create pattern from
            reason: Optional reason why it's a false positive
            created_by: Username of admin creating pattern (default: "user")

        Returns:
            Created pattern or None if secret not found
        """
        # Get the secret with container name
        result = await self.db.execute(
            select(Secret, Container.name)
            .join(Scan, Secret.scan_id == Scan.id)
            .join(Container, Scan.container_id == Container.id)
            .where(Secret.id == secret_id)
        )
        row = result.first()

        if not row:
            return None

        secret, container_name = row

        # Check if pattern already exists
        existing = await self.db.execute(
            select(FalsePositivePattern).where(
                FalsePositivePattern.container_name == container_name,
                FalsePositivePattern.file_path == (secret.file_path or ""),
                FalsePositivePattern.rule_id == secret.rule_id,
            )
        )
        if existing.scalar_one_or_none():
            return None  # Pattern already exists

        # Create new pattern
        pattern = FalsePositivePattern(
            container_name=container_name,
            file_path=secret.file_path or "",
            rule_id=secret.rule_id,
            reason=reason or f"Auto-created from secret #{secret_id}",
            created_by=created_by,  # Use parameter instead of hardcoded value
        )
        self.db.add(pattern)
        await self.db.commit()
        await self.db.refresh(pattern)

        return pattern

    async def get_all(self) -> list[FalsePositivePattern]:
        """
        Get all false positive patterns.

        Returns:
            List of all patterns
        """
        result = await self.db.execute(
            select(FalsePositivePattern).order_by(FalsePositivePattern.created_at.desc())
        )
        return list(result.scalars().all())

    async def get_by_id(self, pattern_id: int) -> FalsePositivePattern | None:
        """
        Get a pattern by ID.

        Args:
            pattern_id: Pattern ID

        Returns:
            Pattern if found, None otherwise
        """
        result = await self.db.execute(
            select(FalsePositivePattern).where(FalsePositivePattern.id == pattern_id)
        )
        return result.scalar_one_or_none()

    async def get_by_container(self, container_name: str) -> list[FalsePositivePattern]:
        """
        Get all patterns for a specific container.

        Args:
            container_name: Container name

        Returns:
            List of patterns
        """
        result = await self.db.execute(
            select(FalsePositivePattern).where(
                FalsePositivePattern.container_name == container_name
            )
        )
        return list(result.scalars().all())

    async def delete(self, pattern_id: int) -> bool:
        """
        Delete a false positive pattern.

        Args:
            pattern_id: Pattern ID

        Returns:
            True if deleted, False if not found
        """
        result = await self.db.execute(
            delete(FalsePositivePattern).where(FalsePositivePattern.id == pattern_id)
        )
        await self.db.commit()
        return result.rowcount > 0  # type: ignore[union-attr]

    async def matches_pattern(
        self, secret: Secret, container_name: str
    ) -> FalsePositivePattern | None:
        """
        Check if a secret matches any false positive pattern.

        Args:
            secret: Secret to check
            container_name: Container name

        Returns:
            Matching pattern if found, None otherwise
        """
        result = await self.db.execute(
            select(FalsePositivePattern).where(
                FalsePositivePattern.container_name == container_name,
                FalsePositivePattern.file_path == (secret.file_path or ""),
                FalsePositivePattern.rule_id == secret.rule_id,
            )
        )
        return result.scalar_one_or_none()

    async def record_match(self, pattern_id: int) -> None:
        """
        Record that a pattern was matched (increment counter).

        Args:
            pattern_id: Pattern ID
        """
        result = await self.db.execute(
            select(FalsePositivePattern).where(FalsePositivePattern.id == pattern_id)
        )
        pattern = result.scalar_one_or_none()

        if pattern:
            pattern.match_count += 1
            pattern.last_matched = get_now()
            await self.db.commit()

    async def count_total(self) -> int:
        """
        Count total patterns.

        Returns:
            Total count
        """
        result = await self.db.execute(select(func.count(FalsePositivePattern.id)))
        return result.scalar_one()
