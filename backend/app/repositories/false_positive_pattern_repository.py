"""Repository for managing persistent false positive patterns.

All write methods in this repository commit directly (leaf operations
called from API routes, never composed in larger transactions).
The ``record_match()`` method is an exception — it is called from the
scan pipeline, but its commit is safe because match-count updates are
independent of the scan's atomic result persistence.
"""

from sqlalchemy import delete, func, or_, select
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

        # Check if exact pattern already exists (including start_line)
        existing = await self.db.execute(
            select(FalsePositivePattern).where(
                FalsePositivePattern.container_name == container_name,
                FalsePositivePattern.file_path == (secret.file_path or ""),
                FalsePositivePattern.rule_id == secret.rule_id,
                FalsePositivePattern.start_line == secret.start_line,
            )
        )
        if existing.scalar_one_or_none():
            return None  # Pattern already exists

        # Create new pattern with precise start_line
        pattern = FalsePositivePattern(
            container_name=container_name,
            file_path=secret.file_path or "",
            rule_id=secret.rule_id,
            start_line=secret.start_line,
            reason=reason or f"Auto-created from secret #{secret_id}",
            created_by=created_by,
        )
        self.db.add(pattern)
        await self.db.commit()  # commit: leaf operation, not composed
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
        await self.db.commit()  # commit: leaf operation, not composed
        return result.rowcount > 0  # type: ignore[union-attr]

    async def delete_and_unsuppress(self, pattern_id: int) -> tuple[bool, int]:
        """Delete a pattern and reset secrets no longer covered by any FP pattern.

        For each secret that was suppressed by this pattern, checks if any OTHER
        pattern still covers it (including wildcard patterns). Only resets secrets
        to 'to_review' if no other pattern matches.

        Args:
            pattern_id: Pattern ID to delete

        Returns:
            Tuple of (was_deleted, unsuppressed_count)
        """
        pattern = await self.get_by_id(pattern_id)
        if not pattern:
            return False, 0

        # Find secrets that match this pattern's key and are currently false_positive
        # Join through Scan -> Container to match container_name
        candidates_query = (
            select(Secret)
            .join(Scan, Secret.scan_id == Scan.id)
            .join(Container, Scan.container_id == Container.id)
            .where(
                Container.name == pattern.container_name,
                Secret.file_path == pattern.file_path,
                Secret.rule_id == pattern.rule_id,
                Secret.status == "false_positive",
            )
        )
        # If pattern has a specific start_line, only consider secrets at that line
        if pattern.start_line is not None:
            candidates_query = candidates_query.where(Secret.start_line == pattern.start_line)

        result = await self.db.execute(candidates_query)
        candidate_secrets = list(result.scalars().all())

        unsuppressed = 0
        for secret in candidate_secrets:
            # Check if any OTHER pattern still covers this secret
            other_pattern = await self.db.execute(
                select(FalsePositivePattern).where(
                    FalsePositivePattern.id != pattern.id,
                    FalsePositivePattern.container_name == pattern.container_name,
                    FalsePositivePattern.file_path == pattern.file_path,
                    FalsePositivePattern.rule_id == pattern.rule_id,
                    or_(
                        FalsePositivePattern.start_line.is_(None),
                        FalsePositivePattern.start_line == secret.start_line,
                    ),
                )
            )
            if not other_pattern.scalars().first():
                secret.status = "to_review"
                secret.updated_at = get_now()
                unsuppressed += 1

        # Delete the pattern
        await self.db.execute(
            delete(FalsePositivePattern).where(FalsePositivePattern.id == pattern_id)
        )
        await self.db.commit()  # commit: leaf operation, not composed
        return True, unsuppressed

    async def matches_pattern(
        self, secret: Secret, container_name: str
    ) -> FalsePositivePattern | None:
        """Check if a secret matches any false positive pattern (hybrid mode).

        NULL start_line patterns act as wildcards (match any line).
        Precise patterns only match their specific start_line.

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
                or_(
                    FalsePositivePattern.start_line.is_(None),
                    FalsePositivePattern.start_line == secret.start_line,
                ),
            )
        )
        return result.scalars().first()

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
            await self.db.commit()  # commit: independent counter update, safe during scan pipeline

    async def count_total(self) -> int:
        """
        Count total patterns.

        Returns:
            Total count
        """
        result = await self.db.execute(select(func.count(FalsePositivePattern.id)))
        return result.scalar_one()
