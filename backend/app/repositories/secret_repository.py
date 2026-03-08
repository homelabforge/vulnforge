"""Secret repository for centralized secret queries with false positive filtering."""

from sqlalchemy import case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Container, Scan, Secret
from app.utils.timezone import get_now


class SecretRepository:
    """Repository for Secret model with consistent false positive filtering."""

    def __init__(self, db: AsyncSession):
        """
        Initialize the repository.

        Args:
            db: AsyncSession database session
        """
        self.db = db

    @staticmethod
    def _severity_order():
        """Return a case expression for proper risk-based severity ordering.

        Orders: CRITICAL (1) > HIGH (2) > MEDIUM (3) > LOW (4) > UNKNOWN (5).
        """
        return case(
            (Secret.severity == "CRITICAL", 1),
            (Secret.severity == "HIGH", 2),
            (Secret.severity == "MEDIUM", 3),
            (Secret.severity == "LOW", 4),
            else_=5,
        )

    @staticmethod
    def _latest_scan_ids_subquery():
        """Subquery returning the latest completed scan ID per container.

        Defines "latest" as most recent by scan_date, with id as tiebreaker.
        Only includes completed scans.
        """
        ranked = (
            select(
                Scan.id.label("scan_id"),
                func.row_number()
                .over(
                    partition_by=Scan.container_id,
                    order_by=(Scan.scan_date.desc(), Scan.id.desc()),
                )
                .label("rn"),
            )
            .where(Scan.scan_status == "completed")
            .subquery()
        )
        return select(ranked.c.scan_id).where(ranked.c.rn == 1)

    @staticmethod
    def _latest_scan_id_for_container(container_id: int):
        """Latest completed scan ID for a specific container.

        Uses the same ranking logic as _latest_scan_ids_subquery():
        scan_date DESC, id DESC, completed only.
        """
        return (
            select(Scan.id)
            .where(Scan.container_id == container_id)
            .where(Scan.scan_status == "completed")
            .order_by(Scan.scan_date.desc(), Scan.id.desc())
            .limit(1)
            .scalar_subquery()
        )

    def _get_active_secrets_query(self):
        """Base query: active secrets from latest completed scan per container.

        Excludes false positives and scopes to latest completed scan.
        Methods needing all-scan access (get_by_scan, get_by_id, get_by_ids)
        use direct select(Secret) queries instead.
        """
        return (
            select(Secret)
            .where(Secret.status != "false_positive")
            .where(Secret.scan_id.in_(self._latest_scan_ids_subquery()))
        )

    async def count_total(self) -> int:
        """Count total active secrets from latest completed scan per container.

        Excludes false positives. Scoped to the latest completed scan per container.
        """
        query = (
            select(func.count(Secret.id))
            .where(Secret.status != "false_positive")
            .where(Secret.scan_id.in_(self._latest_scan_ids_subquery()))
        )
        result = await self.db.execute(query)
        return result.scalar_one()

    async def count_by_container(self, container_id: int) -> int:
        """Count active secrets for a container's latest completed scan.

        Excludes false positives. Scoped to the latest completed scan per container.

        Args:
            container_id: Container ID
        """
        latest_scan_id = self._latest_scan_id_for_container(container_id)
        query = (
            select(func.count(Secret.id))
            .where(Secret.scan_id == latest_scan_id)
            .where(Secret.status != "false_positive")
        )
        result = await self.db.execute(query)
        return result.scalar_one()

    async def count_by_severity(self, severity: str) -> int:
        """Count active secrets by severity level from latest completed scan per container.

        Excludes false positives. Scoped to the latest completed scan per container.

        Args:
            severity: Severity level (CRITICAL, HIGH, MEDIUM, LOW)
        """
        query = (
            select(func.count(Secret.id))
            .where(Secret.severity == severity.upper())
            .where(Secret.status != "false_positive")
            .where(Secret.scan_id.in_(self._latest_scan_ids_subquery()))
        )
        result = await self.db.execute(query)
        return result.scalar_one()

    async def count_by_scan(self, scan_id: int) -> int:
        """
        Count active secrets for a specific scan.

        Args:
            scan_id: Scan ID

        Returns:
            Count of active secrets in the scan
        """
        query = (
            select(func.count(Secret.id))
            .where(Secret.scan_id == scan_id)
            .where(Secret.status != "false_positive")
        )
        result = await self.db.execute(query)
        return result.scalar_one()

    async def get_all_active(
        self,
        severity: str | None = None,
        category: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[Secret]:
        """Get all active secrets with optional filtering.

        Scoped to the latest completed scan per container. Excludes false positives.

        Args:
            severity: Optional severity filter
            category: Optional category filter
            limit: Maximum number of results
            offset: Pagination offset
        """
        query = self._get_active_secrets_query().join(Scan)

        if severity:
            query = query.where(Secret.severity == severity.upper())

        if category:
            query = query.where(Secret.category == category)

        query = query.order_by(Secret.created_at.desc()).limit(limit).offset(offset)

        result = await self.db.execute(query)
        return list(result.scalars().all())

    async def get_by_container(
        self,
        container_id: int,
        limit: int = 100,
        include_false_positives: bool = False,
    ) -> list[Secret]:
        """Get secrets for a container from its latest completed scan.

        Uses _latest_scan_id_for_container() for consistent "latest" definition
        (scan_date DESC, id DESC, completed only).

        Args:
            container_id: Container ID
            limit: Maximum number of secrets to return
            include_false_positives: Whether to include false positives
        """
        latest_scan_id = self._latest_scan_id_for_container(container_id)
        query = select(Secret).where(Secret.scan_id == latest_scan_id)

        if not include_false_positives:
            query = query.where(Secret.status != "false_positive")

        query = query.order_by(self._severity_order(), Secret.category).limit(limit)

        result = await self.db.execute(query)
        return list(result.scalars().all())

    async def get_by_scan(
        self, scan_id: int, limit: int = 100, include_false_positives: bool = False
    ) -> list[Secret]:
        """
        Get secrets for a specific scan.

        Args:
            scan_id: Scan ID
            limit: Maximum number of secrets to return
            include_false_positives: Whether to include false positives

        Returns:
            List of secrets in the scan
        """
        query = select(Secret).where(Secret.scan_id == scan_id)

        if not include_false_positives:
            query = query.where(Secret.status != "false_positive")

        query = query.order_by(self._severity_order(), Secret.category).limit(limit)

        result = await self.db.execute(query)
        return list(result.scalars().all())

    async def get_by_id(self, secret_id: int) -> Secret | None:
        """
        Get a specific secret by ID (includes false positives for detail view).

        Args:
            secret_id: Secret ID

        Returns:
            Secret if found, None otherwise
        """
        result = await self.db.execute(select(Secret).where(Secret.id == secret_id))
        return result.scalar_one_or_none()

    async def get_by_ids(self, secret_ids: list[int]) -> list[Secret]:
        """Get multiple secrets by ID in a single query.

        Args:
            secret_ids: List of secret IDs

        Returns:
            List of found secrets (may be fewer than requested if some IDs don't exist)
        """
        if not secret_ids:
            return []
        result = await self.db.execute(select(Secret).where(Secret.id.in_(secret_ids)))
        return list(result.scalars().all())

    async def get_summary(self) -> dict:
        """Get summary statistics for active secrets from latest completed scan per container.

        Scoped to the latest completed scan per container. Excludes false positives.
        """
        latest_scan_filter = Secret.scan_id.in_(self._latest_scan_ids_subquery())

        # Get total secret count
        total_secrets = await self.count_total()

        # Get secrets by severity
        severity_query = (
            select(Secret.severity, func.count(Secret.id))
            .where(Secret.status != "false_positive")
            .where(latest_scan_filter)
            .group_by(Secret.severity)
        )
        severity_result = await self.db.execute(severity_query)
        severity_counts = {row[0]: row[1] for row in severity_result}

        # Get secrets by category
        category_query = (
            select(Secret.category, func.count(Secret.id))
            .where(Secret.status != "false_positive")
            .where(latest_scan_filter)
            .group_by(Secret.category)
            .order_by(func.count(Secret.id).desc())
            .limit(10)
        )
        category_result = await self.db.execute(category_query)
        category_counts = {row[0]: row[1] for row in category_result}

        # Get affected containers count
        affected_query = (
            select(func.count(func.distinct(Scan.container_id)))
            .select_from(Secret)
            .join(Scan, Secret.scan_id == Scan.id)
            .where(Secret.status != "false_positive")
            .where(latest_scan_filter)
        )
        affected_result = await self.db.execute(affected_query)
        affected_containers = affected_result.scalar_one()

        return {
            "total_secrets": total_secrets,
            "critical_count": severity_counts.get("CRITICAL", 0),
            "high_count": severity_counts.get("HIGH", 0),
            "medium_count": severity_counts.get("MEDIUM", 0),
            "low_count": severity_counts.get("LOW", 0),
            "affected_containers": affected_containers,
            "top_categories": category_counts,
        }

    async def get_for_export(
        self,
        severity: str | None = None,
        category: str | None = None,
        include_false_positives: bool = False,
    ) -> list[tuple[Secret, str]]:
        """Get secrets for export with container names.

        Scoped to the latest completed scan per container.

        Args:
            severity: Optional severity filter
            category: Optional category filter
            include_false_positives: Whether to include false positives

        Returns:
            List of tuples (Secret, container_name)
        """
        query = (
            select(Secret, Container.name)
            .select_from(Secret)
            .join(Scan, Secret.scan_id == Scan.id)
            .join(Container, Scan.container_id == Container.id)
            .where(Secret.scan_id.in_(self._latest_scan_ids_subquery()))
        )

        if not include_false_positives:
            query = query.where(Secret.status != "false_positive")

        if severity:
            query = query.where(Secret.severity == severity.upper())

        if category:
            query = query.where(Secret.category == category)

        query = query.order_by(self._severity_order(), Secret.created_at.desc())

        result = await self.db.execute(query)
        rows = result.all()

        return [(row[0], row[1]) for row in rows]

    async def update_status(
        self, secret_id: int, status: str, notes: str | None = None
    ) -> Secret | None:
        """
        Update a secret's status and notes.

        Args:
            secret_id: Secret ID
            status: New status value
            notes: Optional notes

        Returns:
            Updated secret if found, None otherwise
        """
        result = await self.db.execute(select(Secret).where(Secret.id == secret_id))
        secret = result.scalar_one_or_none()

        if not secret:
            return None

        secret.status = status
        if notes is not None:
            secret.notes = notes
        secret.updated_at = get_now()

        await self.db.commit()
        await self.db.refresh(secret)

        return secret

    async def bulk_update_status(
        self, secret_ids: list[int], status: str, notes: str | None = None
    ) -> int:
        """
        Bulk update multiple secrets' status and notes.

        Args:
            secret_ids: List of secret IDs
            status: New status value
            notes: Optional notes

        Returns:
            Number of secrets updated
        """
        updated_count = 0
        for secret_id in secret_ids:
            result = await self.db.execute(select(Secret).where(Secret.id == secret_id))
            secret = result.scalar_one_or_none()

            if secret:
                secret.status = status
                if notes is not None:
                    secret.notes = notes
                secret.updated_at = get_now()
                updated_count += 1

        await self.db.commit()
        return updated_count
