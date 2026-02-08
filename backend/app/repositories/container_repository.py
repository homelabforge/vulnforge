"""Container repository for centralized container queries."""

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Container, Scan, Vulnerability


class ContainerRepository:
    """Repository for Container model."""

    def __init__(self, db: AsyncSession):
        """
        Initialize the repository.

        Args:
            db: AsyncSession database session
        """
        self.db = db

    @staticmethod
    def _normalize_container_data(data: dict) -> dict:
        """Normalize legacy container payloads to match the current model."""

        normalized = dict(data)

        # Harmonize Docker container identifier fields
        container_id_value = normalized.pop("container_id", None)
        docker_id = normalized.pop("id", None)
        if not container_id_value:
            container_id_value = docker_id
        if container_id_value:
            normalized["container_id"] = container_id_value

        status = normalized.pop("status", None)
        if status is not None and "is_running" not in normalized:
            normalized["is_running"] = str(status).lower() == "running"

        image_value = normalized.get("image")
        if image_value and "image_tag" not in normalized:
            if ":" in image_value:
                image_name, image_tag = image_value.rsplit(":", 1)
            else:
                image_name, image_tag = image_value, "latest"
            normalized["image"] = image_name
            normalized.setdefault("image_tag", image_tag)
        else:
            normalized.setdefault("image_tag", "latest")

        if "image_id" not in normalized:
            image_name = normalized.get("image", "unknown")
            image_tag = normalized.get("image_tag", "latest")
            normalized["image_id"] = f"{image_name}:{image_tag}"

        return normalized

    async def get_all(
        self, limit: int | None = None, offset: int = 0
    ) -> tuple[list[Container], int, int, int]:
        """
        Get all containers with pagination.

        Args:
            limit: Optional limit for pagination
            offset: Pagination offset

        Returns:
            Tuple of (containers list, total count, scanned count, never scanned count)
        """
        # Build query
        query = select(Container).order_by(
            Container.critical_count.desc(), Container.total_vulns.desc()
        )

        # Apply pagination if limit is specified
        if limit is not None:
            query = query.limit(limit).offset(offset)

        # Get containers
        result = await self.db.execute(query)
        containers = list(result.scalars().all())

        # Get total count (all containers)
        total_result = await self.db.execute(select(func.count(Container.id)))
        total = total_result.scalar() or 0

        # Count scanned containers
        scanned_result = await self.db.execute(
            select(func.count(Container.id)).where(Container.last_scan_date.isnot(None))
        )
        scanned = scanned_result.scalar() or 0
        never_scanned = total - scanned

        return containers, total, scanned, never_scanned

    async def get_latest_scans_with_vulnerabilities(
        self, container_ids: list[int]
    ) -> dict[int, tuple[Scan, list[Vulnerability]]]:
        """
        Fetch the most recent scan (and its vulnerabilities) for each container.

        Args:
            container_ids: List of container IDs to fetch scan data for

        Returns:
            Mapping of container ID -> (latest Scan, [Vulnerability, ...])
        """
        if not container_ids:
            return {}

        # Identify latest scan per container using window function
        latest_scan_subquery = (
            select(
                Scan.id.label("scan_id"),
                Scan.container_id.label("container_id"),
                func.row_number()
                .over(
                    partition_by=Scan.container_id,
                    order_by=Scan.scan_date.desc(),
                )
                .label("row_number"),
            )
            .where(Scan.container_id.in_(container_ids))
            .subquery()
        )

        latest_scans_result = await self.db.execute(
            select(Scan)
            .join(latest_scan_subquery, Scan.id == latest_scan_subquery.c.scan_id)
            .where(latest_scan_subquery.c.row_number == 1)
        )
        scans = list(latest_scans_result.scalars().all())

        if not scans:
            return {}

        scan_ids = [scan.id for scan in scans]

        vulnerabilities_result = await self.db.execute(
            select(Vulnerability).where(Vulnerability.scan_id.in_(scan_ids))
        )
        vulnerabilities = list(vulnerabilities_result.scalars().all())

        vuln_map: dict[int, list[Vulnerability]] = {}
        for vuln in vulnerabilities:
            vuln_map.setdefault(vuln.scan_id, []).append(vuln)

        return {scan.container_id: (scan, vuln_map.get(scan.id, [])) for scan in scans}

    async def get_by_id(self, container_id: int) -> Container | None:
        """
        Get a specific container by ID.

        Args:
            container_id: Container ID

        Returns:
            Container if found, None otherwise
        """
        result = await self.db.execute(select(Container).where(Container.id == container_id))
        return result.scalar_one_or_none()

    async def get_by_name(self, name: str) -> Container | None:
        """
        Get a specific container by name.

        Args:
            name: Container name

        Returns:
            Container if found, None otherwise
        """
        result = await self.db.execute(select(Container).where(Container.name == name))
        return result.scalar_one_or_none()

    async def count_total(self) -> int:
        """
        Count total containers.

        Returns:
            Total count of containers
        """
        result = await self.db.execute(select(func.count(Container.id)))
        return result.scalar_one()

    async def count_scanned(self) -> int:
        """
        Count containers that have been scanned.

        Returns:
            Count of scanned containers
        """
        result = await self.db.execute(
            select(func.count(Container.id.distinct())).where(Container.last_scan_date.isnot(None))
        )
        return result.scalar_one()

    async def get_vulnerability_stats(self) -> dict:
        """
        Get aggregated vulnerability statistics across all containers.

        Returns:
            Dictionary with vulnerability statistics
        """
        result = await self.db.execute(
            select(
                func.sum(Container.total_vulns),
                func.sum(Container.fixable_vulns),
                func.sum(Container.critical_count),
                func.sum(Container.high_count),
                func.sum(Container.medium_count),
                func.sum(Container.low_count),
            )
        )
        stats = result.first()

        if stats is None:
            return {
                "total_vulnerabilities": 0,
                "fixable_vulnerabilities": 0,
                "critical_count": 0,
                "high_count": 0,
                "medium_count": 0,
                "low_count": 0,
            }

        return {
            "total_vulnerabilities": stats[0] or 0,
            "fixable_vulnerabilities": stats[1] or 0,
            "critical_count": stats[2] or 0,
            "high_count": stats[3] or 0,
            "medium_count": stats[4] or 0,
            "low_count": stats[5] or 0,
        }

    async def get_top_vulnerable(self, limit: int = 10) -> list[dict]:
        """
        Get top vulnerable containers.

        Args:
            limit: Number of containers to return

        Returns:
            List of container vulnerability summaries
        """
        result = await self.db.execute(
            select(
                Container.name,
                Container.total_vulns,
                Container.fixable_vulns,
                Container.critical_count,
                Container.high_count,
            )
            .where(Container.total_vulns > 0)
            .order_by(Container.critical_count.desc(), Container.high_count.desc())
            .limit(limit)
        )

        return [
            {
                "name": row[0],
                "total_vulns": row[1],
                "fixable_vulns": row[2],
                "critical_count": row[3],
                "high_count": row[4],
            }
            for row in result.fetchall()
        ]

    async def get_most_vulnerable(self) -> tuple[str | None, int]:
        """
        Get the most vulnerable container.

        Returns:
            Tuple of (container name, vulnerability count)
        """
        result = await self.db.execute(
            select(Container.name, Container.total_vulns)
            .where(Container.total_vulns > 0)
            .order_by(Container.total_vulns.desc())
            .limit(1)
        )
        row = result.first()

        if row:
            return row[0], row[1]
        return None, 0

    async def get_last_scan_date(self):
        """
        Get the most recent scan date across all containers.

        Returns:
            Most recent scan date or None
        """
        result = await self.db.execute(
            select(func.max(Scan.scan_date)).where(Scan.scan_status == "completed")
        )
        return result.scalar()

    async def create(self, **container_data) -> Container:
        """
        Create a new container (legacy test compatibility method).

        For tests only - uses flush() instead of commit() to work with
        test fixture-managed transactions.

        Args:
            **container_data: Container fields as keyword arguments

        Returns:
            Created container
        """
        container_data = self._normalize_container_data(container_data)
        container = Container(**container_data)
        self.db.add(container)
        await self.db.flush()  # Use flush for test compatibility
        await self.db.refresh(container)
        return container

    async def update(self, container: Container) -> Container:
        """
        Update a container (legacy test compatibility method).

        Args:
            container: Container with updated fields

        Returns:
            Updated container
        """
        await self.db.flush()  # Use flush for test compatibility
        await self.db.refresh(container)
        return container

    async def get_by_container_id(self, container_id: str) -> Container | None:
        """
        Get container by Docker container ID (legacy test compatibility).

        Args:
            container_id: Docker container ID

        Returns:
            Container if found, None otherwise
        """
        result = await self.db.execute(
            select(Container).where(Container.container_id == container_id)
        )
        return result.scalar_one_or_none()

    async def list_all(self) -> list[Container]:
        """
        List all containers (legacy test compatibility).

        Returns:
            List of all containers
        """
        result = await self.db.execute(select(Container))
        return list(result.scalars().all())

    async def delete(self, container: Container) -> None:
        """
        Delete a container (legacy test compatibility).

        Args:
            container: Container to delete
        """
        await self.db.delete(container)
        await self.db.flush()  # Use flush for test compatibility

    async def create_or_update(self, container_data: dict) -> Container:
        """
        Create a new container or update existing one.

        NOTE: Uses commit() instead of flush() because the primary caller
        (container discovery in containers.py) has no outer transaction
        management — switching to flush() would silently lose data.

        Args:
            container_data: Dictionary with container data

        Returns:
            Created or updated container
        """
        normalized_data = self._normalize_container_data(container_data)

        existing = await self.get_by_name(normalized_data["name"])

        if existing:
            # Update existing
            existing.is_running = normalized_data.get("is_running", existing.is_running)
            existing.image = normalized_data.get("image", existing.image)
            existing.image_tag = normalized_data.get("image_tag", existing.image_tag)
            existing.image_id = normalized_data.get("image_id", existing.image_id)
            existing.last_seen = normalized_data.get("last_seen", existing.last_seen)
            if normalized_data.get("container_id"):
                existing.container_id = normalized_data["container_id"]
            await self.db.commit()
            await self.db.refresh(existing)
            return existing
        else:
            # Create new
            container = Container(**normalized_data)
            self.db.add(container)
            await self.db.commit()
            await self.db.refresh(container)
            return container

    async def remove_missing(
        self,
        active_names: set[str],
        active_ids: set[str],
    ) -> int:
        """
        Remove containers that are no longer reported by Docker.

        Args:
            active_names: Set of container names currently reported by Docker
            active_ids: Set of container IDs currently reported by Docker

        Returns:
            Number of containers removed
        """
        result = await self.db.execute(select(Container))
        stale_containers = list(result.scalars().all())

        removed = 0
        for container in stale_containers:
            container_id = container.container_id
            name = container.name

            if container_id and container_id in active_ids:
                continue
            if name in active_names:
                continue

            await self.db.delete(container)
            removed += 1

        if removed:
            await self.db.commit()

        return removed
