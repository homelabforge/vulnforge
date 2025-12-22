"""Legacy-compatible ScanResult repository implementation."""

from typing import Any

from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.scan import Scan


class ScanResultRepository:
    """Compatibility wrapper that mimics the legacy ScanResultRepository API."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def create(
        self,
        *,
        container_id: int,
        image_name: str,
        scan_type: str = "vulnerability",
        status: str = "in_progress",
        **extra: Any,
    ) -> Scan:
        """Create a scan result compatible with legacy expectations."""

        scan = Scan(
            container_id=container_id,
            image_scanned=image_name,
            scan_type=scan_type,
            scan_status=status,
        )

        # Optional compatibility fields
        if "error_message" in extra:
            scan.error_message = extra["error_message"]
        if "created_at" in extra:
            scan.scan_date = extra["created_at"]

        self.db.add(scan)
        await self.db.flush()  # Use flush instead of commit - let test fixture manage transactions
        await self.db.refresh(scan)
        return scan

    async def get_by_id(self, scan_id: int) -> Scan | None:
        """Return a scan with vulnerabilities and secrets eagerly loaded."""

        result = await self.db.execute(
            select(Scan)
            .options(
                selectinload(Scan.vulnerabilities),
                selectinload(Scan.secrets),
            )
            .where(Scan.id == scan_id)
        )
        return result.scalar_one_or_none()

    async def get_for_container(self, container_id: int) -> list[Scan]:
        """List scans for a container ordered from newest to oldest."""

        result = await self.db.execute(
            select(Scan).where(Scan.container_id == container_id).order_by(desc(Scan.scan_date))
        )
        return list(result.scalars().all())

    async def get_latest_for_container(
        self, container_id: int, scan_type: str | None = None
    ) -> Scan | None:
        """Return the most recent scan for the given container and type."""

        stmt = select(Scan).where(Scan.container_id == container_id)
        if scan_type:
            stmt = stmt.where(Scan.scan_type == scan_type)

        result = await self.db.execute(stmt.order_by(desc(Scan.scan_date)).limit(1))
        return result.scalar_one_or_none()

    async def update(self, scan: Scan) -> Scan:
        """Persist changes made to a scan instance."""

        await self.db.flush()  # Use flush instead of commit - let test fixture manage transactions
        await self.db.refresh(scan)
        return scan

    async def delete(self, scan_id: int) -> None:
        """Delete a scan record by ID."""

        scan = await self.get_by_id(scan_id)
        if scan:
            await self.db.delete(scan)
            await (
                self.db.flush()
            )  # Use flush instead of commit - let test fixture manage transactions

    async def get_all(self) -> list[Scan]:
        """Return every scan ordered by most recent."""

        result = await self.db.execute(select(Scan).order_by(desc(Scan.scan_date)))
        return list(result.scalars().all())
