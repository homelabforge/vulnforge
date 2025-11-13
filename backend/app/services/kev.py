"""KEV (Known Exploited Vulnerabilities) service for CISA catalog integration."""

import logging
from datetime import datetime, timedelta
from typing import Any

import httpx
from app.utils.timezone import get_now

logger = logging.getLogger(__name__)


class KEVService:
    """Service for managing CISA KEV (Known Exploited Vulnerabilities) catalog."""

    CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    DEFAULT_CACHE_HOURS = 12

    def __init__(self):
        """Initialize KEV service."""
        self._kev_catalog: dict[str, dict[str, Any]] = {}  # CVE ID -> KEV data
        self._last_refresh: datetime | None = None
        self._cache_hours = self.DEFAULT_CACHE_HOURS

    async def fetch_kev_catalog(self) -> bool:
        """
        Fetch KEV catalog from CISA.

        Returns:
            True if successful, False otherwise
        """
        try:
            logger.info(f"Fetching KEV catalog from CISA: {self.CISA_KEV_URL}")

            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(self.CISA_KEV_URL)
                response.raise_for_status()

            data = response.json()
            vulnerabilities = data.get("vulnerabilities", [])

            # Build lookup dict: CVE ID -> KEV metadata
            new_catalog = {}
            for vuln in vulnerabilities:
                cve_id = vuln.get("cveID")
                if not cve_id:
                    continue

                # Parse dates
                date_added_str = vuln.get("dateAdded")
                due_date_str = vuln.get("dueDate")

                date_added = None
                due_date = None

                if date_added_str:
                    try:
                        date_added = datetime.strptime(date_added_str, "%Y-%m-%d")
                    except ValueError:
                        logger.warning(f"Invalid dateAdded format for {cve_id}: {date_added_str}")

                if due_date_str:
                    try:
                        due_date = datetime.strptime(due_date_str, "%Y-%m-%d")
                    except ValueError:
                        logger.warning(f"Invalid dueDate format for {cve_id}: {due_date_str}")

                new_catalog[cve_id] = {
                    "cve_id": cve_id,
                    "vendor_project": vuln.get("vendorProject", ""),
                    "product": vuln.get("product", ""),
                    "vulnerability_name": vuln.get("vulnerabilityName", ""),
                    "date_added": date_added,
                    "due_date": due_date,
                    "required_action": vuln.get("requiredAction", ""),
                    "short_description": vuln.get("shortDescription", ""),
                    "notes": vuln.get("notes", ""),
                }

            self._kev_catalog = new_catalog
            self._last_refresh = get_now()

            logger.info(f"KEV catalog updated: {len(self._kev_catalog)} known exploited CVEs")
            return True

        except httpx.HTTPError as e:
            logger.error(f"HTTP error fetching KEV catalog: {e}")
            return False
        except Exception as e:
            logger.error(f"Error fetching KEV catalog: {e}")
            return False

    def is_kev(self, cve_id: str) -> bool:
        """
        Check if a CVE is in the KEV catalog.

        Args:
            cve_id: CVE identifier (e.g., "CVE-2024-1234")

        Returns:
            True if CVE is known to be exploited
        """
        return cve_id in self._kev_catalog

    def get_kev_info(self, cve_id: str) -> dict[str, Any] | None:
        """
        Get KEV information for a specific CVE.

        Args:
            cve_id: CVE identifier

        Returns:
            KEV metadata dict or None if not in catalog
        """
        return self._kev_catalog.get(cve_id)

    def needs_refresh(self) -> bool:
        """
        Check if KEV catalog needs refresh based on cache TTL.

        Returns:
            True if refresh is needed
        """
        if not self._last_refresh:
            return True

        cache_expiry = self._last_refresh + timedelta(hours=self._cache_hours)
        return get_now() > cache_expiry

    def get_last_refresh(self) -> datetime | None:
        """
        Get last refresh timestamp.

        Returns:
            Last refresh datetime or None
        """
        return self._last_refresh

    def get_catalog_size(self) -> int:
        """
        Get number of CVEs in KEV catalog.

        Returns:
            Count of KEV CVEs
        """
        return len(self._kev_catalog)

    def set_cache_hours(self, hours: int):
        """
        Set cache TTL in hours.

        Args:
            hours: Cache duration in hours
        """
        self._cache_hours = hours
        logger.info(f"KEV cache TTL set to {hours} hours")

    async def ensure_catalog_loaded(self) -> bool:
        """
        Ensure KEV catalog is loaded and up-to-date.

        Fetches catalog if not loaded or if cache expired.

        Returns:
            True if catalog is available (fresh or stale)
        """
        # If catalog is empty, force refresh
        if not self._kev_catalog:
            logger.info("KEV catalog empty, fetching initial data")
            return await self.fetch_kev_catalog()

        # If cache expired, try to refresh (but keep old data if fetch fails)
        if self.needs_refresh():
            logger.info("KEV catalog cache expired, refreshing")
            success = await self.fetch_kev_catalog()
            if not success:
                logger.warning("KEV refresh failed, using stale cache")
                # Still return True because we have stale data
                return True
            return True

        # Cache is valid
        return True


# Global KEV service instance
_kev_service: KEVService | None = None


def get_kev_service() -> KEVService:
    """
    Get global KEV service instance (singleton).

    Returns:
        KEV service instance
    """
    global _kev_service
    if _kev_service is None:
        _kev_service = KEVService()
    return _kev_service
