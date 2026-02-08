"""Tests for KEV (Known Exploited Vulnerabilities) service."""

from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch

import pytest


@pytest.mark.asyncio
class TestKEVCatalogFetching:
    """Tests for KEV catalog fetching from CISA."""

    @patch("httpx.AsyncClient.get")
    async def test_fetch_catalog_success(self, mock_get):
        """Test successful KEV catalog fetching."""
        from app.services.kev_service import KEVService

        # Mock CISA response
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "vulnerabilities": [
                {
                    "cveID": "CVE-2024-0001",
                    "vendorProject": "Test Vendor",
                    "product": "Test Product",
                    "vulnerabilityName": "Test Vuln",
                    "dateAdded": "2024-01-01",
                    "shortDescription": "Test description",
                }
            ],
            "dateReleased": "2024-01-01",
        }
        mock_response.status_code = 200
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response

        service = KEVService()
        success = await service.fetch_kev_catalog()

        assert success is True
        assert service.is_kev("CVE-2024-0001")
        info = service.get_kev_info("CVE-2024-0001")
        assert info is not None
        assert info["vendor_project"] == "Test Vendor"

    @patch("httpx.AsyncClient.get")
    async def test_fetch_catalog_network_error(self, mock_get):
        """Test handling network errors during catalog fetch."""
        import httpx

        from app.services.kev_service import KEVService

        mock_get.side_effect = httpx.NetworkError("Connection failed")

        service = KEVService()

        success = await service.fetch_kev_catalog()
        assert success is False

    @patch("httpx.AsyncClient.get")
    async def test_fetch_catalog_malformed_json(self, mock_get):
        """Test handling malformed JSON from CISA."""
        from app.services.kev_service import KEVService

        mock_response = MagicMock()
        mock_response.json.side_effect = ValueError("Invalid JSON")
        mock_response.status_code = 200
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response

        service = KEVService()

        success = await service.fetch_kev_catalog()
        assert success is False


@pytest.mark.asyncio
class TestKEVLookup:
    """Tests for KEV information lookup."""

    async def test_lookup_kev_by_cve(self):
        """Test looking up KEV info by CVE ID."""
        from app.services.kev_service import KEVService

        service = KEVService()

        # Mock catalog
        service._kev_catalog = {
            "CVE-2024-0001": {
                "cve_id": "CVE-2024-0001",
                "vendor_project": "Test",
                "product": "Product",
                "date_added": datetime(2024, 1, 1, tzinfo=UTC),
            }
        }

        result = service.get_kev_info("CVE-2024-0001")

        assert result is not None
        assert result["cve_id"] == "CVE-2024-0001"

    async def test_lookup_nonexistent_cve(self):
        """Test lookup of CVE not in KEV catalog."""
        from app.services.kev_service import KEVService

        service = KEVService()
        service._kev_catalog = {}

        result = service.get_kev_info("CVE-9999-9999")

        assert result is None


@pytest.mark.asyncio
class TestKEVCatalogFreshness:
    """Tests for KEV catalog freshness checking."""

    async def test_catalog_is_fresh(self):
        """Test checking if catalog is fresh."""
        from app.services.kev_service import KEVService

        service = KEVService()
        service.set_cache_hours(12)

        # Set recent fetch time
        service._last_refresh = datetime.now(UTC)

        assert service.needs_refresh() is False

    async def test_catalog_is_stale(self):
        """Test detecting stale catalog."""
        from app.services.kev_service import KEVService

        service = KEVService()
        service.set_cache_hours(12)

        # Set old fetch time
        service._last_refresh = datetime.now(UTC) - timedelta(hours=24)

        assert service.needs_refresh() is True


@pytest.mark.asyncio
class TestKEVOfflineMode:
    """Tests for KEV service offline mode."""

    async def test_use_cached_catalog_when_offline(self):
        """Test using cached catalog when network unavailable."""
        from app.services.kev_service import KEVService

        service = KEVService()

        # Set cached catalog
        service._kev_catalog = {
            "CVE-2024-0001": {
                "cve_id": "CVE-2024-0001",
            }
        }

        # Should use cache even if stale when offline
        result = service.get_kev_info("CVE-2024-0001")

        assert result is not None

    async def test_empty_catalog_handling(self):
        """Test handling empty KEV catalog."""
        from app.services.kev_service import KEVService

        service = KEVService()
        service._kev_catalog = {}

        result = service.get_kev_info("CVE-2024-0001")

        assert result is None
