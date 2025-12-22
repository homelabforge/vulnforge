"""Tests for KEV (Known Exploited Vulnerabilities) service."""

from datetime import timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest


class TestKEVServiceInit:
    """Test KEVService initialization."""

    def test_init_creates_empty_catalog(self):
        """Test initialization creates empty catalog."""
        from app.services.kev import KEVService

        service = KEVService()

        assert service._kev_catalog == {}
        assert service._last_refresh is None
        assert service._cache_hours == KEVService.DEFAULT_CACHE_HOURS


class TestFetchKEVCatalog:
    """Test fetch_kev_catalog method."""

    @pytest.mark.asyncio
    async def test_fetch_kev_catalog_success(self):
        """Test successful KEV catalog fetch."""
        from app.services.kev import KEVService

        service = KEVService()

        mock_response = MagicMock()
        mock_response.json.return_value = {
            "vulnerabilities": [
                {
                    "cveID": "CVE-2021-44228",
                    "vendorProject": "Apache",
                    "product": "Log4j",
                    "vulnerabilityName": "Log4Shell",
                    "dateAdded": "2021-12-10",
                    "dueDate": "2021-12-24",
                    "requiredAction": "Apply updates",
                    "shortDescription": "Remote code execution",
                    "notes": "",
                }
            ]
        }

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_response)
            mock_client.__aenter__.return_value = mock_client
            mock_client.__aexit__.return_value = AsyncMock()
            mock_client_class.return_value = mock_client

            # Act
            result = await service.fetch_kev_catalog()

            # Assert
            assert result is True
            assert "CVE-2021-44228" in service._kev_catalog
            assert service._kev_catalog["CVE-2021-44228"]["product"] == "Log4j"
            assert service._last_refresh is not None

    @pytest.mark.asyncio
    async def test_fetch_kev_catalog_http_error(self):
        """Test KEV catalog fetch with HTTP error."""
        from app.services.kev import KEVService

        service = KEVService()

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(side_effect=httpx.HTTPError("Connection failed"))
            mock_client.__aenter__.return_value = mock_client
            mock_client.__aexit__.return_value = AsyncMock()
            mock_client_class.return_value = mock_client

            # Act
            result = await service.fetch_kev_catalog()

            # Assert
            assert result is False
            assert service._kev_catalog == {}

    @pytest.mark.asyncio
    async def test_fetch_kev_catalog_timeout(self):
        """Test KEV catalog fetch with timeout."""
        from app.services.kev import KEVService

        service = KEVService()

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(side_effect=httpx.TimeoutException("Timeout"))
            mock_client.__aenter__.return_value = mock_client
            mock_client.__aexit__.return_value = AsyncMock()
            mock_client_class.return_value = mock_client

            # Act
            result = await service.fetch_kev_catalog()

            # Assert
            assert result is False


class TestIsKEV:
    """Test is_kev method."""

    def test_is_kev_found(self):
        """Test checking if CVE is in KEV catalog."""
        from app.services.kev import KEVService

        service = KEVService()
        service._kev_catalog = {
            "CVE-2021-44228": {
                "cve_id": "CVE-2021-44228",
                "product": "Log4j",
            }
        }

        # Act
        result = service.is_kev("CVE-2021-44228")

        # Assert
        assert result is True

    def test_is_kev_not_found(self):
        """Test checking CVE not in KEV catalog."""
        from app.services.kev import KEVService

        service = KEVService()
        service._kev_catalog = {}

        # Act
        result = service.is_kev("CVE-2024-99999")

        # Assert
        assert result is False


class TestGetKEVInfo:
    """Test get_kev_info method."""

    def test_get_kev_info_found(self):
        """Test getting KEV info for CVE."""
        from app.services.kev import KEVService

        service = KEVService()
        kev_data = {
            "cve_id": "CVE-2021-44228",
            "product": "Log4j",
            "vendor_project": "Apache",
        }
        service._kev_catalog = {"CVE-2021-44228": kev_data}

        # Act
        result = service.get_kev_info("CVE-2021-44228")

        # Assert
        assert result == kev_data

    def test_get_kev_info_not_found(self):
        """Test getting KEV info for non-KEV CVE."""
        from app.services.kev import KEVService

        service = KEVService()
        service._kev_catalog = {}

        # Act
        result = service.get_kev_info("CVE-2024-99999")

        # Assert
        assert result is None


class TestCacheBehavior:
    """Test cache behavior."""

    @pytest.mark.asyncio
    async def test_needs_refresh_when_stale(self):
        """Test catalog needs refresh when stale."""
        from app.services.kev import KEVService

        service = KEVService()

        # Simulate old refresh
        from app.utils.timezone import get_now

        service._last_refresh = get_now() - timedelta(hours=24)

        # Act
        needs_refresh = service.needs_refresh()

        # Assert
        assert needs_refresh is True

    @pytest.mark.asyncio
    async def test_doesnt_need_refresh_when_fresh(self):
        """Test catalog doesn't need refresh when fresh."""
        from app.services.kev import KEVService

        service = KEVService()

        # Simulate recent refresh
        from app.utils.timezone import get_now

        service._last_refresh = get_now()

        # Act
        needs_refresh = service.needs_refresh()

        # Assert
        assert needs_refresh is False
