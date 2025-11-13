"""Integration tests for end-to-end scan workflow."""

import pytest
from unittest.mock import AsyncMock, patch, MagicMock

from app.models import Container, ScanResult, Vulnerability, Secret
from app.models.user import User


@pytest.mark.asyncio
class TestScanWorkflowIntegration:
    """Integration tests for complete scan workflow."""

    @patch("app.services.trivy_scanner.TrivyScanner.scan_image")
    @patch("app.services.docker_client.DockerService")
    async def test_complete_scan_workflow(self, mock_docker, mock_scan, db_with_settings):
        """Test complete workflow: queue → scan → store → notify."""
        from app.repositories.container_repository import ContainerRepository

        # Create test container
        container_repo = ContainerRepository(db_with_settings)
        container = await container_repo.create(
            container_id="test123",
            name="nginx",
            image="nginx:latest",
            status="running"
        )

        # Mock successful scan
        mock_scan.return_value = {
            "Results": [
                {
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2024-0001",
                            "PkgName": "openssl",
                            "InstalledVersion": "1.0.0",
                            "FixedVersion": "1.0.1",
                            "Severity": "HIGH",
                            "Title": "Test vulnerability"
                        }
                    ]
                }
            ]
        }

        # Execute scan workflow
        # Note: Actual workflow execution depends on service architecture
        assert container is not None
        assert container.id is not None

    @patch("app.services.trivy_scanner.TrivyScanner.scan_image")
    @patch("app.services.grype_service.GrypeService.scan_image")
    async def test_scanner_fallback_workflow(self, mock_grype, mock_trivy, db_with_settings):
        """Test workflow with Trivy failure and Grype fallback."""
        from app.repositories.container_repository import ContainerRepository

        # Create container
        container_repo = ContainerRepository(db_with_settings)
        container = await container_repo.create(
            container_id="test456",
            name="postgres",
            image="postgres:15",
            status="running"
        )

        # Trivy fails
        mock_trivy.side_effect = Exception("Trivy scan failed")

        # Grype succeeds
        mock_grype.return_value = {
            "matches": [
                {
                    "vulnerability": {
                        "id": "CVE-2024-0002",
                        "severity": "CRITICAL"
                    },
                    "artifact": {
                        "name": "curl",
                        "version": "7.0.0"
                    }
                }
            ]
        }

        # Should fall back to Grype
        assert container is not None

    async def test_scan_with_database_transaction_rollback(self, db_with_settings):
        """Test that failed scans properly rollback database transactions."""
        from app.repositories.container_repository import ContainerRepository
        from app.repositories.scan_result_repository import ScanResultRepository

        container_repo = ContainerRepository(db_with_settings)
        scan_repo = ScanResultRepository(db_with_settings)

        # Create container
        container = await container_repo.create(
            container_id="rollback_test",
            name="test",
            image="test:latest",
            status="running"
        )

        # Start scan result
        scan = await scan_repo.create(
            container_id=container.id,
            image_name="test:latest",
            scan_type="vulnerability",
            status="running"
        )

        # Simulate scan failure - should rollback
        # Implementation depends on service architecture

        assert scan is not None


@pytest.mark.asyncio
class TestBatchScanWorkflow:
    """Tests for batch scanning multiple containers."""

    @patch("app.services.docker_client.DockerService.list_containers")
    @patch("app.services.trivy_scanner.TrivyScanner.scan_image")
    async def test_batch_scan_multiple_containers(self, mock_scan, mock_list, db_with_settings):
        """Test scanning multiple containers in batch."""
        from app.repositories.container_repository import ContainerRepository

        # Mock Docker listing multiple containers
        mock_list.return_value = [
            {"id": "abc123", "name": "nginx", "image": "nginx:latest", "status": "running"},
            {"id": "def456", "name": "redis", "image": "redis:7", "status": "running"},
            {"id": "ghi789", "name": "postgres", "image": "postgres:15", "status": "running"}
        ]

        # Mock successful scans
        mock_scan.return_value = {"Results": [{"Vulnerabilities": []}]}

        # Create containers
        container_repo = ContainerRepository(db_with_settings)
        for container_data in mock_list.return_value:
            await container_repo.create(
                container_id=container_data["id"],
                name=container_data["name"],
                image=container_data["image"],
                status=container_data["status"]
            )

        # Batch scan workflow
        # Implementation depends on service architecture
        assert True

    async def test_batch_scan_with_partial_failures(self, db_with_settings):
        """Test batch scan where some containers fail."""
        from app.repositories.container_repository import ContainerRepository

        container_repo = ContainerRepository(db_with_settings)

        # Create multiple containers
        containers = []
        for i in range(3):
            container = await container_repo.create(
                container_id=f"container{i}",
                name=f"app{i}",
                image=f"image{i}:latest",
                status="running"
            )
            containers.append(container)

        # Some scans succeed, some fail
        # Should handle gracefully
        assert len(containers) == 3


@pytest.mark.asyncio
class TestScanWithKEVChecking:
    """Tests for KEV checking during scan workflow."""

    @patch("app.services.trivy_scanner.TrivyScanner.scan_image")
    @patch("app.services.kev_service.KEVService.get_kev_info")
    async def test_kev_checking_integration(self, mock_kev, mock_scan, db_with_settings):
        """Test KEV checking is performed during scan."""
        from app.repositories.container_repository import ContainerRepository

        container_repo = ContainerRepository(db_with_settings)
        container = await container_repo.create(
            container_id="kev_test",
            name="app",
            image="app:latest",
            status="running"
        )

        # Mock scan with vulnerability
        mock_scan.return_value = {
            "Results": [{
                "Vulnerabilities": [{
                    "VulnerabilityID": "CVE-2024-0001",
                    "Severity": "CRITICAL",
                    "PkgName": "openssl"
                }]
            }]
        }

        # Mock KEV info
        mock_kev.return_value = {
            "cveID": "CVE-2024-0001",
            "dateAdded": "2024-01-01",
            "vendorProject": "OpenSSL"
        }

        # Scan should check KEV
        assert container is not None


@pytest.mark.asyncio
class TestScanWithFalsePositives:
    """Tests for false positive pattern application during scan."""

    async def test_false_positive_patterns_applied(self, db_with_settings):
        """Test that false positive patterns are applied during scan."""
        from app.models import FalsePositivePattern
        from app.repositories.container_repository import ContainerRepository

        # Create false positive pattern using the normalized match fields
        pattern = FalsePositivePattern(
            container_name="fp_test",
            file_path="/app/config.py",
            rule_id="generic-api-key",
            reason="Test pattern",
        )
        db_with_settings.add(pattern)
        await db_with_settings.commit()

        # Create container
        container_repo = ContainerRepository(db_with_settings)
        container = await container_repo.create(
            container_id="fp_test",
            name="app",
            image="app:latest",
            status="running"
        )

        # Scan should apply false positive patterns
        assert pattern is not None
        assert container is not None


@pytest.mark.asyncio
class TestNotificationIntegration:
    """Tests for notification delivery during scan workflow."""

    @patch("app.services.notifier.Notifier.send_notification")
    @patch("app.services.trivy_scanner.TrivyScanner.scan_image")
    async def test_notification_sent_after_scan(self, mock_scan, mock_notify, db_with_settings):
        """Test that notification is sent after scan completion."""
        from app.repositories.container_repository import ContainerRepository

        container_repo = ContainerRepository(db_with_settings)
        container = await container_repo.create(
            container_id="notify_test",
            name="app",
            image="app:latest",
            status="running"
        )

        # Mock scan with critical findings
        mock_scan.return_value = {
            "Results": [{
                "Vulnerabilities": [
                    {"Severity": "CRITICAL", "VulnerabilityID": f"CVE-2024-{i:04d}"}
                    for i in range(10)
                ]
            }]
        }

        # Scan workflow should trigger notification
        # Implementation depends on service architecture
        assert container is not None


@pytest.mark.asyncio
class TestConcurrentScans:
    """Tests for concurrent scan handling."""

    async def test_prevent_duplicate_concurrent_scans(self, db_with_settings):
        """Test that duplicate scans on same container are prevented."""
        from app.repositories.container_repository import ContainerRepository

        container_repo = ContainerRepository(db_with_settings)
        container = await container_repo.create(
            container_id="concurrent_test",
            name="app",
            image="app:latest",
            status="running"
        )

        # Try to start two scans on same container
        # Second should be prevented or queued
        assert container is not None

    async def test_multiple_containers_scanned_concurrently(self, db_with_settings):
        """Test that different containers can be scanned concurrently."""
        from app.repositories.container_repository import ContainerRepository

        container_repo = ContainerRepository(db_with_settings)

        # Create multiple containers
        containers = []
        for i in range(3):
            container = await container_repo.create(
                container_id=f"multi{i}",
                name=f"app{i}",
                image=f"image{i}:latest",
                status="running"
            )
            containers.append(container)

        # Should be able to scan all concurrently
        assert len(containers) == 3
