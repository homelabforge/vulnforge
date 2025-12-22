"""Tests for false positive pattern API endpoints.

This module tests the false positive pattern API which provides:
- False positive pattern listing (for secrets)
- Pattern creation from secrets
- Pattern deletion
- Container-specific pattern listing
"""

from datetime import UTC, datetime

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession


class TestListFalsePositivePatterns:
    """Test GET /api/v1/false-positive-patterns/ endpoint."""

    @pytest.mark.asyncio
    async def test_list_all_false_positive_patterns(
        self, authenticated_client: AsyncClient, db_session: AsyncSession
    ):
        """Test listing all false positive patterns."""
        from app.models import FalsePositivePattern

        # Arrange
        patterns = [
            FalsePositivePattern(
                container_name="test-container-1",
                file_path="/app/config.yaml",
                rule_id="generic-api-key",
                reason="Test pattern 1",
                created_by="admin",
                match_count=0,
            ),
            FalsePositivePattern(
                container_name="test-container-2",
                file_path="/etc/secrets.env",
                rule_id="aws-access-token",
                reason="Test pattern 2",
                created_by="admin",
                match_count=5,
            ),
        ]
        for pattern in patterns:
            db_session.add(pattern)
        await db_session.commit()

        # Act
        response = await authenticated_client.get("/api/v1/false-positive-patterns/")

        # Assert
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert len(data) >= 2

    @pytest.mark.asyncio
    async def test_list_patterns_structure(
        self, authenticated_client: AsyncClient, db_session: AsyncSession
    ):
        """Test pattern list response structure."""
        from app.models import FalsePositivePattern

        # Arrange
        pattern = FalsePositivePattern(
            container_name="test-container",
            file_path="/app/test.yaml",
            rule_id="test-rule",
            reason="Test",
            created_by="admin",
            match_count=0,
        )
        db_session.add(pattern)
        await db_session.commit()

        # Act
        response = await authenticated_client.get("/api/v1/false-positive-patterns/")

        # Assert
        assert response.status_code == 200
        data = response.json()
        if len(data) > 0:
            item = data[0]
            assert "id" in item
            assert "container_name" in item
            assert "file_path" in item
            assert "rule_id" in item
            assert "reason" in item
            assert "created_by" in item
            assert "created_at" in item
            assert "match_count" in item


class TestListContainerFalsePositivePatterns:
    """Test GET /api/v1/false-positive-patterns/container/{name} endpoint."""

    @pytest.mark.asyncio
    async def test_list_container_patterns(
        self, authenticated_client: AsyncClient, db_session: AsyncSession
    ):
        """Test listing patterns for a specific container."""
        from app.models import FalsePositivePattern

        # Arrange
        patterns = [
            FalsePositivePattern(
                container_name="target-container",
                file_path="/app/config1.yaml",
                rule_id="rule-1",
                created_by="admin",
                match_count=0,
            ),
            FalsePositivePattern(
                container_name="target-container",
                file_path="/app/config2.yaml",
                rule_id="rule-2",
                created_by="admin",
                match_count=0,
            ),
            FalsePositivePattern(
                container_name="other-container",
                file_path="/app/config.yaml",
                rule_id="rule-3",
                created_by="admin",
                match_count=0,
            ),
        ]
        for pattern in patterns:
            db_session.add(pattern)
        await db_session.commit()

        # Act
        response = await authenticated_client.get(
            "/api/v1/false-positive-patterns/container/target-container"
        )

        # Assert
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        # Should only return patterns for target-container
        for item in data:
            assert item["container_name"] == "target-container"

    @pytest.mark.asyncio
    async def test_list_container_patterns_empty(self, authenticated_client: AsyncClient):
        """Test listing patterns for container with no patterns."""
        # Act
        response = await authenticated_client.get(
            "/api/v1/false-positive-patterns/container/nonexistent"
        )

        # Assert
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert len(data) == 0


class TestCreateFalsePositivePattern:
    """Test POST /api/v1/false-positive-patterns/ endpoint."""

    @pytest.mark.asyncio
    async def test_create_pattern_from_secret(
        self, authenticated_client: AsyncClient, db_session: AsyncSession, make_container, make_scan
    ):
        """Test creating a false positive pattern from a secret."""
        from app.models import Secret

        # Arrange - Create a container, scan, and secret
        container = make_container(name="test-container")
        db_session.add(container)
        await db_session.commit()
        await db_session.refresh(container)

        scan = make_scan(container_id=container.id)
        db_session.add(scan)
        await db_session.commit()
        await db_session.refresh(scan)

        secret = Secret(
            scan_id=scan.id,
            file_path="/app/config.yaml",
            rule_id="generic-api-key",
            category="Generic",
            title="Generic API Key",
            severity="HIGH",
            match="fake-secret-value",
        )
        db_session.add(secret)
        await db_session.commit()
        await db_session.refresh(secret)

        # Act
        response = await authenticated_client.post(
            "/api/v1/false-positive-patterns/",
            json={"secret_id": secret.id, "reason": "Known test secret"},
        )

        # Assert
        assert response.status_code in (200, 201)
        data = response.json()
        assert data["container_name"] == "test-container"
        assert data["file_path"] == "/app/config.yaml"
        assert data["rule_id"] == "generic-api-key"
        assert data["reason"] == "Known test secret"

    @pytest.mark.asyncio
    async def test_create_pattern_nonexistent_secret(self, authenticated_client: AsyncClient):
        """Test creating pattern from nonexistent secret fails."""
        # Act
        response = await authenticated_client.post(
            "/api/v1/false-positive-patterns/", json={"secret_id": 99999, "reason": "Test"}
        )

        # Assert
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_create_pattern_without_reason(
        self, authenticated_client: AsyncClient, db_session: AsyncSession, make_container, make_scan
    ):
        """Test creating pattern without reason is allowed."""
        from app.models import Secret

        # Arrange
        container = make_container(name="test-container")
        db_session.add(container)
        await db_session.commit()
        await db_session.refresh(container)

        scan = make_scan(container_id=container.id)
        db_session.add(scan)
        await db_session.commit()
        await db_session.refresh(scan)

        secret = Secret(
            scan_id=scan.id,
            file_path="/app/test.yaml",
            rule_id="test-rule",
            category="Generic",
            title="Test Secret",
            severity="MEDIUM",
            match="test-match",
        )
        db_session.add(secret)
        await db_session.commit()
        await db_session.refresh(secret)

        # Act
        response = await authenticated_client.post(
            "/api/v1/false-positive-patterns/", json={"secret_id": secret.id}
        )

        # Assert
        assert response.status_code in (200, 201)


class TestDeleteFalsePositivePattern:
    """Test DELETE /api/v1/false-positive-patterns/{pattern_id} endpoint."""

    @pytest.mark.asyncio
    async def test_delete_pattern(
        self, authenticated_client: AsyncClient, db_session: AsyncSession
    ):
        """Test deleting a false positive pattern."""
        from app.models import FalsePositivePattern

        # Arrange
        pattern = FalsePositivePattern(
            container_name="test-container",
            file_path="/app/config.yaml",
            rule_id="test-rule",
            created_by="admin",
            match_count=0,
        )
        db_session.add(pattern)
        await db_session.commit()
        await db_session.refresh(pattern)

        # Act
        response = await authenticated_client.delete(
            f"/api/v1/false-positive-patterns/{pattern.id}"
        )

        # Assert
        assert response.status_code == 200
        data = response.json()
        assert "message" in data

    @pytest.mark.asyncio
    async def test_delete_nonexistent_pattern(self, authenticated_client: AsyncClient):
        """Test deleting nonexistent pattern returns 404."""
        # Act
        response = await authenticated_client.delete("/api/v1/false-positive-patterns/99999")

        # Assert
        assert response.status_code == 404


class TestPatternMatchCount:
    """Test pattern match count tracking."""

    @pytest.mark.asyncio
    async def test_pattern_includes_match_count(
        self, authenticated_client: AsyncClient, db_session: AsyncSession
    ):
        """Test pattern response includes match count."""
        from app.models import FalsePositivePattern

        # Arrange
        pattern = FalsePositivePattern(
            container_name="test-container",
            file_path="/app/config.yaml",
            rule_id="test-rule",
            created_by="admin",
            match_count=42,
        )
        db_session.add(pattern)
        await db_session.commit()

        # Act
        response = await authenticated_client.get("/api/v1/false-positive-patterns/")

        # Assert
        assert response.status_code == 200
        data = response.json()
        found_pattern = next((p for p in data if p["match_count"] == 42), None)
        assert found_pattern is not None
        assert found_pattern["match_count"] == 42


class TestPatternCreatedBy:
    """Test pattern created_by field."""

    @pytest.mark.asyncio
    async def test_pattern_includes_created_by(
        self, authenticated_client: AsyncClient, db_session: AsyncSession
    ):
        """Test pattern includes creator username."""
        from app.models import FalsePositivePattern

        # Arrange
        pattern = FalsePositivePattern(
            container_name="test-container",
            file_path="/app/config.yaml",
            rule_id="test-rule",
            created_by="test-admin",
            match_count=0,
        )
        db_session.add(pattern)
        await db_session.commit()

        # Act
        response = await authenticated_client.get("/api/v1/false-positive-patterns/")

        # Assert
        assert response.status_code == 200
        data = response.json()
        found_pattern = next((p for p in data if p["created_by"] == "test-admin"), None)
        assert found_pattern is not None
        assert found_pattern["created_by"] == "test-admin"


class TestPatternTimestamps:
    """Test pattern timestamp fields."""

    @pytest.mark.asyncio
    async def test_pattern_includes_timestamps(
        self, authenticated_client: AsyncClient, db_session: AsyncSession
    ):
        """Test pattern includes created_at and last_matched."""
        from app.models import FalsePositivePattern

        # Arrange
        pattern = FalsePositivePattern(
            container_name="test-container",
            file_path="/app/config.yaml",
            rule_id="test-rule",
            created_by="admin",
            match_count=1,
            last_matched=datetime.now(UTC),
        )
        db_session.add(pattern)
        await db_session.commit()

        # Act
        response = await authenticated_client.get("/api/v1/false-positive-patterns/")

        # Assert
        assert response.status_code == 200
        data = response.json()
        if len(data) > 0:
            item = data[0]
            assert "created_at" in item
            assert "last_matched" in item
