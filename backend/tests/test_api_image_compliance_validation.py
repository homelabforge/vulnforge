"""N5: image_name validation at the scan-trigger boundary (plan §11).

The user-supplied ``image_name`` is validated against a Docker reference
grammar before it reaches any scanner argv, so a flag-like value (e.g.
``--cache-dir=/x``) is rejected with 400 rather than smuggled into a CLI.
"""

import asyncio
from unittest.mock import MagicMock, patch

import pytest
from httpx import AsyncClient

from app.validators import ValidationError, validate_image_reference


class TestValidateImageReference:
    @pytest.mark.parametrize(
        "ref",
        ["nginx:1.27", "redis:latest", "ghcr.io/org/app@sha256:deadbeefcafe", "alpine"],
    )
    def test_accepts_valid(self, ref):
        assert validate_image_reference(ref) == ref

    @pytest.mark.parametrize(
        "ref",
        ["-foo", "--cache-dir=/x", "", "   ", "evil image", "a;b", "$(whoami)"],
    )
    def test_rejects_invalid(self, ref):
        with pytest.raises(ValidationError):
            validate_image_reference(ref)


@pytest.fixture(autouse=True)
def _reset_scan_task():
    import app.routes.image_compliance as ic

    ic._current_scan_task = None
    yield
    ic._current_scan_task = None


def _make_completed_task() -> asyncio.Task:
    return asyncio.create_task(asyncio.sleep(0))


@pytest.mark.asyncio
class TestTriggerImageScanValidation:
    @pytest.mark.parametrize("bad", ["--cache-dir=/x", "-foo"])
    async def test_rejects_flaglike_image(self, authenticated_client: AsyncClient, bad):
        resp = await authenticated_client.post(
            "/api/v1/image-compliance/scan", params={"image_name": bad}
        )
        assert resp.status_code == 400

    @pytest.mark.parametrize("good", ["nginx:1.27", "ghcr.io/org/app@sha256:deadbeefcafe"])
    async def test_accepts_valid_image(self, authenticated_client: AsyncClient, good):
        with (
            patch("app.routes.image_compliance.DockerService") as mock_docker,
            patch("app.routes.image_compliance.asyncio") as mock_asyncio,
        ):
            mock_docker.return_value = MagicMock()
            mock_asyncio.create_task.return_value = _make_completed_task()
            resp = await authenticated_client.post(
                "/api/v1/image-compliance/scan", params={"image_name": good}
            )
        assert resp.status_code == 200
        assert resp.json()["image_name"] == good
