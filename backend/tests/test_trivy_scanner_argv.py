"""N5: the Trivy scan command terminates flags before the image (plan §11).

``_run_trivy_scan`` builds the argv shared by exec and client modes; the image
is the trailing positional, so a ``--`` must sit immediately before it.
"""

from unittest.mock import MagicMock

import pytest

from app.services.trivy_scanner import TrivyScanner


@pytest.mark.asyncio
async def test_run_trivy_scan_terminates_flags_before_image():
    scanner = TrivyScanner(docker_service=MagicMock())

    captured = {}

    async def cap(container, cmd, **kwargs):
        captured["cmd"] = list(cmd)
        return (0, b'{"Results": []}')

    scanner._exec_trivy_command = cap  # type: ignore[assignment]

    # skip_db_update=False keeps the db-existence check out of the path; we only
    # care that the image is preceded by the "--" flag terminator.
    await scanner._run_trivy_scan(
        MagicMock(),
        ["trivy", "image", "--quiet"],
        "--evil:tag",
        skip_db_update=False,
    )

    cmd = captured["cmd"]
    assert cmd[-1] == "--evil:tag"
    assert cmd[-2] == "--"
