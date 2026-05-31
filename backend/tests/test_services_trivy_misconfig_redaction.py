"""C2 Dockerfile ENV/ARG redaction + N5 Trivy misconfig argv terminator.

Plan §5 (C2): the redactor must cover every Docker ENV/ARG form (``KEY=value``,
``KEY value``, multi-assignment) by inspecting variable *names*, without
over-redacting benign lines.
Plan §11 (N5): the misconfig command builders must put ``--`` immediately
before the (trailing) image so a flag-like reference can't be parsed as an
option.
"""

from unittest.mock import MagicMock, patch

import pytest

from app.services.trivy_misconfig_service import _redact_dockerfile_line


class TestRedactDockerfileLine:
    @pytest.mark.parametrize(
        "line",
        [
            "ENV SECRET_KEY=abc",
            "ENV SECRET_KEY abc",
            "ARG API_TOKEN xyz",
            "ENV FOO=bar TOKEN=baz",
            "env api_key=supersecret",
            "  ENV SECRET_KEY=abc",
            "ARG DB_PASSWORD=hunter2",
        ],
    )
    def test_redacts_sensitive(self, line):
        assert _redact_dockerfile_line(line) == "***REDACTED***"

    @pytest.mark.parametrize(
        "line",
        [
            "ENV PORT=8080",
            "RUN echo hi",
            "ENV PATH=/usr/bin",
            "COPY . /app",
            "ENV NODE_ENV=production",
        ],
    )
    def test_preserves_non_sensitive(self, line):
        assert _redact_dockerfile_line(line) == line


class TestMisconfigArgvTerminator:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("server_mode", [False, True])
    async def test_double_dash_before_image(self, server_mode):
        with patch("app.services.trivy_misconfig_service.DockerService"):
            from app.services.trivy_misconfig_service import TrivyMisconfigService

            service = TrivyMisconfigService()
            service.docker_service.get_trivy_container = MagicMock(return_value=MagicMock())
            service.trivy_scanner.use_server_mode = server_mode
            service.trivy_scanner.server_url = "http://trivy:4954"

            captured = {}

            async def cap(container, cmd, **kwargs):
                captured["cmd"] = list(cmd)
                return (0, '{"Results": []}')

            service.trivy_scanner._exec_trivy_command = cap  # type: ignore[assignment]
            # A flag-like image must NOT be parseable as an option.
            await service.run_misconfig_scan("--evil:tag")

            cmd = captured["cmd"]
            assert cmd[-1] == "--evil:tag"
            assert cmd[-2] == "--"
