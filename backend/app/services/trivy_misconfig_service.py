"""Service for executing Trivy misconfiguration scans."""

import json
import logging
from typing import Any

from docker.errors import DockerException

from app.config import settings
from app.services.docker_client import DockerService
from app.services.trivy_scanner import TrivyScanner
from app.utils.timezone import get_now

logger = logging.getLogger(__name__)


class TrivyMisconfigService:
    """Service for running Trivy-based image misconfiguration scans."""

    def __init__(self, docker_service: DockerService | None = None):
        """
        Initialize Trivy misconfiguration service.

        Args:
            docker_service: Optional Docker service instance.
        """
        self.docker_service = docker_service or DockerService()
        self.trivy_scanner = TrivyScanner(docker_service=self.docker_service)

    async def run_misconfig_scan(
        self, image: str, timeout: int | None = None
    ) -> dict[str, Any] | None:
        """
        Run a Trivy misconfiguration scan for the given image.

        Args:
            image: Image to scan (e.g., 'nginx:latest')
            timeout: Scan timeout in seconds

        Returns:
            Parsed misconfiguration results or None on failure.
        """
        if timeout is None:
            timeout = settings.scan_timeout

        # TODO: Implement timeout functionality for Trivy misconfiguration scans
        # Currently timeout parameter is accepted but not enforced
        _ = timeout  # Acknowledge parameter to suppress unused warning

        logger.info(f"Starting Trivy misconfiguration scan: image={image}")

        try:
            trivy_container = self.docker_service.get_trivy_container()
            if not trivy_container:
                logger.error("Trivy container not available")
                return None

            start_time = get_now()

            # Build Trivy command for misconfiguration scanning
            # Use server mode if configured, otherwise use exec mode
            if self.trivy_scanner.use_server_mode:
                cmd = [
                    "trivy",
                    "image",
                    "--server",
                    self.trivy_scanner.server_url,
                    "--scanners",
                    "misconfig",
                    "--format",
                    "json",
                    "--quiet",
                    image,
                ]
            else:
                cmd = [
                    "trivy",
                    "image",
                    "--scanners",
                    "misconfig",
                    "--format",
                    "json",
                    "--quiet",
                    image,
                ]

            # Execute scan
            exit_code, output = await self.trivy_scanner._exec_trivy_command(
                trivy_container,
                cmd,
                demux=False,
            )

            scan_duration = (get_now() - start_time).total_seconds()

            if exit_code != 0:
                logger.error(f"Trivy misconfiguration scan failed with exit code {exit_code}")
                if output:
                    logger.error(f"Output: {output[:500]}")
                return None

            # Parse JSON output
            try:
                scan_data = json.loads(output)
                logger.info(f"Misconfiguration scan completed in {scan_duration:.2f}s")
                return self._parse_misconfig_output(scan_data, scan_duration)

            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse Trivy JSON output: {e}")
                if output:
                    logger.error(f"Output: {output[:500]}")
                return None

        except DockerException as e:
            logger.error(f"Docker error during misconfiguration scan: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error during misconfiguration scan: {e}")
            return None

    def _parse_misconfig_output(
        self, trivy_data: dict[str, Any], scan_duration: float
    ) -> dict[str, Any]:
        """
        Parse Trivy misconfiguration JSON output into structured data.

        Args:
            trivy_data: Raw Trivy JSON output
            scan_duration: Scan duration in seconds

        Returns:
            Parsed misconfiguration data
        """
        findings = []
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}

        # Trivy output structure: Results -> Misconfigurations
        results = trivy_data.get("Results", [])

        for result in results:
            target = result.get("Target", "unknown")
            misconfigs = result.get("Misconfigurations", [])

            for misconfig in misconfigs:
                # Extract misconfiguration details
                check_id = misconfig.get("ID", "UNKNOWN")
                avd_id = misconfig.get("AVDID", check_id)  # Aqua Vulnerability Database ID
                title = misconfig.get("Title", "Unknown issue")
                description = misconfig.get("Description", "")
                message = misconfig.get("Message", "")
                severity = misconfig.get("Severity", "UNKNOWN")
                resolution = misconfig.get("Resolution", "")

                # Get references
                references = misconfig.get("References", [])
                primary_url = misconfig.get("PrimaryURL", "")

                # Get cause metadata if available
                cause_metadata = misconfig.get("CauseMetadata", {})
                resource = cause_metadata.get("Resource", "")
                provider = cause_metadata.get("Provider", "dockerfile")
                service = cause_metadata.get("Service", "general")
                start_line = cause_metadata.get("StartLine")
                end_line = cause_metadata.get("EndLine")
                code = cause_metadata.get("Code", {})

                # Extract code lines if available
                code_lines = code.get("Lines", [])
                code_snippet = None
                if code_lines:
                    code_snippet = "\n".join(
                        [
                            f"Line {line.get('Number', '?')}: {line.get('Content', '')}"
                            for line in code_lines
                        ]
                    )

                findings.append(
                    {
                        "check_id": avd_id or check_id,  # Prefer AVDID over ID
                        "title": title[:500] if title else None,
                        "description": description[:2000] if description else None,
                        "message": message[:2000] if message else None,
                        "severity": severity,
                        "resolution": resolution[:2000] if resolution else None,
                        "target": target,
                        "resource": resource[:500] if resource else None,
                        "provider": provider,
                        "service": service,
                        "start_line": start_line,
                        "end_line": end_line,
                        "code_snippet": code_snippet[:2000] if code_snippet else None,
                        "primary_url": primary_url if primary_url else None,
                        "references": json.dumps(references) if references else None,
                    }
                )

                # Update severity counts
                severity_counts[severity] = severity_counts.get(severity, 0) + 1

        # Extract image name from Trivy output
        image_name = trivy_data.get("ArtifactName", "unknown")

        return {
            "image": image_name,
            "findings": findings,
            "total_count": len(findings),
            "critical_count": severity_counts["CRITICAL"],
            "high_count": severity_counts["HIGH"],
            "medium_count": severity_counts["MEDIUM"],
            "low_count": severity_counts["LOW"],
            "unknown_count": severity_counts["UNKNOWN"],
            "scan_duration_seconds": int(scan_duration),
        }

    def calculate_compliance_score(self, findings: list[dict[str, Any]]) -> float:
        """
        Calculate a compliance score based on findings severity.

        Score is based on weighted severity:
        - CRITICAL: -10 points
        - HIGH: -5 points
        - MEDIUM: -2 points
        - LOW: -1 point
        - UNKNOWN: -0.5 points

        Maximum score is 100, minimum is 0.

        Args:
            findings: List of misconfiguration findings

        Returns:
            Compliance score (0-100)
        """
        if not findings:
            return 100.0

        # Weight by severity
        weights = {
            "CRITICAL": 10,
            "HIGH": 5,
            "MEDIUM": 2,
            "LOW": 1,
            "UNKNOWN": 0.5,
        }

        total_deductions = sum(
            weights.get(finding.get("severity", "UNKNOWN"), 0) for finding in findings
        )

        # Start at 100 and subtract deductions
        score = max(0.0, 100.0 - total_deductions)

        return round(score, 2)
