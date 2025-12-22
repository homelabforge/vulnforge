"""Service for executing Docker Bench for Security compliance checks."""

import asyncio
import logging
import os
import re
from typing import Any
from urllib.parse import urlparse

from app.config import settings
from app.services.compliance_state import compliance_state
from app.services.docker_client import DockerService
from app.utils.timezone import get_now

logger = logging.getLogger(__name__)


class DockerBenchService:
    """Service for running Docker Bench security compliance scans."""

    def __init__(self, docker_service: DockerService):
        """Initialize Docker Bench service."""
        self.docker_service = docker_service

    async def run_compliance_scan(self) -> dict[str, Any] | None:
        """
        Run Docker Bench for Security compliance scan with real-time progress tracking.

        Returns:
            Dictionary containing scan results or None if scan failed
        """
        try:
            logger.info("Starting Docker Bench security compliance scan")
            start_time = get_now()

            # Initialize progress tracking (Docker Bench typically has ~150 checks)
            compliance_state.start_scan(total_checks=150)

            # Resolve Docker host for Docker Bench from environment variable or settings.
            # Environment variable (DOCKER_HOST) takes precedence, matching Docker CLI behavior.
            # Falls back to settings or local Unix socket for first-run setups.
            docker_host = (
                os.getenv("DOCKER_HOST")
                or settings.docker_socket_proxy
                or "unix:///var/run/docker.sock"
            )

            parsed = urlparse(docker_host)
            if parsed.scheme == "unix":
                # Docker Bench image expects the host socket mounted at /host/var/run/docker.sock.
                # Normalize any unix:// value to that internal path so first-run setups
                # work without extra configuration.
                docker_host_env = "unix:///host/var/run/docker.sock"
            else:
                docker_host_env = docker_host

            logger.info(f"Using Docker host for Docker Bench: {docker_host_env}")

            environment = {
                "DOCKER_HOST": docker_host_env,
            }

            # Attach Docker Bench container to the same network as the
            # running VulnForge container so it can reach the configured
            # Docker host (socket proxy or unix socket).
            network_name: str | None = None
            current_container_id = os.getenv("HOSTNAME")
            if current_container_id:
                try:
                    current_container = self.docker_service.client.containers.get(
                        current_container_id
                    )
                    networks = (
                        current_container.attrs.get("NetworkSettings", {}).get("Networks") or {}
                    )
                    if networks:
                        # Use the first attached network (matches compose order)
                        network_name = next(iter(networks.keys()))
                        logger.info(f"Using Docker Bench network: {network_name}")
                except Exception as exc:  # pragma: no cover - defensive logging
                    logger.warning(
                        f"Failed to determine current container network for Docker Bench: {exc}"
                    )

            # Run Docker Bench in DETACHED mode for log streaming
            volumes = {
                # Mount host directories for file permission checks
                "/etc": {"bind": "/host/etc", "mode": "ro"},
                "/lib/systemd": {"bind": "/host/lib/systemd", "mode": "ro"},
                "/usr/lib/systemd": {"bind": "/host/usr/lib/systemd", "mode": "ro"},
                "/var/lib/docker": {"bind": "/host/var/lib/docker", "mode": "ro"},
            }

            # Only mount docker.sock if using unix socket (not TCP socket proxy)
            if parsed.scheme == "unix":
                volumes["/var/run/docker.sock"] = {
                    "bind": "/host/var/run/docker.sock",
                    "mode": "ro",
                }

            run_kwargs: dict[str, Any] = {
                "image": "vulnforge/docker-bench:latest",  # Custom image with updated Docker client for API compatibility
                "command": [],  # Default command runs all checks
                "environment": environment,
                "volumes": volumes,
                "detach": True,  # Changed to True for streaming
                "cap_add": ["AUDIT_CONTROL"],  # Required for some checks
                "labels": {"managed_by": "vulnforge"},
            }

            if network_name:
                run_kwargs["network"] = network_name

            container = self.docker_service.client.containers.run(**run_kwargs)

            # Stream logs and parse findings
            findings = []
            completed_checks = 0
            full_output = ""
            scan_finished = False

            # Create async task to update progress every 2 seconds
            async def update_progress_periodically():
                """Background task to update progress estimate every 2 seconds."""
                estimated_duration = 80
                while not scan_finished:
                    try:
                        await asyncio.sleep(2)
                        elapsed = (get_now() - start_time).total_seconds()
                        # Estimate progress: linear from 0 to 90% based on time, max 135/150
                        time_estimate = min(int((elapsed / estimated_duration) * 135), 135)

                        # Never go backward - use max of time estimate and actual completed checks
                        current_progress = max(time_estimate, completed_checks)

                        compliance_state.update_progress(
                            check_id=f"~{current_progress}",
                            check_title="Running Docker Bench security checks...",
                            completed=current_progress,
                        )
                        logger.info(
                            f"Progress estimate: {current_progress}/150 (time: {time_estimate}, actual: {completed_checks})"
                        )
                    except asyncio.CancelledError:
                        break
                    except Exception as e:
                        logger.warning(f"Progress update error: {e}")

            # Start progress update task
            progress_task = asyncio.create_task(update_progress_periodically())

            logger.info("Streaming Docker Bench logs for real-time progress...")

            # Wrap blocking operations in executor
            loop = asyncio.get_event_loop()

            def parse_logs():
                nonlocal findings, completed_checks, full_output, scan_finished
                try:
                    for log_line in container.logs(stream=True, follow=True):
                        # Decode log line
                        line = log_line.decode("utf-8") if isinstance(log_line, bytes) else log_line
                        full_output += line

                        # Parse line for check results in real-time
                        finding = self._parse_single_check_line(line)
                        if finding:
                            findings.append(finding)
                            completed_checks += 1

                            # Update progress state with actual findings when available
                            compliance_state.update_progress(
                                check_id=finding["check_id"],
                                check_title=finding["title"],
                                completed=completed_checks,
                            )

                            logger.info(
                                f"Progress: Completed check {completed_checks}: {finding['check_id']} - {finding['title']}"
                            )
                finally:
                    scan_finished = True

            # Run log parsing in executor to avoid blocking
            await loop.run_in_executor(None, parse_logs)

            # Cancel progress update task
            progress_task.cancel()
            try:
                await progress_task
            except asyncio.CancelledError:
                # Task cancelled successfully - expected behavior
                pass

            # Wait for container to finish and get exit code
            result = container.wait()
            exit_code = result.get("StatusCode", 0)

            # Remove container
            container.remove()

            scan_duration = (get_now() - start_time).total_seconds()

            # DON'T finish progress tracking here - let the calling function do it after DB save
            # compliance_state.finish_scan() - MOVED to perform_compliance_scan()

            logger.info(
                f"Docker Bench scan completed in {scan_duration:.2f}s with {len(findings)} findings (exit code: {exit_code})"
            )

            if not findings:
                logger.warning(
                    f"Docker Bench scan produced no findings. Output length: {len(full_output)} chars"
                )
                logger.warning(f"Output preview: {full_output[:500]}")
                return None

            return {
                "scan_duration_seconds": scan_duration,
                "findings": findings,
                "raw_output": full_output,
            }

        except Exception as e:
            logger.error(f"Docker Bench scan failed: {e}", exc_info=True)
            compliance_state.finish_scan()
            return None

    def _parse_single_check_line(self, line: str) -> dict[str, Any] | None:
        """
        Parse a single Docker Bench output line for check results.

        Args:
            line: Single line of Docker Bench output

        Returns:
            Finding dictionary if line contains a check result, None otherwise
        """
        # Strip ANSI color codes
        ansi_escape = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
        line_clean = ansi_escape.sub("", line)

        # Match check pattern: [STATUS] check_id - title
        pattern = r"\[(PASS|WARN|FAIL|INFO|NOTE)\]\s+([\d\.]+)\s*-?\s*(.+?)(?:\n|$)"
        match = re.match(pattern, line_clean)

        if not match:
            return None

        status = match.group(1)
        check_id = match.group(2).strip()
        title = match.group(3).strip()

        return {
            "check_id": check_id,
            "check_number": check_id,
            "title": title,
            "description": None,
            "status": status,
            "severity": self._determine_severity(status),
            "category": self._determine_category(check_id),
            "remediation": None,
            "actual_value": None,
            "expected_value": None,
        }

    def _parse_docker_bench_output(self, output: str) -> list[dict[str, Any]]:
        """
        Parse Docker Bench output into structured findings.

        Docker Bench output format (with ANSI color codes):
        [1;32m[PASS][0m 1.1.1  - Ensure a separate partition for containers has been created
        [1;33m[WARN][0m 1.1.2  - Ensure only trusted users are allowed to control Docker daemon
        [1;31m[FAIL][0m 4.5    - Ensure Content trust for Docker is Enabled
        [1;34m[INFO][0m 1.1.3  - Ensure auditing is configured for the Docker daemon
        [1;37m[NOTE][0m 1.1.4  - Some informational note

        Args:
            output: Raw Docker Bench output text

        Returns:
            List of finding dictionaries
        """
        findings = []

        # Strip ANSI color codes first
        ansi_escape = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
        output_clean = ansi_escape.sub("", output)

        # Updated regex to handle various formats
        # Matches: [STATUS] check_id - title
        pattern = r"\[(PASS|WARN|FAIL|INFO|NOTE)\]\s+([\d\.]+)\s*-?\s*(.+?)(?:\n|$)"

        matches = re.finditer(pattern, output_clean, re.MULTILINE)

        for match in matches:
            status = match.group(1)
            check_id = match.group(2).strip()
            title = match.group(3).strip()

            # Determine category based on check ID prefix
            category = self._determine_category(check_id)

            # Determine severity based on status
            severity = self._determine_severity(status)

            # Try to extract remediation/description from the output
            # Docker Bench sometimes includes additional info after the check line
            remediation = self._extract_remediation(output, check_id)

            finding = {
                "check_id": check_id,
                "check_number": check_id,  # Same as check_id for Docker Bench
                "title": title,
                "description": None,  # Docker Bench doesn't provide detailed descriptions in output
                "status": status,
                "severity": severity,
                "category": category,
                "remediation": remediation,
                "actual_value": None,
                "expected_value": None,
            }

            findings.append(finding)

        logger.info(f"Parsed {len(findings)} findings from Docker Bench output")
        return findings

    def _determine_category(self, check_id: str) -> str:
        """
        Determine category based on check ID prefix.

        Docker Bench categories:
        1.x = Host Configuration
        2.x = Docker daemon configuration
        3.x = Docker daemon configuration files
        4.x = Container Images and Build File
        5.x = Container Runtime
        6.x = Docker Security Operations
        7.x = Docker Swarm Configuration
        """
        if not check_id or not check_id[0].isdigit():
            return "Unknown"

        category_map = {
            "1": "Host Configuration",
            "2": "Docker Daemon Configuration",
            "3": "Docker Daemon Files",
            "4": "Container Images",
            "5": "Container Runtime",
            "6": "Docker Security Operations",
            "7": "Docker Swarm Configuration",
        }

        first_digit = check_id[0]
        return category_map.get(first_digit, "Unknown")

    def _determine_severity(self, status: str) -> str:
        """
        Map Docker Bench status to severity level.

        Args:
            status: PASS, WARN, FAIL, INFO, NOTE

        Returns:
            Severity level: HIGH, MEDIUM, LOW, INFO
        """
        severity_map = {
            "FAIL": "HIGH",
            "WARN": "MEDIUM",
            "PASS": "INFO",
            "INFO": "INFO",
            "NOTE": "LOW",
        }
        return severity_map.get(status, "INFO")

    def _extract_remediation(self, output: str, check_id: str) -> str | None:
        """
        Attempt to extract remediation advice for a specific check.

        Note: Docker Bench output format doesn't always include remediation
        in parseable format. This is a best-effort extraction.
        """
        # For now, return None as Docker Bench doesn't provide structured remediation
        # in the output. We could add a mapping of check_id -> remediation docs later.
        return None

    def calculate_compliance_score(self, findings: list[dict[str, Any]]) -> float:
        """
        Calculate overall compliance score as percentage of passed checks.

        Args:
            findings: List of compliance findings

        Returns:
            Compliance score as percentage (0-100)
        """
        if not findings:
            return 0.0

        # Count total checks (excluding INFO/NOTE which are informational)
        total_checks = sum(1 for f in findings if f["status"] in ["PASS", "WARN", "FAIL"])

        if total_checks == 0:
            return 100.0

        # Count passed checks
        passed_checks = sum(1 for f in findings if f["status"] == "PASS")

        # Calculate score
        score = (passed_checks / total_checks) * 100.0
        return round(score, 2)

    def calculate_category_scores(self, findings: list[dict[str, Any]]) -> dict[str, float]:
        """
        Calculate compliance scores per category.

        Args:
            findings: List of compliance findings

        Returns:
            Dictionary mapping category name to score percentage
        """
        category_scores = {}

        # Group findings by category
        categories: dict[str, list[dict[str, Any]]] = {}
        for finding in findings:
            category = finding["category"]
            if category not in categories:
                categories[category] = []
            categories[category].append(finding)

        # Calculate score for each category
        for category, cat_findings in categories.items():
            total = sum(1 for f in cat_findings if f["status"] in ["PASS", "WARN", "FAIL"])
            if total == 0:
                category_scores[category] = 100.0
                continue

            passed = sum(1 for f in cat_findings if f["status"] == "PASS")
            score = (passed / total) * 100.0
            category_scores[category] = round(score, 2)

        return category_scores

    async def get_scanner_version(self) -> str | None:
        """
        Get the Docker Bench for Security version from the container image.

        Returns:
            Version string or None if unavailable
        """
        try:
            # Try to inspect the image to get version from labels
            image = self.docker_service.client.images.get("docker/docker-bench-security:latest")

            # Check if image has version labels
            if hasattr(image, "labels") and image.labels:
                # Try common version label keys
                for label_key in [
                    "version",
                    "org.opencontainers.image.version",
                    "DOCKER_BENCH_VERSION",
                ]:
                    if label_key in image.labels:
                        return image.labels[label_key].lstrip("v")

            # If no labels, try to extract from image tags
            if hasattr(image, "tags") and image.tags:
                for tag in image.tags:
                    if ":" in tag:
                        version = tag.split(":")[1]
                        if version != "latest":
                            return version.lstrip("v")

            # Fallback: Docker Bench doesn't always have version info in the image
            # Return None to indicate unknown version
            logger.debug("Could not determine Docker Bench version from image")
            return None

        except Exception as e:
            logger.warning(f"Failed to get Docker Bench version: {e}")
            return None
