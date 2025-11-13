"""Service for executing Dockle image linting and best practice checks."""

import asyncio
import json
import logging
import re
from typing import Any

from app.services.docker_client import DockerService
from app.utils.timezone import get_now

logger = logging.getLogger(__name__)


class DockleService:
    """Service for running Dockle image compliance and best practice scans."""

    # Severity mapping from Dockle to our standard levels
    SEVERITY_MAP = {
        "FATAL": "CRITICAL",
        "WARN": "HIGH",
        "INFO": "MEDIUM",
        "SKIP": "LOW",
        "PASS": "INFO",
    }

    # Category mapping for better organization
    CATEGORY_MAP = {
        "CIS": "CIS Benchmarks",
        "DKL": "Dockle Best Practices",
    }

    def __init__(self, docker_service: DockerService):
        """Initialize Dockle service."""
        self.docker_service = docker_service

    async def run_image_scan(self, image_name: str) -> dict[str, Any] | None:
        """
        Run Dockle compliance scan on a Docker image.

        Args:
            image_name: Name or ID of the Docker image to scan

        Returns:
            Dictionary containing scan results or None if scan failed
        """
        try:
            logger.info(f"Starting Dockle image compliance scan for: {image_name}")
            start_time = get_now()

            # Ensure image exists locally
            try:
                self.docker_service.client.images.get(image_name)
            except Exception as e:
                logger.error(f"Image {image_name} not found locally: {e}")
                return None

            # Run Dockle container with JSON output
            # Dockle runs as a one-shot container that scans the specified image
            container = self.docker_service.client.containers.run(
                image="goodwithtech/dockle:latest",
                command=[
                    "--format", "json",
                    "--exit-code", "0",  # Don't fail on findings
                    image_name
                ],
                volumes={
                    "/var/run/docker.sock": {"bind": "/var/run/docker.sock", "mode": "ro"}
                },
                detach=True,
                remove=False,  # Keep container for log retrieval
                labels={"managed_by": "vulnforge"},
            )

            # Wait for container to complete (Dockle is fast, usually < 10 seconds)
            loop = asyncio.get_event_loop()

            def wait_for_completion():
                """Wait for container to finish."""
                result = container.wait(timeout=60)
                return result

            # Run blocking wait in executor
            exit_info = await loop.run_in_executor(None, wait_for_completion)

            # Get container logs
            def get_logs():
                """Retrieve container logs."""
                return container.logs().decode('utf-8', errors='replace')

            output = await loop.run_in_executor(None, get_logs)

            # Clean up container
            try:
                container.remove()
            except Exception as e:
                logger.warning(f"Failed to remove Dockle container: {e}")

            # Parse JSON output
            try:
                scan_data = json.loads(output)
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse Dockle JSON output: {e}")
                logger.debug(f"Raw output: {output[:500]}")
                return None

            # Calculate scan duration
            end_time = get_now()
            duration_seconds = (end_time - start_time).total_seconds()

            # Transform Dockle output to our standardized format
            findings = self._transform_findings(scan_data, image_name)

            logger.info(
                f"Dockle scan completed for {image_name}: "
                f"{len(findings)} findings in {duration_seconds:.2f}s"
            )

            return {
                "image_name": image_name,
                "scan_duration_seconds": duration_seconds,
                "findings": findings,
                "raw_data": scan_data,  # Store original for debugging
            }

        except asyncio.TimeoutError:
            logger.error(f"Dockle scan timed out for image: {image_name}")
            return None
        except Exception as e:
            logger.error(f"Dockle scan failed for {image_name}: {e}", exc_info=True)
            return None

    def _transform_findings(self, scan_data: dict[str, Any], image_name: str) -> list[dict[str, Any]]:
        """
        Transform Dockle JSON output to standardized finding format.

        Dockle JSON structure:
        {
            "summary": {
                "fatal": 0,
                "warn": 5,
                "info": 10,
                "skip": 0,
                "pass": 15
            },
            "details": [
                {
                    "code": "CIS-DI-0001",
                    "title": "Create a user for the container",
                    "level": "WARN",
                    "alerts": ["Last user should not be root"]
                },
                ...
            ]
        }

        Args:
            scan_data: Raw Dockle JSON output
            image_name: Image that was scanned

        Returns:
            List of standardized findings
        """
        findings = []

        details = scan_data.get("details", [])

        for detail in details:
            code = detail.get("code", "UNKNOWN")
            title = detail.get("title", "Unknown check")
            level = detail.get("level", "INFO")
            alerts = detail.get("alerts", [])

            # Determine category based on code prefix
            category = "Dockle Best Practices"
            if code.startswith("CIS-"):
                category = "CIS Benchmarks"
            elif code.startswith("DKL-"):
                category = "Dockle Recommendations"

            # Map Dockle severity to our standard
            severity = self.SEVERITY_MAP.get(level, "MEDIUM")

            # Determine status based on severity
            if level == "PASS":
                status = "PASS"
            elif level == "SKIP":
                status = "SKIP"
            elif level in ["FATAL", "WARN"]:
                status = "FAIL"
            else:
                status = "INFO"

            # Build description from alerts
            description = "\n".join(f"• {alert}" for alert in alerts) if alerts else None

            # Generate remediation guidance based on check code
            remediation = self._get_remediation(code, title)

            finding = {
                "check_id": code,
                "check_number": code,  # Dockle uses same format
                "title": title,
                "description": description,
                "status": status,
                "severity": severity,
                "category": category,
                "remediation": remediation,
                "image_name": image_name,
                "alerts": alerts,  # Store raw alerts for detail view
            }

            findings.append(finding)

        if not findings:
            summary = scan_data.get("summary", {}) or {}

            def _safe_int(value):
                try:
                    return int(value)
                except (TypeError, ValueError):
                    return 0

            for key, severity, status, label in (
                ("fatal", "CRITICAL", "FAIL", "Critical issues reported"),
                ("warn", "HIGH", "FAIL", "Warnings reported"),
                ("info", "MEDIUM", "INFO", "Informational notices"),
                ("skip", "LOW", "SKIP", "Checks skipped"),
            ):
                count = _safe_int(summary.get(key))
                if count <= 0:
                    continue
                findings.append(
                    {
                        "check_id": f"SUMMARY-{key.upper()}",
                        "check_number": None,
                        "title": label,
                        "description": "Dockle reported this category in the summary but did not include per-check details in JSON output.",
                        "status": status,
                        "severity": severity,
                        "category": "Dockle Summary",
                        "remediation": None,
                        "image_name": image_name,
                        "alerts": [f"Count: {count}"],
                        "first_seen": get_now(),
                        "last_seen": get_now(),
                    }
                )

        return findings

    def _get_remediation(self, code: str, title: str) -> str:
        """
        Get remediation guidance for specific Dockle check codes.

        Args:
            code: Dockle check code (e.g., "CIS-DI-0001")
            title: Check title

        Returns:
            Remediation guidance string
        """
        # Comprehensive remediation guide based on common Dockle checks
        remediation_guide = {
            "CIS-DI-0001": "Add a non-root USER directive in your Dockerfile: USER appuser",
            "CIS-DI-0002": "Use HEALTHCHECK in Dockerfile to define container health monitoring",
            "CIS-DI-0005": "Enable Content Trust: export DOCKER_CONTENT_TRUST=1",
            "CIS-DI-0006": "Add HEALTHCHECK instruction to monitor container health",
            "CIS-DI-0007": "Don't use 'update' instructions alone in Dockerfile",
            "CIS-DI-0008": "Remove setuid/setgid permissions from files in image",
            "CIS-DI-0009": "Use COPY instead of ADD in Dockerfile unless extracting archives",
            "CIS-DI-0010": "Don't store secrets (passwords, keys) in Dockerfile or image layers",
            "CIS-DI-0011": "Only install necessary packages to minimize attack surface",
            "DKL-DI-0001": "Avoid using 'latest' tag; use specific version tags",
            "DKL-DI-0002": "Avoid using 'sudo' in Dockerfile commands",
            "DKL-DI-0003": "Use absolute paths in WORKDIR instructions",
            "DKL-DI-0004": "Avoid duplicate instructions in Dockerfile",
            "DKL-DI-0005": "Don't use deprecated MAINTAINER; use LABEL maintainer instead",
            "DKL-LI-0001": "Minimize the number of layers in your image",
            "DKL-LI-0002": "Delete cache and temporary files in the same RUN instruction",
        }

        # Return specific remediation if available, otherwise generic guidance
        if code in remediation_guide:
            return remediation_guide[code]

        # Generic remediation based on category
        if code.startswith("CIS-"):
            return f"Review CIS Docker Benchmark for {title}. Consult: https://www.cisecurity.org/benchmark/docker"
        elif code.startswith("DKL-"):
            return f"Review Dockle best practices for {title}. Consult: https://github.com/goodwithtech/dockle"

        return f"Review and address: {title}"

    def calculate_image_score(self, findings: list[dict[str, Any]]) -> float:
        """
        Calculate overall image compliance score (0-100).

        Score calculation:
        - PASS: +1 point
        - FAIL (FATAL/WARN): -2 points
        - INFO/SKIP: 0 points
        - Score = (points / total_checks) * 100, normalized to 0-100

        Args:
            findings: List of findings

        Returns:
            Compliance score percentage (0-100)
        """
        if not findings:
            return 100.0

        points = 0
        total_checks = len(findings)

        for finding in findings:
            status = finding.get("status", "INFO")
            if status == "PASS":
                points += 1
            elif status == "FAIL":
                points -= 2
            # INFO and SKIP contribute 0 points

        # Normalize to 0-100 range
        # Max points = total_checks (all PASS)
        # Min points = -2 * total_checks (all FAIL)
        # Range = 3 * total_checks
        score_range = 3 * total_checks
        normalized_points = points + (2 * total_checks)  # Shift to positive range
        score = (normalized_points / score_range) * 100

        return max(0.0, min(100.0, score))  # Clamp to 0-100

    def calculate_category_scores(self, findings: list[dict[str, Any]]) -> dict[str, float]:
        """
        Calculate compliance score breakdown by category.

        Args:
            findings: List of findings

        Returns:
            Dictionary mapping category name to score percentage
        """
        category_findings = {}

        # Group findings by category
        for finding in findings:
            category = finding.get("category", "Unknown")
            if category not in category_findings:
                category_findings[category] = []
            category_findings[category].append(finding)

        # Calculate score for each category
        category_scores = {}
        for category, cat_findings in category_findings.items():
            category_scores[category] = self.calculate_image_score(cat_findings)

        return category_scores

    async def scan_all_containers(self, container_names: list[str] | None = None) -> dict[str, Any]:
        """
        Scan all or specified containers' images with Dockle.

        Args:
            container_names: List of container names to scan, or None for all

        Returns:
            Dictionary with scan results per image
        """
        try:
            # Get list of containers
            if container_names:
                containers = [
                    c for c in self.docker_service.client.containers.list(all=True)
                    if c.name in container_names
                ]
            else:
                containers = self.docker_service.client.containers.list(all=True)

            # Extract unique images
            images_to_scan = {}
            for container in containers:
                image_id = container.image.id
                image_tags = container.image.tags
                image_name = image_tags[0] if image_tags else image_id

                if image_id not in images_to_scan:
                    images_to_scan[image_id] = {
                        "name": image_name,
                        "containers": []
                    }
                images_to_scan[image_id]["containers"].append(container.name)

            logger.info(f"Scanning {len(images_to_scan)} unique images with Dockle")

            # Scan each unique image
            results = {}
            for image_id, image_info in images_to_scan.items():
                image_name = image_info["name"]
                scan_result = await self.run_image_scan(image_name)

                if scan_result:
                    scan_result["affected_containers"] = image_info["containers"]
                    results[image_name] = scan_result

            return {
                "total_images": len(images_to_scan),
                "scanned_images": len(results),
                "results": results,
            }

        except Exception as e:
            logger.error(f"Failed to scan containers with Dockle: {e}", exc_info=True)
            return {
                "total_images": 0,
                "scanned_images": 0,
                "results": {},
                "error": str(e),
            }
