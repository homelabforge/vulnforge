"""Trivy scanner service for vulnerability scanning."""

import asyncio
import json
import logging
from datetime import datetime
from typing import Any

from docker.errors import DockerException

from app.config import settings
from app.services.docker_client import DockerService
from app.utils.timezone import get_now

logger = logging.getLogger(__name__)


class TrivyScanner:
    """Service for executing Trivy vulnerability scans."""

    def __init__(self, docker_service: DockerService):
        """
        Initialize Trivy scanner.

        Args:
            docker_service: Docker service instance
        """
        self.docker_service = docker_service
        self._exec_lock = asyncio.Lock()

        # Determine scan mode from configuration
        self.server_url = settings.trivy_server
        self.use_server_mode = bool(self.server_url)

        if self.use_server_mode:
            logger.info(f"Trivy client mode enabled (server: {self.server_url})")
        else:
            logger.info(f"Trivy docker exec mode enabled (container: {settings.trivy_container_name})")

    async def _exec_trivy_command(self, container, cmd: list[str], **kwargs):
        """
        Run a command inside the Trivy container with concurrency control.

        Trivy writes to a shared cache inside the container; running multiple
        scans simultaneously can corrupt initialization. We serialize exec
        calls so only one Trivy process manipulates the cache at a time.
        """
        async with self._exec_lock:
            return await asyncio.to_thread(
                container.exec_run,
                cmd,
                **kwargs,
            )

    async def _trivy_db_exists(self, container) -> bool:
        """Check whether the Trivy vulnerability database file exists."""
        try:
            exit_code, _ = await self._exec_trivy_command(
                container,
                ["sh", "-c", "test -f /root/.cache/trivy/db/trivy.db"],
                demux=False,
            )
            return exit_code == 0
        except Exception as exc:
            logger.debug("Failed to check Trivy DB existence: %s", exc)
            return False

    async def _clear_trivy_cache(self, container) -> None:
        """Remove the Trivy database cache inside the helper container."""
        try:
            await self._exec_trivy_command(
                container,
                ["sh", "-c", "rm -rf /root/.cache/trivy/db && mkdir -p /root/.cache/trivy/db"],
                demux=False,
            )
        except Exception as exc:
            logger.warning("Failed to reset Trivy DB cache: %s", exc)

    async def _run_trivy_scan(
        self,
        container,
        base_cmd: list[str],
        image: str,
        skip_db_update: bool,
    ) -> tuple[int, bytes | str | None]:
        """
        Execute the Trivy scan, retrying on database errors (corruption, locking).
        Allows multiple retries for locking (with backoff), one retry for corruption.
        """
        last_exit_code: int | None = None
        last_output: bytes | str | None = None
        local_skip = skip_db_update
        retried_on_db_corruption = False
        lock_retry_count = 0
        max_lock_retries = 3

        for attempt in range(max_lock_retries + 2):  # Allow multiple lock retries + corruption retry
            cmd = list(base_cmd)

            if local_skip:
                if await self._trivy_db_exists(container):
                    cmd.append("--skip-db-update")
                    logger.info("Using cached Trivy database (offline mode)")
                else:
                    logger.info("Trivy database not initialized; performing full update")
                    local_skip = False

            cmd.append(image)

            last_exit_code, last_output = await self._exec_trivy_command(
                container,
                cmd,
                demux=False,
            )

            if last_exit_code == 0:
                return last_exit_code, last_output

            output_text = (
                last_output.decode("utf-8", errors="ignore")
                if isinstance(last_output, (bytes, bytearray))
                else str(last_output)
            )

            if local_skip and "--skip-db-update cannot be specified on the first run" in output_text:
                logger.warning("Trivy cache missing; retrying without --skip-db-update")
                await self._clear_trivy_cache(container)
                local_skip = False
                continue

            # Handle database locking - retry multiple times with backoff
            if (
                lock_retry_count < max_lock_retries
                and "vulnerability database may be in use by another process" in output_text
            ):
                lock_retry_count += 1
                wait_time = 2 + (lock_retry_count * 2)  # Exponential backoff: 4s, 6s, 8s
                logger.warning(
                    f"Trivy database locked by another process; "
                    f"waiting {wait_time}s and retrying (attempt {lock_retry_count}/{max_lock_retries})"
                )
                await asyncio.sleep(wait_time)
                continue

            # Handle database corruption - clear cache and retry once
            if (
                not retried_on_db_corruption
                and (
                    "db corrupted" in output_text
                    or "failed to download vulnerability DB" in output_text
                )
            ):
                retried_on_db_corruption = True
                logger.warning("Trivy database error detected; refreshing cache and retrying")
                await self._clear_trivy_cache(container)
                local_skip = False
                continue

            break

        return last_exit_code or 1, last_output

    async def _scan_via_exec(
        self, image: str, scan_secrets: bool = True, timeout: int | None = None,
        skip_db_update: bool = False
    ) -> dict[str, Any] | None:
        """
        Scan an image with Trivy using docker exec mode.

        Args:
            image: Image to scan (e.g., 'nginx:latest')
            scan_secrets: Enable secret scanning (default: True)
            timeout: Scan timeout in seconds
            skip_db_update: Skip database update (use cached DB) - improves offline resilience

        Returns:
            Parsed scan results or None on error
        """
        if timeout is None:
            timeout = settings.scan_timeout

        try:
            trivy_container = self.docker_service.get_trivy_container()
            if not trivy_container:
                logger.error("Trivy container not available")
                return None

            logger.info(f"Scanning image: {image} (secrets: {scan_secrets}, skip_db_update: {skip_db_update})")
            start_time = get_now()

            # Build scanner list
            scanners = ["vuln"]
            if scan_secrets:
                scanners.append("secret")

            # Execute Trivy scan with both vulnerability and secret scanning
            # Command: trivy image --scanners vuln,secret --format json --quiet [--skip-db-update] <image>
            base_cmd = [
                "trivy", "image",
                "--scanners", ",".join(scanners),
                "--format", "json",
                "--quiet",
            ]

            exit_code, output = await self._run_trivy_scan(
                trivy_container,
                base_cmd,
                image,
                skip_db_update,
            )

            scan_duration = (get_now() - start_time).total_seconds()

            if exit_code != 0:
                logger.error(f"Trivy scan failed with exit code {exit_code}")
                logger.error(f"Output: {output[:500]}")  # First 500 chars
                return None

            # Parse JSON output
            try:
                scan_data = json.loads(output)
                logger.info(f"Scan completed in {scan_duration:.2f}s")
                return self._parse_trivy_output(scan_data, scan_duration)

            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse Trivy JSON output: {e}")
                logger.error(f"Output: {output[:500]}")
                return None

        except DockerException as e:
            logger.error(f"Docker error during scan: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error during scan: {e}")
            return None

    async def _scan_via_client_mode(
        self, image: str, scan_secrets: bool = True, timeout: int | None = None,
        skip_db_update: bool = False
    ) -> dict[str, Any] | None:
        """
        Scan an image with Trivy using client mode pointing to server.

        Args:
            image: Image to scan (e.g., 'nginx:latest')
            scan_secrets: Enable secret scanning (default: True)
            timeout: Scan timeout in seconds
            skip_db_update: Skip database update (use cached DB) - improves offline resilience

        Returns:
            Parsed scan results or None on error
        """
        if timeout is None:
            timeout = settings.scan_timeout

        try:
            trivy_container = self.docker_service.get_trivy_container()
            if not trivy_container:
                logger.error("Trivy container not available for client mode")
                return None

            logger.info(f"Scanning image: {image} (mode: client, secrets: {scan_secrets}, skip_db_update: {skip_db_update})")
            start_time = get_now()

            # Build scanner list
            scanners = ["vuln"]
            if scan_secrets:
                scanners.append("secret")

            # Execute Trivy scan in client mode pointing to server
            # Command: trivy image --server <url> --scanners vuln,secret --format json --quiet [--skip-db-update] <image>
            base_cmd = [
                "trivy", "image",
                "--server", self.server_url,  # Client mode: point to server
                "--scanners", ",".join(scanners),
                "--format", "json",
                "--quiet",
            ]

            exit_code, output = await self._run_trivy_scan(
                trivy_container,
                base_cmd,
                image,
                skip_db_update,
            )

            scan_duration = (get_now() - start_time).total_seconds()

            if exit_code != 0:
                logger.error(f"Trivy client mode scan failed with exit code {exit_code}")
                logger.error(f"Output: {output[:500]}")  # First 500 chars
                return None

            # Parse JSON output
            try:
                scan_data = json.loads(output)
                logger.info(f"Scan completed in {scan_duration:.2f}s (client mode)")
                return self._parse_trivy_output(scan_data, scan_duration)

            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse Trivy JSON output: {e}")
                logger.error(f"Output: {output[:500]}")
                return None

        except DockerException as e:
            logger.error(f"Docker error during client mode scan: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error during client mode scan: {e}")
            return None

    async def scan_image(
        self, image: str, scan_secrets: bool = True, timeout: int | None = None,
        skip_db_update: bool = False
    ) -> dict[str, Any] | None:
        """
        Scan an image with Trivy for vulnerabilities and optionally secrets.

        Automatically uses client mode (pointing to server) if TRIVY_SERVER is configured,
        falling back to docker exec mode on failure or if server not configured.

        Args:
            image: Image to scan (e.g., 'nginx:latest')
            scan_secrets: Enable secret scanning (default: True)
            timeout: Scan timeout in seconds
            skip_db_update: Skip database update (use cached DB) - improves offline resilience

        Returns:
            Parsed scan results or None on error
        """
        # Try client mode first if server configured
        if self.use_server_mode:
            try:
                result = await self._scan_via_client_mode(image, scan_secrets, timeout, skip_db_update)
                if result is not None:
                    return result
                # Client mode returned None, try fallback
                logger.warning("Client mode returned no results, falling back to exec mode")
            except Exception as e:
                logger.warning(f"Client mode failed ({e}), falling back to exec mode")

        # Use exec mode (either as fallback or as primary when server not configured)
        return await self._scan_via_exec(image, scan_secrets, timeout, skip_db_update)

    def _parse_trivy_output(
        self, trivy_data: dict[str, Any], scan_duration: float
    ) -> dict[str, Any]:
        """
        Parse Trivy JSON output into structured data.

        Args:
            trivy_data: Raw Trivy JSON output
            scan_duration: Scan duration in seconds

        Returns:
            Parsed vulnerability data
        """
        vulnerabilities = []
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
        fixable_count = 0

        # Trivy output structure: Results -> Vulnerabilities
        results = trivy_data.get("Results", [])

        for result in results:
            target = result.get("Target", "unknown")
            vulns = result.get("Vulnerabilities", [])

            for vuln in vulns:
                cve_id = vuln.get("VulnerabilityID", "UNKNOWN")
                package_name = vuln.get("PkgName", "unknown")
                severity = vuln.get("Severity", "UNKNOWN")
                installed_version = vuln.get("InstalledVersion", "")
                fixed_version = vuln.get("FixedVersion", "")

                # Determine if fixable
                is_fixable = bool(fixed_version and fixed_version != "")

                # Get CVSS score
                cvss_score = None
                if "CVSS" in vuln:
                    # Try to extract score from various CVSS formats
                    cvss_data = vuln["CVSS"]
                    if isinstance(cvss_data, dict):
                        # Try different vendors
                        for vendor in ["nvd", "redhat", "ghsa"]:
                            if vendor in cvss_data:
                                v3_score = cvss_data[vendor].get("V3Score")
                                if v3_score:
                                    cvss_score = v3_score
                                    break

                # Get primary URL
                primary_url = vuln.get("PrimaryURL", "")

                # Get references
                references = vuln.get("References", [])
                references_json = json.dumps(references) if references else None

                # Get title and description
                title = vuln.get("Title", "")
                description = vuln.get("Description", "")

                vulnerabilities.append(
                    {
                        "cve_id": cve_id,
                        "package_name": package_name,
                        "severity": severity,
                        "cvss_score": cvss_score,
                        "title": title[:500] if title else None,  # Limit length
                        "description": description[:2000] if description else None,
                        "installed_version": installed_version,
                        "fixed_version": fixed_version if fixed_version else None,
                        "is_fixable": is_fixable,
                        "primary_url": primary_url if primary_url else None,
                        "references": references_json,
                        "target": target,
                    }
                )

                # Update counts
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
                if is_fixable:
                    fixable_count += 1

        # Parse secrets
        secrets = self._parse_trivy_secrets(trivy_data)

        return {
            "vulnerabilities": vulnerabilities,
            "secrets": secrets,
            "total_count": len(vulnerabilities),
            "fixable_count": fixable_count,
            "critical_count": severity_counts["CRITICAL"],
            "high_count": severity_counts["HIGH"],
            "medium_count": severity_counts["MEDIUM"],
            "low_count": severity_counts["LOW"],
            "scan_duration_seconds": scan_duration,
            "secret_count": len(secrets),
        }

    def _parse_trivy_secrets(self, trivy_data: dict[str, Any]) -> list[dict[str, Any]]:
        """
        Parse Trivy secret scan results from JSON output.

        Args:
            trivy_data: Raw Trivy JSON output

        Returns:
            List of parsed secrets
        """
        secrets = []

        # Trivy output structure: Results -> Secrets
        results = trivy_data.get("Results", [])

        for result in results:
            target = result.get("Target", "unknown")
            secret_findings = result.get("Secrets", [])

            for secret in secret_findings:
                # Extract code snippet from Code.Lines array - BUT REDACT FOR SECURITY
                code_lines = secret.get("Code", {}).get("Lines", [])

                # Redact code lines to prevent secret exposure in database
                redacted_lines = []
                if code_lines:
                    for line in code_lines:
                        redacted_lines.append({
                            "Number": line.get("Number"),
                            "Content": "***REDACTED***",  # Hide actual secret
                            "IsCause": line.get("IsCause", False)
                        })

                    # Format for display (line numbers only, content redacted)
                    code_snippet = "\n".join(
                        [f"Line {line['Number']}: ***REDACTED***" for line in redacted_lines]
                    )
                else:
                    code_snippet = None

                # Extract layer information
                layer_info = secret.get("Layer", {})
                layer_digest = layer_info.get("Digest") if layer_info else None

                # Redact the match field as well (even though Trivy may have partially redacted it)
                match_value = secret.get("Match", "")
                redacted_match = "***REDACTED***" if match_value else ""

                secrets.append(
                    {
                        "rule_id": secret.get("RuleID", "unknown"),
                        "category": secret.get("Category", "Generic"),
                        "title": secret.get("Title", "Unknown Secret"),
                        "severity": secret.get("Severity", "UNKNOWN"),
                        "match": redacted_match,  # Fully redacted for security
                        "start_line": secret.get("StartLine"),
                        "end_line": secret.get("EndLine"),
                        "code_snippet": code_snippet,  # Redacted line numbers only
                        "layer_digest": layer_digest,
                        "file_path": target,  # Target contains file path for secrets
                        "redacted": True,  # Flag indicating content is redacted
                    }
                )

        if secrets:
            logger.info(f"Found {len(secrets)} secrets during scan")

        return secrets

    async def get_database_info(self) -> dict[str, Any] | None:
        """
        Get Trivy vulnerability database information.

        Returns:
            Database info dict or None on error
        """
        try:
            trivy_container = self.docker_service.get_trivy_container()
            if not trivy_container:
                logger.error("Trivy container not available")
                return None

            # Execute trivy --version
            cmd = ["trivy", "--version"]
            exit_code, output = await self._exec_trivy_command(
                trivy_container,
                cmd,
                demux=False,
            )

            if exit_code != 0:
                logger.error(f"Trivy version command failed with exit code {exit_code}")
                return None

            # Parse output
            # Format: Version: X.Y.Z
            #         Vulnerability DB:
            #           Version: N
            #           UpdatedAt: TIMESTAMP
            #           NextUpdate: TIMESTAMP
            #         ...

            lines = output.decode('utf-8').split('\n')
            db_info = {}

            in_vuln_db_section = False
            for line in lines:
                line = line.strip()

                if "Vulnerability DB:" in line:
                    in_vuln_db_section = True
                    continue

                if in_vuln_db_section:
                    if "Version:" in line and "db_version" not in db_info:
                        db_info["db_version"] = int(line.split(":")[-1].strip())
                    elif "UpdatedAt:" in line:
                        db_info["updated_at"] = line.split("UpdatedAt:")[-1].strip()
                    elif "NextUpdate:" in line:
                        db_info["next_update"] = line.split("NextUpdate:")[-1].strip()
                    elif "DownloadedAt:" in line:
                        db_info["downloaded_at"] = line.split("DownloadedAt:")[-1].strip()
                    elif line and not line.startswith(" ") and ":" in line:
                        # Next section started
                        break

            if not db_info:
                logger.error("Failed to parse Trivy database info")
                return None

            return db_info

        except Exception as e:
            logger.error(f"Error getting Trivy database info: {e}")
            return None

    async def check_db_freshness(self, max_age_hours: int = 24) -> tuple[bool, int | None]:
        """
        Check if Trivy database is fresh enough to skip updates.

        Args:
            max_age_hours: Maximum age in hours to consider DB fresh (default: 24)

        Returns:
            Tuple of (is_fresh: bool, age_hours: int | None)
            Returns (False, None) if DB info unavailable
        """
        try:
            db_info = await self.get_database_info()
            if not db_info or "updated_at" not in db_info:
                logger.warning("Cannot determine Trivy DB age - DB info unavailable")
                return False, None

            # Parse updated_at timestamp
            # Format can be ISO8601 ("2025-10-28T12:34:56.789Z") or Go format ("2025-10-28 06:30:22.195426703 +0000 UTC")
            from datetime import datetime, timezone
            updated_at_str = db_info["updated_at"]

            try:
                # Try ISO8601 format first
                updated_at = datetime.fromisoformat(updated_at_str.replace('Z', '+00:00'))
            except ValueError:
                # Try Go timestamp format: "2025-10-28 06:30:22.195426703 +0000 UTC"
                # Remove " UTC" suffix and parse
                if " UTC" in updated_at_str:
                    updated_at_str = updated_at_str.replace(" UTC", "")
                    # Format: "2025-10-28 06:30:22.195426703 +0000"
                    # Truncate nanoseconds to microseconds (Python only supports 6 digits)
                    import re
                    # Match: date time.nanoseconds timezone
                    match = re.match(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\.(\d+) (.+)', updated_at_str)
                    if match:
                        date_time = match.group(1)
                        nanos = match.group(2)[:6]  # Truncate to microseconds
                        tz = match.group(3)
                        updated_at_str = f"{date_time}.{nanos} {tz}"
                    updated_at = datetime.strptime(updated_at_str, "%Y-%m-%d %H:%M:%S.%f %z")

            # Calculate age
            now = datetime.now(timezone.utc)
            age = now - updated_at
            age_hours = int(age.total_seconds() / 3600)

            is_fresh = age_hours < max_age_hours

            logger.info(f"Trivy DB age: {age_hours} hours (fresh: {is_fresh}, threshold: {max_age_hours}h)")
            return is_fresh, age_hours

        except Exception as e:
            logger.error(f"Error checking Trivy DB freshness: {e}")
            return False, None

    async def get_scanner_version(self) -> str | None:
        """
        Get Trivy scanner version.

        Returns:
            Scanner version string or None on error
        """
        try:
            trivy_container = self.docker_service.get_trivy_container()
            if not trivy_container:
                logger.error("Trivy container not available")
                return None

            # Execute trivy --version
            cmd = ["trivy", "--version"]
            exit_code, output = await self._exec_trivy_command(
                trivy_container,
                cmd,
                demux=False,
            )

            if exit_code != 0:
                logger.error(f"Trivy version command failed with exit code {exit_code}")
                return None

            # Parse output - first line format: "Version: X.Y.Z"
            lines = output.decode('utf-8').split('\n')
            for line in lines:
                if line.strip().startswith("Version:"):
                    version = line.split(":")[-1].strip()
                    return version

            logger.error("Failed to parse Trivy version from output")
            return None

        except Exception as e:
            logger.error(f"Error getting Trivy scanner version: {e}")
            return None
