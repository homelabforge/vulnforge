"""Native VulnForge compliance checker service.

Replaces Docker Bench with a Python-based checker that:
- Queries Docker API directly (no container spin-up)
- Only runs relevant homelab checks
- Includes built-in remediation guidance
- Supports per-check enable/disable
"""

import json
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.data.compliance_checks import (
    CONTAINER_CHECKS,
    DAEMON_CHECKS,
    DEFAULT_ENABLED_CHECKS,
    HOST_CHECKS,
    IMAGE_CHECKS,
    ComplianceCheck,
    Severity,
    Status,
)
from app.services.compliance_state import compliance_state
from app.services.docker_client import DockerService
from app.utils.timezone import get_now

logger = logging.getLogger(__name__)

# Secret patterns to detect in environment variables
SECRET_PATTERNS = [
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "auth",
    "credential",
    "private_key",
    "access_key",
]


@dataclass
class FindingResult:
    """Result of a single compliance check."""

    check_id: str
    title: str
    description: str
    category: str
    status: Status
    severity: Severity
    target: str | None = None  # Container/image name for per-target checks
    actual_value: str | None = None
    expected_value: str | None = None
    remediation: dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanResult:
    """Result of a compliance scan."""

    findings: list[FindingResult]
    total_checks: int
    passed: int
    warned: int
    failed: int
    info: int
    skipped: int
    compliance_score: float
    category_scores: dict[str, float]
    duration_seconds: float


class ComplianceChecker:
    """Native VulnForge compliance checker."""

    def __init__(self, docker_service: DockerService):
        """Initialize compliance checker with Docker service."""
        self.docker = docker_service
        self.enabled_checks: set[str] = DEFAULT_ENABLED_CHECKS.copy()
        # Host paths - mounted read-only in container
        self.host_etc = Path(os.getenv("HOST_ETC_PATH", "/host/etc"))
        self.host_var_run = Path(os.getenv("HOST_VAR_RUN_PATH", "/host/var/run"))

    def set_enabled_checks(self, check_ids: set[str]) -> None:
        """Set which checks are enabled."""
        self.enabled_checks = check_ids

    async def run_scan(self) -> ScanResult:
        """
        Run all enabled compliance checks.

        Returns:
            ScanResult with all findings and summary statistics
        """
        start_time = get_now()
        findings: list[FindingResult] = []

        # Calculate total checks to run
        total_checks = self._calculate_total_checks()
        compliance_state.start_scan(total_checks=total_checks)

        try:
            completed = 0

            # Run daemon checks (once)
            logger.info("Running daemon configuration checks")
            daemon_findings = await self._run_daemon_checks()
            findings.extend(daemon_findings)
            completed += len(DAEMON_CHECKS)
            compliance_state.update_progress("VF-D", "Daemon checks complete", completed)

            # Run container checks (per container)
            logger.info("Running container runtime checks")
            container_findings = await self._run_container_checks()
            findings.extend(container_findings)
            completed += len(container_findings)
            compliance_state.update_progress("VF-C", "Container checks complete", completed)

            # Run image checks (per unique image)
            logger.info("Running image security checks")
            image_findings = await self._run_image_checks()
            findings.extend(image_findings)
            completed += len(image_findings)
            compliance_state.update_progress("VF-I", "Image checks complete", completed)

            # Run host checks
            logger.info("Running host configuration checks")
            host_findings = await self._run_host_checks()
            findings.extend(host_findings)
            completed += len(HOST_CHECKS)
            compliance_state.update_progress("VF-H", "Host checks complete", completed)

            # Calculate summary statistics
            duration = (get_now() - start_time).total_seconds()
            result = self._calculate_summary(findings, duration)

            logger.info(
                f"Compliance scan complete: {result.passed}/{result.total_checks} passed "
                f"({result.compliance_score:.1f}%) in {duration:.1f}s"
            )

            return result

        finally:
            compliance_state.finish_scan()

    def _calculate_total_checks(self) -> int:
        """Calculate total number of checks to run."""
        total = 0

        # Daemon checks (run once each)
        for check in DAEMON_CHECKS:
            if check.id in self.enabled_checks:
                total += 1

        # Container checks (per container)
        try:
            containers = self.docker.client.containers.list(all=True)
            container_count = len(containers)
            enabled_container_checks = sum(
                1 for c in CONTAINER_CHECKS if c.id in self.enabled_checks
            )
            total += container_count * enabled_container_checks
        except Exception as e:
            logger.warning(f"Could not count containers: {e}")
            total += len(CONTAINER_CHECKS)  # Fallback estimate

        # Image checks (per unique image)
        try:
            containers = self.docker.client.containers.list(all=True)
            unique_images = {c.image.id for c in containers if c.image}
            image_count = len(unique_images)
            enabled_image_checks = sum(1 for c in IMAGE_CHECKS if c.id in self.enabled_checks)
            total += image_count * enabled_image_checks
        except Exception as e:
            logger.warning(f"Could not count images: {e}")
            total += len(IMAGE_CHECKS)  # Fallback estimate

        # Host checks (run once each)
        for check in HOST_CHECKS:
            if check.id in self.enabled_checks:
                total += 1

        return total

    # =========================================================================
    # DAEMON CHECKS
    # =========================================================================

    async def _run_daemon_checks(self) -> list[FindingResult]:
        """Run all enabled daemon configuration checks."""
        findings = []
        daemon_config = self._read_daemon_json()

        for check in DAEMON_CHECKS:
            if check.id not in self.enabled_checks:
                continue

            compliance_state.update_progress(check.id, check.title, len(findings))

            try:
                if check.id == "VF-D-001":
                    finding = self._check_daemon_icc(check, daemon_config)
                elif check.id == "VF-D-002":
                    finding = self._check_daemon_userland_proxy(check, daemon_config)
                elif check.id == "VF-D-003":
                    finding = self._check_daemon_no_new_privileges(check, daemon_config)
                elif check.id == "VF-D-004":
                    finding = self._check_daemon_live_restore(check, daemon_config)
                elif check.id == "VF-D-005":
                    finding = self._check_daemon_log_rotation(check, daemon_config)
                elif check.id == "VF-D-006":
                    finding = self._check_daemon_dns(check, daemon_config)
                else:
                    finding = self._create_skipped_finding(check, "Check not implemented")

                findings.append(finding)
            except Exception as e:
                logger.error(f"Error running check {check.id}: {e}")
                findings.append(self._create_error_finding(check, str(e)))

        return findings

    def _read_daemon_json(self) -> dict[str, Any]:
        """Read Docker daemon.json configuration."""
        daemon_json_path = self.host_etc / "docker" / "daemon.json"
        try:
            if daemon_json_path.exists():
                return json.loads(daemon_json_path.read_text())
        except Exception as e:
            logger.warning(f"Could not read daemon.json: {e}")
        return {}

    def _check_daemon_icc(self, check: ComplianceCheck, config: dict) -> FindingResult:
        """VF-D-001: Check if inter-container communication is disabled."""
        icc_value = config.get("icc")
        is_disabled = icc_value is False

        return self._create_finding(
            check,
            status=Status.PASS if is_disabled else Status.WARN,
            actual_value=str(icc_value) if icc_value is not None else "not set (default: true)",
            expected_value="false",
        )

    def _check_daemon_userland_proxy(self, check: ComplianceCheck, config: dict) -> FindingResult:
        """VF-D-002: Check if userland proxy is disabled."""
        proxy_value = config.get("userland-proxy")
        is_disabled = proxy_value is False

        return self._create_finding(
            check,
            status=Status.PASS if is_disabled else Status.WARN,
            actual_value=str(proxy_value) if proxy_value is not None else "not set (default: true)",
            expected_value="false",
        )

    def _check_daemon_no_new_privileges(
        self, check: ComplianceCheck, config: dict
    ) -> FindingResult:
        """VF-D-003: Check if no-new-privileges default is enabled."""
        nnp_value = config.get("no-new-privileges")
        is_enabled = nnp_value is True

        return self._create_finding(
            check,
            status=Status.PASS if is_enabled else Status.WARN,
            actual_value=str(nnp_value) if nnp_value is not None else "not set (default: false)",
            expected_value="true",
        )

    def _check_daemon_live_restore(self, check: ComplianceCheck, config: dict) -> FindingResult:
        """VF-D-004: Check if live restore is enabled."""
        lr_value = config.get("live-restore")
        is_enabled = lr_value is True

        return self._create_finding(
            check,
            status=Status.PASS if is_enabled else Status.WARN,
            actual_value=str(lr_value) if lr_value is not None else "not set (default: false)",
            expected_value="true",
        )

    def _check_daemon_log_rotation(self, check: ComplianceCheck, config: dict) -> FindingResult:
        """VF-D-005: Check if log rotation is configured."""
        log_driver = config.get("log-driver", "json-file")
        log_opts = config.get("log-opts", {})
        max_size = log_opts.get("max-size")
        max_file = log_opts.get("max-file")

        is_configured = log_driver == "json-file" and max_size is not None

        return self._create_finding(
            check,
            status=Status.PASS if is_configured else Status.WARN,
            actual_value=f"driver={log_driver}, max-size={max_size}, max-file={max_file}",
            expected_value="json-file with max-size and max-file configured",
        )

    def _check_daemon_dns(self, check: ComplianceCheck, config: dict) -> FindingResult:
        """VF-D-006: Check if custom DNS is configured (informational)."""
        dns_servers = config.get("dns", [])
        has_custom_dns = len(dns_servers) > 0

        return self._create_finding(
            check,
            status=Status.INFO if has_custom_dns else Status.INFO,
            actual_value=", ".join(dns_servers) if dns_servers else "using system DNS",
            expected_value="Custom DNS servers (informational)",
        )

    # =========================================================================
    # CONTAINER CHECKS
    # =========================================================================

    async def _run_container_checks(self) -> list[FindingResult]:
        """Run all enabled container runtime checks."""
        findings = []

        try:
            containers = self.docker.client.containers.list(all=True)
        except Exception as e:
            logger.error(f"Could not list containers: {e}")
            return findings

        for container in containers:
            for check in CONTAINER_CHECKS:
                if check.id not in self.enabled_checks:
                    continue

                try:
                    attrs = container.attrs
                    host_config = attrs.get("HostConfig", {})

                    if check.id == "VF-C-001":
                        finding = self._check_container_memory(check, container, host_config)
                    elif check.id == "VF-C-002":
                        finding = self._check_container_cpu(check, container, host_config)
                    elif check.id == "VF-C-003":
                        finding = self._check_container_no_new_privileges(
                            check, container, host_config
                        )
                    elif check.id == "VF-C-004":
                        finding = self._check_container_capabilities(check, container, host_config)
                    elif check.id == "VF-C-005":
                        finding = self._check_container_healthcheck(check, container, attrs)
                    elif check.id == "VF-C-006":
                        finding = self._check_container_restart_policy(
                            check, container, host_config
                        )
                    elif check.id == "VF-C-007":
                        finding = self._check_container_readonly(check, container, host_config)
                    elif check.id == "VF-C-008":
                        finding = self._check_container_privileged(check, container, host_config)
                    else:
                        finding = self._create_skipped_finding(
                            check, "Check not implemented", container.name
                        )

                    findings.append(finding)
                except Exception as e:
                    logger.error(f"Error running check {check.id} on {container.name}: {e}")
                    findings.append(self._create_error_finding(check, str(e), container.name))

        return findings

    def _check_container_memory(
        self, check: ComplianceCheck, container: Any, host_config: dict
    ) -> FindingResult:
        """VF-C-001: Check if memory limit is configured."""
        memory_limit = host_config.get("Memory", 0)
        has_limit = memory_limit > 0

        if has_limit:
            actual = f"{memory_limit // 1024 // 1024}MB"
        else:
            actual = "unlimited"

        return self._create_finding(
            check,
            status=Status.PASS if has_limit else Status.WARN,
            target=container.name,
            actual_value=actual,
            expected_value="Memory limit set (e.g., 512m)",
        )

    def _check_container_cpu(
        self, check: ComplianceCheck, container: Any, host_config: dict
    ) -> FindingResult:
        """VF-C-002: Check if CPU shares are configured (informational)."""
        cpu_shares = host_config.get("CpuShares", 0)

        return self._create_finding(
            check,
            status=Status.INFO,
            target=container.name,
            actual_value=str(cpu_shares) if cpu_shares else "default (1024)",
            expected_value="CPU shares configured (informational)",
        )

    def _check_container_no_new_privileges(
        self, check: ComplianceCheck, container: Any, host_config: dict
    ) -> FindingResult:
        """VF-C-003: Check if no-new-privileges is set."""
        security_opts = host_config.get("SecurityOpt", []) or []
        has_nnp = any("no-new-privileges" in opt for opt in security_opts)

        return self._create_finding(
            check,
            status=Status.PASS if has_nnp else Status.WARN,
            target=container.name,
            actual_value="enabled" if has_nnp else "not set",
            expected_value="no-new-privileges:true",
        )

    def _check_container_capabilities(
        self, check: ComplianceCheck, container: Any, host_config: dict
    ) -> FindingResult:
        """VF-C-004: Check if capabilities are dropped."""
        cap_drop = host_config.get("CapDrop", []) or []
        cap_add = host_config.get("CapAdd", []) or []

        # Best: cap_drop ALL, worst: cap_add with sensitive caps
        has_drop_all = "ALL" in cap_drop or "all" in cap_drop
        sensitive_caps = {"SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "DAC_OVERRIDE"}
        has_sensitive = bool(set(cap_add or []) & sensitive_caps)

        if has_drop_all and not has_sensitive:
            status = Status.PASS
            actual = f"cap_drop: ALL, cap_add: {cap_add or 'none'}"
        elif cap_drop:
            status = Status.PASS
            actual = f"cap_drop: {cap_drop}, cap_add: {cap_add or 'none'}"
        else:
            status = Status.WARN
            actual = f"cap_drop: none, cap_add: {cap_add or 'none'}"

        return self._create_finding(
            check,
            status=status,
            target=container.name,
            actual_value=actual,
            expected_value="cap_drop: ALL (or specific capabilities)",
        )

    def _check_container_healthcheck(
        self, check: ComplianceCheck, container: Any, attrs: dict
    ) -> FindingResult:
        """VF-C-005: Check if health check is configured."""
        config = attrs.get("Config", {})
        healthcheck = config.get("Healthcheck")
        has_healthcheck = healthcheck is not None and healthcheck.get("Test")

        if has_healthcheck:
            test_cmd = healthcheck.get("Test", [])
            actual = f"configured: {' '.join(test_cmd[:3])}..."
        else:
            actual = "not configured"

        return self._create_finding(
            check,
            status=Status.PASS if has_healthcheck else Status.WARN,
            target=container.name,
            actual_value=actual,
            expected_value="HEALTHCHECK configured",
        )

    def _check_container_restart_policy(
        self, check: ComplianceCheck, container: Any, host_config: dict
    ) -> FindingResult:
        """VF-C-006: Check if restart policy is limited."""
        restart_policy = host_config.get("RestartPolicy", {})
        policy_name = restart_policy.get("Name", "no")
        max_retry = restart_policy.get("MaximumRetryCount", 0)

        # "always" and "unless-stopped" are unlimited
        is_limited = policy_name in ("no", "on-failure") or (
            policy_name == "on-failure" and max_retry > 0
        )

        return self._create_finding(
            check,
            status=Status.PASS if is_limited else Status.WARN,
            target=container.name,
            actual_value=f"{policy_name}" + (f" (max: {max_retry})" if max_retry else ""),
            expected_value="on-failure:5 or similar limited policy",
        )

    def _check_container_readonly(
        self, check: ComplianceCheck, container: Any, host_config: dict
    ) -> FindingResult:
        """VF-C-007: Check if root filesystem is read-only (informational)."""
        read_only = host_config.get("ReadonlyRootfs", False)

        return self._create_finding(
            check,
            status=Status.INFO,
            target=container.name,
            actual_value="read-only" if read_only else "read-write",
            expected_value="read-only (when possible)",
        )

    def _check_container_privileged(
        self, check: ComplianceCheck, container: Any, host_config: dict
    ) -> FindingResult:
        """VF-C-008: Check if container is running privileged."""
        privileged = host_config.get("Privileged", False)

        return self._create_finding(
            check,
            status=Status.FAIL if privileged else Status.PASS,
            target=container.name,
            actual_value="privileged" if privileged else "unprivileged",
            expected_value="unprivileged",
        )

    # =========================================================================
    # IMAGE CHECKS
    # =========================================================================

    async def _run_image_checks(self) -> list[FindingResult]:
        """Run all enabled image security checks."""
        findings = []

        try:
            containers = self.docker.client.containers.list(all=True)
            # Get unique images
            seen_images: set[str] = set()
            images_to_check = []
            for container in containers:
                image_id = container.image.id if container.image else None
                if image_id and image_id not in seen_images:
                    seen_images.add(image_id)
                    images_to_check.append(container.image)
        except Exception as e:
            logger.error(f"Could not list images: {e}")
            return findings

        for image in images_to_check:
            image_name = image.tags[0] if image.tags else image.id[:12]

            for check in IMAGE_CHECKS:
                if check.id not in self.enabled_checks:
                    continue

                try:
                    attrs = image.attrs
                    config = attrs.get("Config", {})

                    if check.id == "VF-I-001":
                        finding = self._check_image_user(check, image_name, config)
                    elif check.id == "VF-I-002":
                        finding = self._check_image_healthcheck(check, image_name, config)
                    elif check.id == "VF-I-003":
                        finding = self._check_image_secrets(check, image_name, config)
                    elif check.id == "VF-I-004":
                        finding = self._check_image_tag(check, image_name, image.tags)
                    else:
                        finding = self._create_skipped_finding(
                            check, "Check not implemented", image_name
                        )

                    findings.append(finding)
                except Exception as e:
                    logger.error(f"Error running check {check.id} on image: {e}")
                    findings.append(self._create_error_finding(check, str(e), image_name))

        return findings

    def _check_image_user(
        self, check: ComplianceCheck, image_name: str, config: dict
    ) -> FindingResult:
        """VF-I-001: Check if non-root user is configured."""
        user = config.get("User", "")
        has_user = bool(user) and user != "root" and user != "0"

        return self._create_finding(
            check,
            status=Status.PASS if has_user else Status.WARN,
            target=image_name,
            actual_value=user if user else "root (default)",
            expected_value="Non-root user (e.g., appuser, 1000)",
        )

    def _check_image_healthcheck(
        self, check: ComplianceCheck, image_name: str, config: dict
    ) -> FindingResult:
        """VF-I-002: Check if HEALTHCHECK instruction is present."""
        healthcheck = config.get("Healthcheck")
        has_healthcheck = healthcheck is not None and healthcheck.get("Test")

        return self._create_finding(
            check,
            status=Status.PASS if has_healthcheck else Status.WARN,
            target=image_name,
            actual_value="present" if has_healthcheck else "not defined",
            expected_value="HEALTHCHECK instruction in Dockerfile",
        )

    def _check_image_secrets(
        self, check: ComplianceCheck, image_name: str, config: dict
    ) -> FindingResult:
        """VF-I-003: Check for secrets in environment variables."""
        env_vars = config.get("Env", []) or []
        suspicious_vars = []

        for env in env_vars:
            if "=" in env:
                key = env.split("=")[0].lower()
                if any(pattern in key for pattern in SECRET_PATTERNS):
                    suspicious_vars.append(env.split("=")[0])

        has_secrets = len(suspicious_vars) > 0

        return self._create_finding(
            check,
            status=Status.WARN if has_secrets else Status.PASS,
            target=image_name,
            actual_value=f"Suspicious: {', '.join(suspicious_vars)}"
            if has_secrets
            else "No secrets detected",
            expected_value="No secrets in environment variables",
        )

    def _check_image_tag(
        self, check: ComplianceCheck, image_name: str, tags: list
    ) -> FindingResult:
        """VF-I-004: Check if image uses :latest tag (informational)."""
        uses_latest = any(":latest" in tag for tag in (tags or []))

        return self._create_finding(
            check,
            status=Status.INFO,
            target=image_name,
            actual_value="uses :latest" if uses_latest else "specific tag",
            expected_value="Specific version tag (informational)",
        )

    # =========================================================================
    # HOST CHECKS
    # =========================================================================

    async def _run_host_checks(self) -> list[FindingResult]:
        """Run all enabled host configuration checks."""
        findings = []

        for check in HOST_CHECKS:
            if check.id not in self.enabled_checks:
                continue

            compliance_state.update_progress(check.id, check.title, len(findings))

            try:
                if check.id == "VF-H-001":
                    finding = self._check_host_audit_rules(check)
                elif check.id == "VF-H-002":
                    finding = self._check_host_socket_permissions(check)
                else:
                    finding = self._create_skipped_finding(check, "Check not implemented")

                findings.append(finding)
            except Exception as e:
                logger.error(f"Error running check {check.id}: {e}")
                findings.append(self._create_error_finding(check, str(e)))

        return findings

    def _check_host_audit_rules(self, check: ComplianceCheck) -> FindingResult:
        """VF-H-001: Check if Docker audit rules are configured."""
        audit_rules_path = self.host_etc / "audit" / "rules.d" / "docker.rules"

        try:
            if audit_rules_path.exists():
                content = audit_rules_path.read_text()
                has_docker_rules = "/usr/bin/docker" in content or "/var/lib/docker" in content
                return self._create_finding(
                    check,
                    status=Status.PASS if has_docker_rules else Status.WARN,
                    actual_value="Docker audit rules found"
                    if has_docker_rules
                    else "Incomplete rules",
                    expected_value="Audit rules for Docker daemon",
                )
            else:
                return self._create_finding(
                    check,
                    status=Status.WARN,
                    actual_value="No docker.rules file found",
                    expected_value="/etc/audit/rules.d/docker.rules",
                )
        except Exception as e:
            return self._create_finding(
                check,
                status=Status.SKIP,
                actual_value=f"Could not check: {e}",
                expected_value="Audit rules for Docker",
            )

    def _check_host_socket_permissions(self, check: ComplianceCheck) -> FindingResult:
        """VF-H-002: Check Docker socket permissions."""
        socket_path = self.host_var_run / "docker.sock"

        try:
            if socket_path.exists():
                stat_info = socket_path.stat()
                mode = oct(stat_info.st_mode)[-3:]
                # Expected: 660 (rw-rw----)
                is_secure = mode in ("660", "600")

                return self._create_finding(
                    check,
                    status=Status.PASS if is_secure else Status.WARN,
                    actual_value=f"mode: {mode}",
                    expected_value="660 or 600",
                )
            else:
                return self._create_finding(
                    check,
                    status=Status.SKIP,
                    actual_value="Socket not found at expected path",
                    expected_value="Docker socket with restricted permissions",
                )
        except Exception as e:
            return self._create_finding(
                check,
                status=Status.SKIP,
                actual_value=f"Could not check: {e}",
                expected_value="Restricted socket permissions",
            )

    # =========================================================================
    # HELPER METHODS
    # =========================================================================

    def _create_finding(
        self,
        check: ComplianceCheck,
        status: Status,
        actual_value: str | None = None,
        expected_value: str | None = None,
        target: str | None = None,
    ) -> FindingResult:
        """Create a finding result from a check."""
        return FindingResult(
            check_id=check.id,
            title=check.title,
            description=check.description,
            category=check.category,
            status=status,
            severity=check.severity,
            target=target,
            actual_value=actual_value,
            expected_value=expected_value,
            remediation={
                "summary": check.remediation.summary,
                "compose": check.remediation.compose,
                "docker_run": check.remediation.docker_run,
                "daemon_json": check.remediation.daemon_json,
                "dockerfile": check.remediation.dockerfile,
                "host_command": check.remediation.host_command,
                "docs_url": check.remediation.docs_url,
            },
        )

    def _create_skipped_finding(
        self, check: ComplianceCheck, reason: str, target: str | None = None
    ) -> FindingResult:
        """Create a skipped finding result."""
        return FindingResult(
            check_id=check.id,
            title=check.title,
            description=check.description,
            category=check.category,
            status=Status.SKIP,
            severity=check.severity,
            target=target,
            actual_value=reason,
            expected_value=None,
            remediation={},
        )

    def _create_error_finding(
        self, check: ComplianceCheck, error: str, target: str | None = None
    ) -> FindingResult:
        """Create an error finding result."""
        return FindingResult(
            check_id=check.id,
            title=check.title,
            description=check.description,
            category=check.category,
            status=Status.SKIP,
            severity=check.severity,
            target=target,
            actual_value=f"Error: {error}",
            expected_value=None,
            remediation={},
        )

    def _calculate_summary(self, findings: list[FindingResult], duration: float) -> ScanResult:
        """Calculate summary statistics from findings."""
        passed = sum(1 for f in findings if f.status == Status.PASS)
        warned = sum(1 for f in findings if f.status == Status.WARN)
        failed = sum(1 for f in findings if f.status == Status.FAIL)
        info = sum(1 for f in findings if f.status == Status.INFO)
        skipped = sum(1 for f in findings if f.status == Status.SKIP)

        total = passed + warned + failed  # Exclude INFO and SKIP from score calculation
        compliance_score = (passed / total * 100) if total > 0 else 100.0

        # Calculate per-category scores
        category_scores: dict[str, float] = {}
        categories = set(f.category for f in findings)
        for category in categories:
            cat_findings = [f for f in findings if f.category == category]
            cat_passed = sum(1 for f in cat_findings if f.status == Status.PASS)
            cat_total = sum(
                1 for f in cat_findings if f.status in (Status.PASS, Status.WARN, Status.FAIL)
            )
            category_scores[category] = (cat_passed / cat_total * 100) if cat_total > 0 else 100.0

        return ScanResult(
            findings=findings,
            total_checks=len(findings),
            passed=passed,
            warned=warned,
            failed=failed,
            info=info,
            skipped=skipped,
            compliance_score=compliance_score,
            category_scores=category_scores,
            duration_seconds=duration,
        )
