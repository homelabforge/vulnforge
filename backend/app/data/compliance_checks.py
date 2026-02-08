"""Compliance check definitions for VulnForge native compliance checker.

This module defines all compliance checks with their metadata, severity levels,
and remediation guidance. Checks are organized by category:
- Daemon (VF-D-*): Docker daemon configuration
- Container (VF-C-*): Container runtime security
- Image (VF-I-*): Container image security
- Host (VF-H-*): Host system configuration
"""

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Literal


class Severity(StrEnum):
    """Check severity levels."""

    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Status(StrEnum):
    """Check result status."""

    PASS = "PASS"
    WARN = "WARN"
    FAIL = "FAIL"
    INFO = "INFO"
    SKIP = "SKIP"


CheckType = Literal["daemon", "container", "image", "host"]
Category = Literal["Daemon Configuration", "Container Runtime", "Image Security", "Host Configuration"]


@dataclass
class Remediation:
    """Remediation guidance for a compliance check."""

    summary: str
    compose: str | None = None
    docker_run: str | None = None
    daemon_json: str | None = None
    dockerfile: str | None = None
    host_command: str | None = None
    docs_url: str | None = None


@dataclass
class ComplianceCheck:
    """Definition of a compliance check."""

    id: str
    title: str
    description: str
    category: Category
    severity: Severity
    check_type: CheckType
    enabled_default: bool = True
    remediation: Remediation = field(default_factory=lambda: Remediation(summary="No remediation available"))


# =============================================================================
# DAEMON CONFIGURATION CHECKS (VF-D-*)
# =============================================================================

DAEMON_CHECKS: list[ComplianceCheck] = [
    ComplianceCheck(
        id="VF-D-001",
        title="Inter-container communication disabled",
        description="Containers on the default bridge network should not be able to communicate "
        "with each other unless explicitly linked. This prevents lateral movement if a container is compromised.",
        category="Daemon Configuration",
        severity=Severity.MEDIUM,
        check_type="daemon",
        remediation=Remediation(
            summary="Disable inter-container communication (ICC) in daemon.json",
            daemon_json='{\n  "icc": false\n}',
            docs_url="https://docs.docker.com/engine/network/drivers/bridge/#options",
        ),
    ),
    ComplianceCheck(
        id="VF-D-002",
        title="Userland proxy disabled",
        description="The userland proxy (docker-proxy) should be disabled in favor of hairpin NAT "
        "which is more efficient and doesn't require additional processes.",
        category="Daemon Configuration",
        severity=Severity.LOW,
        check_type="daemon",
        remediation=Remediation(
            summary="Disable userland proxy in daemon.json",
            daemon_json='{\n  "userland-proxy": false\n}',
            docs_url="https://docs.docker.com/engine/network/packet-filtering-firewalls/",
        ),
    ),
    ComplianceCheck(
        id="VF-D-003",
        title="No-new-privileges default enabled",
        description="By default, containers should not be able to gain additional privileges. "
        "This prevents privilege escalation attacks via setuid/setgid binaries.",
        category="Daemon Configuration",
        severity=Severity.HIGH,
        check_type="daemon",
        remediation=Remediation(
            summary="Enable no-new-privileges as default in daemon.json",
            daemon_json='{\n  "no-new-privileges": true\n}',
            docs_url="https://docs.docker.com/engine/security/#linux-kernel-capabilities",
        ),
    ),
    ComplianceCheck(
        id="VF-D-004",
        title="Live restore enabled",
        description="Live restore keeps containers running when the Docker daemon is stopped, "
        "reducing downtime during daemon upgrades.",
        category="Daemon Configuration",
        severity=Severity.LOW,
        check_type="daemon",
        remediation=Remediation(
            summary="Enable live restore in daemon.json",
            daemon_json='{\n  "live-restore": true\n}',
            docs_url="https://docs.docker.com/engine/containers/live-restore/",
        ),
    ),
    ComplianceCheck(
        id="VF-D-005",
        title="Log rotation configured",
        description="Container logs should have size limits and rotation configured to prevent "
        "disk exhaustion from runaway logging.",
        category="Daemon Configuration",
        severity=Severity.MEDIUM,
        check_type="daemon",
        remediation=Remediation(
            summary="Configure log rotation in daemon.json",
            daemon_json='{\n  "log-driver": "json-file",\n  "log-opts": {\n    "max-size": "10m",\n    "max-file": "3"\n  }\n}',
            docs_url="https://docs.docker.com/engine/logging/configure/",
        ),
    ),
    ComplianceCheck(
        id="VF-D-006",
        title="Custom DNS configured",
        description="Custom DNS servers are configured for container name resolution. "
        "This is informational - verify DNS servers are trusted.",
        category="Daemon Configuration",
        severity=Severity.INFO,
        check_type="daemon",
        enabled_default=False,
        remediation=Remediation(
            summary="Configure DNS servers in daemon.json if needed",
            daemon_json='{\n  "dns": ["10.10.1.11", "1.1.1.1"]\n}',
            docs_url="https://docs.docker.com/engine/daemon/",
        ),
    ),
]


# =============================================================================
# CONTAINER RUNTIME CHECKS (VF-C-*)
# =============================================================================

CONTAINER_CHECKS: list[ComplianceCheck] = [
    ComplianceCheck(
        id="VF-C-001",
        title="Memory limit configured",
        description="Containers should have memory limits to prevent resource exhaustion "
        "and ensure fair resource allocation across containers.",
        category="Container Runtime",
        severity=Severity.MEDIUM,
        check_type="container",
        remediation=Remediation(
            summary="Add memory limit to container configuration",
            compose="services:\n  myservice:\n    mem_limit: 512m\n    memswap_limit: 512m",
            docker_run="docker run --memory=512m --memory-swap=512m IMAGE",
            docs_url="https://docs.docker.com/engine/containers/resource_constraints/#memory",
        ),
    ),
    ComplianceCheck(
        id="VF-C-002",
        title="CPU shares configured",
        description="CPU shares define relative CPU priority. This is informational - "
        "default shares (1024) are usually appropriate.",
        category="Container Runtime",
        severity=Severity.INFO,
        check_type="container",
        enabled_default=False,
        remediation=Remediation(
            summary="Set CPU shares for relative priority",
            compose="services:\n  myservice:\n    cpu_shares: 512  # Half of default 1024",
            docker_run="docker run --cpu-shares=512 IMAGE",
            docs_url="https://docs.docker.com/engine/containers/resource_constraints/#cpu",
        ),
    ),
    ComplianceCheck(
        id="VF-C-003",
        title="No-new-privileges set",
        description="Container should not be able to gain additional privileges via setuid/setgid "
        "binaries. This prevents privilege escalation attacks.",
        category="Container Runtime",
        severity=Severity.HIGH,
        check_type="container",
        remediation=Remediation(
            summary="Enable no-new-privileges security option",
            compose="services:\n  myservice:\n    security_opt:\n      - no-new-privileges:true",
            docker_run="docker run --security-opt=no-new-privileges:true IMAGE",
            docs_url="https://docs.docker.com/engine/security/#linux-kernel-capabilities",
        ),
    ),
    ComplianceCheck(
        id="VF-C-004",
        title="Capabilities dropped",
        description="Linux capabilities should be dropped to the minimum required. "
        "Containers should not run with all capabilities.",
        category="Container Runtime",
        severity=Severity.MEDIUM,
        check_type="container",
        remediation=Remediation(
            summary="Drop all capabilities and add only what's needed",
            compose="services:\n  myservice:\n    cap_drop:\n      - ALL\n    cap_add:\n      - NET_BIND_SERVICE  # Only if needed",
            docker_run="docker run --cap-drop=ALL --cap-add=NET_BIND_SERVICE IMAGE",
            docs_url="https://docs.docker.com/engine/security/#linux-kernel-capabilities",
        ),
    ),
    ComplianceCheck(
        id="VF-C-005",
        title="Health check configured",
        description="Containers should have health checks defined to allow Docker and orchestrators "
        "to monitor container health and restart unhealthy containers.",
        category="Container Runtime",
        severity=Severity.LOW,
        check_type="container",
        remediation=Remediation(
            summary="Add healthcheck to container configuration",
            compose='services:\n  myservice:\n    healthcheck:\n      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]\n      interval: 30s\n      timeout: 10s\n      retries: 3\n      start_period: 40s',
            docker_run='docker run --health-cmd="curl -f http://localhost:8080/health" --health-interval=30s IMAGE',
            docs_url="https://docs.docker.com/reference/dockerfile/#healthcheck",
        ),
    ),
    ComplianceCheck(
        id="VF-C-006",
        title="Restart policy limited",
        description="Restart policy should be limited to prevent infinite restart loops. "
        "Use 'on-failure' with a max retry count instead of 'always'.",
        category="Container Runtime",
        severity=Severity.LOW,
        check_type="container",
        remediation=Remediation(
            summary="Use on-failure restart policy with retry limit",
            compose="services:\n  myservice:\n    restart: on-failure:5",
            docker_run="docker run --restart=on-failure:5 IMAGE",
            docs_url="https://docs.docker.com/engine/containers/start-containers-automatically/",
        ),
    ),
    ComplianceCheck(
        id="VF-C-007",
        title="Read-only root filesystem",
        description="Container root filesystem should be read-only when possible. "
        "This is informational as many applications require write access.",
        category="Container Runtime",
        severity=Severity.INFO,
        check_type="container",
        enabled_default=False,
        remediation=Remediation(
            summary="Mount root filesystem as read-only",
            compose="services:\n  myservice:\n    read_only: true\n    tmpfs:\n      - /tmp\n      - /var/run",
            docker_run="docker run --read-only --tmpfs /tmp --tmpfs /var/run IMAGE",
            docs_url="https://docs.docker.com/engine/security/#using-read-only-containers",
        ),
    ),
    ComplianceCheck(
        id="VF-C-008",
        title="Not running as privileged",
        description="Containers should never run in privileged mode as this gives full access "
        "to the host system, defeating container isolation.",
        category="Container Runtime",
        severity=Severity.HIGH,
        check_type="container",
        remediation=Remediation(
            summary="Remove privileged flag - use specific capabilities instead",
            compose="services:\n  myservice:\n    privileged: false  # Never use privileged: true\n    cap_add:\n      - SYS_PTRACE  # Add specific capabilities if needed",
            docker_run="docker run IMAGE  # Don't use --privileged",
            docs_url="https://docs.docker.com/engine/containers/run/#runtime-privilege-and-linux-capabilities",
        ),
    ),
]


# =============================================================================
# IMAGE SECURITY CHECKS (VF-I-*)
# =============================================================================

IMAGE_CHECKS: list[ComplianceCheck] = [
    ComplianceCheck(
        id="VF-I-001",
        title="Non-root user configured",
        description="Container images should define a non-root user. Running as root inside a container "
        "increases the risk of container escape vulnerabilities.",
        category="Image Security",
        severity=Severity.MEDIUM,
        check_type="image",
        remediation=Remediation(
            summary="Add USER instruction to Dockerfile",
            dockerfile="# Create non-root user\nRUN useradd --uid 1000 --user-group --system --create-home appuser\nUSER appuser",
            docs_url="https://docs.docker.com/reference/dockerfile/#user",
        ),
    ),
    ComplianceCheck(
        id="VF-I-002",
        title="HEALTHCHECK instruction present",
        description="Container images should include a HEALTHCHECK instruction to define "
        "how to verify the container is still working.",
        category="Image Security",
        severity=Severity.LOW,
        check_type="image",
        remediation=Remediation(
            summary="Add HEALTHCHECK instruction to Dockerfile",
            dockerfile='HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \\\n    CMD curl -f http://localhost:8080/health || exit 1',
            docs_url="https://docs.docker.com/reference/dockerfile/#healthcheck",
        ),
    ),
    ComplianceCheck(
        id="VF-I-003",
        title="No secrets in environment variables",
        description="Container environment variables should not contain secrets, passwords, or API keys. "
        "These are visible in docker inspect and process listings.",
        category="Image Security",
        severity=Severity.HIGH,
        check_type="image",
        remediation=Remediation(
            summary="Use Docker secrets or mounted files instead of environment variables",
            compose="services:\n  myservice:\n    secrets:\n      - db_password\n    environment:\n      - DB_PASSWORD_FILE=/run/secrets/db_password\n\nsecrets:\n  db_password:\n    file: ./secrets/db_password.txt",
            docs_url="https://docs.docker.com/compose/how-tos/use-secrets/",
        ),
    ),
    ComplianceCheck(
        id="VF-I-004",
        title="Image not using :latest tag",
        description="Images should use specific version tags instead of :latest for reproducibility "
        "and to avoid unexpected updates.",
        category="Image Security",
        severity=Severity.INFO,
        check_type="image",
        enabled_default=False,
        remediation=Remediation(
            summary="Use specific version tags for images",
            compose="services:\n  myservice:\n    image: nginx:1.25.3-alpine  # Instead of nginx:latest",
            dockerfile="FROM python:3.12-slim  # Instead of python:latest",
            docs_url="https://docs.docker.com/reference/dockerfile/#from",
        ),
    ),
]


# =============================================================================
# HOST CONFIGURATION CHECKS (VF-H-*)
# =============================================================================

HOST_CHECKS: list[ComplianceCheck] = [
    ComplianceCheck(
        id="VF-H-001",
        title="Docker audit rules configured",
        description="Audit rules should be configured to track Docker daemon activities "
        "for security monitoring and forensics.",
        category="Host Configuration",
        severity=Severity.MEDIUM,
        check_type="host",
        remediation=Remediation(
            summary="Create audit rules for Docker",
            host_command="""sudo tee /etc/audit/rules.d/docker.rules << 'EOF'
-w /usr/bin/docker -k docker
-w /var/lib/docker -k docker
-w /etc/docker -k docker
-w /lib/systemd/system/docker.service -k docker
-w /lib/systemd/system/docker.socket -k docker
-w /etc/docker/daemon.json -k docker
EOF
sudo systemctl restart auditd""",
            docs_url="https://docs.docker.com/engine/security/audit/",
        ),
    ),
    ComplianceCheck(
        id="VF-H-002",
        title="Docker socket permissions restricted",
        description="The Docker socket should have restricted permissions. "
        "Only trusted users should have access to avoid privilege escalation.",
        category="Host Configuration",
        severity=Severity.MEDIUM,
        check_type="host",
        remediation=Remediation(
            summary="Verify Docker socket permissions (should be srw-rw---- owned by root:docker)",
            host_command="ls -la /var/run/docker.sock\n# Expected: srw-rw---- 1 root docker\n# If too permissive: sudo chmod 660 /var/run/docker.sock",
            docs_url="https://docs.docker.com/engine/security/protect-access/",
        ),
    ),
]


# =============================================================================
# COMBINED CHECK REGISTRY
# =============================================================================

ALL_CHECKS: dict[str, ComplianceCheck] = {
    check.id: check
    for check in DAEMON_CHECKS + CONTAINER_CHECKS + IMAGE_CHECKS + HOST_CHECKS
}

CHECKS_BY_TYPE: dict[CheckType, list[ComplianceCheck]] = {
    "daemon": DAEMON_CHECKS,
    "container": CONTAINER_CHECKS,
    "image": IMAGE_CHECKS,
    "host": HOST_CHECKS,
}

# Default enabled check IDs
DEFAULT_ENABLED_CHECKS: set[str] = {
    check.id for check in ALL_CHECKS.values() if check.enabled_default
}


def get_check(check_id: str) -> ComplianceCheck | None:
    """Get a check by ID."""
    return ALL_CHECKS.get(check_id)


def get_checks_by_category(category: Category) -> list[ComplianceCheck]:
    """Get all checks in a category."""
    return [check for check in ALL_CHECKS.values() if check.category == category]


def get_enabled_checks(enabled_ids: set[str] | None = None) -> list[ComplianceCheck]:
    """Get all enabled checks based on provided IDs or defaults."""
    ids = enabled_ids if enabled_ids is not None else DEFAULT_ENABLED_CHECKS
    return [check for check in ALL_CHECKS.values() if check.id in ids]
