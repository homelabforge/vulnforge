"""Network connectivity checking utilities."""

import asyncio
import logging
from dataclasses import dataclass
from enum import Enum
from typing import Optional

logger = logging.getLogger(__name__)


class ConnectivityStatus(Enum):
    """Network connectivity status levels."""

    ONLINE = "online"  # Full internet connectivity
    DEGRADED = "degraded"  # Partial connectivity (some hosts unreachable)
    OFFLINE = "offline"  # No internet connectivity
    UNKNOWN = "unknown"  # Cannot determine status


@dataclass
class ConnectivityCheck:
    """Result of a network connectivity check."""

    status: ConnectivityStatus
    reachable_hosts: list[str]
    unreachable_hosts: list[str]
    latency_ms: Optional[float]
    error: Optional[str]

    @property
    def is_online(self) -> bool:
        """Check if system has internet connectivity."""
        return self.status == ConnectivityStatus.ONLINE

    @property
    def has_partial_connectivity(self) -> bool:
        """Check if system has partial connectivity."""
        return self.status == ConnectivityStatus.DEGRADED

    @property
    def is_offline(self) -> bool:
        """Check if system is offline."""
        return self.status == ConnectivityStatus.OFFLINE


class NetworkConnectivityChecker:
    """
    Check network connectivity to essential services.

    Tests connectivity to vulnerability database update servers
    and other critical infrastructure.
    """

    # Critical hosts for vulnerability scanning
    DEFAULT_TEST_HOSTS = [
        "ghcr.io",  # GitHub Container Registry (Trivy DB)
        "toolbox-data.anchore.io",  # Grype DB
        "github.com",  # GitHub (general connectivity)
    ]

    def __init__(self, test_hosts: Optional[list[str]] = None, timeout: float = 5.0):
        """
        Initialize network connectivity checker.

        Args:
            test_hosts: List of hosts to test (default: vulnerability DB hosts)
            timeout: Timeout for each connectivity test in seconds
        """
        self.test_hosts = test_hosts or self.DEFAULT_TEST_HOSTS
        self.timeout = timeout

    async def check_connectivity(self) -> ConnectivityCheck:
        """
        Check network connectivity to test hosts.

        Returns:
            ConnectivityCheck with status and host reachability
        """
        reachable = []
        unreachable = []
        total_latency = 0.0
        error_msg = None

        try:
            # Test each host
            for host in self.test_hosts:
                is_reachable, latency = await self._check_host(host)
                if is_reachable:
                    reachable.append(host)
                    if latency:
                        total_latency += latency
                else:
                    unreachable.append(host)

            # Determine overall status
            if len(reachable) == len(self.test_hosts):
                status = ConnectivityStatus.ONLINE
            elif len(reachable) > 0:
                status = ConnectivityStatus.DEGRADED
            elif len(unreachable) == len(self.test_hosts):
                status = ConnectivityStatus.OFFLINE
            else:
                status = ConnectivityStatus.UNKNOWN

            # Calculate average latency
            avg_latency = total_latency / len(reachable) if reachable else None

            logger.info(
                f"Network check: {status.value} - "
                f"{len(reachable)}/{len(self.test_hosts)} hosts reachable"
            )

            return ConnectivityCheck(
                status=status,
                reachable_hosts=reachable,
                unreachable_hosts=unreachable,
                latency_ms=avg_latency,
                error=error_msg,
            )

        except Exception as e:
            logger.error(f"Network connectivity check failed: {e}")
            return ConnectivityCheck(
                status=ConnectivityStatus.UNKNOWN,
                reachable_hosts=[],
                unreachable_hosts=self.test_hosts,
                latency_ms=None,
                error=str(e),
            )

    async def _check_host(self, host: str) -> tuple[bool, Optional[float]]:
        """
        Check if a specific host is reachable.

        Args:
            host: Hostname or IP to check

        Returns:
            Tuple of (is_reachable, latency_ms)
        """
        try:
            import time

            start = time.time()

            # Try to open TCP connection to port 443 (HTTPS)
            try:
                await asyncio.wait_for(
                    asyncio.open_connection(host, 443), timeout=self.timeout
                )
                latency = (time.time() - start) * 1000  # Convert to ms
                logger.debug(f"Host {host} reachable (latency: {latency:.2f}ms)")
                return True, latency
            except (asyncio.TimeoutError, OSError, ConnectionRefusedError):
                # Try port 80 (HTTP) as fallback
                try:
                    await asyncio.wait_for(
                        asyncio.open_connection(host, 80), timeout=self.timeout
                    )
                    latency = (time.time() - start) * 1000
                    logger.debug(f"Host {host} reachable on port 80 (latency: {latency:.2f}ms)")
                    return True, latency
                except (asyncio.TimeoutError, OSError, ConnectionRefusedError):
                    logger.debug(f"Host {host} unreachable")
                    return False, None

        except Exception as e:
            logger.error(f"Error checking host {host}: {e}")
            return False, None

    async def quick_check(self) -> bool:
        """
        Quick connectivity check (tests only one host).

        Returns:
            True if internet is reachable, False otherwise
        """
        if not self.test_hosts:
            return False

        # Test first host only for quick check
        is_reachable, _ = await self._check_host(self.test_hosts[0])
        return is_reachable


# Singleton instance
_connectivity_checker: Optional[NetworkConnectivityChecker] = None


def get_connectivity_checker() -> NetworkConnectivityChecker:
    """Get or create the global connectivity checker instance."""
    global _connectivity_checker
    if _connectivity_checker is None:
        _connectivity_checker = NetworkConnectivityChecker()
    return _connectivity_checker
