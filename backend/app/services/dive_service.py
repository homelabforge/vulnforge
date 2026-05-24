"""Dive service for Docker image efficiency analysis."""

import asyncio
import io
import json
import logging
import tarfile
from typing import Any

from docker.errors import DockerException, NotFound

from app.config import settings
from app.services.docker_client import DockerService
from app.utils.timezone import get_now

logger = logging.getLogger(__name__)


class DiveError(Exception):
    """Custom exception for Dive analysis failures."""

    pass


class DiveService:
    """Service for Docker image efficiency analysis using Dive."""

    def __init__(self, docker_service: DockerService):
        """
        Initialize Dive service.

        Args:
            docker_service: Docker service instance
        """
        self.docker_service = docker_service
        self._exec_lock = asyncio.Lock()

    async def analyze_image(self, image: str, timeout: int | None = None) -> dict[str, Any]:
        """
        Analyze image with Dive for efficiency metrics.

        Args:
            image: Image to analyze (e.g., 'nginx:latest')
            timeout: Analysis timeout in seconds (default from settings)

        Returns:
            {
                "efficiency_score": 0.986,  # 0.0-1.0
                "inefficient_bytes": 3739971,
                "image_size_bytes": 151816288,
                "layer_count": 7,
                "analysis_duration": 5.2
            }

        Raises:
            DiveError: If analysis fails
        """
        if timeout is None:
            timeout = settings.dive_timeout

        try:
            dive_container = self.docker_service.client.containers.get(settings.dive_container_name)
        except NotFound:
            raise DiveError(
                f"Dive container '{settings.dive_container_name}' not found. "
                "Please ensure the Dive container is running."
            )
        except DockerException as e:
            raise DiveError(f"Failed to connect to Dive container: {e}")
        except Exception as e:
            # requests.exceptions.ReadTimeout and other network errors are not
            # DockerException subclasses; wrap them so _run_dive_analysis keeps
            # the scan non-fatal.
            raise DiveError(f"Failed to connect to Dive container: {e}")

        logger.info(f"Analyzing image efficiency: {image}")
        start_time = get_now()

        # Generate safe filename for output
        safe_filename = image.replace(":", "_").replace("/", "_")
        output_file = f"/output/{safe_filename}.json"

        # Execute: dive <image> --ci -j /output/result.json
        cmd = ["dive", image, "--ci", "-j", output_file]

        try:
            async with self._exec_lock:
                # Ensure no stale output remains from prior runs
                await asyncio.to_thread(
                    dive_container.exec_run,
                    ["rm", "-f", output_file],
                    demux=False,
                )

                # Start dive detached so we can bound wall time. exec_run blocks
                # in a thread until completion; asyncio.wait_for would only free
                # the awaiter, leaving the dive process running and holding the
                # socket-proxy connection. Detached exec + poll + killall lets us
                # actually stop a runaway analysis.
                exit_code = await self._run_dive_exec(dive_container, cmd, timeout, image)
                duration = (get_now() - start_time).total_seconds()

                if exit_code != 0:
                    raise DiveError(f"Dive analysis failed (exit {exit_code}) for {image}")

                # Read JSON output from container
                try:
                    tar_stream, _ = await asyncio.to_thread(
                        dive_container.get_archive,
                        output_file,
                    )
                    archive_bytes = b"".join(tar_stream)
                    tar = tarfile.open(fileobj=io.BytesIO(archive_bytes))
                    member_file = tar.extractfile(tar.getmembers()[0])
                    if member_file is None:
                        raise DiveError("Failed to extract Dive JSON output from archive")
                    json_content = member_file.read()
                    dive_data = json.loads(json_content)
                finally:
                    await asyncio.to_thread(
                        dive_container.exec_run,
                        ["rm", "-f", output_file],
                        demux=False,
                    )
        except DiveError:
            # Re-raise DiveError as-is
            raise
        except json.JSONDecodeError as e:
            raise DiveError(f"Failed to parse Dive JSON output: {e}")
        except DockerException as e:
            raise DiveError(f"Docker error during Dive analysis: {e}")
        except Exception as e:
            raise DiveError(f"Unexpected error during Dive analysis: {e}")

        # Parse image metrics
        image_data = dive_data.get("image", {})
        layer_data = dive_data.get("layer", [])

        efficiency_score = image_data.get("efficiencyScore", 0.0)
        inefficient_bytes = image_data.get("inefficientBytes", 0)
        image_size_bytes = image_data.get("sizeBytes", 0)
        layer_count = len(layer_data)

        result = {
            "efficiency_score": efficiency_score,
            "inefficient_bytes": inefficient_bytes,
            "image_size_bytes": image_size_bytes,
            "layer_count": layer_count,
            "analysis_duration": duration,
        }

        logger.info(
            f"Dive analysis complete: {efficiency_score:.2%} efficient, "
            f"{layer_count} layers, {inefficient_bytes:,} bytes wasted, {duration:.1f}s"
        )

        return result

    async def _run_dive_exec(
        self,
        dive_container: Any,
        cmd: list[str],
        timeout: int,
        image: str,
    ) -> int:
        """Run dive detached inside the dive container with a wall-clock timeout.

        Returns the exec exit code. Raises DiveError on timeout after attempting
        to kill the runaway dive process (SIGTERM, then SIGKILL after a grace
        period). Caller must hold ``self._exec_lock`` — the killall is safe only
        because that lock guarantees a single in-flight dive run.
        """
        api = self.docker_service.client.api
        create = await asyncio.to_thread(api.exec_create, dive_container.id, cmd)
        exec_id = create["Id"]
        await asyncio.to_thread(api.exec_start, exec_id, detach=True)

        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        poll_interval = 0.5

        while True:
            inspect = await asyncio.to_thread(api.exec_inspect, exec_id)
            if not inspect.get("Running"):
                exit_code = inspect.get("ExitCode")
                return exit_code if exit_code is not None else -1
            if loop.time() >= deadline:
                await self._kill_dive_process(dive_container)
                raise DiveError(f"Dive analysis timed out after {timeout}s for {image}")
            await asyncio.sleep(poll_interval)

    async def _kill_dive_process(self, dive_container: Any) -> None:
        """SIGTERM the dive process, escalate to SIGKILL if it doesn't exit.

        Best-effort. Errors are logged but not raised — the caller is already
        on the timeout path and will surface its own DiveError.
        """
        try:
            await asyncio.to_thread(dive_container.exec_run, ["killall", "dive"], demux=False)
            await asyncio.sleep(2)
            check = await asyncio.to_thread(
                dive_container.exec_run, ["pgrep", "-x", "dive"], demux=False
            )
            # busybox pgrep: exit 0 = match found (still running)
            still_running = isinstance(check, tuple) and check[0] == 0
            if still_running:
                await asyncio.to_thread(
                    dive_container.exec_run,
                    ["killall", "-9", "dive"],
                    demux=False,
                )
        except Exception:
            logger.warning("Failed to kill stuck dive process", exc_info=True)
