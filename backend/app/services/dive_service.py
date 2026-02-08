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

        # TODO: Implement timeout functionality for Dive analysis
        # Currently timeout parameter is accepted but not enforced
        _ = timeout  # Acknowledge parameter to suppress unused warning

        try:
            dive_container = self.docker_service.client.containers.get(settings.dive_container_name)
        except NotFound:
            raise DiveError(
                f"Dive container '{settings.dive_container_name}' not found. "
                "Please ensure the Dive container is running."
            )
        except DockerException as e:
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

                exit_code, output = await asyncio.to_thread(
                    dive_container.exec_run,
                    cmd,
                    demux=False,
                )
                duration = (get_now() - start_time).total_seconds()

                if exit_code != 0:
                    error_msg = output.decode("utf-8")[:500] if output else "Unknown error"
                    raise DiveError(f"Dive analysis failed (exit {exit_code}): {error_msg}")

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
