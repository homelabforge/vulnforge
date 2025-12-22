"""Docker client service for container discovery and management."""

import logging
import os
from typing import Any
from urllib.parse import urlparse

import docker
from docker.errors import DockerException

from app.config import settings

logger = logging.getLogger(__name__)


class DockerService:
    """Service for interacting with Docker API."""

    def __init__(self):
        """Initialize Docker client with connection fallbacks."""
        self.client = self._connect_with_fallbacks()

    def _connect_with_fallbacks(self) -> docker.DockerClient:
        """
        Attempt to connect to Docker using multiple hosts.

        Returns:
            Connected DockerClient

        Raises:
            DockerException: If all attempts fail
        """
        candidates: list[str] = []

        def _add_candidate(url: str | None):
            if url and url not in candidates:
                candidates.append(url)

        # 1. Environment variable takes highest priority (matches docker CLI behavior)
        #    Set via compose DOCKER_HOST environment variable
        _add_candidate(os.getenv("DOCKER_HOST"))

        # 2. Config fallback for local development without compose
        _add_candidate(settings.docker_socket_proxy)

        # 3. Docker Desktop / WSL fallback
        docker_host = os.getenv("DOCKER_HOST") or settings.docker_socket_proxy or ""
        parsed = urlparse(docker_host)
        if parsed.scheme == "tcp":
            default_port = parsed.port or 2375
            _add_candidate(f"tcp://host.docker.internal:{default_port}")

        # 4. Native Linux fallback
        _add_candidate("unix:///var/run/docker.sock")

        errors: list[str] = []
        for base_url in candidates:
            if not base_url:
                continue
            try:
                client = docker.DockerClient(base_url=base_url, timeout=60)
                client.ping()
                logger.info(f"Connected to Docker at {base_url}")
                return client
            except DockerException as exc:
                errors.append(f"{base_url}: {exc}")
                logger.warning(f"Docker connection attempt failed for {base_url}: {exc}")

        message = "Failed to connect to Docker using available hosts. Attempts: " + "; ".join(
            errors
        )
        logger.error(message)
        raise DockerException(message)

    def list_containers(self, all_containers: bool = True) -> list[dict[str, Any]]:
        """
        List all containers.

        Args:
            all_containers: Include stopped containers

        Returns:
            List of container information dictionaries
        """
        try:
            containers = self.client.containers.list(all=all_containers)
            result = []

            for container in containers:
                # Get image info
                image = container.image
                image_tags = image.tags if image.tags else [f"{image.id[:12]}"]
                image_name, image_tag = self._parse_image_tag(image_tags[0])

                result.append(
                    {
                        "id": container.id,
                        "container_id": container.id,
                        "name": container.name,
                        "image": image_name,
                        "image_tag": image_tag,
                        "image_id": image.id,
                        "image_full": image_tags[0],
                        "status": container.status,
                        "is_running": container.status == "running",
                    }
                )

            logger.info(f"Found {len(result)} containers")
            return result

        except DockerException as e:
            logger.error(f"Error listing containers: {e}")
            return []

    def get_container(self, container_name: str) -> dict[str, Any] | None:
        """
        Get information about a specific container.

        Args:
            container_name: Name of the container

        Returns:
            Container information or None if not found
        """
        try:
            container = self.client.containers.get(container_name)
            image = container.image
            image_tags = image.tags if image.tags else [f"{image.id[:12]}"]
            image_name, image_tag = self._parse_image_tag(image_tags[0])

            return {
                "id": container.id,
                "name": container.name,
                "image": image_name,
                "image_tag": image_tag,
                "image_id": image.id,
                "image_full": image_tags[0],
                "status": container.status,
                "is_running": container.status == "running",
            }
        except docker.errors.NotFound:
            logger.warning(f"Container {container_name} not found")
            return None
        except DockerException as e:
            logger.error(f"Error getting container {container_name}: {e}")
            return None

    def container_exists(self, container_name: str) -> bool:
        """
        Check if a container exists.

        Args:
            container_name: Name of the container

        Returns:
            True if container exists
        """
        try:
            self.client.containers.get(container_name)
            return True
        except docker.errors.NotFound:
            return False
        except DockerException as e:
            logger.error(f"Error checking container {container_name}: {e}")
            return False

    def get_trivy_container(self) -> Any | None:
        """
        Get the Trivy container.

        Returns:
            Trivy container object or None
        """
        try:
            return self.client.containers.get(settings.trivy_container_name)
        except docker.errors.NotFound:
            logger.error(f"Trivy container '{settings.trivy_container_name}' not found")
            return None
        except DockerException as e:
            logger.error(f"Error getting Trivy container: {e}")
            return None

    @staticmethod
    def _parse_image_tag(image_full: str) -> tuple[str, str]:
        """
        Parse image name and tag from full image string.

        Args:
            image_full: Full image string (e.g., 'nginx:latest')

        Returns:
            Tuple of (image_name, tag)
        """
        if ":" in image_full:
            parts = image_full.rsplit(":", 1)
            return parts[0], parts[1]
        return image_full, "latest"

    def close(self):
        """Close Docker client connection."""
        if hasattr(self, "client"):
            self.client.close()
            logger.info("Docker client closed")
