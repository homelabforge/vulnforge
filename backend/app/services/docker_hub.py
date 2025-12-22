"""Docker Hub API client for checking image versions."""

import logging
from datetime import datetime, timedelta

import httpx

from app.config import settings
from app.utils.timezone import get_now

logger = logging.getLogger(__name__)


class DockerHubClient:
    """Client for interacting with Docker Hub and GitHub Container Registry APIs."""

    def __init__(self):
        """Initialize Docker Hub client with caching."""
        self._cache: dict[str, tuple[str, datetime]] = {}
        self._cache_duration = timedelta(hours=6)  # Cache for 6 hours

    async def get_latest_tag(self, repository: str, registry: str = "docker.io") -> str | None:
        """
        Get the latest version tag for a repository from Docker Hub or GHCR.

        Args:
            repository: Repository name (e.g., "aquasec/trivy", "aquasecurity/trivy-db")
            registry: Registry type - "docker.io" for Docker Hub or "ghcr.io" for GitHub Container Registry

        Returns:
            Latest semantic version tag (e.g., "0.67.2") or None if not found

        Example:
            >>> client = DockerHubClient()
            >>> version = await client.get_latest_tag("aquasec/trivy")
            >>> print(version)  # "0.67.2"
            >>> db_version = await client.get_latest_tag("aquasecurity/trivy-db", registry="ghcr.io")
            >>> print(db_version)  # "2"
        """
        cache_key = f"{registry}/{repository}"

        # Check cache first
        cached = self._get_from_cache(cache_key)
        if cached:
            return cached

        try:
            if registry == "ghcr.io":
                latest_version = await self._fetch_ghcr_tags(repository)
            else:
                latest_version = await self._fetch_dockerhub_tags(repository)

            if latest_version:
                self._add_to_cache(cache_key, latest_version)
                logger.info(f"Found latest version for {registry}/{repository}: {latest_version}")
                return latest_version

            logger.warning(f"No semantic version tags found for {registry}/{repository}")
            return None

        except httpx.HTTPError as e:
            logger.error(f"HTTP error fetching tags for {registry}/{repository}: {e}")
            return None
        except Exception as e:
            logger.error(f"Error fetching latest tag for {registry}/{repository}: {e}")
            return None

    async def _fetch_dockerhub_tags(self, repository: str) -> str | None:
        """
        Fetch tags from Docker Hub API.

        Args:
            repository: Repository name (e.g., "aquasec/trivy")

        Returns:
            Latest version or None
        """
        url = f"https://hub.docker.com/v2/repositories/{repository}/tags"
        params = {
            "page_size": 100,  # Get more tags to find semantic versions
            "ordering": "last_updated",  # Sort by most recently updated
        }

        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(url, params=params)
            response.raise_for_status()

        data = response.json()
        tags = data.get("results", [])
        return self._extract_latest_version(tags)

    async def _fetch_ghcr_tags(self, repository: str) -> str | None:
        """
        Fetch tags from GitHub Container Registry API.

        GHCR uses a different API structure than Docker Hub.
        We'll use the GitHub Packages API to list versions.

        Args:
            repository: Repository name (e.g., "aquasecurity/trivy-db")

        Returns:
            Latest version or None
        """
        # Extract org and package name
        parts = repository.split("/")
        if len(parts) != 2:
            logger.error(f"Invalid GHCR repository format: {repository}")
            return None

        org, package = parts

        # GitHub Packages API endpoint
        # Note: GitHub API requires authentication even for public packages
        url = f"https://api.github.com/orgs/{org}/packages/container/{package}/versions"

        # Build headers with optional authentication
        headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}

        # Add GitHub token if available
        if settings.github_token:
            headers["Authorization"] = f"Bearer {settings.github_token}"
            logger.debug(f"Using GitHub token for GHCR API request to {org}/{package}")
        else:
            logger.warning(
                "No GitHub token configured - GHCR API may fail with 401. Set GITHUB_TOKEN environment variable."
            )

        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(url, headers=headers)

            # If org endpoint fails, try user endpoint
            if response.status_code == 404:
                url = f"https://api.github.com/users/{org}/packages/container/{package}/versions"
                response = await client.get(url, headers=headers)

            response.raise_for_status()

        data = response.json()

        # Extract tags from versions
        tags = []
        for version in data:
            if "metadata" in version and "container" in version["metadata"]:
                version_tags = version["metadata"]["container"].get("tags", [])
                for tag in version_tags:
                    tags.append({"name": tag})

        return self._extract_latest_version(tags)

    def _extract_latest_version(self, tags: list[dict]) -> str | None:
        """
        Extract the latest semantic version from a list of tags.

        Args:
            tags: List of tag objects from Docker Hub API

        Returns:
            Latest semantic version string or None
        """
        versions = []

        for tag_data in tags:
            tag_name = tag_data.get("name", "")

            # Skip non-semantic version tags
            if tag_name in ["latest", "main", "master", "dev"]:
                continue

            # Remove 'v' prefix if present (e.g., "v0.67.2" -> "0.67.2")
            if tag_name.startswith("v"):
                tag_name = tag_name[1:]

            # Check if it's a valid semantic version (x.y.z)
            if self._is_semantic_version(tag_name):
                versions.append(tag_name)

        if not versions:
            return None

        # Sort versions and return the latest
        # This handles versions like "0.67.2", "0.68.0", "0.102.0" correctly
        versions.sort(key=lambda v: [int(x) for x in v.split(".")], reverse=True)
        return versions[0]

    def _is_semantic_version(self, version: str) -> bool:
        """
        Check if a string is a valid semantic version (x.y.z).

        Args:
            version: Version string to check

        Returns:
            True if valid semantic version, False otherwise
        """
        parts = version.split(".")
        if len(parts) != 3:
            return False

        try:
            # All parts must be integers
            for part in parts:
                int(part)
            return True
        except ValueError:
            return False

    def _get_from_cache(self, repository: str) -> str | None:
        """
        Get a cached version if it exists and is not expired.

        Args:
            repository: Repository name

        Returns:
            Cached version or None
        """
        if repository not in self._cache:
            return None

        version, cached_at = self._cache[repository]
        age = get_now() - cached_at

        if age < self._cache_duration:
            logger.debug(f"Using cached version for {repository}: {version}")
            return version

        # Cache expired, remove it
        del self._cache[repository]
        return None

    def _add_to_cache(self, repository: str, version: str) -> None:
        """
        Add a version to the cache.

        Args:
            repository: Repository name
            version: Version string
        """
        self._cache[repository] = (version, get_now())

    def clear_cache(self) -> None:
        """Clear all cached versions."""
        self._cache.clear()
        logger.info("Docker Hub version cache cleared")

    async def get_github_release_version(self, repo: str) -> str | None:
        """
        Get the latest release version from a GitHub repository.

        Args:
            repo: Repository in format "owner/repo" (e.g., "docker/docker-bench-security")

        Returns:
            Latest release version string (e.g., "1.6.1") or None if unavailable
        """
        cache_key = f"github_release:{repo}"

        # Check cache
        if cache_key in self._cache:
            cached_version, cached_time = self._cache[cache_key]
            if get_now() - cached_time < self._cache_duration:
                logger.debug(f"Using cached GitHub release version for {repo}: {cached_version}")
                return cached_version

        try:
            # GitHub API endpoint for latest release
            url = f"https://api.github.com/repos/{repo}/releases/latest"

            # Build headers with optional authentication
            headers = {
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            }

            # Add GitHub token if available
            if settings.github_token:
                headers["Authorization"] = f"Bearer {settings.github_token}"
                logger.debug(f"Using GitHub token for release API request to {repo}")
            else:
                logger.warning(
                    "No GitHub token configured - GitHub API may be rate limited. Set GITHUB_TOKEN environment variable."
                )

            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(url, headers=headers)
                response.raise_for_status()

            data = response.json()
            tag_name = data.get("tag_name", "")

            # Remove 'v' prefix if present (e.g., "v1.6.1" -> "1.6.1")
            version = tag_name.lstrip("v")

            if version:
                # Cache the result
                self._cache[cache_key] = (version, get_now())
                logger.info(f"Found latest GitHub release for {repo}: {version}")
                return version

            return None

        except httpx.HTTPStatusError as e:
            logger.error(f"HTTP error fetching GitHub release for {repo}: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error fetching GitHub release for {repo}: {e}")
            return None


_docker_hub_client: DockerHubClient | None = None


def get_docker_hub_client() -> DockerHubClient:
    """
    Get the global Docker Hub client instance.

    Returns:
        DockerHubClient instance
    """
    global _docker_hub_client
    if _docker_hub_client is None:
        _docker_hub_client = DockerHubClient()
    return _docker_hub_client
