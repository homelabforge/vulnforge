"""Configuration settings for VulnForge."""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Application
    app_name: str = "VulnForge"
    port: int = 8787
    log_level: str = "INFO"
    timezone: str = "UTC"  # Timezone for timestamps (e.g., "America/New_York", "Europe/London")

    # Database
    database_url: str = "sqlite+aiosqlite:////data/vulnforge.db"

    # Docker (can be overridden by DOCKER_HOST or database setting)
    docker_socket_proxy: str = "unix:///var/run/docker.sock"
    trivy_container_name: str = "trivy"
    trivy_server: str | None = (
        None  # Optional: Trivy server URL for client mode (e.g., http://trivy:8080)
    )
    dive_container_name: str = "dive"

    # Scanner configuration
    compliance_enabled: bool = True  # Docker Bench for Security compliance scanner

    # Scanning
    scan_schedule: str = "0 2 * * *"  # Daily at 2 AM
    scan_timeout: int = 300  # 5 minutes per container
    dive_timeout: int = 120  # 2 minutes for Dive analysis
    parallel_scans: int = 3  # Number of containers to scan in parallel

    # Trivy retry configuration
    trivy_max_lock_retries: int = 3  # Max retries for database lock errors
    trivy_max_corruption_retries: int = 1  # Max retries for cache corruption
    trivy_lock_retry_base_wait: int = 2  # Base wait time in seconds for lock retries
    trivy_lock_retry_backoff_multiplier: int = 2  # Backoff multiplier (4s, 6s, 8s)

    # Notifications
    ntfy_url: str = "https://ntfy:443"
    ntfy_topic: str = "vulnforge"
    ntfy_enabled: bool = True
    ntfy_token: str | None = None  # Optional access token for authentication

    # Notification thresholds
    notify_on_scan_complete: bool = True
    notify_on_critical: bool = True
    notify_threshold_critical: int = 1  # Alert if X or more critical CVEs found
    notify_threshold_high: int = 10  # Alert if X or more high CVEs found

    # Data retention
    keep_scan_history_days: int = 90

    # UI preferences
    default_severity_filter: str = "all"  # all, critical, high, medium, low
    default_show_fixable_only: bool = False

    # CORS settings
    cors_origins: str = '["https://vulnforge.starett.net", "http://localhost:5173"]'

    # GitHub API (optional - for checking Trivy DB updates via GHCR)
    github_token: str | None = None  # Optional GitHub token for API access

    # Database migrations
    strict_migrations: bool = True  # Fail startup if migrations fail (False for test environments)


settings = Settings()
