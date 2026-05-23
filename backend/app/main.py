"""VulnForge FastAPI application.

Architecture Contract: Single-Worker, Process-Local
====================================================
VulnForge MUST run as a single Granian worker (--workers 1). Multiple
subsystems rely on in-process state that is not shared across workers:

- ScanQueue singleton (scan_queue.py) — priority queue, active scan tracking
- Compliance module globals (compliance.py) — task state for running scans
- SettingsManager TTL cache (settings_manager.py) — avoids DB round-trips
- app_settings.timezone mutation (settings.py / timezone.py) — in-process hot-reload

Scaling to multiple workers would cause: duplicate scans, stale caches,
split-brain queue state, and timezone reads returning stale values.

This is intentional — VulnForge scans a homelab, not a fleet.
"""

import json
import logging
import os
import re
from contextlib import asynccontextmanager
from importlib.metadata import version as pkg_version
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from sqlalchemy import select

from app.config import settings as app_settings
from app.database import db_session, init_db
from app.middleware.auth import AuthenticationMiddleware
from app.models import Container
from app.routes import (
    activity,
    api_keys,
    compliance,
    containers,
    false_positive_patterns,
    image_compliance,
    maintenance,
    notifications,
    scans,
    secrets,
    system,
    user_auth,
    vulnerabilities,
    widget,
)
from app.routes import (
    settings as settings_api,
)
from app.services.bootstrap import consume_bootstrap_token, ensure_bootstrap_token
from app.services.docker_client import DockerService
from app.services.enhanced_notifier import get_enhanced_notifier
from app.services.scan_queue import get_scan_queue
from app.services.scheduler import ScanScheduler
from app.services.settings_manager import SettingsManager
from app.services.trivy_scanner import TrivyScanner
from app.utils.log_redaction import sanitize_for_log


def _configure_logging() -> None:
    """Configure root logging.

    When VULNFORGE_LOG_PRETTY is truthy, use Rich with a layout that matches
    the tidewatch / myfinances pino-pretty look: time-only prefix (Docker adds
    the date in its log driver), colored level, no logger-name column, no
    wrapping. Otherwise fall back to the plain machine-friendly format
    suitable for log aggregators.
    """
    level = app_settings.log_level
    pretty = os.getenv("VULNFORGE_LOG_PRETTY", "false").lower() in ("true", "1", "yes")

    handlers: list[logging.Handler]
    fmt: str
    if pretty:
        try:
            from rich.console import Console
            from rich.logging import RichHandler

            # Force a wide console so long log lines don't wrap to multiple
            # rows. Docker's log capture reports the terminal width as 80
            # which makes Rich fold messages aggressively.
            console = Console(
                width=240,
                force_terminal=True,
                no_color=False,
                highlight=False,
            )
            handlers = [
                RichHandler(
                    console=console,
                    rich_tracebacks=True,
                    show_path=False,
                    omit_repeated_times=False,
                    markup=False,
                    log_time_format="[%X]",
                )
            ]
            # Rich already shows time + level columns; we deliberately drop
            # the logger name so the output mirrors myfinances' compact
            # `[HH:MM:SS] LEVEL: message` shape.
            fmt = "%(message)s"
        except ImportError:
            handlers = [logging.StreamHandler()]
            fmt = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    else:
        handlers = [logging.StreamHandler()]
        fmt = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

    logging.basicConfig(level=level, format=fmt, handlers=handlers, force=True)


_configure_logging()
logger = logging.getLogger(__name__)


# Match a Granian access log line and capture the request path and status code.
# Granian's default access format is similar to the Apache combined format:
#   <client> [<date>] "<method> <path>[?query] HTTP/x" <status> <bytes>
# Previous substring match was too loose ("/health" matched "/health-status"
# too) and never inspected the status code, so failing healthchecks were also
# silently dropped. We now require:
#   - exact path match (anchored before ? or whitespace)
#   - status in the canonical position after the closing quote
_ACCESS_LOG_PATTERN = re.compile(
    r'"(?:GET|HEAD|POST|PUT|DELETE|PATCH|OPTIONS)\s+'
    r"(?P<path>[^\s?]+)"
    r'(?:\?[^\s"]*)?\s+[^"]+"\s+'
    r"(?P<status>\d{3})"
)


class HealthCheckLogFilter(logging.Filter):
    """Suppress successful health-check access log lines.

    Docker's healthcheck hits /health every few seconds; logging each line
    buries everything else. Failures (status >= 400) still pass through so a
    flapping liveness check is visible.
    """

    def __init__(self, paths: tuple[str, ...] = ("/health", "/healthz")) -> None:
        super().__init__()
        self.paths = paths

    def filter(self, record: logging.LogRecord) -> bool:
        match = _ACCESS_LOG_PATTERN.search(record.getMessage())
        if not match:
            return True
        if match.group("path") not in self.paths:
            return True
        try:
            status = int(match.group("status"))
        except ValueError:
            return True
        return status >= 400


logging.getLogger("granian.access").addFilter(HealthCheckLogFilter())

# Global instances
scheduler = None
scan_queue = None


async def discover_containers_startup():
    """Discover containers on startup."""
    try:
        logger.info("Auto-discovering containers on startup...")
        docker_service = DockerService()

        async with db_session() as db:
            docker_containers = docker_service.list_containers(all_containers=True)
            discovered = []

            for dc in docker_containers:
                # Check if container exists
                result = await db.execute(select(Container).where(Container.name == dc["name"]))
                container = result.scalar_one_or_none()

                if container:
                    # Update existing
                    container.is_running = dc["is_running"]
                    container.image = dc["image"]
                    container.image_tag = dc["image_tag"]
                    container.image_id = dc["image_id"]
                else:
                    # Create new
                    container = Container(
                        name=dc["name"],
                        image=dc["image"],
                        image_tag=dc["image_tag"],
                        image_id=dc["image_id"],
                        is_running=dc["is_running"],
                    )
                    db.add(container)
                    discovered.append(dc["name"])

            await db.commit()
            logger.info(
                f"Auto-discovery complete: {len(docker_containers)} total, {len(discovered)} new containers"
            )

        docker_service.close()
    except Exception as e:
        logger.error(f"Error during startup container discovery: {e}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan events."""
    global scheduler, scan_queue

    # Startup
    logger.info("Starting VulnForge...")
    await init_db()
    logger.info("Database initialized")

    # Initialize default settings
    async with db_session() as db:
        settings_manager = SettingsManager(db)
        await settings_manager.initialize_defaults()
        logger.info("Default settings initialized")

        # Get parallel_scans setting for queue workers
        parallel_scans = await settings_manager.get_int("parallel_scans", default=3) or 3

    # Bootstrap token for first-run setup protection
    async with db_session() as db:
        sm = SettingsManager(db)
        admin_username = await sm.get("user_auth_admin_username")
        if admin_username and admin_username.strip():
            # Admin exists — clean up any leftover bootstrap token
            consume_bootstrap_token()
        else:
            # No admin — ensure a bootstrap token exists
            token = ensure_bootstrap_token()
            if os.environ.get("VULNFORGE_BOOTSTRAP_TOKEN"):
                logger.info("Bootstrap token provided via environment")
            else:
                logger.info(
                    "\n"
                    "========================================================\n"
                    "  FIRST-RUN SETUP TOKEN: %s\n"
                    "  Enter this token at /setup to create the admin account.\n"
                    "========================================================",
                    token,
                )

    # Auto-discover containers on startup
    await discover_containers_startup()

    # Initialize default notification rules
    enhanced_notifier = get_enhanced_notifier()
    await enhanced_notifier.create_default_rules()
    logger.info("Notification rules initialized")

    # Create shared TrivyScanner instance for all workers.
    trivy_scanner = TrivyScanner()
    logger.info("Shared TrivyScanner instance created")

    # Start scan queue with shared scanner
    scan_queue = get_scan_queue()
    await scan_queue.start(num_workers=parallel_scans, trivy_scanner=trivy_scanner)
    logger.info(f"Scan queue started with {parallel_scans} workers")

    # Start scheduler
    scheduler = ScanScheduler()

    # Get scan and compliance settings from database
    async with db_session() as db:
        settings_manager = SettingsManager(db)
        scan_schedule = await settings_manager.get(
            "scan_schedule", default=app_settings.scan_schedule
        )
        compliance_enabled = await settings_manager.get_bool(
            "compliance_scan_enabled", default=True
        )
        compliance_schedule = await settings_manager.get("compliance_scan_schedule", "0 3 * * 0")
        kev_enabled = await settings_manager.get_bool("kev_catalog_enabled", default=True)

        # Start with scan scheduling
        scheduler.start(
            scan_schedule=scan_schedule,
            compliance_schedule=compliance_schedule if compliance_enabled else None,
            kev_enabled=kev_enabled if kev_enabled is not None else True,
        )
        logger.info(f"Scheduler started with vulnerability scan schedule: {scan_schedule}")

        if compliance_enabled:
            logger.info(f"Compliance scanning enabled with schedule: {compliance_schedule}")
        else:
            logger.info("Compliance scanning disabled")

    yield

    # Shutdown
    logger.info("Shutting down VulnForge...")

    # Stop scan queue
    if scan_queue:
        await scan_queue.stop()
        logger.info("Scan queue stopped")

    # Stop scheduler
    if scheduler:
        scheduler.stop()
        logger.info("Scheduler stopped")


# Read version from installed package metadata (works in Docker / site-packages)
try:
    _APP_VERSION = pkg_version("vulnforge")
except Exception:
    _APP_VERSION = "0.0.0"

# Create FastAPI app
app = FastAPI(
    title="VulnForge",
    description="Docker vulnerability scanner and remediation dashboard powered by Trivy",
    version=_APP_VERSION,
    lifespan=lifespan,
)

# Rate limiter setup — shared instance from app.rate_limit
from app.rate_limit import limiter  # noqa: E402

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)  # type: ignore[arg-type]

# Status codes that indicate the client can safely retry
_RETRYABLE_STATUS_CODES = frozenset({502, 503, 504})

# Error type classification by status code range
_ERROR_TYPE_MAP: dict[int, str] = {
    400: "validation_error",
    401: "authentication_error",
    403: "authorization_error",
    404: "not_found",
    409: "conflict",
    422: "validation_error",
    429: "rate_limited",
}


@app.exception_handler(HTTPException)
async def _http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    """Standardize all HTTP error responses to match frontend ApiErrorResponse interface."""
    status = exc.status_code
    error_type = _ERROR_TYPE_MAP.get(status, "server_error" if status >= 500 else "client_error")

    return JSONResponse(
        status_code=status,
        content={
            "detail": exc.detail or "An error occurred",
            "status_code": status,
            "error_type": error_type,
            "suggestions": [],
            "is_retryable": status in _RETRYABLE_STATUS_CODES,
        },
    )


# Authentication middleware (must be before CORS)
app.add_middleware(AuthenticationMiddleware)

# CORS middleware - load allowed origins from settings
# Default origins include production domain and localhost for development
cors_origins_default = ["https://vulnforge.starett.net", "http://localhost:5173"]
try:
    # Try to load from settings at startup (will use defaults if not found)
    cors_origins = (
        json.loads(app_settings.cors_origins)
        if hasattr(app_settings, "cors_origins")
        else cors_origins_default
    )
except json.JSONDecodeError, AttributeError:
    cors_origins = cors_origins_default

logger.info(f"CORS allowed origins: {cors_origins}")

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
    allow_headers=["*"],
    max_age=600,  # Cache preflight requests for 10 minutes
)


# Health endpoint (must be before static files)
@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "service": "VulnForge"}


# Include routers
app.include_router(activity.router, prefix="/api/v1/activity", tags=["Activity"])
app.include_router(api_keys.router)  # Prefix already defined in router
app.include_router(user_auth.router, prefix="/api/v1", tags=["User Authentication"])
app.include_router(compliance.router, prefix="/api/v1/compliance", tags=["Compliance"])
app.include_router(
    image_compliance.router, prefix="/api/v1/image-compliance", tags=["Image Compliance"]
)
app.include_router(containers.router, prefix="/api/v1/containers", tags=["Containers"])
app.include_router(scans.router, prefix="/api/v1/scans", tags=["Scans"])
app.include_router(
    vulnerabilities.router, prefix="/api/v1/vulnerabilities", tags=["Vulnerabilities"]
)
app.include_router(secrets.router, prefix="/api/v1", tags=["Secrets"])
app.include_router(
    false_positive_patterns.router,
    prefix="/api/v1/false-positive-patterns",
    tags=["False Positive Patterns"],
)
app.include_router(widget.router, prefix="/api/v1/widget", tags=["Widget"])
app.include_router(settings_api.router, prefix="/api/v1/settings", tags=["Settings"])
app.include_router(system.router, prefix="/api/v1/system", tags=["System"])
app.include_router(maintenance.router, prefix="/api/v1/maintenance", tags=["Maintenance"])
app.include_router(notifications.router, prefix="/api/v1/notifications", tags=["Notifications"])

# Mount static files for frontend (must be last - catches all remaining routes)
static_dir = Path("/app/static")
if static_dir.exists():
    # Vite emits content-hashed filenames under /assets (e.g. main-abc123.js),
    # which are immutable for the life of the build. `public, max-age=31536000,
    # immutable` stops browsers and Cloudflare from revalidating these on every
    # navigation — the source of most post-deploy reload latency.
    class ImmutableStaticFiles(StaticFiles):
        async def get_response(self, path, scope):
            response = await super().get_response(path, scope)
            if response.status_code == 200:
                response.headers["Cache-Control"] = "public, max-age=31536000, immutable"
            return response

    app.mount(
        "/assets",
        ImmutableStaticFiles(directory=str(static_dir / "assets")),
        name="assets",
    )

    from fastapi.responses import FileResponse

    # The SW script must not be long-cached (otherwise we can't ship updates);
    # browsers also limit SW script caching to a max of 24h. The catch-all
    # below would otherwise serve it without explicit cache headers.
    @app.get("/sw.js", include_in_schema=False)
    async def service_worker():
        return FileResponse(
            static_dir / "sw.js",
            media_type="application/javascript",
            headers={"Cache-Control": "no-cache"},
        )

    @app.get("/offline.html", include_in_schema=False)
    async def offline_page():
        return FileResponse(static_dir / "offline.html", media_type="text/html")

    @app.get("/{full_path:path}")
    async def serve_spa(full_path: str, request: Request):
        """Serve index.html for all non-API routes (SPA fallback)."""
        # Don't intercept API routes - let them 404 naturally if not found
        if full_path.startswith("api/"):
            # This should never happen if routes are properly defined
            # Return 404 to signal the API endpoint doesn't exist
            from fastapi import HTTPException

            raise HTTPException(status_code=404, detail=f"API endpoint not found: /{full_path}")

        # Normalize and validate path to prevent directory traversal
        try:
            # Resolve to absolute path and check it's within static_dir
            requested_path = (static_dir / full_path).resolve()
            static_dir_resolved = static_dir.resolve()

            # Security check: Ensure the resolved path is within static_dir
            if not str(requested_path).startswith(str(static_dir_resolved)):
                logger.warning("Path traversal attempt blocked: %s", sanitize_for_log(full_path))
                return FileResponse(static_dir / "index.html")

            # Re-derive from validated relative path to break taint tracking.
            # After the startswith check, compute the safe relative component
            # and reconstruct from the known-safe static_dir base.
            relative = requested_path.relative_to(static_dir_resolved)
            safe_path = (static_dir_resolved / relative).resolve()

            # If requesting a file that exists, serve it
            if safe_path.is_file():
                return FileResponse(str(safe_path))

        except (ValueError, OSError) as e:
            logger.warning(
                "Invalid path request: %s - %s", sanitize_for_log(full_path), sanitize_for_log(e)
            )

        # Otherwise, serve index.html for client-side routing
        return FileResponse(static_dir / "index.html")
