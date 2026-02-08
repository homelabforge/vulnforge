"""VulnForge FastAPI application."""

import json
import logging
from contextlib import asynccontextmanager
from importlib.metadata import version as pkg_version
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from sqlalchemy import select

from app.config import settings as app_settings
from app.database import db_session, init_db
from app.middleware.auth import AuthenticationMiddleware
from app.models import Container
from app.routes import (
    activity,
    api_keys,
    auth,
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
from app.services.docker_client import DockerService
from app.services.enhanced_notifier import get_enhanced_notifier
from app.services.scan_queue import get_scan_queue
from app.services.scheduler import ScanScheduler
from app.services.settings_manager import SettingsManager
from app.services.trivy_scanner import TrivyScanner

# Configure logging
logging.basicConfig(
    level=getattr(logging, app_settings.log_level),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)

logger = logging.getLogger(__name__)


# Filter to exclude health check endpoints from access logs
class EndpointFilter(logging.Filter):
    """Filter to exclude specific endpoints from Granian access logs."""

    def __init__(self, excluded_paths: list[str]) -> None:
        super().__init__()
        self.excluded_paths = excluded_paths

    def filter(self, record: logging.LogRecord) -> bool:
        """Return False if the log record is for an excluded endpoint."""
        # Granian access logs have the path in the message
        message = record.getMessage()
        return not any(path in message for path in self.excluded_paths)


# Apply filter to granian access logger to exclude health checks
logging.getLogger("granian.access").addFilter(EndpointFilter(["/health"]))

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

# Rate limiter setup
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)  # type: ignore[arg-type]

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
except (json.JSONDecodeError, AttributeError):
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
app.include_router(auth.router, prefix="/api/v1/auth", tags=["Authentication"])
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
    # Serve static assets
    app.mount("/assets", StaticFiles(directory=str(static_dir / "assets")), name="assets")

    # Catch-all route for SPA - serves index.html for all non-API routes
    from fastapi.responses import FileResponse

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
                logger.warning(f"Path traversal attempt blocked: {full_path}")
                return FileResponse(static_dir / "index.html")

            # If requesting a file that exists, serve it
            if requested_path.is_file():
                return FileResponse(requested_path)

        except (ValueError, OSError) as e:
            logger.warning(f"Invalid path request: {full_path} - {e}")

        # Otherwise, serve index.html for client-side routing
        return FileResponse(static_dir / "index.html")
