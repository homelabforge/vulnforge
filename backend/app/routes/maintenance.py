"""Maintenance API endpoints."""

import json
import shutil
from datetime import datetime
from pathlib import Path

import httpx
import sqlalchemy.exc
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import get_db
from app.dependencies.auth import require_admin
from app.models import Vulnerability
from app.models.user import User
from app.services.cache_manager import get_cache
from app.services.cleanup_service import CleanupService
from app.services.kev import get_kev_service
from app.services.settings_manager import SettingsManager
from app.utils.path_normalization import normalize_path
from app.utils.timezone import get_now

router = APIRouter()


@router.post("/cleanup")
async def trigger_cleanup(db: AsyncSession = Depends(get_db), user: User = Depends(require_admin)):
    """Manually trigger cleanup of old scan history."""
    result = await CleanupService.cleanup_old_scans(db)
    return {
        "status": "completed",
        **result,
    }


@router.get("/cleanup/stats")
async def get_cleanup_stats(
    db: AsyncSession = Depends(get_db), user: User = Depends(require_admin)
):
    """Get statistics about cleanable data."""
    stats = await CleanupService.get_cleanup_stats(db)
    return stats


@router.get("/cache/stats")
async def get_cache_stats(user: User = Depends(require_admin)):
    """Get cache statistics."""
    cache = get_cache()
    return cache.get_stats()


@router.post("/cache/clear")
async def clear_cache(user: User = Depends(require_admin)):
    """Clear all cached data."""
    cache = get_cache()
    await cache.clear()
    return {"status": "cleared", "message": "All cache entries cleared"}


@router.post("/backup")
async def create_backup(user: User = Depends(require_admin)):
    """
    Create a manual backup of the database.

    Returns:
        Backup file information including filename and path
    """
    try:
        # Get database path from settings
        db_url = settings.database_url
        if not db_url.startswith("sqlite"):
            raise HTTPException(
                status_code=400, detail="Backups are only supported for SQLite databases"
            )

        # Extract database file path
        db_path = db_url.replace("sqlite+aiosqlite://", "")
        db_file = Path(db_path)

        if not db_file.exists():
            raise HTTPException(status_code=404, detail="Database file not found")

        # Create backup directory
        backup_dir = db_file.parent / "backups"
        backup_dir.mkdir(exist_ok=True)

        # Generate backup filename with timestamp
        timestamp = get_now().strftime("%Y%m%d_%H%M%S")
        backup_filename = f"vulnforge_backup_{timestamp}.db"
        backup_path = backup_dir / backup_filename

        # Copy database file
        shutil.copy2(db_file, backup_path)

        # Get file size
        file_size = backup_path.stat().st_size

        return {
            "status": "success",
            "filename": backup_filename,
            "path": str(backup_path),
            "size_bytes": file_size,
            "size_mb": round(file_size / 1024 / 1024, 2),
            "created_at": get_now().isoformat(),
        }
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=f"Permission denied creating backup: {e}")
    except OSError as e:
        raise HTTPException(status_code=500, detail=f"File system error during backup: {e}")


@router.get("/backup/list")
async def list_backups(user: User = Depends(require_admin)):
    """
    List all available database backups.

    Returns:
        List of backup files with metadata
    """
    try:
        # Get database path
        db_url = settings.database_url
        db_path = db_url.replace("sqlite+aiosqlite://", "")
        db_file = Path(db_path)

        backup_dir = db_file.parent / "backups"

        if not backup_dir.exists():
            return {"backups": []}

        # List all backup files
        backups = []
        for backup_file in sorted(backup_dir.glob("vulnforge_backup_*.db"), reverse=True):
            stat = backup_file.stat()
            backups.append(
                {
                    "filename": backup_file.name,
                    "path": str(backup_file),
                    "size_bytes": stat.st_size,
                    "size_mb": round(stat.st_size / 1024 / 1024, 2),
                    "created_at": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                }
            )

        return {"backups": backups, "total": len(backups)}
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=f"Permission denied accessing backups: {e}")
    except OSError as e:
        raise HTTPException(status_code=500, detail=f"File system error listing backups: {e}")


@router.get("/backup/download/{filename}")
async def download_backup(filename: str, user: User = Depends(require_admin)):
    """
    Download a specific backup file.

    Args:
        filename: Name of the backup file to download

    Returns:
        File download response
    """
    try:
        # Get backup directory
        db_url = settings.database_url
        db_path = db_url.replace("sqlite+aiosqlite://", "")
        db_file = Path(db_path)
        backup_dir = db_file.parent / "backups"

        # Normalize and validate path to prevent directory traversal
        safe_filename = normalize_path(filename, backup_dir)
        backup_file = backup_dir / safe_filename

        if not backup_file.exists():
            raise HTTPException(status_code=404, detail="Backup file not found")

        return FileResponse(
            path=str(backup_file),
            filename=safe_filename,
            media_type="application/x-sqlite3",
        )
    except HTTPException:
        raise
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=f"Permission denied reading backup: {e}")
    except OSError as e:
        raise HTTPException(status_code=500, detail=f"File system error during download: {e}")


@router.delete("/backup/{filename}")
async def delete_backup(filename: str, user: User = Depends(require_admin)):
    """
    Delete a specific backup file.

    Args:
        filename: Name of the backup file to delete

    Returns:
        Deletion confirmation
    """
    try:
        # Get backup file path
        db_url = settings.database_url
        db_path = db_url.replace("sqlite+aiosqlite://", "")
        db_file = Path(db_path)
        backup_dir = db_file.parent / "backups"

        # Normalize and validate path to prevent directory traversal
        safe_filename = normalize_path(filename, backup_dir)
        backup_file = backup_dir / safe_filename

        if not backup_file.exists():
            raise HTTPException(status_code=404, detail="Backup file not found")

        # Delete the file
        backup_file.unlink()

        return {
            "status": "success",
            "message": f"Backup {filename} deleted successfully",
        }
    except HTTPException:
        raise
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=f"Permission denied deleting backup: {e}")
    except OSError as e:
        raise HTTPException(status_code=500, detail=f"File system error during deletion: {e}")


@router.post("/backup/restore/{filename}")
async def restore_backup(filename: str, user: User = Depends(require_admin)):
    """
    Restore database from a backup file.

    IMPORTANT: This will replace the current database with the backup.
    The application will need to restart after restore.

    Args:
        filename: Name of the backup file to restore from

    Returns:
        Restoration status and instructions
    """
    try:
        # Get paths
        db_url = settings.database_url
        db_path = db_url.replace("sqlite+aiosqlite://", "")
        db_file = Path(db_path)
        backup_dir = db_file.parent / "backups"

        # Normalize and validate path to prevent directory traversal
        safe_filename = normalize_path(filename, backup_dir)
        backup_file = backup_dir / safe_filename

        if not backup_file.exists():
            raise HTTPException(status_code=404, detail="Backup file not found")

        # Create a safety backup of current database before restoring
        timestamp = get_now().strftime("%Y%m%d_%H%M%S")
        safety_backup = backup_dir / f"pre_restore_{timestamp}.db"

        try:
            shutil.copy2(db_file, safety_backup)
        except PermissionError as e:
            raise HTTPException(
                status_code=403, detail=f"Permission denied creating safety backup: {e}"
            )
        except OSError as e:
            raise HTTPException(
                status_code=500, detail=f"File system error creating safety backup: {e}"
            )

        # Perform the restore
        try:
            # Close any open connections first (best effort)
            # The actual database file replacement
            shutil.copy2(backup_file, db_file)

            return {
                "status": "success",
                "message": f"Database restored from {filename}",
                "safety_backup": safety_backup.name,
                "note": "Application may need to restart to fully apply changes. Refresh the page.",
            }
        except PermissionError as e:
            # If restore fails, try to restore the safety backup
            try:
                shutil.copy2(safety_backup, db_file)
                raise HTTPException(
                    status_code=403, detail=f"Permission denied during restore (rolled back): {e}"
                )
            except OSError:
                raise HTTPException(
                    status_code=500,
                    detail=f"Restore failed and rollback also failed. Safety backup at: {safety_backup.name}",
                )
        except OSError as e:
            # If restore fails, try to restore the safety backup
            try:
                shutil.copy2(safety_backup, db_file)
                raise HTTPException(
                    status_code=500, detail=f"File system error during restore (rolled back): {e}"
                )
            except OSError:
                raise HTTPException(
                    status_code=500,
                    detail=f"Restore failed and rollback also failed. Safety backup at: {safety_backup.name}",
                )
    except HTTPException:
        raise
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=f"Permission denied during restore: {e}")
    except OSError as e:
        raise HTTPException(status_code=500, detail=f"File system error during restore: {e}")


@router.post("/backup/upload")
async def upload_backup(file: bytes | None = None):
    """
    Upload and restore a backup file from user's computer.

    This allows restoring backups that were downloaded to local storage.

    Returns:
        Upload and restoration status
    """
    # This endpoint would handle file upload
    # For now, we'll focus on restoring from existing backups
    raise HTTPException(
        status_code=501, detail="Upload restore not yet implemented. Use existing backups for now."
    )


@router.post("/kev/refresh")
async def refresh_kev_catalog(
    db: AsyncSession = Depends(get_db), user: User = Depends(require_admin)
):
    """
    Manually refresh KEV (Known Exploited Vulnerabilities) catalog from CISA.

    Forces immediate download of latest KEV catalog and re-checks all vulnerabilities.

    Returns:
        Refresh status with counts of updated vulnerabilities
    """
    try:
        kev_service = get_kev_service()

        # Fetch latest KEV catalog
        success = await kev_service.fetch_kev_catalog()
        if not success:
            raise HTTPException(status_code=500, detail="Failed to fetch KEV catalog from CISA")

        # Update last refresh timestamp in settings
        settings_manager = SettingsManager(db)
        last_refresh = kev_service.get_last_refresh()
        await settings_manager.set(
            "kev_last_refresh",
            last_refresh.isoformat() if last_refresh else "",
        )

        # Re-check all existing vulnerabilities against updated KEV catalog
        result = await db.execute(select(Vulnerability))
        vulnerabilities = result.scalars().all()

        updated_count = 0
        newly_flagged = 0
        newly_unflagged = 0

        for vuln in vulnerabilities:
            kev_info = kev_service.get_kev_info(vuln.cve_id)

            if kev_info:
                # CVE is in KEV catalog
                if not vuln.is_kev:
                    vuln.is_kev = True
                    vuln.kev_added_date = kev_info.get("date_added")
                    vuln.kev_due_date = kev_info.get("due_date")
                    updated_count += 1
                    newly_flagged += 1
            else:
                # CVE is not in KEV catalog (or was removed)
                if vuln.is_kev:
                    vuln.is_kev = False
                    vuln.kev_added_date = None
                    vuln.kev_due_date = None
                    updated_count += 1
                    newly_unflagged += 1

        await db.commit()

        return {
            "status": "success",
            "message": "KEV catalog refreshed successfully",
            "kev_catalog_size": kev_service.get_catalog_size(),
            "last_refresh": last_refresh.isoformat() if last_refresh else None,
            "vulnerabilities_checked": len(vulnerabilities),
            "vulnerabilities_updated": updated_count,
            "newly_flagged_as_kev": newly_flagged,
            "newly_unflagged_as_kev": newly_unflagged,
        }

    except HTTPException:
        raise
    except httpx.TimeoutException:
        raise HTTPException(
            status_code=504, detail="KEV catalog fetch timed out - CISA may be slow"
        )
    except httpx.ConnectError:
        raise HTTPException(
            status_code=503, detail="Cannot connect to CISA - check network connectivity"
        )
    except httpx.HTTPStatusError as e:
        raise HTTPException(status_code=e.response.status_code, detail=f"CISA returned error: {e}")
    except json.JSONDecodeError:
        raise HTTPException(status_code=500, detail="Invalid KEV catalog format received from CISA")


@router.get("/kev/status")
async def get_kev_status(db: AsyncSession = Depends(get_db), user: User = Depends(require_admin)):
    """
    Get KEV catalog status and statistics.

    Returns:
        KEV catalog information and refresh status
    """
    try:
        kev_service = get_kev_service()
        settings_manager = SettingsManager(db)

        # Get settings
        kev_enabled = await settings_manager.get_bool("kev_checking_enabled", default=True)
        last_refresh_str = await settings_manager.get("kev_last_refresh", default="")

        # Get KEV stats from database
        result = await db.execute(select(func.count(Vulnerability.id)).where(Vulnerability.is_kev))
        kev_vuln_count = result.scalar_one()

        return {
            "kev_enabled": kev_enabled,
            "catalog_size": kev_service.get_catalog_size(),
            "last_refresh": last_refresh_str or None,
            "needs_refresh": kev_service.needs_refresh(),
            "kev_vulnerabilities_in_db": kev_vuln_count,
            "cache_hours": await settings_manager.get_int("kev_cache_hours", default=12),
        }

    except sqlalchemy.exc.OperationalError:
        raise HTTPException(status_code=503, detail="Database temporarily unavailable")
    except sqlalchemy.exc.SQLAlchemyError as e:
        raise HTTPException(status_code=500, detail=f"Database error: {e}")
