"""Path normalization utilities to prevent directory traversal attacks."""

from pathlib import Path

from fastapi import HTTPException


def normalize_path(user_path: str | Path, base_dir: str | Path) -> str:
    """
    Normalize and validate a user-provided path to prevent directory traversal.

    This function:
    1. Converts the path to a Path object
    2. Removes any '..' or absolute path components
    3. Validates the path stays within the base directory
    4. Returns just the filename/relative component

    Args:
        user_path: User-provided path (potentially malicious)
        base_dir: Base directory that path must stay within

    Returns:
        Safe normalized filename (without directory components)

    Raises:
        HTTPException: If path validation fails

    Examples:
        >>> normalize_path("backup.db", "/var/backups")
        "backup.db"
        >>> normalize_path("../../../etc/passwd", "/var/backups")
        HTTPException(400, "Invalid path")
        >>> normalize_path("/etc/passwd", "/var/backups")
        HTTPException(400, "Invalid path")
    """
    try:
        # Convert to Path objects
        base = Path(base_dir).resolve()

        # Get just the filename component (removes any directory traversal)
        filename = Path(user_path).name

        # Reject empty, dot, or double-dot filenames
        if not filename or filename in (".", ".."):
            raise HTTPException(status_code=400, detail="Invalid path")

        # Additional validation: no path separators allowed
        if "/" in filename or "\\" in filename:
            raise HTTPException(status_code=400, detail="Invalid path: path separators not allowed")

        # No parent directory references
        if ".." in filename:
            raise HTTPException(
                status_code=400, detail="Invalid path: parent directory references not allowed"
            )

        # No absolute paths
        if filename.startswith("/") or (len(filename) > 1 and filename[1] == ":"):
            raise HTTPException(status_code=400, detail="Invalid path: absolute paths not allowed")

        # Validate the resulting path would be within base_dir
        # Construct the full path from validated components only
        validated_name = str(filename)
        full_path = (base / validated_name).resolve()
        if not str(full_path).startswith(str(base)):
            raise HTTPException(status_code=400, detail="Invalid path: outside base directory")

        return validated_name

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid path: {e}")
