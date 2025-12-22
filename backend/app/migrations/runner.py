"""Database migration runner with automatic discovery and tracking."""

import importlib.util
import inspect
import logging
from pathlib import Path

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

logger = logging.getLogger(__name__)


class MigrationRunner:
    """Handles database migration discovery, tracking, and execution."""

    def __init__(self, engine: AsyncEngine, migrations_dir: Path):
        """
        Initialize migration runner.

        Args:
            engine: SQLAlchemy async engine
            migrations_dir: Path to directory containing migration files
        """
        self.engine = engine
        self.migrations_dir = Path(migrations_dir)

    async def _ensure_migration_tracking_table(self) -> None:
        """Create schema_migrations table if it doesn't exist."""
        async with self.engine.begin() as conn:
            await conn.execute(
                text("""
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    migration_name VARCHAR(255) NOT NULL UNIQUE,
                    applied_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL
                )
            """)
            )
            logger.debug("Migration tracking table verified")

    async def _get_applied_migrations(self) -> set[str]:
        """
        Get set of already-applied migration names.

        Returns:
            Set of migration names (without .py extension)
        """
        async with self.engine.begin() as conn:
            result = await conn.execute(
                text("SELECT migration_name FROM schema_migrations ORDER BY id")
            )
            applied = {row[0] for row in result}
            logger.debug(f"Found {len(applied)} applied migration(s)")
            return applied

    async def _mark_migration_applied(self, name: str) -> None:
        """
        Record migration as complete.

        Args:
            name: Migration name (without .py extension)
        """
        async with self.engine.begin() as conn:
            await conn.execute(
                text("INSERT INTO schema_migrations (migration_name) VALUES (:name)"),
                {"name": name},
            )
            logger.debug(f"Marked migration '{name}' as applied")

    def _discover_migrations(self) -> list[tuple[str, Path]]:
        """
        Find all migration files and return sorted list.

        Returns:
            List of (migration_name, file_path) tuples sorted by filename
        """
        migrations = []

        # Find all .py files in migrations directory
        for filepath in self.migrations_dir.glob("*.py"):
            # Skip __init__.py, runner.py, and README
            if filepath.name in ("__init__.py", "runner.py", "README.md"):
                continue

            # Extract name without extension
            migration_name = filepath.stem
            migrations.append((migration_name, filepath))

        # Sort by filename (numeric prefix ensures correct order)
        migrations.sort(key=lambda x: x[0])

        logger.debug(f"Discovered {len(migrations)} migration file(s)")
        return migrations

    async def _load_and_run_migration(self, name: str, path: Path) -> None:
        """
        Dynamically import and execute a migration file.

        Args:
            name: Migration name (without .py extension)
            path: Path to migration file

        Raises:
            Exception: If migration fails to load or execute
        """
        # Load module dynamically
        spec = importlib.util.spec_from_file_location(name, path)
        if spec is None or spec.loader is None:
            raise ImportError(f"Could not load migration module: {path}")

        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        # Execute upgrade/migrate/up function (try in order of preference)
        migration_func = None
        if hasattr(module, "upgrade"):
            migration_func = module.upgrade
        elif hasattr(module, "migrate"):
            migration_func = module.migrate
        elif hasattr(module, "up"):
            migration_func = module.up

        if migration_func is None:
            raise AttributeError(f"Migration {name} missing upgrade(), migrate(), or up() function")

        logger.info(f"Running migration: {name}")
        # Check if function expects a db parameter
        sig = inspect.signature(migration_func)
        if len(sig.parameters) > 0:
            # New-style migration - pass connection
            async with self.engine.begin() as conn:
                await migration_func(conn)
        else:
            # Old-style migration - no parameters
            await migration_func()

    async def run_pending_migrations(self) -> None:
        """
        Main orchestration method - runs all pending migrations.

        This method:
        1. Ensures migration tracking table exists
        2. Gets list of already-applied migrations
        3. Discovers all available migrations
        4. Runs pending migrations in order
        5. Marks each as applied after successful execution

        Stops on first failure without marking failed migration as applied.
        """
        # Ensure tracking table exists
        await self._ensure_migration_tracking_table()

        # Get applied migrations
        applied = await self._get_applied_migrations()

        # Discover all migrations
        all_migrations = self._discover_migrations()

        # Filter to pending only
        pending = [(name, path) for name, path in all_migrations if name not in applied]

        if not pending:
            logger.info("No pending migrations")
            return

        logger.info(f"Found {len(pending)} pending migration(s)")

        # Run each pending migration
        successful = 0
        for name, path in pending:
            try:
                await self._load_and_run_migration(name, path)
                await self._mark_migration_applied(name)
                successful += 1
            except Exception as e:
                logger.error(f"Migration '{name}' failed: {e}")
                logger.error("Stopping migration run - fix errors and restart")
                raise

        logger.info(f"✓ All {successful} migration(s) applied successfully")


async def run_migrations(engine: AsyncEngine, migrations_dir: Path) -> None:
    """
    Convenience function to run all pending migrations.

    Args:
        engine: SQLAlchemy async engine
        migrations_dir: Path to directory containing migration files

    Example:
        >>> await run_migrations(engine, Path('/app/migrations'))
    """
    runner = MigrationRunner(engine, migrations_dir)
    await runner.run_pending_migrations()
