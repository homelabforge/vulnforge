"""Add target field to compliance_findings table.

The target field stores the container or image name for per-target checks,
enabling the native compliance checker to show results per container/image.
"""

import os
from pathlib import Path

from sqlalchemy import create_engine, text


def upgrade():
    """Add target column to compliance_findings table."""
    # Get database path from environment
    data_dir = Path(os.getenv("DATA_DIR", "/data"))
    database_path = data_dir / "vulnforge.db"
    database_url = f"sqlite:///{database_path}"

    engine = create_engine(database_url)

    with engine.begin() as conn:
        # Check if column already exists
        result = conn.execute(text("PRAGMA table_info(compliance_findings)"))
        existing_columns = {row[1] for row in result.fetchall()}

        if "target" in existing_columns:
            print("  → Column 'target' already exists, skipping")
            return

        # Add target column
        conn.execute(
            text("""
                ALTER TABLE compliance_findings
                ADD COLUMN target VARCHAR(255)
            """)
        )
        print("  Added 'target' column to compliance_findings")

        # Create index for target column
        result = conn.execute(
            text(
                "SELECT name FROM sqlite_master WHERE type='index' AND name='ix_compliance_findings_target'"
            )
        )
        if not result.fetchone():
            conn.execute(
                text("CREATE INDEX ix_compliance_findings_target ON compliance_findings(target)")
            )
            print("  Created index on 'target' column")


def downgrade():
    """Remove target column (not supported in SQLite)."""
    print("  Downgrade not supported for SQLite (cannot drop columns)")


if __name__ == "__main__":
    upgrade()
