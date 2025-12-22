"""Add user authentication support (single-user JWT auth).

This migration adds:
- oidc_states table for OAuth2 state/nonce tracking
- oidc_pending_links table for password verification during account linking
- User authentication-related settings (user_auth_mode, admin profile, OIDC config)

Note: This is separate from the existing API authentication middleware which handles
ForwardAuth headers and API keys for external system integration.
"""

import logging

from sqlalchemy import text

logger = logging.getLogger(__name__)


async def check_table_exists(conn, table: str) -> bool:
    """Check if a table exists."""
    result = await conn.execute(
        text("SELECT name FROM sqlite_master WHERE type='table' AND name=:table"), {"table": table}
    )
    return result.fetchone() is not None


async def upgrade(conn):
    """Add user authentication support."""
    logger.info("Migration 004: Adding user authentication support")

    # ================================================================
    # STEP 1: Create oidc_states table
    # ================================================================
    logger.info("Step 1: Creating oidc_states table...")

    if not await check_table_exists(conn, "oidc_states"):
        await conn.execute(
            text("""
            CREATE TABLE oidc_states (
                state TEXT PRIMARY KEY NOT NULL,
                nonce TEXT NOT NULL,
                redirect_uri TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
                expires_at TIMESTAMP NOT NULL
            )
        """)
        )

        # Create index for cleanup operations
        await conn.execute(
            text("CREATE INDEX idx_oidc_states_expires_at ON oidc_states(expires_at)")
        )

        logger.info("  ✓ Created oidc_states table with indexes")
    else:
        logger.info("  ⊘ Table already exists: oidc_states")

    # ================================================================
    # STEP 2: Create oidc_pending_links table
    # ================================================================
    logger.info("Step 2: Creating oidc_pending_links table...")

    if not await check_table_exists(conn, "oidc_pending_links"):
        await conn.execute(
            text("""
            CREATE TABLE oidc_pending_links (
                token TEXT PRIMARY KEY NOT NULL,
                username TEXT NOT NULL,
                oidc_claims TEXT NOT NULL,
                userinfo_claims TEXT,
                provider_name TEXT NOT NULL,
                attempt_count INTEGER DEFAULT 0 NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
                expires_at TIMESTAMP NOT NULL
            )
        """)
        )

        # Create indexes
        await conn.execute(
            text("CREATE INDEX idx_oidc_pending_links_username ON oidc_pending_links(username)")
        )
        await conn.execute(
            text("CREATE INDEX idx_oidc_pending_links_expires_at ON oidc_pending_links(expires_at)")
        )

        logger.info("  ✓ Created oidc_pending_links table with indexes")
    else:
        logger.info("  ⊘ Table already exists: oidc_pending_links")

    # ================================================================
    # STEP 3: Insert user authentication settings
    # ================================================================
    logger.info("Step 3: Adding user authentication settings...")

    settings = [
        # Auth mode
        (
            "user_auth_mode",
            "none",
            "security",
            "User authentication mode (none, local, oidc)",
            False,
        ),
        # Admin profile
        ("user_auth_admin_username", "", "security", "Admin username for user auth", False),
        ("user_auth_admin_email", "", "security", "Admin email address for user auth", False),
        (
            "user_auth_admin_password_hash",
            "",
            "security",
            "Admin password hash (Argon2) for user auth",
            True,
        ),
        ("user_auth_admin_full_name", "", "security", "Admin full name for user auth", False),
        (
            "user_auth_admin_auth_method",
            "local",
            "security",
            "Admin authentication method (local or oidc)",
            False,
        ),
        ("user_auth_admin_oidc_subject", "", "security", "Admin OIDC subject (sub claim)", False),
        ("user_auth_admin_oidc_provider", "", "security", "Admin OIDC provider name", False),
        (
            "user_auth_admin_created_at",
            "",
            "security",
            "Timestamp when admin account was created",
            False,
        ),
        ("user_auth_admin_last_login", "", "security", "Timestamp of last admin login", False),
        # OIDC/SSO configuration
        (
            "user_auth_oidc_enabled",
            "false",
            "security",
            "Enable OIDC/SSO for user authentication",
            False,
        ),
        (
            "user_auth_oidc_provider_name",
            "",
            "security",
            "OIDC provider name (e.g., Authentik, Keycloak)",
            False,
        ),
        ("user_auth_oidc_issuer_url", "", "security", "OIDC issuer/discovery URL", False),
        ("user_auth_oidc_client_id", "", "security", "OIDC client ID", False),
        ("user_auth_oidc_client_secret", "", "security", "OIDC client secret", True),
        (
            "user_auth_oidc_redirect_uri",
            "",
            "security",
            "OIDC redirect URI (auto-generated if empty)",
            False,
        ),
        (
            "user_auth_oidc_scopes",
            "openid profile email",
            "security",
            "OIDC scopes to request (space-separated)",
            False,
        ),
        (
            "user_auth_oidc_username_claim",
            "preferred_username",
            "security",
            "OIDC claim to use for username",
            False,
        ),
        (
            "user_auth_oidc_email_claim",
            "email",
            "security",
            "OIDC claim to use for email address",
            False,
        ),
        (
            "user_auth_oidc_link_token_expire_minutes",
            "5",
            "security",
            "Pending link token expiry in minutes",
            False,
        ),
        (
            "user_auth_oidc_link_max_password_attempts",
            "3",
            "security",
            "Max password attempts for account linking",
            False,
        ),
    ]

    for key, value, category, description, is_sensitive in settings:
        # Check if setting already exists
        result = await conn.execute(text("SELECT key FROM settings WHERE key = :key"), {"key": key})
        if not result.fetchone():
            # Check if is_sensitive column exists (from migration 001)
            result = await conn.execute(text("PRAGMA table_info(settings)"))
            columns = [row[1] for row in result]

            if "is_sensitive" in columns:
                await conn.execute(
                    text("""
                        INSERT INTO settings (key, value, is_sensitive, category, description, updated_at)
                        VALUES (:key, :value, :is_sensitive, :category, :description, CURRENT_TIMESTAMP)
                    """),
                    {
                        "key": key,
                        "value": value,
                        "is_sensitive": 1 if is_sensitive else 0,
                        "category": category,
                        "description": description,
                    },
                )
            else:
                # Fallback for older schema without is_sensitive
                await conn.execute(
                    text("""
                        INSERT INTO settings (key, value, category, description, updated_at)
                        VALUES (:key, :value, :category, :description, CURRENT_TIMESTAMP)
                    """),
                    {"key": key, "value": value, "category": category, "description": description},
                )
            logger.info(f"  ✓ Added setting: {key}")
        else:
            logger.info(f"  ⊘ Setting already exists: {key}")

    # ================================================================
    # Verification
    # ================================================================
    logger.info("Verifying migration...")

    # Check tables
    result = await conn.execute(
        text(
            "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE '%oidc%' ORDER BY name"
        )
    )
    tables = [row[0] for row in result.fetchall()]
    logger.info(f"  OIDC tables: {', '.join(tables) if tables else 'none'}")

    # Check auth settings
    result = await conn.execute(text("SELECT COUNT(*) FROM settings WHERE key LIKE 'user_auth_%'"))
    setting_count = result.scalar()
    logger.info(f"  User auth settings: {setting_count}")

    logger.info("✓ Migration 004 completed successfully")
