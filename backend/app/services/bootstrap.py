"""Bootstrap token for first-run setup protection.

On first start with no admin account, VulnForge generates a one-time setup
token and prints it to container logs.  The /setup and /cancel-setup endpoints
require this token, preventing a "first caller wins" takeover on fresh installs.

The token can also be supplied via the VULNFORGE_BOOTSTRAP_TOKEN env var for
CI / automated deployments.
"""

import logging
import os
import secrets
from pathlib import Path

logger = logging.getLogger(__name__)

BOOTSTRAP_TOKEN_FILE = Path("/data/.bootstrap_token")


def get_bootstrap_token() -> str | None:
    """Read bootstrap token from env var or persisted file.

    Returns:
        The token string, or None if the token has been consumed / was never
        created (i.e. admin already exists).
    """
    env_token = os.environ.get("VULNFORGE_BOOTSTRAP_TOKEN")
    if env_token:
        return env_token
    if BOOTSTRAP_TOKEN_FILE.exists():
        return BOOTSTRAP_TOKEN_FILE.read_text().strip()
    return None


def ensure_bootstrap_token() -> str:
    """Return existing token or generate and persist a new one.

    Called by the application lifespan on startup when no admin account exists.

    Returns:
        The bootstrap token string.
    """
    existing = get_bootstrap_token()
    if existing:
        return existing
    # No env var and no file — generate and persist
    token = secrets.token_urlsafe(32)
    BOOTSTRAP_TOKEN_FILE.write_text(token)
    BOOTSTRAP_TOKEN_FILE.chmod(0o600)
    return token


def consume_bootstrap_token() -> None:
    """Delete the persisted token file after successful setup.

    Safe to call when the file does not exist (no-op).
    """
    if BOOTSTRAP_TOKEN_FILE.exists():
        BOOTSTRAP_TOKEN_FILE.unlink()
