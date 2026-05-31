"""N2: login username-enumeration timing hardening (plan §8).

Both the wrong-password branch and the unknown-username branch must run exactly
one Argon2 verify, so response latency cannot distinguish "no such user" from
"wrong password". We prove this structurally by swapping the module-level
``ph`` hasher for a spy and counting ``verify`` calls (argon2's
``PasswordHasher.verify`` attribute is read-only, so we replace the whole
object rather than patching the method).
"""

import pytest
from argon2.exceptions import VerifyMismatchError
from sqlalchemy.ext.asyncio import AsyncSession

from app.services import user_auth as user_auth_service
from app.services.settings_manager import SettingsManager


class _SpyHasher:
    """Stand-in for the Argon2 hasher that counts verify() calls."""

    def __init__(self) -> None:
        self.calls = 0

    def verify(self, _hash: str, _password: str) -> bool:
        self.calls += 1
        raise VerifyMismatchError("mismatch")


@pytest.mark.asyncio
async def test_username_miss_and_wrong_password_both_verify_once(
    db_session: AsyncSession, monkeypatch
):
    sm = SettingsManager(db_session)
    await sm.set("user_auth_mode", "local")
    await sm.set("user_auth_admin_username", "admin")
    # Stored hash is created with the real hasher (before the spy is installed).
    await sm.set(
        "user_auth_admin_password_hash",
        user_auth_service.hash_password("Correct-Horse-1!"),
    )
    await sm.set("user_auth_admin_auth_method", "local")

    spy = _SpyHasher()
    monkeypatch.setattr(user_auth_service, "ph", spy)

    # Branch A: correct username, wrong password -> verify_password runs once.
    result_a = await user_auth_service.authenticate_user_admin(db_session, "admin", "wrong")
    assert result_a is None
    assert spy.calls == 1

    # Branch B: unknown username -> dummy verify still runs exactly once.
    spy.calls = 0
    result_b = await user_auth_service.authenticate_user_admin(db_session, "ghost", "whatever")
    assert result_b is None
    assert spy.calls == 1
