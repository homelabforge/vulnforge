"""Shared rate limiter instance for VulnForge.

Import this module instead of creating per-file Limiter instances.
The limiter must be registered with ``app.state.limiter`` in main.py
for slowapi's exception handler to fire.
"""

from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)
