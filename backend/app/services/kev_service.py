"""Compatibility shim for legacy KEV service import paths."""

from app.services.kev import KEVService  # noqa: F401

__all__ = ["KEVService"]
