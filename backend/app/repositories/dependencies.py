"""Dependency injection for repositories."""

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_db
from app.repositories.container_repository import ContainerRepository
from app.repositories.false_positive_pattern_repository import FalsePositivePatternRepository
from app.repositories.secret_repository import SecretRepository
from app.repositories.vulnerability_repository import VulnerabilityRepository
from app.services.activity_logger import ActivityLogger


def get_secret_repository(db: AsyncSession = Depends(get_db)) -> SecretRepository:
    """
    Get SecretRepository instance.

    Args:
        db: Database session from dependency

    Returns:
        SecretRepository instance
    """
    return SecretRepository(db)


def get_vulnerability_repository(
    db: AsyncSession = Depends(get_db),
) -> VulnerabilityRepository:
    """
    Get VulnerabilityRepository instance.

    Args:
        db: Database session from dependency

    Returns:
        VulnerabilityRepository instance
    """
    return VulnerabilityRepository(db)


def get_container_repository(db: AsyncSession = Depends(get_db)) -> ContainerRepository:
    """
    Get ContainerRepository instance.

    Args:
        db: Database session from dependency

    Returns:
        ContainerRepository instance
    """
    return ContainerRepository(db)


def get_fp_pattern_repository(
    db: AsyncSession = Depends(get_db),
) -> FalsePositivePatternRepository:
    """
    Get FalsePositivePatternRepository instance.

    Args:
        db: Database session from dependency

    Returns:
        FalsePositivePatternRepository instance
    """
    return FalsePositivePatternRepository(db)


def get_activity_logger(db: AsyncSession = Depends(get_db)) -> ActivityLogger:
    """
    Get ActivityLogger instance.

    Args:
        db: Database session from dependency

    Returns:
        ActivityLogger instance
    """
    return ActivityLogger(db)
