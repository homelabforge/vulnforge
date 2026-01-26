"""API endpoints for API key management."""

import logging

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.schemas.api_key import APIKeyCreate, APIKeyCreated, APIKeyList, APIKeyResponse
from app.services.api_key_service import APIKeyService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/api-keys", tags=["api-keys"])


@router.post("", response_model=APIKeyCreated, status_code=201)
async def create_api_key(
    key_data: APIKeyCreate,
    db: AsyncSession = Depends(get_db),
):
    """
    Create a new API key.

    Returns the full API key in the response - this is the ONLY time it will be shown.
    The key should be saved immediately by the client.

    Args:
        key_data: Name and optional description for the key
        db: Database session

    Returns:
        APIKeyCreated with full key (shown only once)
    """
    try:
        api_key, plaintext_key = await APIKeyService.create_api_key(
            db=db,
            name=key_data.name,
            description=key_data.description,
            created_by="admin",  # TODO: Get from request.state.user when we have user context
        )

        # Return response with full key
        return APIKeyCreated(
            id=api_key.id,
            name=api_key.name,
            description=api_key.description,
            key=plaintext_key,
            key_prefix=api_key.key_prefix,
            created_at=api_key.created_at,
            created_by=api_key.created_by,
        )
    except Exception as e:
        logger.error(f"Failed to create API key: {e}")
        raise HTTPException(status_code=500, detail="Failed to create API key")


@router.get("", response_model=APIKeyList)
async def list_api_keys(
    include_revoked: bool = False,
    db: AsyncSession = Depends(get_db),
):
    """
    List all API keys.

    By default, only active (non-revoked) keys are returned.

    Args:
        include_revoked: Include revoked keys in results
        db: Database session

    Returns:
        List of API keys (without the actual key values)
    """
    try:
        keys = await APIKeyService.list_api_keys(db, include_revoked=include_revoked)

        # Convert to response models
        key_responses = [
            APIKeyResponse(
                id=key.id,
                name=key.name,
                description=key.description,
                key_prefix=key.key_prefix,
                created_at=key.created_at,
                last_used_at=key.last_used_at,
                revoked_at=key.revoked_at,
                is_active=key.is_active(),
                created_by=key.created_by,
            )
            for key in keys
        ]

        return APIKeyList(keys=key_responses, total=len(key_responses))
    except Exception as e:
        logger.error(f"Failed to list API keys: {e}")
        raise HTTPException(status_code=500, detail="Failed to list API keys")


@router.get("/{key_id}", response_model=APIKeyResponse)
async def get_api_key(
    key_id: int,
    db: AsyncSession = Depends(get_db),
):
    """
    Get details of a specific API key.

    Args:
        key_id: ID of the API key
        db: Database session

    Returns:
        API key details (without the actual key value)
    """
    try:
        api_key = await APIKeyService.get_api_key(db, key_id)

        if not api_key:
            raise HTTPException(status_code=404, detail="API key not found")

        return APIKeyResponse(
            id=api_key.id,
            name=api_key.name,
            description=api_key.description,
            key_prefix=api_key.key_prefix,
            created_at=api_key.created_at,
            last_used_at=api_key.last_used_at,
            revoked_at=api_key.revoked_at,
            is_active=api_key.is_active(),
            created_by=api_key.created_by,
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get API key: {e}")
        raise HTTPException(status_code=500, detail="Failed to get API key")


@router.delete("/{key_id}", response_model=APIKeyResponse)
async def revoke_api_key(
    key_id: int,
    db: AsyncSession = Depends(get_db),
):
    """
    Revoke an API key (soft delete).

    The key will no longer be valid for authentication but remains in the database
    for audit purposes.

    Args:
        key_id: ID of the API key to revoke
        db: Database session

    Returns:
        Updated API key with revoked_at timestamp
    """
    try:
        api_key = await APIKeyService.revoke_api_key(db, key_id)

        if not api_key:
            raise HTTPException(status_code=404, detail="API key not found")

        return APIKeyResponse(
            id=api_key.id,
            name=api_key.name,
            description=api_key.description,
            key_prefix=api_key.key_prefix,
            created_at=api_key.created_at,
            last_used_at=api_key.last_used_at,
            revoked_at=api_key.revoked_at,
            is_active=api_key.is_active(),
            created_by=api_key.created_by,
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to revoke API key: {e}")
        raise HTTPException(status_code=500, detail="Failed to revoke API key")
