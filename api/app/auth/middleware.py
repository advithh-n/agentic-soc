"""Authentication middleware — extracts user from JWT and sets tenant context."""

from uuid import UUID

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.jwt import decode_token
from app.services.database import get_db

bearer_scheme = HTTPBearer()


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
) -> dict:
    """Extract and validate the current user from the Authorization header.

    Returns a dict with: user_id, tenant_id, role, email
    """
    payload = decode_token(credentials.credentials)
    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        )

    if payload.get("type") != "access":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Expected access token, got refresh token",
        )

    return {
        "user_id": UUID(payload["sub"]),
        "tenant_id": UUID(payload["tenant_id"]),
        "role": payload["role"],
        "email": payload["email"],
    }


async def set_tenant_context(
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
) -> AsyncSession:
    """Set the PostgreSQL session variable for row-level security.

    This ensures all queries in this request are scoped to the tenant.
    """
    await db.execute(
        text("SELECT set_config('app.current_tenant', :tid, true)"),
        {"tid": str(current_user["tenant_id"])},
    )
    return db
