"""Authentication routes — login, refresh, API key management."""

from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.jwt import create_access_token, create_refresh_token, decode_token, verify_password
from app.auth.middleware import get_current_user
from app.auth.rbac import require_permission
from app.models.tenant import User
from app.services.audit_service import write_audit_log
from app.services.database import get_db

router = APIRouter()


# ─── Schemas ───────────────────────────────────────────────

class LoginRequest(BaseModel):
    email: str
    password: str
    tenant_slug: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class RefreshRequest(BaseModel):
    refresh_token: str


# ─── Routes ────────────────────────────────────────────────

@router.post("/login", response_model=TokenResponse)
async def login(req: LoginRequest, db: AsyncSession = Depends(get_db)):
    """Authenticate user and return JWT token pair."""
    from app.models.tenant import Tenant

    # Find tenant by slug
    result = await db.execute(
        select(Tenant).where(Tenant.slug == req.tenant_slug, Tenant.is_active == True)
    )
    tenant = result.scalar_one_or_none()
    if not tenant:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Find user
    result = await db.execute(
        select(User).where(
            User.tenant_id == tenant.id,
            User.email == req.email,
            User.is_active == True,
        )
    )
    user = result.scalar_one_or_none()
    if not user or not verify_password(req.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Update last login
    user.last_login = datetime.now(timezone.utc)
    await db.commit()

    # Create tokens
    access_token = create_access_token(user.id, tenant.id, user.role, user.email)
    refresh_token = create_refresh_token(user.id, tenant.id)

    # Audit log
    await write_audit_log(
        db, tenant.id, "user", str(user.id), "auth.login",
        "user", str(user.id), {"email": user.email},
    )

    from app.config import settings
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=settings.jwt_access_token_expire_minutes * 60,
    )


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(req: RefreshRequest, db: AsyncSession = Depends(get_db)):
    """Exchange a refresh token for a new access token."""
    payload = decode_token(req.refresh_token)
    if not payload or payload.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    user_id = UUID(payload["sub"])
    tenant_id = UUID(payload["tenant_id"])

    # Verify user still exists and is active
    result = await db.execute(
        select(User).where(User.id == user_id, User.is_active == True)
    )
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=401, detail="User not found or inactive")

    access_token = create_access_token(user.id, tenant_id, user.role, user.email)
    new_refresh = create_refresh_token(user.id, tenant_id)

    from app.config import settings
    return TokenResponse(
        access_token=access_token,
        refresh_token=new_refresh,
        expires_in=settings.jwt_access_token_expire_minutes * 60,
    )


@router.get("/me")
async def get_me(current_user: dict = Depends(get_current_user)):
    """Return the current authenticated user's info."""
    return {
        "user_id": str(current_user["user_id"]),
        "tenant_id": str(current_user["tenant_id"]),
        "role": current_user["role"],
        "email": current_user["email"],
    }
