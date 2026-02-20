"""Admin routes — tenant management, user management, module config, API keys, notifications, audit log."""

import hashlib
import json
import secrets
from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.jwt import hash_password
from app.auth.middleware import get_current_user, set_tenant_context
from app.auth.rbac import require_permission
from app.models.tenant import ApiKey, Tenant, User
from app.services.audit_service import verify_audit_chain, write_audit_log
from app.services.database import get_db

router = APIRouter()


# ─── Schemas ──────────────────────────────────────────────

class CreateUserRequest(BaseModel):
    email: str
    password: str
    role: str = "viewer"


class UpdateUserRequest(BaseModel):
    role: str | None = None
    is_active: bool | None = None


class UserOut(BaseModel):
    id: UUID
    email: str
    role: str
    is_active: bool
    last_login: datetime | None

    model_config = {"from_attributes": True}


class TenantOut(BaseModel):
    id: UUID
    name: str
    slug: str
    plan: str
    is_active: bool

    model_config = {"from_attributes": True}


class ModuleConfigOut(BaseModel):
    module_name: str
    is_enabled: bool
    thresholds: dict


class UpdateModuleRequest(BaseModel):
    is_enabled: bool | None = None
    thresholds: dict | None = None


class CreateApiKeyRequest(BaseModel):
    name: str
    role: str = "api_only"
    scopes: list[str] = []


class ApiKeyOut(BaseModel):
    id: UUID
    name: str
    prefix: str
    role: str
    scopes: list[str]
    is_active: bool
    created_at: datetime

    model_config = {"from_attributes": True}


class ApiKeyCreated(ApiKeyOut):
    key: str  # Full key shown only once


class NotificationSettings(BaseModel):
    slack_webhook_url: str | None = None
    email_enabled: bool = False
    email_recipients: list[str] = []
    severity_filter: list[str] = ["critical", "high"]


# ─── Tenant Routes ────────────────────────────────────────

@router.get("/tenants", response_model=list[TenantOut])
async def list_tenants(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List all tenants (owner only)."""
    _check = require_permission("manage_tenants")(current_user)
    result = await db.execute(select(Tenant))
    return [TenantOut.model_validate(t) for t in result.scalars().all()]


# ─── User Routes ──────────────────────────────────────────

@router.get("/users", response_model=list[UserOut])
async def list_users(
    db: AsyncSession = Depends(set_tenant_context),
    current_user: dict = Depends(get_current_user),
):
    """List users in the current tenant."""
    _check = require_permission("manage_users")(current_user)
    result = await db.execute(
        select(User).where(User.tenant_id == current_user["tenant_id"])
    )
    return [UserOut.model_validate(u) for u in result.scalars().all()]


@router.post("/users", response_model=UserOut, status_code=201)
async def create_user(
    req: CreateUserRequest,
    db: AsyncSession = Depends(set_tenant_context),
    current_user: dict = Depends(get_current_user),
):
    """Create a new user in the current tenant."""
    _check = require_permission("manage_users")(current_user)

    valid_roles = {"owner", "admin", "analyst", "viewer", "api_only"}
    if req.role not in valid_roles:
        raise HTTPException(status_code=400, detail=f"Invalid role. Must be one of: {valid_roles}")

    # Check duplicate
    existing = await db.execute(
        select(User).where(
            User.tenant_id == current_user["tenant_id"],
            User.email == req.email,
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="User with this email already exists")

    user = User(
        tenant_id=current_user["tenant_id"],
        email=req.email,
        password_hash=hash_password(req.password),
        role=req.role,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)

    await write_audit_log(
        db, current_user["tenant_id"], "user", str(current_user["user_id"]),
        "user.created", "user", str(user.id),
        {"email": req.email, "role": req.role},
    )

    return UserOut.model_validate(user)


@router.put("/users/{user_id}", response_model=UserOut)
async def update_user(
    user_id: UUID,
    req: UpdateUserRequest,
    db: AsyncSession = Depends(set_tenant_context),
    current_user: dict = Depends(get_current_user),
):
    """Update a user's role or active status."""
    _check = require_permission("manage_users")(current_user)

    result = await db.execute(
        select(User).where(
            User.id == user_id,
            User.tenant_id == current_user["tenant_id"],
        )
    )
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    changes = {}
    if req.role is not None:
        valid_roles = {"owner", "admin", "analyst", "viewer", "api_only"}
        if req.role not in valid_roles:
            raise HTTPException(status_code=400, detail=f"Invalid role. Must be one of: {valid_roles}")
        user.role = req.role
        changes["role"] = req.role
    if req.is_active is not None:
        user.is_active = req.is_active
        changes["is_active"] = req.is_active

    await db.commit()
    await db.refresh(user)

    await write_audit_log(
        db, current_user["tenant_id"], "user", str(current_user["user_id"]),
        "user.updated", "user", str(user_id),
        changes,
    )

    return UserOut.model_validate(user)


@router.delete("/users/{user_id}")
async def deactivate_user(
    user_id: UUID,
    db: AsyncSession = Depends(set_tenant_context),
    current_user: dict = Depends(get_current_user),
):
    """Soft-delete (deactivate) a user."""
    _check = require_permission("manage_users")(current_user)

    if str(user_id) == str(current_user["user_id"]):
        raise HTTPException(status_code=400, detail="Cannot deactivate yourself")

    result = await db.execute(
        select(User).where(
            User.id == user_id,
            User.tenant_id == current_user["tenant_id"],
        )
    )
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.is_active = False
    await db.commit()

    await write_audit_log(
        db, current_user["tenant_id"], "user", str(current_user["user_id"]),
        "user.deactivated", "user", str(user_id),
        {"email": user.email},
    )

    return {"status": "deactivated", "user_id": str(user_id)}


# ─── Module Config Routes ────────────────────────────────

DEFAULT_MODULES = [
    {"module_name": "stripe_carding", "is_enabled": True, "thresholds": {"velocity_window_seconds": 300, "max_failures": 5}},
    {"module_name": "auth_anomaly", "is_enabled": True, "thresholds": {"brute_force_window_seconds": 300, "max_attempts": 10}},
    {"module_name": "infrastructure", "is_enabled": True, "thresholds": {"port_scan_window_seconds": 60, "max_ports": 20}},
    {"module_name": "ai_agent_monitor", "is_enabled": True, "thresholds": {"token_spike_multiplier": 3.0, "hallucination_threshold": 0.7}},
]


@router.get("/modules", response_model=list[ModuleConfigOut])
async def list_modules(
    db: AsyncSession = Depends(set_tenant_context),
    current_user: dict = Depends(get_current_user),
):
    """List module configurations. Returns defaults if no rows exist."""
    _check = require_permission("manage_users")(current_user)

    result = await db.execute(
        text("SELECT module_name, is_enabled, thresholds FROM module_configs WHERE tenant_id = :tid"),
        {"tid": str(current_user["tenant_id"])},
    )
    rows = result.fetchall()

    if rows:
        return [
            ModuleConfigOut(module_name=r.module_name, is_enabled=r.is_enabled, thresholds=r.thresholds or {})
            for r in rows
        ]

    # Return defaults
    return [ModuleConfigOut(**m) for m in DEFAULT_MODULES]


@router.put("/modules/{module_name}", response_model=ModuleConfigOut)
async def update_module(
    module_name: str,
    req: UpdateModuleRequest,
    db: AsyncSession = Depends(set_tenant_context),
    current_user: dict = Depends(get_current_user),
):
    """Toggle module enabled state or update thresholds (UPSERT)."""
    _check = require_permission("manage_users")(current_user)

    valid_modules = {m["module_name"] for m in DEFAULT_MODULES}
    if module_name not in valid_modules:
        raise HTTPException(status_code=400, detail=f"Unknown module. Must be one of: {valid_modules}")

    # Find default for this module
    default = next(m for m in DEFAULT_MODULES if m["module_name"] == module_name)

    is_enabled = req.is_enabled if req.is_enabled is not None else default["is_enabled"]
    thresholds = req.thresholds if req.thresholds is not None else default["thresholds"]

    await db.execute(
        text("""
            INSERT INTO module_configs (tenant_id, module_name, is_enabled, thresholds)
            VALUES (:tid, :name, :enabled, :thresholds)
            ON CONFLICT (tenant_id, module_name) DO UPDATE
            SET is_enabled = :enabled, thresholds = :thresholds, updated_at = NOW()
        """),
        {
            "tid": str(current_user["tenant_id"]),
            "name": module_name,
            "enabled": is_enabled,
            "thresholds": json.dumps(thresholds),
        },
    )
    await db.commit()

    await write_audit_log(
        db, current_user["tenant_id"], "user", str(current_user["user_id"]),
        "module.updated", "module", module_name,
        {"is_enabled": is_enabled, "thresholds": thresholds},
    )

    return ModuleConfigOut(module_name=module_name, is_enabled=is_enabled, thresholds=thresholds)


# ─── API Key Routes ──────────────────────────────────────

@router.get("/api-keys", response_model=list[ApiKeyOut])
async def list_api_keys(
    db: AsyncSession = Depends(set_tenant_context),
    current_user: dict = Depends(get_current_user),
):
    """List API keys (shows prefix only, never full key)."""
    _check = require_permission("manage_users")(current_user)

    result = await db.execute(
        select(ApiKey).where(ApiKey.tenant_id == current_user["tenant_id"])
    )
    keys = result.scalars().all()
    return [
        ApiKeyOut(
            id=k.id, name=k.name, prefix=k.prefix, role=k.role,
            scopes=k.scopes or [], is_active=k.is_active,
            created_at=k.created_at.isoformat() if k.created_at else "",
        )
        for k in keys
    ]


@router.post("/api-keys", response_model=ApiKeyCreated, status_code=201)
async def create_api_key(
    req: CreateApiKeyRequest,
    db: AsyncSession = Depends(set_tenant_context),
    current_user: dict = Depends(get_current_user),
):
    """Create a new API key. Returns the full key ONCE."""
    _check = require_permission("manage_users")(current_user)

    # Generate a secure key
    raw_key = f"soc_{secrets.token_urlsafe(32)}"
    prefix = raw_key[:8]
    key_hash_val = hashlib.sha256(raw_key.encode()).hexdigest()

    api_key = ApiKey(
        tenant_id=current_user["tenant_id"],
        created_by=current_user["user_id"],
        name=req.name,
        key_hash=key_hash_val,
        prefix=prefix,
        role=req.role,
        scopes=req.scopes,
    )
    db.add(api_key)
    await db.commit()
    await db.refresh(api_key)

    await write_audit_log(
        db, current_user["tenant_id"], "user", str(current_user["user_id"]),
        "api_key.created", "api_key", str(api_key.id),
        {"name": req.name, "prefix": prefix},
    )

    return ApiKeyCreated(
        id=api_key.id, name=api_key.name, prefix=prefix, role=api_key.role,
        scopes=api_key.scopes or [], is_active=api_key.is_active,
        created_at=api_key.created_at.isoformat() if api_key.created_at else "",
        key=raw_key,
    )


@router.delete("/api-keys/{key_id}")
async def revoke_api_key(
    key_id: UUID,
    db: AsyncSession = Depends(set_tenant_context),
    current_user: dict = Depends(get_current_user),
):
    """Revoke an API key."""
    _check = require_permission("manage_users")(current_user)

    result = await db.execute(
        select(ApiKey).where(
            ApiKey.id == key_id,
            ApiKey.tenant_id == current_user["tenant_id"],
        )
    )
    key = result.scalar_one_or_none()
    if not key:
        raise HTTPException(status_code=404, detail="API key not found")

    key.is_active = False
    await db.commit()

    await write_audit_log(
        db, current_user["tenant_id"], "user", str(current_user["user_id"]),
        "api_key.revoked", "api_key", str(key_id),
        {"name": key.name},
    )

    return {"status": "revoked", "key_id": str(key_id)}


# ─── Notification Settings Routes ────────────────────────

@router.get("/notifications", response_model=NotificationSettings)
async def get_notifications(
    db: AsyncSession = Depends(set_tenant_context),
    current_user: dict = Depends(get_current_user),
):
    """Read notification settings from tenant settings JSONB."""
    _check = require_permission("manage_users")(current_user)

    result = await db.execute(
        text("SELECT settings FROM tenants WHERE id = :tid"),
        {"tid": str(current_user["tenant_id"])},
    )
    row = result.fetchone()
    settings_data = row.settings if row and row.settings else {}

    return NotificationSettings(
        slack_webhook_url=settings_data.get("slack_webhook_url"),
        email_enabled=settings_data.get("email_enabled", False),
        email_recipients=settings_data.get("email_recipients", []),
        severity_filter=settings_data.get("severity_filter", ["critical", "high"]),
    )


@router.put("/notifications", response_model=NotificationSettings)
async def update_notifications(
    req: NotificationSettings,
    db: AsyncSession = Depends(set_tenant_context),
    current_user: dict = Depends(get_current_user),
):
    """Update notification settings in tenant settings JSONB."""
    _check = require_permission("manage_users")(current_user)

    notif_data = {
        "slack_webhook_url": req.slack_webhook_url,
        "email_enabled": req.email_enabled,
        "email_recipients": req.email_recipients,
        "severity_filter": req.severity_filter,
    }

    await db.execute(
        text("""
            UPDATE tenants
            SET settings = COALESCE(settings, '{}'::jsonb) || :notif::jsonb
            WHERE id = :tid
        """),
        {
            "tid": str(current_user["tenant_id"]),
            "notif": json.dumps(notif_data),
        },
    )
    await db.commit()

    await write_audit_log(
        db, current_user["tenant_id"], "user", str(current_user["user_id"]),
        "notifications.updated", "tenant", str(current_user["tenant_id"]),
        {"email_enabled": req.email_enabled, "severity_filter": req.severity_filter},
    )

    return req


@router.post("/notifications/test")
async def test_notification(
    db: AsyncSession = Depends(set_tenant_context),
    current_user: dict = Depends(get_current_user),
):
    """Send a test Slack message using the tenant's configured webhook."""
    _check = require_permission("manage_users")(current_user)

    result = await db.execute(
        text("SELECT settings FROM tenants WHERE id = :tid"),
        {"tid": str(current_user["tenant_id"])},
    )
    row = result.fetchone()
    settings_data = row.settings if row and row.settings else {}
    webhook_url = settings_data.get("slack_webhook_url")

    if not webhook_url:
        raise HTTPException(status_code=400, detail="No Slack webhook URL configured")

    import httpx
    payload = {
        "text": "Agentic SOC test notification - your webhook is working!",
        "blocks": [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": ":white_check_mark: *Agentic SOC Test Notification*\nYour Slack webhook is configured correctly.",
                },
            },
        ],
    }

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(webhook_url, json=payload)
            if resp.status_code == 200:
                return {"status": "sent", "message": "Test notification sent successfully"}
            else:
                raise HTTPException(
                    status_code=502,
                    detail=f"Slack returned {resp.status_code}: {resp.text[:200]}",
                )
    except httpx.RequestError as e:
        raise HTTPException(status_code=502, detail=f"Failed to reach Slack: {str(e)}")


# ─── Audit Log Routes ────────────────────────────────────

@router.get("/audit-log")
async def query_audit_log(
    action: str | None = None,
    resource_type: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Query the audit log for the current tenant."""
    _check = require_permission("view_audit_log")(current_user)

    # Count query
    count_query = "SELECT COUNT(*) FROM audit_log WHERE tenant_id = :tid"
    count_params: dict = {"tid": str(current_user["tenant_id"])}

    query = "SELECT * FROM audit_log WHERE tenant_id = :tid"
    params: dict = {"tid": str(current_user["tenant_id"])}

    if action:
        query += " AND action = :action"
        params["action"] = action
        count_query += " AND action = :action"
        count_params["action"] = action
    if resource_type:
        query += " AND resource_type = :rtype"
        params["rtype"] = resource_type
        count_query += " AND resource_type = :rtype"
        count_params["rtype"] = resource_type

    # Get total count
    total_result = await db.execute(text(count_query), count_params)
    total = total_result.scalar() or 0

    query += " ORDER BY timestamp DESC LIMIT :limit OFFSET :offset"
    params["limit"] = page_size
    params["offset"] = (page - 1) * page_size

    result = await db.execute(text(query), params)
    rows = result.fetchall()

    return {
        "entries": [
            {
                "id": row.id,
                "timestamp": str(row.timestamp),
                "actor_type": row.actor_type,
                "actor_id": row.actor_id,
                "action": row.action,
                "resource_type": row.resource_type,
                "resource_id": row.resource_id,
                "details": row.details,
                "row_hash": row.row_hash,
            }
            for row in rows
        ],
        "total": total,
        "page": page,
        "page_size": page_size,
    }


@router.get("/audit-log/verify")
async def verify_audit_integrity(
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Verify the integrity of the audit log hash chain."""
    _check = require_permission("view_audit_log")(current_user)
    result = await verify_audit_chain(db, current_user["tenant_id"])
    return result
