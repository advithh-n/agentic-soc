"""Response action approval routes."""

from datetime import datetime, timezone
from uuid import UUID

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select, or_
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.middleware import get_current_user, set_tenant_context
from app.auth.rbac import require_permission
from app.models.alert import ResponseAction
from app.services.audit_service import write_audit_log

router = APIRouter()


class ActionOut(BaseModel):
    id: UUID
    action_type: str
    parameters: dict
    risk_level: str
    status: str
    proposed_by: str
    critic_review: dict | None
    created_at: str

    model_config = {"from_attributes": True}


class ApproveRequest(BaseModel):
    pass


class DenyRequest(BaseModel):
    reason: str


@router.get("/pending", response_model=list[ActionOut])
async def list_pending_actions(
    db: AsyncSession = Depends(set_tenant_context),
    current_user: dict = Depends(get_current_user),
):
    """List all pending response actions awaiting approval."""
    _check = require_permission("approve_actions")(current_user)

    result = await db.execute(
        select(ResponseAction).where(
            ResponseAction.tenant_id == current_user["tenant_id"],
            ResponseAction.status == "pending",
        ).order_by(ResponseAction.created_at.asc())
    )

    return [ActionOut.model_validate(a) for a in result.scalars().all()]


@router.post("/{action_id}/approve", response_model=ActionOut)
async def approve_action(
    action_id: UUID,
    db: AsyncSession = Depends(set_tenant_context),
    current_user: dict = Depends(get_current_user),
):
    """Approve a pending response action."""
    _check = require_permission("approve_actions")(current_user)

    result = await db.execute(
        select(ResponseAction).where(
            ResponseAction.id == action_id,
            ResponseAction.tenant_id == current_user["tenant_id"],
        )
    )
    action = result.scalar_one_or_none()
    if not action:
        raise HTTPException(status_code=404, detail="Action not found")

    if action.status != "pending":
        raise HTTPException(status_code=400, detail=f"Action is {action.status}, not pending")

    # Analysts can only approve low/medium risk
    if current_user["role"] == "analyst" and action.risk_level in ("high", "critical"):
        raise HTTPException(
            status_code=403,
            detail="Analysts can only approve low/medium risk actions",
        )

    action.status = "approved"
    action.approved_by = current_user["user_id"]
    await db.commit()
    await db.refresh(action)

    await write_audit_log(
        db, current_user["tenant_id"], "user", str(current_user["user_id"]),
        "action.approved", "response_action", str(action_id),
        {"action_type": action.action_type, "risk_level": action.risk_level},
    )

    return ActionOut.model_validate(action)


@router.post("/{action_id}/deny", response_model=ActionOut)
async def deny_action(
    action_id: UUID,
    req: DenyRequest,
    db: AsyncSession = Depends(set_tenant_context),
    current_user: dict = Depends(get_current_user),
):
    """Deny a pending response action with a reason."""
    _check = require_permission("approve_actions")(current_user)

    result = await db.execute(
        select(ResponseAction).where(
            ResponseAction.id == action_id,
            ResponseAction.tenant_id == current_user["tenant_id"],
        )
    )
    action = result.scalar_one_or_none()
    if not action:
        raise HTTPException(status_code=404, detail="Action not found")

    if action.status != "pending":
        raise HTTPException(status_code=400, detail=f"Action is {action.status}, not pending")

    action.status = "denied"
    action.outcome = {"denied_reason": req.reason}
    await db.commit()
    await db.refresh(action)

    await write_audit_log(
        db, current_user["tenant_id"], "user", str(current_user["user_id"]),
        "action.denied", "response_action", str(action_id),
        {"reason": req.reason},
    )

    return ActionOut.model_validate(action)


# ─── New: Execute + History endpoints ─────────────────────


class ActionHistoryItem(BaseModel):
    id: UUID
    action_type: str
    parameters: dict
    risk_level: str
    status: str
    proposed_by: str
    critic_review: dict | None
    outcome: dict | None
    executed_at: datetime | None
    created_at: datetime

    model_config = {"from_attributes": True}


class ActionHistoryResponse(BaseModel):
    actions: list[ActionHistoryItem]
    total: int


@router.post("/{action_id}/execute", response_model=ActionOut)
async def trigger_execute_action(
    action_id: UUID,
    db: AsyncSession = Depends(set_tenant_context),
    current_user: dict = Depends(get_current_user),
):
    """Mark an approved action for execution (poll loop picks it up within 10s)."""
    _check = require_permission("approve_actions")(current_user)

    result = await db.execute(
        select(ResponseAction).where(
            ResponseAction.id == action_id,
            ResponseAction.tenant_id == current_user["tenant_id"],
        )
    )
    action = result.scalar_one_or_none()
    if not action:
        raise HTTPException(status_code=404, detail="Action not found")

    if action.status not in ("approved", "pending"):
        raise HTTPException(
            status_code=400,
            detail=f"Action is {action.status}, must be approved or pending to execute",
        )

    # If pending, approve first
    if action.status == "pending":
        if current_user["role"] == "analyst" and action.risk_level in ("high", "critical"):
            raise HTTPException(
                status_code=403,
                detail="Analysts can only execute low/medium risk actions",
            )
        action.approved_by = current_user["user_id"]

    action.status = "approved"
    await db.commit()
    await db.refresh(action)

    await write_audit_log(
        db, current_user["tenant_id"], "user", str(current_user["user_id"]),
        "action.execute_triggered", "response_action", str(action_id),
        {"action_type": action.action_type, "risk_level": action.risk_level},
    )

    return ActionOut.model_validate(action)


@router.get("/history", response_model=ActionHistoryResponse)
async def get_action_history(
    status: Optional[str] = Query(None, description="Filter by status"),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(set_tenant_context),
    current_user: dict = Depends(get_current_user),
):
    """List executed, failed, and rolled_back actions with pagination."""
    query = select(ResponseAction).where(
        ResponseAction.tenant_id == current_user["tenant_id"],
    )

    if status:
        query = query.where(ResponseAction.status == status)
    else:
        query = query.where(
            or_(
                ResponseAction.status == "executed",
                ResponseAction.status == "failed",
                ResponseAction.status == "rolled_back",
                ResponseAction.status == "approved",
                ResponseAction.status == "executing",
            )
        )

    # Count total
    from sqlalchemy import func
    count_query = select(func.count()).select_from(query.subquery())
    total = await db.scalar(count_query)

    # Paginate
    query = query.order_by(ResponseAction.created_at.desc())
    query = query.offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(query)

    actions = [ActionHistoryItem.model_validate(a) for a in result.scalars().all()]
    return ActionHistoryResponse(actions=actions, total=total or 0)
