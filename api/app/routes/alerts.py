"""Alert CRUD routes."""

import csv
import io
from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.middleware import get_current_user, set_tenant_context
from app.auth.rbac import require_permission
from app.models.alert import Alert
from app.services.audit_service import write_audit_log

router = APIRouter()


# ─── Schemas ───────────────────────────────────────────────

class AlertOut(BaseModel):
    id: UUID
    source: str
    event_type: str
    severity: str
    confidence: float | None
    status: str
    title: str
    description: str | None
    mitre_technique: str | None
    atlas_technique: str | None
    trace_id: str | None
    created_at: datetime
    triaged_at: datetime | None

    model_config = {"from_attributes": True}


class AlertDetail(AlertOut):
    raw_payload: dict | None
    enrichment: dict | None
    artifacts: list | None
    triage_result: dict | None
    resolved_by: str | None
    resolution: str | None
    resolved_at: datetime | None
    incident_id: UUID | None


class AlertListResponse(BaseModel):
    alerts: list[AlertOut]
    total: int
    page: int
    page_size: int


class EscalateRequest(BaseModel):
    reason: str | None = None


class CloseRequest(BaseModel):
    resolution: str
    status: str = "resolved"


# ─── Routes ────────────────────────────────────────────────

@router.get("", response_model=AlertListResponse)
async def list_alerts(
    status: str | None = None,
    severity: str | None = None,
    source: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(set_tenant_context),
    current_user: dict = Depends(get_current_user),
):
    """List alerts for the current tenant with filtering and pagination."""
    query = select(Alert).where(Alert.tenant_id == current_user["tenant_id"])

    if status:
        query = query.where(Alert.status == status)
    if severity:
        query = query.where(Alert.severity == severity)
    if source:
        query = query.where(Alert.source == source)

    # Total count
    count_query = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_query)).scalar()

    # Paginate
    query = query.order_by(Alert.created_at.desc())
    query = query.offset((page - 1) * page_size).limit(page_size)

    result = await db.execute(query)
    alerts = result.scalars().all()

    return AlertListResponse(
        alerts=[AlertOut.model_validate(a) for a in alerts],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/export")
async def export_alerts_csv(
    status: str | None = None,
    severity: str | None = None,
    source: str | None = None,
    db: AsyncSession = Depends(set_tenant_context),
    current_user: dict = Depends(get_current_user),
):
    """Export alerts as CSV with optional filters."""
    query = select(Alert).where(Alert.tenant_id == current_user["tenant_id"])

    if status:
        query = query.where(Alert.status == status)
    if severity:
        query = query.where(Alert.severity == severity)
    if source:
        query = query.where(Alert.source == source)

    query = query.order_by(Alert.created_at.desc()).limit(10000)
    result = await db.execute(query)
    alerts = result.scalars().all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "id", "source", "event_type", "severity", "confidence", "status",
        "title", "description", "mitre_technique", "atlas_technique",
        "trace_id", "created_at", "triaged_at", "resolved_at",
    ])

    for a in alerts:
        writer.writerow([
            str(a.id), a.source, a.event_type, a.severity,
            a.confidence, a.status, a.title,
            (a.description or "")[:500], a.mitre_technique,
            a.atlas_technique, a.trace_id,
            a.created_at.isoformat() if a.created_at else "",
            a.triaged_at.isoformat() if a.triaged_at else "",
            a.resolved_at.isoformat() if a.resolved_at else "",
        ])

    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=alerts_export.csv"},
    )


@router.get("/{alert_id}", response_model=AlertDetail)
async def get_alert(
    alert_id: UUID,
    db: AsyncSession = Depends(set_tenant_context),
    current_user: dict = Depends(get_current_user),
):
    """Get full alert detail including raw payload and enrichment."""
    result = await db.execute(
        select(Alert).where(
            Alert.id == alert_id,
            Alert.tenant_id == current_user["tenant_id"],
        )
    )
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    return AlertDetail.model_validate(alert)


@router.post("/{alert_id}/escalate")
async def escalate_alert(
    alert_id: UUID,
    req: EscalateRequest,
    db: AsyncSession = Depends(set_tenant_context),
    current_user: dict = Depends(get_current_user),
):
    """Manually escalate an alert to investigation."""
    _check = require_permission("investigate")(current_user)

    result = await db.execute(
        select(Alert).where(
            Alert.id == alert_id,
            Alert.tenant_id == current_user["tenant_id"],
        )
    )
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    alert.status = "investigating"
    await db.commit()

    await write_audit_log(
        db, current_user["tenant_id"], "user", str(current_user["user_id"]),
        "alert.escalated", "alert", str(alert_id),
        {"reason": req.reason},
    )

    # Publish to triage queue for agent pickup
    from app.services.redis_service import publish_alert_for_triage
    await publish_alert_for_triage(
        str(current_user["tenant_id"]), str(alert_id),
        alert.severity, alert.source, alert.event_type,
    )

    return {"status": "escalated", "alert_id": str(alert_id)}


@router.post("/{alert_id}/close")
async def close_alert(
    alert_id: UUID,
    req: CloseRequest,
    db: AsyncSession = Depends(set_tenant_context),
    current_user: dict = Depends(get_current_user),
):
    """Close an alert with a resolution."""
    _check = require_permission("investigate")(current_user)

    result = await db.execute(
        select(Alert).where(
            Alert.id == alert_id,
            Alert.tenant_id == current_user["tenant_id"],
        )
    )
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    from datetime import datetime, timezone
    alert.status = req.status
    alert.resolution = req.resolution
    alert.resolved_by = current_user["email"]
    alert.resolved_at = datetime.now(timezone.utc)
    await db.commit()

    await write_audit_log(
        db, current_user["tenant_id"], "user", str(current_user["user_id"]),
        "alert.closed", "alert", str(alert_id),
        {"resolution": req.resolution, "status": req.status},
    )

    return {"status": "closed", "alert_id": str(alert_id)}
