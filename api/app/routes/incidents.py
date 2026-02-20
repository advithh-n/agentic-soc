"""Incident management routes."""

from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, field_serializer
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.middleware import get_current_user, set_tenant_context
from app.auth.rbac import require_permission
from app.models.alert import Alert, Incident, ResponseAction
from app.services.audit_service import write_audit_log

router = APIRouter()


class IncidentCreate(BaseModel):
    title: str
    severity: str
    description: str | None = None
    alert_ids: list[UUID] = []


class IncidentOut(BaseModel):
    id: UUID
    title: str
    severity: str
    status: str
    description: str | None
    blast_radius: dict | None
    root_cause: str | None
    created_at: datetime

    model_config = {"from_attributes": True}

    @field_serializer("created_at")
    def serialize_created_at(self, v: datetime) -> str:
        return v.isoformat() if v else ""


class LinkedAlert(BaseModel):
    id: str
    title: str
    event_type: str
    severity: str
    status: str
    confidence: float | None
    created_at: str

    model_config = {"from_attributes": True}


class LinkedAction(BaseModel):
    id: str
    action_type: str
    risk_level: str
    status: str
    proposed_by: str
    critic_review: dict | None
    created_at: str

    model_config = {"from_attributes": True}


class IncidentDetailOut(IncidentOut):
    timeline: list | None
    alerts: list[LinkedAlert]
    response_actions: list[LinkedAction]
    alert_count: int


class IncidentListResponse(BaseModel):
    incidents: list[IncidentOut]
    total: int


@router.get("", response_model=IncidentListResponse)
async def list_incidents(
    status: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(set_tenant_context),
    current_user: dict = Depends(get_current_user),
):
    """List incidents for the current tenant."""
    query = select(Incident).where(Incident.tenant_id == current_user["tenant_id"])
    if status:
        query = query.where(Incident.status == status)

    count_q = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_q)).scalar()

    query = query.order_by(Incident.created_at.desc()).offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(query)

    return IncidentListResponse(
        incidents=[IncidentOut.model_validate(i) for i in result.scalars().all()],
        total=total,
    )


@router.post("", response_model=IncidentOut, status_code=201)
async def create_incident(
    req: IncidentCreate,
    db: AsyncSession = Depends(set_tenant_context),
    current_user: dict = Depends(get_current_user),
):
    """Create a new incident, optionally linking alerts."""
    _check = require_permission("investigate")(current_user)

    incident = Incident(
        tenant_id=current_user["tenant_id"],
        title=req.title,
        severity=req.severity,
        description=req.description,
    )
    db.add(incident)
    await db.flush()

    # Link alerts to this incident
    if req.alert_ids:
        from app.models.alert import Alert
        for aid in req.alert_ids:
            result = await db.execute(
                select(Alert).where(Alert.id == aid, Alert.tenant_id == current_user["tenant_id"])
            )
            alert = result.scalar_one_or_none()
            if alert:
                alert.incident_id = incident.id

    await db.commit()
    await db.refresh(incident)

    await write_audit_log(
        db, current_user["tenant_id"], "user", str(current_user["user_id"]),
        "incident.created", "incident", str(incident.id),
        {"title": req.title, "alert_count": len(req.alert_ids)},
    )

    return IncidentOut.model_validate(incident)


@router.get("/{incident_id}", response_model=IncidentDetailOut)
async def get_incident(
    incident_id: UUID,
    db: AsyncSession = Depends(set_tenant_context),
    current_user: dict = Depends(get_current_user),
):
    """Get incident detail with related alerts and response actions."""
    result = await db.execute(
        select(Incident).where(
            Incident.id == incident_id,
            Incident.tenant_id == current_user["tenant_id"],
        )
    )
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    # Fetch linked alerts
    alert_result = await db.execute(
        select(Alert).where(Alert.incident_id == incident_id)
        .order_by(Alert.created_at.desc())
        .limit(100)
    )
    linked_alerts = [
        LinkedAlert(
            id=str(a.id), title=a.title, event_type=a.event_type,
            severity=a.severity, status=a.status, confidence=a.confidence,
            created_at=a.created_at.isoformat() if a.created_at else "",
        )
        for a in alert_result.scalars().all()
    ]

    # Fetch response actions
    action_result = await db.execute(
        select(ResponseAction).where(ResponseAction.incident_id == incident_id)
        .order_by(ResponseAction.created_at.desc())
        .limit(50)
    )
    linked_actions = [
        LinkedAction(
            id=str(a.id), action_type=a.action_type, risk_level=a.risk_level,
            status=a.status, proposed_by=a.proposed_by,
            critic_review=a.critic_review,
            created_at=a.created_at.isoformat() if a.created_at else "",
        )
        for a in action_result.scalars().all()
    ]

    return IncidentDetailOut(
        id=incident.id,
        title=incident.title,
        severity=incident.severity,
        status=incident.status,
        description=incident.description,
        blast_radius=incident.blast_radius,
        root_cause=incident.root_cause,
        timeline=incident.timeline,
        created_at=incident.created_at.isoformat() if incident.created_at else "",
        alerts=linked_alerts,
        response_actions=linked_actions,
        alert_count=len(linked_alerts),
    )


@router.get("/{incident_id}/report")
async def generate_incident_report(
    incident_id: UUID,
    db: AsyncSession = Depends(set_tenant_context),
    current_user: dict = Depends(get_current_user),
):
    """Generate a structured JSON report for an incident."""
    result = await db.execute(
        select(Incident).where(
            Incident.id == incident_id,
            Incident.tenant_id == current_user["tenant_id"],
        )
    )
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    # Fetch linked alerts
    alert_result = await db.execute(
        select(Alert).where(Alert.incident_id == incident_id)
        .order_by(Alert.created_at.asc())
        .limit(200)
    )
    alerts = alert_result.scalars().all()

    # Fetch response actions
    action_result = await db.execute(
        select(ResponseAction).where(ResponseAction.incident_id == incident_id)
        .order_by(ResponseAction.created_at.asc())
        .limit(100)
    )
    actions = action_result.scalars().all()

    return {
        "report": {
            "generated_at": datetime.utcnow().isoformat(),
            "generated_by": current_user["email"],
            "incident": {
                "id": str(incident.id),
                "title": incident.title,
                "severity": incident.severity,
                "status": incident.status,
                "description": incident.description,
                "root_cause": incident.root_cause,
                "blast_radius": incident.blast_radius,
                "created_at": incident.created_at.isoformat() if incident.created_at else None,
                "resolved_at": incident.resolved_at.isoformat() if incident.resolved_at else None,
            },
            "alerts": [
                {
                    "id": str(a.id),
                    "title": a.title,
                    "severity": a.severity,
                    "source": a.source,
                    "event_type": a.event_type,
                    "status": a.status,
                    "mitre_technique": a.mitre_technique,
                    "created_at": a.created_at.isoformat() if a.created_at else None,
                }
                for a in alerts
            ],
            "response_actions": [
                {
                    "id": str(a.id),
                    "action_type": a.action_type,
                    "risk_level": a.risk_level,
                    "status": a.status,
                    "proposed_by": a.proposed_by,
                    "executed_at": a.executed_at.isoformat() if a.executed_at else None,
                    "outcome": a.outcome,
                }
                for a in actions
            ],
            "timeline": incident.timeline or [],
            "summary": {
                "alert_count": len(alerts),
                "action_count": len(actions),
                "actions_executed": sum(1 for a in actions if a.status == "executed"),
                "actions_pending": sum(1 for a in actions if a.status in ("pending", "approved")),
                "unique_sources": list(set(a.source for a in alerts)),
                "severity_distribution": {
                    sev: sum(1 for a in alerts if a.severity == sev)
                    for sev in ["critical", "high", "medium", "low"]
                    if any(a.severity == sev for a in alerts)
                },
            },
        }
    }
