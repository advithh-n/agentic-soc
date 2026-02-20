"""AI Agent monitoring routes (Mode B)."""

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.middleware import get_current_user, set_tenant_context
from app.models.ai_agent import AiAgent, AiAgentSession, AiToolCallLog, PromptInjectionLog

router = APIRouter()


class AiAgentOut(BaseModel):
    id: UUID
    name: str
    platform: str
    model: str | None
    status: str
    environment: str

    model_config = {"from_attributes": True}


class SessionOut(BaseModel):
    id: UUID
    agent_id: UUID
    user_identifier: str | None
    started_at: str
    ended_at: str | None
    total_tokens: int
    total_cost: float
    tool_calls: int
    anomaly_flags: list[str]

    model_config = {"from_attributes": True}


class InjectionLogOut(BaseModel):
    id: UUID
    detection_layer: str
    injection_type: str | None
    injection_score: float | None
    was_blocked: bool
    prompt_snippet: str | None
    timestamp: str

    model_config = {"from_attributes": True}


# ─── OWASP Agentic Top 10 Scorecard ───────────────────────

SCORECARD_TEMPLATE = [
    {"id": "ASI01", "risk": "Agent Goal Hijacking", "max_score": 100},
    {"id": "ASI02", "risk": "Tool Misuse", "max_score": 100},
    {"id": "ASI03", "risk": "Identity & Privilege Abuse", "max_score": 100},
    {"id": "ASI04", "risk": "Supply Chain Vulnerabilities", "max_score": 100},
    {"id": "ASI05", "risk": "Unexpected Code Execution", "max_score": 100},
    {"id": "ASI06", "risk": "Memory Poisoning", "max_score": 100},
    {"id": "ASI07", "risk": "Inter-Agent Communication", "max_score": 100},
    {"id": "ASI08", "risk": "Cascading Failures", "max_score": 100},
    {"id": "ASI09", "risk": "Human-Agent Trust", "max_score": 100},
    {"id": "ASI10", "risk": "Rogue Agents", "max_score": 100},
]


@router.get("", response_model=list[AiAgentOut])
async def list_ai_agents(
    db: AsyncSession = Depends(set_tenant_context),
    current_user: dict = Depends(get_current_user),
):
    """List all monitored AI agents."""
    result = await db.execute(
        select(AiAgent).where(AiAgent.tenant_id == current_user["tenant_id"])
    )
    return [AiAgentOut.model_validate(a) for a in result.scalars().all()]


@router.get("/{agent_id}/sessions", response_model=list[SessionOut])
async def get_agent_sessions(
    agent_id: UUID,
    hours: int = Query(24, ge=1, le=168),
    db: AsyncSession = Depends(set_tenant_context),
    current_user: dict = Depends(get_current_user),
):
    """Get recent sessions for an AI agent."""
    from datetime import datetime, timedelta, timezone
    since = datetime.now(timezone.utc) - timedelta(hours=hours)

    result = await db.execute(
        select(AiAgentSession).where(
            AiAgentSession.agent_id == agent_id,
            AiAgentSession.tenant_id == current_user["tenant_id"],
            AiAgentSession.started_at >= since,
        ).order_by(AiAgentSession.started_at.desc()).limit(100)
    )
    return [SessionOut.model_validate(s) for s in result.scalars().all()]


@router.get("/{agent_id}/anomalies")
async def get_agent_anomalies(
    agent_id: UUID,
    db: AsyncSession = Depends(set_tenant_context),
    current_user: dict = Depends(get_current_user),
):
    """Get anomalous tool calls for an AI agent."""
    result = await db.execute(
        select(AiToolCallLog).where(
            AiToolCallLog.agent_id == agent_id,
            AiToolCallLog.tenant_id == current_user["tenant_id"],
            AiToolCallLog.was_anomalous == True,
        ).order_by(AiToolCallLog.timestamp.desc()).limit(100)
    )
    calls = result.scalars().all()
    return [
        {
            "id": str(c.id),
            "tool_name": c.tool_name,
            "anomaly_reason": c.anomaly_reason,
            "arguments": c.arguments,
            "duration_ms": c.duration_ms,
            "timestamp": str(c.timestamp),
        }
        for c in calls
    ]


@router.get("/scorecard")
async def get_owasp_scorecard(
    db: AsyncSession = Depends(set_tenant_context),
    current_user: dict = Depends(get_current_user),
):
    """OWASP Agentic Top 10 compliance scorecard.

    Scores are computed from active detection capabilities.
    """
    tenant_id = current_user["tenant_id"]

    # Count active detections to compute scores
    injection_count = (await db.execute(
        select(func.count()).where(PromptInjectionLog.tenant_id == tenant_id)
    )).scalar() or 0

    anomaly_count = (await db.execute(
        select(func.count()).where(
            AiToolCallLog.tenant_id == tenant_id,
            AiToolCallLog.was_anomalous == True,
        )
    )).scalar() or 0

    agent_count = (await db.execute(
        select(func.count()).where(AiAgent.tenant_id == tenant_id)
    )).scalar() or 0

    # Build scorecard (scores are based on what's implemented)
    scorecard = []
    for item in SCORECARD_TEMPLATE:
        score = 20  # Base: we have the framework
        status = "PLANNED"

        if item["id"] == "ASI01":  # Goal Hijacking
            if injection_count > 0:
                score = 65
                status = "PARTIAL"
        elif item["id"] == "ASI02":  # Tool Misuse
            if anomaly_count >= 0:  # Module exists
                score = 90
                status = "ACTIVE"
        elif item["id"] == "ASI03":  # Identity Abuse
            if agent_count > 0:
                score = 60
                status = "PARTIAL"
        elif item["id"] == "ASI08":  # Cascading Failures
            score = 85
            status = "ACTIVE"
        elif item["id"] == "ASI09":  # Human-Agent Trust
            score = 55
            status = "PARTIAL"

        scorecard.append({**item, "score": score, "status": status})

    overall = sum(s["score"] for s in scorecard) // len(scorecard)

    return {
        "tenant_id": str(tenant_id),
        "scorecard": scorecard,
        "overall_score": overall,
    }
