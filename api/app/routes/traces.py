"""Execution trace routes — agent pipeline audit trail."""

from uuid import UUID

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.middleware import get_current_user, set_tenant_context

router = APIRouter()


class TraceStep(BaseModel):
    id: str
    agent_name: str
    trace_id: str
    step_number: int
    step_type: str
    input_data: dict | None
    output_data: dict | None
    tool_calls: list | None
    tokens_used: int
    duration_ms: int | None
    timestamp: str


class TraceListResponse(BaseModel):
    steps: list[TraceStep]
    total: int


@router.get("", response_model=TraceListResponse)
async def list_traces(
    alert_id: str | None = None,
    trace_id: str | None = None,
    agent_name: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(100, ge=1, le=500),
    db: AsyncSession = Depends(set_tenant_context),
    current_user: dict = Depends(get_current_user),
):
    """List execution traces, filtered by alert, trace_id, or agent."""
    tenant_id = str(current_user["tenant_id"])

    conditions = ["tenant_id = :tenant_id"]
    params: dict = {"tenant_id": tenant_id}

    if alert_id:
        conditions.append("alert_id = :alert_id")
        params["alert_id"] = alert_id
    if trace_id:
        conditions.append("trace_id = :trace_id")
        params["trace_id"] = trace_id
    if agent_name:
        conditions.append("agent_name = :agent_name")
        params["agent_name"] = agent_name

    where = " AND ".join(conditions)

    count_result = await db.execute(
        text(f"SELECT COUNT(*) FROM execution_traces WHERE {where}"), params
    )
    total = count_result.scalar()

    params["limit"] = page_size
    params["offset"] = (page - 1) * page_size

    result = await db.execute(
        text(f"""
            SELECT id, agent_name, trace_id, step_number, step_type,
                   input_data, output_data, tool_calls, tokens_used,
                   duration_ms, timestamp
            FROM execution_traces
            WHERE {where}
            ORDER BY trace_id, step_number
            LIMIT :limit OFFSET :offset
        """),
        params,
    )

    steps = []
    for row in result.mappings().all():
        steps.append(TraceStep(
            id=str(row["id"]),
            agent_name=row["agent_name"],
            trace_id=row["trace_id"],
            step_number=row["step_number"],
            step_type=row["step_type"],
            input_data=row["input_data"],
            output_data=row["output_data"],
            tool_calls=row["tool_calls"],
            tokens_used=row["tokens_used"] or 0,
            duration_ms=row["duration_ms"],
            timestamp=row["timestamp"].isoformat() if row["timestamp"] else "",
        ))

    return TraceListResponse(steps=steps, total=total)
