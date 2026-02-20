"""Execution Tracer — logs each pipeline step to execution_traces table.

Provides an audit trail for every investigation, recording inputs,
outputs, tool calls, and timing for each step.
"""

import json
import time
import uuid

import asyncpg
import structlog

logger = structlog.get_logger()


class ExecutionTracer:
    """Traces a single investigation run, logging each step to PostgreSQL."""

    def __init__(self, db_pool: asyncpg.Pool, tenant_id: str, alert_id: str, agent_name: str = "investigation"):
        self.db_pool = db_pool
        self.tenant_id = tenant_id
        self.alert_id = alert_id
        self.agent_name = agent_name
        self.trace_id = f"inv-{uuid.uuid4().hex[:12]}"
        self.step_counter = 0
        self.total_tokens = 0

    async def log_step(
        self,
        step_type: str,
        input_data: dict | None = None,
        output_data: dict | None = None,
        tool_calls: list | None = None,
        tokens_used: int = 0,
        duration_ms: int | None = None,
    ):
        """Record a single pipeline step."""
        self.step_counter += 1
        self.total_tokens += tokens_used

        try:
            async with self.db_pool.acquire() as conn:
                await conn.execute(
                    """
                    INSERT INTO execution_traces
                        (id, tenant_id, alert_id, agent_name, trace_id,
                         step_number, step_type, input_data, output_data,
                         tool_calls, tokens_used, duration_ms)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9::jsonb, $10::jsonb, $11, $12)
                    """,
                    str(uuid.uuid4()),
                    self.tenant_id,
                    self.alert_id,
                    self.agent_name,
                    self.trace_id,
                    self.step_counter,
                    step_type,
                    json.dumps(input_data or {}),
                    json.dumps(output_data or {}),
                    json.dumps(tool_calls or []),
                    tokens_used,
                    duration_ms,
                )
        except Exception as e:
            logger.warning("tracer.log_step.failed", trace_id=self.trace_id, step=step_type, error=str(e))


class StepTimer:
    """Context manager to measure step duration in milliseconds."""

    def __init__(self):
        self.duration_ms: int = 0

    def __enter__(self):
        self._start = time.perf_counter()
        return self

    def __exit__(self, *_):
        self.duration_ms = int((time.perf_counter() - self._start) * 1000)
