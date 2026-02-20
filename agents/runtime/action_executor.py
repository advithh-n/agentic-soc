"""Action Executor — executes approved response actions via integration adapters.

Responsibilities:
  1. Execute individual approved actions by dispatching to the correct adapter
  2. Execute all auto-approved actions after critic review (post-critic hook)
  3. Poll loop for human-approved actions (picked up within 10s)
  4. Track execution outcome in response_actions table
  5. Log every step to execution_traces via ExecutionTracer
  6. Prevent double-execution via SELECT ... FOR UPDATE SKIP LOCKED

Status transitions: approved → executing → executed | failed | rolled_back
"""

import asyncio
import json
import uuid
from datetime import datetime, timezone

import asyncpg
import structlog

from runtime.execution_tracer import ExecutionTracer, StepTimer
from runtime.integrations.base import get_adapter, AdapterResult

logger = structlog.get_logger()


class ActionExecutor:
    """Core execution engine for response actions."""

    def __init__(self, db_pool: asyncpg.Pool):
        self.db_pool = db_pool
        self.stats = {
            "actions_executed": 0,
            "actions_failed": 0,
        }

    async def execute_action(self, action_id: str, tenant_id: str | None = None) -> bool:
        """Execute a single approved action.

        Uses SELECT ... FOR UPDATE SKIP LOCKED to prevent double-execution.
        Returns True if executed successfully.
        """
        async with self.db_pool.acquire() as conn:
            # Atomic lock + fetch
            row = await conn.fetchrow(
                """
                SELECT id, tenant_id, alert_id, incident_id, action_type,
                       parameters, risk_level, status
                FROM response_actions
                WHERE id = $1 AND status = 'approved'
                FOR UPDATE SKIP LOCKED
                """,
                action_id,
            )

            if not row:
                logger.debug("executor.skip", action_id=action_id, reason="not approved or locked")
                return False

            action_type = row["action_type"]
            params = row["parameters"] if isinstance(row["parameters"], dict) else json.loads(row["parameters"] or "{}")
            t_id = str(row["tenant_id"])
            alert_id = str(row["alert_id"]) if row["alert_id"] else None

            # Set status to executing
            await conn.execute(
                "UPDATE response_actions SET status = 'executing' WHERE id = $1",
                action_id,
            )

        # Create tracer for audit trail
        tracer = ExecutionTracer(
            self.db_pool, t_id,
            alert_id or str(action_id),
            agent_name="action_executor",
        )

        await tracer.log_step(
            "action_start",
            input_data={"action_id": str(action_id), "action_type": action_type, "params": params},
        )

        # Dispatch to adapter
        adapter = get_adapter(action_type)
        if not adapter:
            await self._mark_failed(action_id, f"No adapter registered for {action_type}")
            await tracer.log_step("action_failed", output_data={"error": f"No adapter for {action_type}"})
            self.stats["actions_failed"] += 1
            return False

        with StepTimer() as timer:
            try:
                result: AdapterResult = await adapter.execute(action_type, params)
            except Exception as e:
                await self._mark_failed(action_id, str(e))
                await tracer.log_step("action_error", output_data={"error": str(e)}, duration_ms=timer.duration_ms)
                self.stats["actions_failed"] += 1
                return False

        if result.success:
            await self._mark_executed(action_id, result)
            await tracer.log_step(
                "action_executed",
                output_data=result.details,
                duration_ms=timer.duration_ms,
            )
            self.stats["actions_executed"] += 1
            logger.info(
                "executor.action_executed",
                action_id=str(action_id),
                action_type=action_type,
                duration_ms=timer.duration_ms,
            )
            return True
        else:
            await self._mark_failed(action_id, result.error or "Adapter returned failure")
            await tracer.log_step(
                "action_failed",
                output_data={"error": result.error, "details": result.details},
                duration_ms=timer.duration_ms,
            )
            self.stats["actions_failed"] += 1
            return False

    async def execute_approved_for_alert(self, alert_id: str) -> int:
        """Execute all auto-approved actions for an alert (post-critic hook).

        Returns count of successfully executed actions.
        """
        async with self.db_pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT id FROM response_actions
                WHERE alert_id = $1 AND status = 'approved'
                ORDER BY created_at ASC
                """,
                alert_id,
            )

        if not rows:
            return 0

        executed = 0
        for row in rows:
            ok = await self.execute_action(str(row["id"]))
            if ok:
                executed += 1

        logger.info(
            "executor.batch_complete",
            alert_id=alert_id,
            executed=executed,
            total=len(rows),
        )
        return executed

    async def poll_loop(self, interval: int = 10) -> None:
        """Background loop — picks up human-approved actions every `interval` seconds."""
        logger.info("executor.poll_loop_started", interval=interval)
        while True:
            try:
                async with self.db_pool.acquire() as conn:
                    rows = await conn.fetch(
                        """
                        SELECT id FROM response_actions
                        WHERE status = 'approved'
                        ORDER BY created_at ASC
                        LIMIT 10
                        """,
                    )

                for row in rows:
                    await self.execute_action(str(row["id"]))

            except asyncpg.exceptions.ConnectionDoesNotExistError:
                logger.warning("executor.poll_db_disconnected")
            except Exception as e:
                logger.error("executor.poll_error", error=str(e))

            await asyncio.sleep(interval)

    # ─── Internal helpers ──────────────────────────────────

    async def _mark_executed(self, action_id: str, result: AdapterResult) -> None:
        """Update action to executed status with outcome."""
        outcome = {
            "status": "executed",
            "details": result.details,
            "executed_at": datetime.now(timezone.utc).isoformat(),
        }
        rollback = None
        if result.rollback_params:
            rollback = json.dumps(result.rollback_params)

        async with self.db_pool.acquire() as conn:
            await conn.execute(
                """
                UPDATE response_actions
                SET status = 'executed',
                    outcome = $1::jsonb,
                    executed_at = NOW(),
                    rollback_action = COALESCE($2::jsonb, rollback_action)
                WHERE id = $3
                """,
                json.dumps(outcome),
                rollback,
                action_id,
            )

    async def _mark_failed(self, action_id: str, error: str) -> None:
        """Update action to failed status."""
        outcome = {
            "status": "failed",
            "error": error,
            "failed_at": datetime.now(timezone.utc).isoformat(),
        }
        async with self.db_pool.acquire() as conn:
            await conn.execute(
                """
                UPDATE response_actions
                SET status = 'failed',
                    outcome = $1::jsonb
                WHERE id = $2
                """,
                json.dumps(outcome),
                action_id,
            )
