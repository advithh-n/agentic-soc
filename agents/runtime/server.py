"""Agent runtime — consumer loop + health API.

Reads alerts from the Redis triage queue, runs the triage agent,
and writes results back to PostgreSQL.
"""

import asyncio
import json
import os
import signal
import sys

import asyncpg
import redis.asyncio as aioredis
import structlog
import uvicorn
from fastapi import FastAPI
from pydantic_settings import BaseSettings

from runtime.triage_agent import triage_alert
from runtime.investigation_agent import investigate_alert
from runtime.critic_agent import review_investigation
from runtime.slack_notifier import notify_alert, is_configured as slack_configured
from runtime.integrations.registry import register_all_adapters
from runtime.action_executor import ActionExecutor
from runtime.playbook_engine import PlaybookEngine
from runtime.tools import is_llm_available

logger = structlog.get_logger()


class AgentSettings(BaseSettings):
    database_url: str = "postgresql+asyncpg://soc_admin:changeme@localhost:5432/agentic_soc"
    redis_url: str = "redis://:changeme@localhost:6379/0"
    log_level: str = "INFO"
    consumer_group: str = "agent-runtime"
    consumer_name: str = f"agent-{os.getpid()}"
    batch_size: int = 5
    block_ms: int = 5000
    triage_stream: str = "soc:alerts:triage"
    anthropic_api_key: str = ""

    model_config = {"env_file": ".env", "extra": "ignore"}


settings = AgentSettings()

# Health API
health_app = FastAPI(title="Agentic SOC — Agent Runtime")
agent_stats = {
    "status": "starting",
    "alerts_triaged": 0,
    "verdicts": {"true_positive": 0, "false_positive": 0, "needs_investigation": 0},
    "escalations": 0,
    "investigations": 0,
    "incidents_created": 0,
    "critic_reviews": 0,
    "actions_approved": 0,
    "actions_denied": 0,
    "actions_escalated": 0,
    "actions_executed": 0,
    "actions_failed": 0,
    "playbooks_run": 0,
    "mode": "pending",  # Updated at startup after is_llm_available() check
}


@health_app.get("/health")
async def health():
    return agent_stats


class AgentRuntime:
    """Consumer loop — reads from triage queue, runs agent, writes results."""

    def __init__(self):
        self.redis: aioredis.Redis | None = None
        self.db_pool: asyncpg.Pool | None = None
        self.running = False
        self.executor: ActionExecutor | None = None
        self.playbook_engine: PlaybookEngine | None = None

    def _get_pg_dsn(self) -> str:
        return settings.database_url.replace("postgresql+asyncpg://", "postgresql://")

    async def start(self):
        """Initialize connections."""
        self.redis = aioredis.from_url(settings.redis_url, decode_responses=True)
        await self.redis.ping()
        logger.info("redis.connected")

        self.db_pool = await asyncpg.create_pool(
            self._get_pg_dsn(), min_size=2, max_size=5,
        )
        logger.info("postgres.pool_created")

        # Create consumer group
        try:
            await self.redis.xgroup_create(
                settings.triage_stream, settings.consumer_group,
                id="0", mkstream=True,
            )
            logger.info("triage.group_created", stream=settings.triage_stream)
        except aioredis.ResponseError as e:
            if "BUSYGROUP" not in str(e):
                raise

        # Initialize response automation
        register_all_adapters()
        self.executor = ActionExecutor(self.db_pool)
        self.playbook_engine = PlaybookEngine(self.db_pool, self.executor)
        logger.info("executor.initialized")

        self.running = True
        agent_stats["status"] = "running"
        agent_stats["mode"] = "llm" if is_llm_available() else "rule_based"
        logger.info(
            "agent.started",
            mode=agent_stats["mode"],
            stream=settings.triage_stream,
        )

    async def consume_loop(self):
        """Main consumer loop — reads alerts from triage queue."""
        while self.running:
            try:
                results = await self.redis.xreadgroup(
                    groupname=settings.consumer_group,
                    consumername=settings.consumer_name,
                    streams={settings.triage_stream: ">"},
                    count=settings.batch_size,
                    block=settings.block_ms,
                )

                if not results:
                    continue

                for stream_key, messages in results:
                    for msg_id, fields in messages:
                        await self._process_triage_message(msg_id, fields)
                        await self.redis.xack(
                            settings.triage_stream,
                            settings.consumer_group,
                            msg_id,
                        )

            except aioredis.ConnectionError:
                logger.error("redis.disconnected, retrying in 5s")
                await asyncio.sleep(5)
            except Exception as e:
                logger.error("agent.error", error=str(e))
                await asyncio.sleep(1)

    async def _process_triage_message(self, msg_id: str, fields: dict):
        """Process a single triage queue message."""
        alert_id = fields.get("alert_id")
        tenant_id = fields.get("tenant_id")

        if not alert_id:
            logger.warning("triage.missing_alert_id", msg_id=msg_id)
            return

        logger.info("triage.processing", alert_id=alert_id)

        # Fetch full alert from PostgreSQL
        alert = await self._fetch_alert(alert_id)
        if not alert:
            logger.warning("triage.alert_not_found", alert_id=alert_id)
            return

        # Run triage agent
        try:
            result = await triage_alert(alert)
        except Exception as e:
            logger.error("triage.agent_error", alert_id=alert_id, error=str(e))
            return

        # Write triage result back to PostgreSQL
        await self._update_alert_triage(alert_id, result.to_dict())

        # Publish triage event to WebSocket live feed
        ws_payload = json.dumps({
            "type": "triage",
            "data": {
                "alert_id": alert_id,
                "verdict": result.verdict.value,
                "severity_adjusted": result.severity_adjusted,
                "confidence": result.confidence,
                "recommended_action": result.recommended_action,
                "escalate": result.escalate,
            },
        })
        await self.redis.publish(
            f"soc:{tenant_id}:alerts:live", ws_payload
        )

        # Update stats
        agent_stats["alerts_triaged"] += 1
        agent_stats["verdicts"][result.verdict.value] = (
            agent_stats["verdicts"].get(result.verdict.value, 0) + 1
        )
        if result.escalate:
            agent_stats["escalations"] += 1

        # Slack notification for HIGH/CRITICAL true positives
        if (
            result.verdict.value == "true_positive"
            and result.severity_adjusted in ("high", "critical")
            and slack_configured()
        ):
            await notify_alert(alert, result.to_dict(), self.db_pool)

        logger.info(
            "triage.completed",
            alert_id=alert_id,
            verdict=result.verdict.value,
            severity=f"{alert.get('severity')} → {result.severity_adjusted}",
            escalate=result.escalate,
            action=result.recommended_action,
        )

        # Investigation — triggered for escalated HIGH/CRITICAL alerts
        if result.escalate and result.severity_adjusted in ("high", "critical"):
            try:
                await self._update_alert_investigation(alert_id, status="investigating")
                inv_result = await investigate_alert(alert, result.to_dict(), self.db_pool)
                await self._update_alert_investigation(
                    alert_id,
                    status="investigating",
                    incident_id=inv_result.incident_id,
                    investigation_result=inv_result.to_dict(),
                )
                agent_stats["investigations"] += 1
                if inv_result.incident_created:
                    agent_stats["incidents_created"] += 1

                # Critic review — runs when investigation proposes actions
                if inv_result.requires_critic_review or inv_result.response_actions:
                    try:
                        critic_result = await review_investigation(
                            inv_result.to_dict(), self.db_pool, alert["tenant_id"], alert_id,
                        )
                        agent_stats["critic_reviews"] += 1
                        agent_stats["actions_approved"] += critic_result.actions_approved
                        agent_stats["actions_denied"] += critic_result.actions_denied
                        agent_stats["actions_escalated"] += critic_result.actions_escalated

                        # Post-critic hook: execute auto-approved actions
                        if critic_result.actions_approved > 0 and self.executor:
                            prev_failed = self.executor.stats["actions_failed"]
                            executed = await self.executor.execute_approved_for_alert(alert_id)
                            agent_stats["actions_executed"] += executed
                            new_failures = self.executor.stats["actions_failed"] - prev_failed
                            agent_stats["actions_failed"] += new_failures
                    except Exception as e:
                        logger.error("critic.agent_error", alert_id=alert_id, error=str(e))

            except Exception as e:
                logger.error("investigation.agent_error", alert_id=alert_id, error=str(e))

    async def _fetch_alert(self, alert_id: str) -> dict | None:
        """Fetch full alert details from PostgreSQL."""
        async with self.db_pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                SELECT id, tenant_id, source, event_type, severity, confidence,
                       status, title, description, raw_payload, artifacts,
                       mitre_technique, atlas_technique, trace_id, created_at
                FROM alerts WHERE id = $1
                """,
                alert_id,  # asyncpg handles UUID string
            )
            if not row:
                return None

            return {
                "id": str(row["id"]),
                "tenant_id": str(row["tenant_id"]),
                "source": row["source"],
                "event_type": row["event_type"],
                "severity": row["severity"],
                "confidence": row["confidence"],
                "status": row["status"],
                "title": row["title"],
                "description": row["description"],
                "raw_payload": row["raw_payload"],
                "artifacts": row["artifacts"],
                "mitre_technique": row["mitre_technique"],
                "trace_id": row["trace_id"],
                "created_at": row["created_at"].isoformat() if row["created_at"] else None,
            }

    async def _update_alert_triage(self, alert_id: str, triage_result: dict):
        """Write triage result back to the alert."""
        async with self.db_pool.acquire() as conn:
            await conn.execute(
                """
                UPDATE alerts
                SET triage_result = $1::jsonb,
                    status = CASE
                        WHEN $2 = 'true_positive' THEN 'triaged'
                        WHEN $2 = 'false_positive' THEN 'false_positive'
                        ELSE 'triaged'
                    END,
                    triaged_at = NOW()
                WHERE id = $3
                """,
                json.dumps(triage_result),
                triage_result["verdict"],
                alert_id,
            )

    async def _update_alert_investigation(
        self,
        alert_id: str,
        status: str = "investigating",
        incident_id: str | None = None,
        investigation_result: dict | None = None,
    ):
        """Update alert with investigation status and link to incident."""
        async with self.db_pool.acquire() as conn:
            if investigation_result and incident_id:
                await conn.execute(
                    """
                    UPDATE alerts
                    SET status = $1,
                        incident_id = $2,
                        enrichment = COALESCE(enrichment, '{}'::jsonb) || $3::jsonb
                    WHERE id = $4
                    """,
                    status,
                    incident_id,
                    json.dumps({"investigation": investigation_result}),
                    alert_id,
                )
            else:
                await conn.execute(
                    "UPDATE alerts SET status = $1 WHERE id = $2",
                    status,
                    alert_id,
                )

    async def playbook_consumer_loop(self):
        """Consume playbook run requests from Redis stream soc:playbook:run."""
        stream = "soc:playbook:run"
        group = "agent-runtime"
        consumer = f"pb-{os.getpid()}"

        # Create consumer group
        try:
            await self.redis.xgroup_create(stream, group, id="0", mkstream=True)
        except aioredis.ResponseError as e:
            if "BUSYGROUP" not in str(e):
                raise

        logger.info("playbook.consumer_started", stream=stream)

        while self.running:
            try:
                results = await self.redis.xreadgroup(
                    groupname=group, consumername=consumer,
                    streams={stream: ">"}, count=1, block=5000,
                )
                if not results:
                    continue

                for _, messages in results:
                    for msg_id, fields in messages:
                        try:
                            playbook_name = fields.get("playbook_name")
                            incident_id = fields.get("incident_id")
                            tenant_id = fields.get("tenant_id")
                            context = json.loads(fields.get("context", "{}"))

                            if self.playbook_engine and playbook_name and incident_id:
                                result = await self.playbook_engine.run_playbook(
                                    playbook_name, incident_id, tenant_id, context,
                                )
                                agent_stats["playbooks_run"] += 1
                                agent_stats["actions_executed"] += result.actions_executed
                                logger.info(
                                    "playbook.executed",
                                    playbook=playbook_name,
                                    created=result.actions_created,
                                    executed=result.actions_executed,
                                )
                        except Exception as e:
                            logger.error("playbook.consumer_error", msg_id=msg_id, error=str(e))

                        await self.redis.xack(stream, group, msg_id)

            except aioredis.ConnectionError:
                await asyncio.sleep(5)
            except Exception as e:
                logger.error("playbook.loop_error", error=str(e))
                await asyncio.sleep(1)

    async def stop(self):
        """Graceful shutdown."""
        self.running = False
        if self.redis:
            await self.redis.aclose()
        if self.db_pool:
            await self.db_pool.close()
        agent_stats["status"] = "stopped"
        logger.info("agent.stopped")


async def main():
    runtime = AgentRuntime()

    loop = asyncio.get_event_loop()
    if sys.platform != "win32":
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, lambda: asyncio.create_task(runtime.stop()))

    await runtime.start()

    health_server = uvicorn.Server(
        uvicorn.Config(health_app, host="0.0.0.0", port=8070, log_level="warning")
    )

    try:
        await asyncio.gather(
            runtime.consume_loop(),
            runtime.executor.poll_loop(interval=10),
            runtime.playbook_consumer_loop(),
            health_server.serve(),
        )
    except (KeyboardInterrupt, SystemExit):
        await runtime.stop()


if __name__ == "__main__":
    asyncio.run(main())
