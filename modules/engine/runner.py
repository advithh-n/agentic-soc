"""Module engine runner — Redis Stream consumer loop.

This is the main entry point for the module-engine container.
It reads from Redis Streams, dispatches events to modules, and
writes generated alerts to PostgreSQL.
"""

import asyncio
import json
import os
import signal
import sys
from datetime import datetime
from uuid import UUID

import asyncpg
import redis.asyncio as aioredis
import structlog
from fastapi import FastAPI
from pydantic_settings import BaseSettings
import uvicorn

from engine.models import AlertModel, StreamEvent
from engine.registry import build_registry

logger = structlog.get_logger()


class ModuleSettings(BaseSettings):
    database_url: str = "postgresql+asyncpg://soc_admin:changeme@localhost:5432/agentic_soc"
    redis_url: str = "redis://:changeme@localhost:6379/0"
    log_level: str = "INFO"
    consumer_group: str = "module-engine"
    consumer_name: str = f"consumer-{os.getpid()}"
    batch_size: int = 10
    block_ms: int = 5000
    default_tenant: str = "a0000000-0000-0000-0000-000000000001"

    model_config = {"env_file": ".env", "extra": "ignore"}


settings = ModuleSettings()

# Health check API
health_app = FastAPI()
engine_stats = {"status": "starting", "modules": [], "events_processed": 0}


@health_app.get("/health")
async def health():
    return engine_stats


class ModuleEngine:
    """Main consumer loop — reads streams, dispatches to modules, writes alerts."""

    def __init__(self):
        self.registry = build_registry()
        self.redis: aioredis.Redis | None = None
        self.db_pool: asyncpg.Pool | None = None
        self.running = False

    def _get_pg_dsn(self) -> str:
        """Convert SQLAlchemy URL to plain PostgreSQL DSN for asyncpg."""
        return settings.database_url.replace("postgresql+asyncpg://", "postgresql://")

    async def start(self):
        """Initialize connections and start consuming."""
        # Redis connection
        self.redis = aioredis.from_url(settings.redis_url, decode_responses=True)
        await self.redis.ping()
        logger.info("redis.connected")

        # PostgreSQL connection pool (reused across all alert writes)
        self.db_pool = await asyncpg.create_pool(
            self._get_pg_dsn(),
            min_size=2,
            max_size=10,
        )
        logger.info("postgres.pool_created")

        # Startup hooks for all modules
        for module in self.registry.modules:
            await module.on_startup()

        # Create consumer groups for all streams
        tenant = settings.default_tenant
        for stream_suffix in self.registry.all_streams:
            stream_key = f"{tenant}:{stream_suffix}"
            try:
                await self.redis.xgroup_create(
                    stream_key, settings.consumer_group, id="0", mkstream=True
                )
                logger.info("stream.group_created", stream=stream_key)
            except aioredis.ResponseError as e:
                if "BUSYGROUP" in str(e):
                    pass  # Group already exists
                else:
                    raise

        self.running = True
        engine_stats["status"] = "running"
        engine_stats["modules"] = [m.stats for m in self.registry.modules]

        logger.info("engine.started", modules=len(self.registry.modules))

    async def consume_loop(self):
        """Main consumer loop — reads from all streams."""
        tenant = settings.default_tenant
        streams = {
            f"{tenant}:{s}": ">" for s in self.registry.all_streams
        }

        while self.running:
            try:
                results = await self.redis.xreadgroup(
                    groupname=settings.consumer_group,
                    consumername=settings.consumer_name,
                    streams=streams,
                    count=settings.batch_size,
                    block=settings.block_ms,
                )

                if not results:
                    continue

                for stream_key, messages in results:
                    # Extract stream suffix (e.g., "streams:stripe" from "tenant:streams:stripe")
                    parts = stream_key.split(":", 1)
                    stream_suffix = parts[1] if len(parts) > 1 else stream_key

                    modules = self.registry.get_modules_for_stream(stream_suffix)

                    for msg_id, fields in messages:
                        event = self._parse_event(msg_id, fields)
                        if not event:
                            await self.redis.xack(stream_key, settings.consumer_group, msg_id)
                            continue

                        for module in modules:
                            try:
                                alerts = await module.process_event(event)
                                module.event_count += 1

                                for alert in alerts:
                                    await self._write_alert(alert)
                                    module.alert_count += 1

                            except Exception as e:
                                module.error_count += 1
                                logger.error(
                                    "module.error",
                                    module=module.name,
                                    error=str(e),
                                    event_id=msg_id,
                                )

                        # ACK after all modules have processed
                        await self.redis.xack(stream_key, settings.consumer_group, msg_id)
                        engine_stats["events_processed"] += 1

                # Update stats
                engine_stats["modules"] = [m.stats for m in self.registry.modules]

            except aioredis.ConnectionError:
                logger.error("redis.disconnected, retrying in 5s")
                await asyncio.sleep(5)
            except Exception as e:
                logger.error("engine.error", error=str(e))
                await asyncio.sleep(1)

    def _parse_event(self, entry_id: str, fields: dict) -> StreamEvent | None:
        """Parse a Redis Stream entry into a StreamEvent."""
        try:
            raw = fields.get("raw_payload", "{}")
            meta = fields.get("metadata", "{}")
            return StreamEvent(
                entry_id=entry_id,
                tenant_id=fields.get("tenant_id", ""),
                source=fields.get("source", ""),
                event_type=fields.get("event_type", ""),
                severity_hint=fields.get("severity_hint", "medium"),
                timestamp=fields.get("timestamp", datetime.utcnow().isoformat()),
                raw_payload=json.loads(raw) if isinstance(raw, str) else raw,
                trace_id=fields.get("trace_id", ""),
                metadata=json.loads(meta) if isinstance(meta, str) else meta,
            )
        except Exception as e:
            logger.error("event.parse_error", entry_id=entry_id, error=str(e))
            return None

    async def _write_alert(self, alert: AlertModel):
        """Write an alert to PostgreSQL (pooled) and publish to triage queue."""
        async with self.db_pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO alerts
                    (id, tenant_id, source, event_type, severity, confidence,
                     title, description, raw_payload, artifacts,
                     mitre_technique, atlas_technique, trace_id)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
                """,
                alert.id,
                UUID(alert.tenant_id),
                alert.source,
                alert.event_type,
                alert.severity.value,
                alert.confidence,
                alert.title,
                alert.description,
                json.dumps(alert.raw_payload) if alert.raw_payload else None,
                json.dumps([a.model_dump() for a in alert.artifacts]),
                alert.mitre_technique,
                alert.atlas_technique,
                alert.trace_id,
            )

        # Publish to triage queue if severity warrants agent attention
        if alert.severity.value in ("medium", "high", "critical"):
            await self.redis.xadd(
                "soc:alerts:triage",
                {
                    "tenant_id": alert.tenant_id,
                    "alert_id": str(alert.id),
                    "severity": alert.severity.value,
                    "source": alert.source,
                    "event_type": alert.event_type,
                    "timestamp": alert.created_at.isoformat(),
                },
                maxlen=10000,
                approximate=True,
            )

        # Publish to WebSocket live feed via Redis pub/sub
        ws_payload = json.dumps({
            "type": "alert",
            "data": {
                "id": str(alert.id),
                "title": alert.title,
                "severity": alert.severity.value,
                "source": alert.source,
                "event_type": alert.event_type,
                "confidence": alert.confidence,
                "mitre_technique": alert.mitre_technique,
                "atlas_technique": alert.atlas_technique,
                "created_at": alert.created_at.isoformat(),
            },
        })
        await self.redis.publish(
            f"soc:{alert.tenant_id}:alerts:live", ws_payload
        )

        logger.info(
            "alert.created",
            alert_id=str(alert.id),
            severity=alert.severity.value,
            source=alert.source,
            title=alert.title,
        )

    async def stop(self):
        """Graceful shutdown."""
        self.running = False
        for module in self.registry.modules:
            await module.on_shutdown()
        if self.redis:
            await self.redis.aclose()
        if self.db_pool:
            await self.db_pool.close()
        engine_stats["status"] = "stopped"
        logger.info("engine.stopped")


async def main():
    engine = ModuleEngine()

    # Signal handling for graceful shutdown
    loop = asyncio.get_event_loop()
    if sys.platform != "win32":
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, lambda: asyncio.create_task(engine.stop()))

    await engine.start()

    # Run health server and consumer loop concurrently
    health_server = uvicorn.Server(
        uvicorn.Config(health_app, host="0.0.0.0", port=8060, log_level="warning")
    )

    try:
        await asyncio.gather(
            engine.consume_loop(),
            health_server.serve(),
        )
    except (KeyboardInterrupt, SystemExit):
        await engine.stop()


if __name__ == "__main__":
    asyncio.run(main())
