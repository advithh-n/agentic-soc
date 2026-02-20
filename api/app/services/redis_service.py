"""Redis client for streams, cache, and pub/sub."""

import json
from datetime import datetime
from typing import Any
from uuid import UUID

import redis.asyncio as aioredis
import structlog

from app.config import settings

logger = structlog.get_logger()

redis_client = aioredis.from_url(
    settings.redis_url,
    decode_responses=True,
    max_connections=20,
)


class UUIDEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, UUID):
            return str(obj)
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super().default(obj)


async def publish_event(
    stream: str,
    tenant_id: str,
    source: str,
    event_type: str,
    severity_hint: str,
    raw_payload: dict[str, Any],
    trace_id: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> str:
    """Publish a security event to a Redis Stream.

    Returns the stream entry ID.
    Uses MAXLEN ~ 100000 for approximate trimming.
    """
    event = {
        "tenant_id": tenant_id,
        "source": source,
        "event_type": event_type,
        "severity_hint": severity_hint,
        "timestamp": datetime.utcnow().isoformat(),
        "raw_payload": json.dumps(raw_payload, cls=UUIDEncoder),
        "trace_id": trace_id or "",
        "metadata": json.dumps(metadata or {}, cls=UUIDEncoder),
    }

    entry_id = await redis_client.xadd(
        stream,
        event,
        maxlen=100000,
        approximate=True,
    )

    logger.info(
        "event.published",
        stream=stream,
        entry_id=entry_id,
        source=source,
        event_type=event_type,
        tenant_id=tenant_id,
    )

    return entry_id


async def publish_alert_for_triage(
    tenant_id: str,
    alert_id: str,
    severity: str,
    source: str,
    event_type: str,
) -> str:
    """Publish an alert to the triage queue for agent processing."""
    return await redis_client.xadd(
        f"soc:alerts:triage",
        {
            "tenant_id": tenant_id,
            "alert_id": alert_id,
            "severity": severity,
            "source": source,
            "event_type": event_type,
            "timestamp": datetime.utcnow().isoformat(),
        },
        maxlen=10000,
        approximate=True,
    )
