"""Webhook ingestion routes — receives events from external sources."""

import hashlib
import hmac
from uuid import uuid4

import structlog
from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.services.database import get_db
from app.services.redis_service import publish_event

logger = structlog.get_logger()
router = APIRouter()


# ─── Schemas ───────────────────────────────────────────────

class GenericWebhookPayload(BaseModel):
    source: str
    event_type: str
    severity_hint: str = "medium"
    payload: dict


# ─── Helpers ───────────────────────────────────────────────

def verify_stripe_signature(payload: bytes, sig_header: str, secret: str) -> bool:
    """Verify Stripe webhook signature (v1)."""
    try:
        elements = dict(item.split("=", 1) for item in sig_header.split(","))
        timestamp = elements.get("t", "")
        signature = elements.get("v1", "")

        signed_payload = f"{timestamp}.{payload.decode()}"
        expected = hmac.HMAC(
            secret.encode(), signed_payload.encode(), hashlib.sha256
        ).hexdigest()

        return hmac.compare_digest(expected, signature)
    except Exception:
        return False


# ─── Routes ────────────────────────────────────────────────

@router.post("/stripe")
async def ingest_stripe(
    request: Request,
    stripe_signature: str = Header(None, alias="Stripe-Signature"),
):
    """Receive Stripe webhooks and publish to Redis Stream.

    Handles: charge.succeeded, charge.failed, charge.dispute.created,
    radar.early_fraud_warning.created, etc.
    """
    body = await request.body()

    # Verify signature in production
    if settings.stripe_webhook_secret and stripe_signature:
        if not verify_stripe_signature(body, stripe_signature, settings.stripe_webhook_secret):
            raise HTTPException(status_code=401, detail="Invalid Stripe signature")

    import json
    payload = json.loads(body)

    event_type = payload.get("type", "unknown")
    trace_id = f"stripe-{payload.get('id', uuid4().hex[:12])}"

    # Determine severity hint based on event type
    severity_map = {
        "charge.dispute.created": "high",
        "radar.early_fraud_warning.created": "high",
        "charge.failed": "medium",
        "charge.succeeded": "low",
    }
    severity = severity_map.get(event_type, "medium")

    # Default tenant for now — in multi-tenant mode, resolve from webhook URL or header
    tenant_id = "a0000000-0000-0000-0000-000000000001"

    entry_id = await publish_event(
        stream=f"{tenant_id}:streams:stripe",
        tenant_id=tenant_id,
        source="stripe",
        event_type=event_type,
        severity_hint=severity,
        raw_payload=payload,
        trace_id=trace_id,
    )

    logger.info("stripe.webhook.ingested", event_type=event_type, trace_id=trace_id)

    return {"received": True, "trace_id": trace_id, "stream_id": entry_id}


@router.post("/clerk")
async def ingest_clerk(request: Request):
    """Receive Clerk authentication webhooks."""
    body = await request.body()
    import json
    payload = json.loads(body)

    event_type = payload.get("type", "unknown")
    trace_id = f"clerk-{payload.get('data', {}).get('id', uuid4().hex[:12])}"

    severity_map = {
        "session.created": "low",
        "user.created": "low",
        "session.revoked": "medium",
        "user.deleted": "medium",
    }
    severity = severity_map.get(event_type, "low")

    tenant_id = "a0000000-0000-0000-0000-000000000001"

    entry_id = await publish_event(
        stream=f"{tenant_id}:streams:auth",
        tenant_id=tenant_id,
        source="clerk",
        event_type=event_type,
        severity_hint=severity,
        raw_payload=payload,
        trace_id=trace_id,
    )

    return {"received": True, "trace_id": trace_id, "stream_id": entry_id}


@router.post("/aws")
async def ingest_aws(request: Request):
    """Receive AWS CloudTrail events via SNS."""
    body = await request.body()
    import json
    payload = json.loads(body)

    # SNS sends a SubscriptionConfirmation first
    if payload.get("Type") == "SubscriptionConfirmation":
        # Auto-confirm (in production, validate the topic ARN)
        import httpx
        async with httpx.AsyncClient() as client:
            await client.get(payload["SubscribeURL"])
        return {"confirmed": True}

    event_type = "cloudtrail"
    trace_id = f"aws-{uuid4().hex[:12]}"
    tenant_id = "a0000000-0000-0000-0000-000000000001"

    entry_id = await publish_event(
        stream=f"{tenant_id}:streams:infra",
        tenant_id=tenant_id,
        source="aws",
        event_type=event_type,
        severity_hint="medium",
        raw_payload=payload,
        trace_id=trace_id,
    )

    return {"received": True, "trace_id": trace_id, "stream_id": entry_id}


@router.post("/wazuh")
async def ingest_wazuh(request: Request):
    """Receive Wazuh alert webhooks."""
    body = await request.body()
    import json
    payload = json.loads(body)

    rule_level = payload.get("rule", {}).get("level", 5)
    severity = "low" if rule_level < 7 else "medium" if rule_level < 10 else "high" if rule_level < 13 else "critical"

    trace_id = f"wazuh-{payload.get('id', uuid4().hex[:12])}"
    tenant_id = "a0000000-0000-0000-0000-000000000001"

    entry_id = await publish_event(
        stream=f"{tenant_id}:streams:infra",
        tenant_id=tenant_id,
        source="wazuh",
        event_type=payload.get("rule", {}).get("description", "wazuh_alert"),
        severity_hint=severity,
        raw_payload=payload,
        trace_id=trace_id,
    )

    return {"received": True, "trace_id": trace_id, "stream_id": entry_id}


@router.post("/langfuse")
async def ingest_langfuse(request: Request):
    """Receive Langfuse trace events for AI agent monitoring."""
    body = await request.body()
    import json
    payload = json.loads(body)

    trace_id = f"langfuse-{payload.get('id', uuid4().hex[:12])}"
    tenant_id = "a0000000-0000-0000-0000-000000000001"

    entry_id = await publish_event(
        stream=f"{tenant_id}:streams:ai",
        tenant_id=tenant_id,
        source="langfuse",
        event_type="ai_trace",
        severity_hint="low",
        raw_payload=payload,
        trace_id=trace_id,
    )

    return {"received": True, "trace_id": trace_id, "stream_id": entry_id}


@router.post("/guardrails")
async def ingest_guardrails(request: Request):
    """Receive NeMo Guardrails block events."""
    body = await request.body()
    import json
    payload = json.loads(body)

    trace_id = f"guardrails-{uuid4().hex[:12]}"
    tenant_id = "a0000000-0000-0000-0000-000000000001"

    entry_id = await publish_event(
        stream=f"{tenant_id}:streams:ai",
        tenant_id=tenant_id,
        source="nemo_guardrails",
        event_type=payload.get("event_type", "guardrail_block"),
        severity_hint="high",
        raw_payload=payload,
        trace_id=trace_id,
    )

    return {"received": True, "trace_id": trace_id, "stream_id": entry_id}


@router.post("/generic")
async def ingest_generic(
    payload: GenericWebhookPayload,
):
    """Generic webhook receiver — tenant-configurable."""
    trace_id = f"generic-{uuid4().hex[:12]}"
    tenant_id = "a0000000-0000-0000-0000-000000000001"

    stream_map = {
        "stripe": "streams:stripe",
        "clerk": "streams:auth",
        "aws": "streams:infra",
        "wazuh": "streams:infra",
        "langfuse": "streams:ai",
    }
    stream = f"{tenant_id}:{stream_map.get(payload.source, 'streams:generic')}"

    entry_id = await publish_event(
        stream=stream,
        tenant_id=tenant_id,
        source=payload.source,
        event_type=payload.event_type,
        severity_hint=payload.severity_hint,
        raw_payload=payload.payload,
        trace_id=trace_id,
    )

    return {"received": True, "trace_id": trace_id, "stream_id": entry_id}
