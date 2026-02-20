"""Slack notification service — sends alert notifications via webhook.

Fires on:
  - TRUE_POSITIVE verdicts with HIGH or CRITICAL severity
  - Alerts that are escalated to investigation

Webhook URL resolution order:
  1. Database: tenants.settings->>'slack_webhook_url' (cached 5 minutes)
  2. Environment: SLACK_WEBHOOK_URL env var
  3. Not configured (gracefully skipped)
"""

import os
import time

import asyncpg
import httpx
import structlog

logger = structlog.get_logger()

SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL", "")

# In-memory cache for DB webhook URLs: {tenant_id: (url, timestamp)}
_webhook_cache: dict[str, tuple[str, float]] = {}
_CACHE_TTL = 300  # 5 minutes

SEVERITY_EMOJI = {
    "critical": ":rotating_light:",
    "high": ":warning:",
    "medium": ":large_yellow_circle:",
    "low": ":white_circle:",
}

VERDICT_COLOR = {
    "true_positive": "#ef4444",
    "needs_investigation": "#eab308",
    "false_positive": "#22c55e",
}


async def get_webhook_url(tenant_id: str, db_pool: asyncpg.Pool | None = None) -> str:
    """Get Slack webhook URL, checking DB first (cached), then env var."""
    now = time.time()

    # Check cache
    if tenant_id in _webhook_cache:
        cached_url, cached_at = _webhook_cache[tenant_id]
        if now - cached_at < _CACHE_TTL:
            return cached_url

    # Try DB lookup
    if db_pool:
        try:
            async with db_pool.acquire() as conn:
                row = await conn.fetchrow(
                    "SELECT settings->>'slack_webhook_url' AS url FROM tenants WHERE id = $1",
                    tenant_id,
                )
                if row and row["url"]:
                    _webhook_cache[tenant_id] = (row["url"], now)
                    return row["url"]
        except Exception as e:
            logger.warning("slack.db_lookup_failed", error=str(e))

    # Fallback to env var
    _webhook_cache[tenant_id] = (SLACK_WEBHOOK_URL, now)
    return SLACK_WEBHOOK_URL


def is_configured() -> bool:
    return bool(SLACK_WEBHOOK_URL)


async def notify_alert(
    alert: dict,
    triage_result: dict,
    db_pool: asyncpg.Pool | None = None,
) -> bool:
    """Send a Slack notification for a triaged alert.

    Returns True if notification was sent successfully.
    """
    tenant_id = alert.get("tenant_id", "")
    webhook_url = await get_webhook_url(tenant_id, db_pool) if tenant_id else SLACK_WEBHOOK_URL

    if not webhook_url:
        return False

    severity = triage_result.get("severity_adjusted", alert.get("severity", "medium"))
    verdict = triage_result.get("verdict", "unknown")
    emoji = SEVERITY_EMOJI.get(severity, ":grey_question:")
    color = VERDICT_COLOR.get(verdict, "#6b7280")

    title = alert.get("title", "Unknown Alert")
    source = alert.get("source", "unknown")
    event_type = alert.get("event_type", "unknown")
    reasoning = triage_result.get("reasoning", "No reasoning available")
    action = triage_result.get("recommended_action", "review")
    confidence = triage_result.get("confidence", 0)
    mitre = triage_result.get("mitre_techniques", [])

    # Extract IOC artifacts
    artifacts = alert.get("artifacts", [])
    if isinstance(artifacts, str):
        import json
        try:
            artifacts = json.loads(artifacts)
        except Exception:
            artifacts = []

    artifact_text = ""
    if artifacts:
        lines = [f"`{a['type']}`: `{a['value']}`" for a in artifacts[:5]]
        artifact_text = "\n".join(lines)

    # Build Slack message
    blocks = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"{emoji} SOC Alert: {severity.upper()}",
            },
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*{title}*\n`{source}` | `{event_type}`",
            },
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Verdict:*\n{verdict.replace('_', ' ').title()}"},
                {"type": "mrkdwn", "text": f"*Confidence:*\n{confidence:.0%}"},
                {"type": "mrkdwn", "text": f"*Severity:*\n{severity.upper()}"},
                {"type": "mrkdwn", "text": f"*Action:*\n{action.replace('_', ' ').title()}"},
            ],
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Reasoning:*\n>{reasoning}",
            },
        },
    ]

    if mitre:
        blocks.append({
            "type": "context",
            "elements": [
                {"type": "mrkdwn", "text": f"MITRE ATT&CK: {', '.join(mitre)}"},
            ],
        })

    if artifact_text:
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Indicators:*\n{artifact_text}",
            },
        })

    blocks.append({"type": "divider"})

    payload = {
        "text": f"{emoji} {severity.upper()} — {title}",
        "blocks": blocks,
    }

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(webhook_url, json=payload)
            if resp.status_code == 200:
                logger.info("slack.notification_sent", alert_id=alert.get("id"), severity=severity)
                return True
            else:
                logger.warning(
                    "slack.notification_failed",
                    status=resp.status_code,
                    body=resp.text[:200],
                )
                return False
    except Exception as e:
        logger.error("slack.notification_error", error=str(e))
        return False
