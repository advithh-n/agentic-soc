"""Notification adapter — wraps Slack webhook + PagerDuty mock.

Handles: notify_fraud_team, notify_security, notify_ops
Delegates Slack messages to the existing slack_notifier module.
"""

import asyncio
import os
from datetime import datetime, timezone

import httpx
import structlog

from runtime.integrations.base import BaseAdapter, AdapterResult

logger = structlog.get_logger()

SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL", "")
PAGERDUTY_KEY = os.getenv("PAGERDUTY_ROUTING_KEY", "")

CHANNEL_MAP = {
    "notify_fraud_team": "#soc-fraud",
    "notify_security": "#soc-security",
    "notify_ops": "#soc-ops",
}


class NotificationAdapter(BaseAdapter):
    """Slack + PagerDuty notification adapter."""

    async def execute(self, action_type: str, params: dict) -> AdapterResult:
        channel = CHANNEL_MAP.get(action_type, "#soc-general")
        message = params.get("message", f"SOC automated response: {action_type}")
        incident_id = params.get("incident_id", "unknown")
        severity = params.get("severity", "high")

        results = {}

        # Slack notification
        slack_ok = await self._send_slack(channel, message, incident_id, severity)
        results["slack"] = {"sent": slack_ok, "channel": channel}

        # PagerDuty for critical severity
        if severity == "critical":
            pd_ok = await self._send_pagerduty(message, incident_id)
            results["pagerduty"] = {"triggered": pd_ok}

        return AdapterResult(
            success=slack_ok,
            details={
                "action": action_type,
                "channels": results,
                "notified_at": datetime.now(timezone.utc).isoformat(),
            },
        )

    async def _send_slack(self, channel: str, message: str, incident_id: str, severity: str) -> bool:
        if not SLACK_WEBHOOK_URL:
            logger.info("notification.slack_skipped", reason="no webhook configured")
            return True  # Not a failure, just not configured

        payload = {
            "text": f":shield: *SOC Response* — {message}",
            "blocks": [
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": f":shield: *Automated Response Executed*\n{message}"},
                },
                {
                    "type": "context",
                    "elements": [
                        {"type": "mrkdwn", "text": f"Incident: `{incident_id}` | Severity: *{severity.upper()}* | Channel: {channel}"},
                    ],
                },
            ],
        }
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.post(SLACK_WEBHOOK_URL, json=payload)
                return resp.status_code == 200
        except Exception as e:
            logger.error("notification.slack_error", error=str(e))
            return False

    async def _send_pagerduty(self, message: str, incident_id: str) -> bool:
        if not PAGERDUTY_KEY:
            logger.info("notification.pagerduty_skipped", reason="no routing key")
            return True

        # Mock PagerDuty — in production, POST to events.pagerduty.com/v2/enqueue
        await asyncio.sleep(0.05)
        logger.info("notification.pagerduty_triggered", incident_id=incident_id)
        return True
