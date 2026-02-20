"""Playbook API routes — list and trigger response playbooks."""

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.auth.middleware import get_current_user, set_tenant_context
from app.auth.rbac import require_permission
from app.services.redis_service import redis_client

router = APIRouter()


class PlaybookOut(BaseModel):
    name: str
    description: str
    event_types: list[str]
    severity_min: str
    action_count: int
    actions: list[dict]


class RunPlaybookRequest(BaseModel):
    incident_id: str
    context: dict | None = None


class RunPlaybookResponse(BaseModel):
    status: str
    playbook: str
    message: str


# ─── Static playbook definitions (mirrored from engine) ──
PLAYBOOK_DEFS = [
    {
        "name": "carding_response",
        "description": "Block attacker IP, freeze Stripe payments, notify fraud team",
        "event_types": ["stripe.charge.failed", "carding_attack", "rapid_card_testing", "card_velocity_spike"],
        "severity_min": "high",
        "action_count": 3,
        "actions": [
            {"action_type": "block_ip", "risk_level": "auto", "description": "Block attacker IP at Traefik edge"},
            {"action_type": "freeze_stripe_payments", "risk_level": "high", "description": "Freeze all Stripe payouts"},
            {"action_type": "notify_fraud_team", "risk_level": "auto", "description": "Alert fraud team via Slack"},
        ],
    },
    {
        "name": "auth_compromise",
        "description": "Revoke sessions, force password reset, enable logging, notify security",
        "event_types": ["brute_force", "credential_stuffing", "impossible_travel", "account_takeover"],
        "severity_min": "high",
        "action_count": 4,
        "actions": [
            {"action_type": "revoke_all_sessions", "risk_level": "high", "description": "Kill all active sessions"},
            {"action_type": "force_password_reset", "risk_level": "high", "description": "Force password reset"},
            {"action_type": "enable_enhanced_logging", "risk_level": "auto", "description": "Enable verbose auth logging"},
            {"action_type": "notify_security", "risk_level": "auto", "description": "Alert security team via Slack"},
        ],
    },
    {
        "name": "infra_breach",
        "description": "Revert SG changes, disable IAM user, rotate keys, notify ops",
        "event_types": ["security_group_change", "unauthorized_api_call", "iam_privilege_escalation", "unusual_api_activity"],
        "severity_min": "high",
        "action_count": 4,
        "actions": [
            {"action_type": "revert_security_group", "risk_level": "high", "description": "Revert SG modifications"},
            {"action_type": "disable_iam_user", "risk_level": "critical", "description": "Disable compromised IAM user"},
            {"action_type": "rotate_api_key", "risk_level": "high", "description": "Rotate compromised API keys"},
            {"action_type": "notify_ops", "risk_level": "auto", "description": "Alert ops team via Slack"},
        ],
    },
    {
        "name": "ai_agent_threat",
        "description": "Disable AI agent, enable logging, notify security",
        "event_types": ["prompt_injection", "jailbreak_attempt", "data_exfiltration", "tool_call_loop", "token_abuse"],
        "severity_min": "medium",
        "action_count": 3,
        "actions": [
            {"action_type": "disable_user", "risk_level": "high", "description": "Disable compromised AI agent"},
            {"action_type": "enable_enhanced_logging", "risk_level": "auto", "description": "Enable verbose AI logging"},
            {"action_type": "notify_security", "risk_level": "auto", "description": "Alert security team via Slack"},
        ],
    },
]


@router.get("", response_model=list[PlaybookOut])
async def list_playbooks(
    current_user: dict = Depends(get_current_user),
):
    """List all available response playbooks."""
    return PLAYBOOK_DEFS


@router.post("/{playbook_name}/run", response_model=RunPlaybookResponse)
async def run_playbook(
    playbook_name: str,
    req: RunPlaybookRequest,
    current_user: dict = Depends(get_current_user),
):
    """Trigger a playbook run via Redis stream (consumed by agent-runtime)."""
    _check = require_permission("approve_actions")(current_user)

    valid_names = [p["name"] for p in PLAYBOOK_DEFS]
    if playbook_name not in valid_names:
        raise HTTPException(status_code=404, detail=f"Playbook '{playbook_name}' not found")

    # Publish to Redis stream for agent-runtime to consume
    import json
    await redis_client.xadd(
        "soc:playbook:run",
        {
            "playbook_name": playbook_name,
            "incident_id": req.incident_id,
            "tenant_id": str(current_user["tenant_id"]),
            "context": json.dumps(req.context or {}),
            "requested_by": str(current_user["user_id"]),
        },
    )

    return RunPlaybookResponse(
        status="queued",
        playbook=playbook_name,
        message=f"Playbook '{playbook_name}' queued for incident {req.incident_id}",
    )
