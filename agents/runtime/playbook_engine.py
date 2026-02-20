"""Playbook Engine — orchestrates multi-step response playbooks.

Built-in playbooks:
  1. carding_response: block_ip → freeze_stripe → notify_fraud
  2. auth_compromise: revoke_sessions → force_reset → enhanced_logging → notify_security
  3. infra_breach: revert_sg → disable_iam → rotate_keys → notify_ops
  4. ai_agent_threat: disable_user → enhanced_logging → notify_security

Each playbook defines ordered actions with parameter templates that get
resolved from incident context. Actions are created as response_actions
in the database and auto-risk actions execute immediately.
"""

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone

import asyncpg
import structlog

from runtime.execution_tracer import ExecutionTracer
from runtime.action_executor import ActionExecutor

logger = structlog.get_logger()


@dataclass
class PlaybookAction:
    """A single step in a playbook."""
    action_type: str
    risk_level: str  # auto, high, critical
    param_template: dict = field(default_factory=dict)
    description: str = ""


@dataclass
class PlaybookDef:
    """Definition of a response playbook."""
    name: str
    description: str
    event_types: list[str]  # which event_types trigger recommendation
    severity_min: str  # minimum severity for recommendation
    actions: list[PlaybookAction] = field(default_factory=list)


@dataclass
class PlaybookRunResult:
    """Result of running a playbook."""
    playbook_name: str
    actions_created: int
    actions_executed: int
    action_ids: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


# ─── Built-in playbooks ──────────────────────────────────

PLAYBOOKS: dict[str, PlaybookDef] = {
    "carding_response": PlaybookDef(
        name="carding_response",
        description="Block attacker IP, freeze Stripe payments, notify fraud team",
        event_types=["stripe.charge.failed", "carding_attack", "rapid_card_testing", "card_velocity_spike"],
        severity_min="high",
        actions=[
            PlaybookAction(
                action_type="block_ip",
                risk_level="auto",
                param_template={"ip": "{source_ip}"},
                description="Block attacker IP at Traefik edge",
            ),
            PlaybookAction(
                action_type="freeze_stripe_payments",
                risk_level="high",
                param_template={"reason": "Carding attack — automated SOC response for incident {incident_id}"},
                description="Freeze all Stripe payouts to prevent further fraud",
            ),
            PlaybookAction(
                action_type="notify_fraud_team",
                risk_level="auto",
                param_template={
                    "message": "Carding attack detected — IP {source_ip} blocked, Stripe frozen",
                    "incident_id": "{incident_id}",
                    "severity": "{severity}",
                },
                description="Alert fraud team via Slack",
            ),
        ],
    ),
    "auth_compromise": PlaybookDef(
        name="auth_compromise",
        description="Revoke sessions, force password reset, enable logging, notify security",
        event_types=["brute_force", "credential_stuffing", "impossible_travel", "account_takeover"],
        severity_min="high",
        actions=[
            PlaybookAction(
                action_type="revoke_all_sessions",
                risk_level="high",
                param_template={"user_id": "{user_id}", "username": "{username}"},
                description="Kill all active sessions for compromised user",
            ),
            PlaybookAction(
                action_type="force_password_reset",
                risk_level="high",
                param_template={"user_id": "{user_id}", "username": "{username}"},
                description="Force password reset and send notification email",
            ),
            PlaybookAction(
                action_type="enable_enhanced_logging",
                risk_level="auto",
                param_template={"services": ["auth", "session-manager"]},
                description="Enable verbose auth logging for forensics",
            ),
            PlaybookAction(
                action_type="notify_security",
                risk_level="auto",
                param_template={
                    "message": "Auth compromise — user {username} sessions revoked, password reset",
                    "incident_id": "{incident_id}",
                    "severity": "{severity}",
                },
                description="Alert security team via Slack",
            ),
        ],
    ),
    "infra_breach": PlaybookDef(
        name="infra_breach",
        description="Revert SG changes, disable IAM user, rotate keys, notify ops",
        event_types=["security_group_change", "unauthorized_api_call", "iam_privilege_escalation", "unusual_api_activity"],
        severity_min="high",
        actions=[
            PlaybookAction(
                action_type="revert_security_group",
                risk_level="high",
                param_template={"security_group_id": "{security_group_id}", "region": "{region}"},
                description="Revert unauthorized security group modifications",
            ),
            PlaybookAction(
                action_type="disable_iam_user",
                risk_level="critical",
                param_template={"iam_user": "{iam_user}", "username": "{username}"},
                description="Disable compromised IAM user credentials",
            ),
            PlaybookAction(
                action_type="rotate_api_key",
                risk_level="high",
                param_template={"key_prefix": "{key_prefix}"},
                description="Rotate potentially compromised API keys",
            ),
            PlaybookAction(
                action_type="notify_ops",
                risk_level="auto",
                param_template={
                    "message": "Infra breach — SG reverted, IAM disabled, keys rotated",
                    "incident_id": "{incident_id}",
                    "severity": "{severity}",
                },
                description="Alert ops team via Slack",
            ),
        ],
    ),
    "ai_agent_threat": PlaybookDef(
        name="ai_agent_threat",
        description="Disable AI agent, enable logging, notify security",
        event_types=["prompt_injection", "jailbreak_attempt", "data_exfiltration", "tool_call_loop", "token_abuse"],
        severity_min="medium",
        actions=[
            PlaybookAction(
                action_type="disable_user",
                risk_level="high",
                param_template={"user_id": "{agent_id}", "username": "{agent_name}"},
                description="Disable the compromised AI agent",
            ),
            PlaybookAction(
                action_type="enable_enhanced_logging",
                risk_level="auto",
                param_template={"services": ["langfuse", "guardrails", "agent-runtime"]},
                description="Enable verbose logging for AI agent forensics",
            ),
            PlaybookAction(
                action_type="notify_security",
                risk_level="auto",
                param_template={
                    "message": "AI agent threat — {agent_name} disabled, monitoring enhanced",
                    "incident_id": "{incident_id}",
                    "severity": "{severity}",
                },
                description="Alert security team via Slack",
            ),
        ],
    ),
}

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


class PlaybookEngine:
    """Orchestrates playbook execution."""

    def __init__(self, db_pool: asyncpg.Pool, executor: ActionExecutor):
        self.db_pool = db_pool
        self.executor = executor
        self.stats = {"playbooks_run": 0}

    def get_recommended_playbook(self, event_type: str, severity: str) -> PlaybookDef | None:
        """Match an incident to the best playbook based on event_type and severity."""
        for pb in PLAYBOOKS.values():
            if event_type in pb.event_types:
                if SEVERITY_ORDER.get(severity, 0) >= SEVERITY_ORDER.get(pb.severity_min, 0):
                    return pb
        return None

    def list_playbooks(self) -> list[dict]:
        """Return all playbook definitions for the API."""
        return [
            {
                "name": pb.name,
                "description": pb.description,
                "event_types": pb.event_types,
                "severity_min": pb.severity_min,
                "action_count": len(pb.actions),
                "actions": [
                    {
                        "action_type": a.action_type,
                        "risk_level": a.risk_level,
                        "description": a.description,
                    }
                    for a in pb.actions
                ],
            }
            for pb in PLAYBOOKS.values()
        ]

    async def run_playbook(
        self,
        playbook_name: str,
        incident_id: str,
        tenant_id: str,
        context: dict | None = None,
    ) -> PlaybookRunResult:
        """Run a playbook: create actions → execute auto-risk immediately.

        Args:
            playbook_name: Name of the playbook to run
            incident_id: ID of the linked incident
            tenant_id: Tenant scope
            context: Variables for template resolution (source_ip, user_id, etc.)
        """
        playbook = PLAYBOOKS.get(playbook_name)
        if not playbook:
            return PlaybookRunResult(
                playbook_name=playbook_name,
                actions_created=0,
                actions_executed=0,
                errors=[f"Unknown playbook: {playbook_name}"],
            )

        ctx = context or {}
        ctx.setdefault("incident_id", incident_id)
        ctx.setdefault("severity", "high")

        tracer = ExecutionTracer(
            self.db_pool, tenant_id, incident_id,
            agent_name="playbook_engine",
        )

        await tracer.log_step(
            "playbook_start",
            input_data={"playbook": playbook_name, "incident_id": incident_id, "context": ctx},
        )

        result = PlaybookRunResult(playbook_name=playbook_name, actions_created=0, actions_executed=0)

        # Get alert_id from incident
        alert_id = await self._get_alert_id_for_incident(incident_id)

        for step_action in playbook.actions:
            # Resolve parameter templates
            params = self._resolve_params(step_action.param_template, ctx)

            # Create response_action in DB
            action_id = str(uuid.uuid4())
            try:
                async with self.db_pool.acquire() as conn:
                    await conn.execute(
                        """
                        INSERT INTO response_actions
                            (id, tenant_id, alert_id, incident_id, action_type,
                             parameters, risk_level, status, proposed_by, created_at)
                        VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8, $9, NOW())
                        """,
                        action_id,
                        tenant_id,
                        alert_id,
                        incident_id,
                        step_action.action_type,
                        json.dumps(params),
                        step_action.risk_level,
                        "approved" if step_action.risk_level == "auto" else "pending",
                        f"playbook:{playbook_name}",
                    )
                result.actions_created += 1
                result.action_ids.append(action_id)
            except Exception as e:
                result.errors.append(f"Failed to create {step_action.action_type}: {e}")
                continue

            # Execute auto-risk actions immediately
            if step_action.risk_level == "auto":
                ok = await self.executor.execute_action(action_id, tenant_id)
                if ok:
                    result.actions_executed += 1
                else:
                    result.errors.append(f"Failed to execute {step_action.action_type}")

        await tracer.log_step(
            "playbook_complete",
            output_data={
                "actions_created": result.actions_created,
                "actions_executed": result.actions_executed,
                "errors": result.errors,
            },
        )

        self.stats["playbooks_run"] += 1
        logger.info(
            "playbook.completed",
            playbook=playbook_name,
            incident_id=incident_id,
            created=result.actions_created,
            executed=result.actions_executed,
            errors=len(result.errors),
        )

        return result

    def _resolve_params(self, template: dict, context: dict) -> dict:
        """Resolve {variable} placeholders in param template from context."""
        resolved = {}
        for key, value in template.items():
            if isinstance(value, str) and "{" in value:
                for ctx_key, ctx_val in context.items():
                    value = value.replace(f"{{{ctx_key}}}", str(ctx_val))
                resolved[key] = value
            elif isinstance(value, list):
                resolved[key] = value
            else:
                resolved[key] = value
        return resolved

    async def _get_alert_id_for_incident(self, incident_id: str) -> str | None:
        """Get the first alert linked to an incident."""
        try:
            async with self.db_pool.acquire() as conn:
                row = await conn.fetchrow(
                    "SELECT id FROM alerts WHERE incident_id = $1 LIMIT 1",
                    incident_id,
                )
                return str(row["id"]) if row else None
        except Exception:
            return None
