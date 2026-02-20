"""Critic Agent — reviews investigation findings and proposed response actions.

Responsibilities:
  1. Validate investigation quality (sufficient evidence, logical reasoning)
  2. Review each proposed response action against security policies
  3. Approve auto-risk actions immediately
  4. Approve/deny high-risk actions based on evidence strength
  5. Flag critical-risk actions for mandatory human approval
  6. Write critic_review JSONB to response_actions table
  7. Log all decisions to execution_traces for audit

Modes:
  - Rule-based (default): Policy-driven approval matrix, no LLM needed
  - LLM-enhanced: Uses Claude Sonnet 4.5 for nuanced reasoning on edge cases
"""

import json
import os
import uuid
from datetime import datetime, timezone

import asyncpg
import structlog

from runtime.execution_tracer import ExecutionTracer, StepTimer
from runtime.tools import is_llm_available

logger = structlog.get_logger()


# ─── Policy definitions ─────────────────────────────────

# Minimum investigation confidence to auto-approve actions at each risk level
CONFIDENCE_THRESHOLDS = {
    "auto": 0.0,       # Always approve
    "low": 0.4,        # Approve if investigation confidence >= 0.4
    "high": 0.7,       # Approve if confidence >= 0.7 AND sufficient IOCs
    "critical": 1.1,   # Never auto-approve — always requires human
}

# Minimum IOC count to support action approval
MIN_IOCS_FOR_APPROVAL = {
    "auto": 0,
    "low": 0,
    "high": 1,
    "critical": 2,
}

# Action-specific policies
ACTION_POLICIES = {
    "block_ip": {
        "max_auto_risk": "auto",
        "requires_ioc_match": True,
        "description": "Block IP at firewall — low impact, easily reversible",
    },
    "enable_enhanced_logging": {
        "max_auto_risk": "auto",
        "requires_ioc_match": False,
        "description": "Enable verbose logging — no user impact",
    },
    "rotate_api_key": {
        "max_auto_risk": "high",
        "requires_ioc_match": True,
        "max_blast_radius": 50,
        "description": "Rotate API key — service disruption possible",
    },
    "disable_user": {
        "max_auto_risk": "high",
        "requires_ioc_match": True,
        "max_blast_radius": 20,
        "description": "Disable user account — direct user impact",
    },
    "revoke_all_sessions": {
        "max_auto_risk": "critical",
        "requires_ioc_match": True,
        "max_blast_radius": 100,
        "description": "Revoke all sessions — widespread user disruption",
    },
    "notify_affected_users": {
        "max_auto_risk": "high",
        "requires_ioc_match": False,
        "description": "Send breach notification — reputational impact, not reversible",
    },
}

RISK_ORDER = {"auto": 0, "low": 1, "high": 2, "critical": 3}


class CriticResult:
    """Result of critic review for an investigation."""

    def __init__(
        self,
        actions_reviewed: int,
        actions_approved: int,
        actions_denied: int,
        actions_escalated: int,
        investigation_quality: str,
        policy_violations: list[str],
        reasoning: str,
    ):
        self.actions_reviewed = actions_reviewed
        self.actions_approved = actions_approved
        self.actions_denied = actions_denied
        self.actions_escalated = actions_escalated
        self.investigation_quality = investigation_quality
        self.policy_violations = policy_violations
        self.reasoning = reasoning

    def to_dict(self) -> dict:
        return {
            "actions_reviewed": self.actions_reviewed,
            "actions_approved": self.actions_approved,
            "actions_denied": self.actions_denied,
            "actions_escalated": self.actions_escalated,
            "investigation_quality": self.investigation_quality,
            "policy_violations": self.policy_violations,
            "reasoning": self.reasoning,
            "reviewed_at": datetime.now(timezone.utc).isoformat(),
            "critic_mode": "llm" if is_llm_available() else "rule_based",
        }


# ─── Investigation quality assessment ───────────────────

def _assess_investigation_quality(investigation_result: dict) -> tuple[str, list[str]]:
    """Rate investigation quality and identify gaps.

    Returns (quality_grade, list_of_issues).
    Grade: 'sufficient', 'marginal', 'insufficient'
    """
    issues = []

    confidence = investigation_result.get("confidence", 0)
    iocs = investigation_result.get("iocs", [])
    timeline = investigation_result.get("timeline", [])
    blast_radius = investigation_result.get("blast_radius", {})
    root_cause = investigation_result.get("root_cause", "")

    # Check confidence
    if confidence < 0.5:
        issues.append(f"Low investigation confidence ({confidence:.0%})")

    # Check IOCs
    if not iocs:
        issues.append("No IOCs extracted — investigation may lack supporting evidence")
    elif len(iocs) < 2:
        issues.append(f"Only {len(iocs)} IOC found — limited corroboration")

    # Check timeline
    if len(timeline) < 2:
        issues.append("Sparse timeline — insufficient event correlation")

    # Check blast radius
    total_entities = blast_radius.get("total_entities", 0)
    if total_entities == 0:
        issues.append("Blast radius unknown — graph traversal returned no results")

    # Check root cause
    if not root_cause or "requires further" in root_cause.lower():
        issues.append("Root cause analysis inconclusive")

    # Determine grade
    if len(issues) == 0:
        grade = "sufficient"
    elif len(issues) <= 2 and confidence >= 0.5:
        grade = "marginal"
    else:
        grade = "insufficient"

    return grade, issues


# ─── Action review logic ────────────────────────────────

def _review_action(
    action: dict,
    investigation_result: dict,
    quality_grade: str,
) -> dict:
    """Review a single response action against policies.

    Returns critic_review dict with decision and reasoning.
    """
    action_type = action.get("action_type", "unknown")
    risk_level = action.get("risk_level", "high")
    policy = ACTION_POLICIES.get(action_type, {})

    confidence = investigation_result.get("confidence", 0)
    iocs = investigation_result.get("iocs", [])
    blast_radius = investigation_result.get("blast_radius", {})
    total_entities = blast_radius.get("total_entities", 0)

    violations = []
    decision = "approved"
    reasons = []

    # Already approved (auto-risk) — just validate
    if action.get("status") == "approved" and risk_level == "auto":
        return {
            "decision": "approved",
            "reasoning": f"Auto-risk action '{action_type}' pre-approved. Validated by critic — will be executed by ActionExecutor.",
            "violations": [],
            "reviewed_by": "critic_agent",
        }

    # Rule 1: Critical actions ALWAYS need human approval
    if risk_level == "critical":
        decision = "escalated"
        reasons.append(f"Critical-risk action '{action_type}' requires mandatory human approval")

    # Rule 2: Insufficient investigation quality → deny high-risk actions
    elif quality_grade == "insufficient" and RISK_ORDER.get(risk_level, 2) >= 2:
        decision = "denied"
        violations.append("POLICY: Cannot approve high/critical actions with insufficient investigation quality")
        reasons.append("Investigation quality insufficient to support this action")

    # Rule 3: Check confidence threshold
    elif confidence < CONFIDENCE_THRESHOLDS.get(risk_level, 1.0):
        decision = "denied"
        threshold = CONFIDENCE_THRESHOLDS.get(risk_level, 1.0)
        violations.append(
            f"POLICY: Confidence {confidence:.0%} below threshold {threshold:.0%} for {risk_level}-risk actions"
        )
        reasons.append(f"Investigation confidence ({confidence:.0%}) too low for {risk_level}-risk action")

    # Rule 4: Check IOC match requirement
    elif policy.get("requires_ioc_match") and len(iocs) < MIN_IOCS_FOR_APPROVAL.get(risk_level, 1):
        decision = "denied"
        violations.append(f"POLICY: {risk_level}-risk action requires {MIN_IOCS_FOR_APPROVAL.get(risk_level, 1)}+ IOCs")
        reasons.append("Insufficient IOC evidence to support action")

    # Rule 5: Check blast radius limits
    elif policy.get("max_blast_radius") and total_entities > policy["max_blast_radius"]:
        decision = "escalated"
        reasons.append(
            f"Blast radius ({total_entities} entities) exceeds limit ({policy['max_blast_radius']}) "
            f"for '{action_type}' — escalating to human"
        )

    # Rule 6: Marginal quality + high risk → escalate instead of auto-approve
    elif quality_grade == "marginal" and RISK_ORDER.get(risk_level, 2) >= 2:
        decision = "escalated"
        reasons.append("Marginal investigation quality — escalating high-risk action for human review")

    else:
        decision = "approved"
        reasons.append(
            f"Action '{action_type}' approved: confidence {confidence:.0%}, "
            f"{len(iocs)} IOCs, quality '{quality_grade}'"
        )

    return {
        "decision": decision,
        "reasoning": "; ".join(reasons),
        "violations": violations,
        "reviewed_by": "critic_agent",
        "reviewed_at": datetime.now(timezone.utc).isoformat(),
    }


# ─── Rule-based critic ──────────────────────────────────

async def critic_rule_based(
    investigation_result: dict,
    db_pool: asyncpg.Pool,
    tenant_id: str,
    alert_id: str,
) -> CriticResult:
    """Rule-based critic — applies policy matrix to all pending actions."""
    tracer = ExecutionTracer(db_pool, tenant_id, alert_id, agent_name="critic")

    # Step 1: Assess investigation quality
    with StepTimer() as t:
        quality_grade, quality_issues = _assess_investigation_quality(investigation_result)
    await tracer.log_step(
        "quality_assessment",
        input_data={"confidence": investigation_result.get("confidence"), "ioc_count": len(investigation_result.get("iocs", []))},
        output_data={"grade": quality_grade, "issues": quality_issues},
        duration_ms=t.duration_ms,
    )
    logger.info("critic.quality_assessed", alert_id=alert_id, grade=quality_grade, issues=len(quality_issues))

    # Step 2: Fetch pending actions for this alert's incident
    incident_id = investigation_result.get("incident_id")
    with StepTimer() as t:
        async with db_pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT id, action_type, parameters, risk_level, status
                FROM response_actions
                WHERE (alert_id = $1 OR incident_id = $2)
                  AND status IN ('pending', 'approved')
                ORDER BY created_at
                """,
                alert_id,
                incident_id,
            )
        actions = [dict(r) for r in rows]
        # Convert UUID to str for JSON serialization
        for a in actions:
            a["id"] = str(a["id"])
    await tracer.log_step(
        "fetch_actions",
        output_data={"action_count": len(actions)},
        duration_ms=t.duration_ms,
    )

    # Step 3: Review each action
    approved = 0
    denied = 0
    escalated = 0
    all_violations = []

    with StepTimer() as t:
        for action in actions:
            review = _review_action(action, investigation_result, quality_grade)

            # Write critic_review to response_actions table
            new_status = {
                "approved": "approved",
                "denied": "denied",
                "escalated": "pending",  # stays pending for human
            }.get(review["decision"], "pending")

            # Keep auto-approved actions as approved for the executor
            if action["status"] == "approved" and action.get("risk_level") == "auto":
                new_status = "approved"

            async with db_pool.acquire() as conn:
                await conn.execute(
                    """
                    UPDATE response_actions
                    SET critic_review = $1::jsonb,
                        status = $2
                    WHERE id = $3
                    """,
                    json.dumps(review),
                    new_status,
                    action["id"],
                )

            if review["decision"] == "approved":
                approved += 1
            elif review["decision"] == "denied":
                denied += 1
            elif review["decision"] == "escalated":
                escalated += 1

            all_violations.extend(review.get("violations", []))

    await tracer.log_step(
        "action_reviews",
        output_data={
            "reviewed": len(actions),
            "approved": approved,
            "denied": denied,
            "escalated": escalated,
            "violations": all_violations,
        },
        duration_ms=t.duration_ms,
    )

    reasoning = (
        f"Critic reviewed {len(actions)} actions for alert {alert_id}. "
        f"Investigation quality: {quality_grade}. "
        f"Approved: {approved}, Denied: {denied}, Escalated to human: {escalated}."
    )
    if quality_issues:
        reasoning += f" Quality issues: {'; '.join(quality_issues[:3])}."
    if all_violations:
        reasoning += f" Policy violations: {'; '.join(all_violations[:3])}."

    return CriticResult(
        actions_reviewed=len(actions),
        actions_approved=approved,
        actions_denied=denied,
        actions_escalated=escalated,
        investigation_quality=quality_grade,
        policy_violations=all_violations,
        reasoning=reasoning,
    )


# ─── LLM-enhanced critic ────────────────────────────────

async def critic_llm(
    investigation_result: dict,
    db_pool: asyncpg.Pool,
    tenant_id: str,
    alert_id: str,
) -> CriticResult:
    """LLM-enhanced critic — runs rule-based first, then asks LLM for edge cases."""
    # Always run rule-based first
    rb_result = await critic_rule_based(investigation_result, db_pool, tenant_id, alert_id)

    # Only invoke LLM if there are escalated actions that need nuanced review
    if rb_result.actions_escalated == 0 and not rb_result.policy_violations:
        return rb_result

    try:
        import anthropic
    except ImportError:
        logger.warning("anthropic not installed, returning rule-based critic result")
        return rb_result

    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        return rb_result

    prompt = f"""You are a senior SOC manager reviewing an investigation and proposed response actions.

INVESTIGATION SUMMARY:
- Confidence: {investigation_result.get('confidence', 0):.0%}
- Root Cause: {investigation_result.get('root_cause', 'unknown')}
- IOCs: {len(investigation_result.get('iocs', []))}
- Blast Radius: {json.dumps(investigation_result.get('blast_radius', {}), default=str)[:500]}
- Timeline Events: {len(investigation_result.get('timeline', []))}

RESPONSE ACTIONS (pending human review):
{json.dumps(investigation_result.get('response_actions', []), indent=2, default=str)[:1500]}

RULE-BASED REVIEW:
- Quality Grade: {rb_result.investigation_quality}
- Approved: {rb_result.actions_approved}
- Denied: {rb_result.actions_denied}
- Escalated: {rb_result.actions_escalated}
- Policy Violations: {rb_result.policy_violations}

For each escalated action, provide your recommendation as JSON:
{{
  "recommendations": [
    {{
      "action_type": "...",
      "recommendation": "approve" | "deny" | "modify",
      "reasoning": "..."
    }}
  ],
  "overall_assessment": "brief overall assessment of the investigation and response plan"
}}"""

    try:
        client = anthropic.Anthropic(api_key=api_key)
        response = client.messages.create(
            model="claude-sonnet-4-5-20250929",
            max_tokens=1000,
            messages=[{"role": "user", "content": prompt}],
        )
        text = response.content[0].text

        start = text.find("{")
        end = text.rfind("}") + 1
        if start >= 0 and end > start:
            llm_data = json.loads(text[start:end])
        else:
            raise ValueError("No JSON found in LLM response")

        # Log LLM review step
        tracer = ExecutionTracer(db_pool, tenant_id, alert_id, agent_name="critic")
        await tracer.log_step(
            "llm_review",
            input_data={"model": "claude-sonnet-4-5-20250929"},
            output_data=llm_data,
            tokens_used=response.usage.input_tokens + response.usage.output_tokens,
        )

        # Enhance reasoning with LLM assessment
        overall = llm_data.get("overall_assessment", "")
        if overall:
            rb_result.reasoning += f" LLM assessment: {overall}"

        return rb_result

    except Exception as e:
        logger.warning("llm.critic.failed", error=str(e))
        return rb_result


# ─── Main entry point ────────────────────────────────────

async def review_investigation(
    investigation_result: dict,
    db_pool: asyncpg.Pool,
    tenant_id: str,
    alert_id: str,
) -> CriticResult:
    """Review an investigation and its proposed actions.

    Uses LLM if available, otherwise rule-based policy evaluation.
    """
    logger.info("critic.triggered", alert_id=alert_id, incident_id=investigation_result.get("incident_id"))

    if is_llm_available():
        result = await critic_llm(investigation_result, db_pool, tenant_id, alert_id)
    else:
        result = await critic_rule_based(investigation_result, db_pool, tenant_id, alert_id)

    logger.info(
        "critic.completed",
        alert_id=alert_id,
        reviewed=result.actions_reviewed,
        approved=result.actions_approved,
        denied=result.actions_denied,
        escalated=result.actions_escalated,
        quality=result.investigation_quality,
        violations=len(result.policy_violations),
    )

    return result
