"""Investigation Agent — deep multi-source correlation for escalated alerts.

Pipeline (7 steps):
  1. INTAKE      — extract artifacts (IPs, emails, domains) from alert + triage
  2. CORRELATION — query CloudTrail, AbuseIPDB, Neo4j for related events
  3. TIMELINE    — build chronological event sequence
  4. BLAST RADIUS — Neo4j graph traversal (alert → assets → services → users)
  5. ROOT CAUSE  — trace to initial attack vector
  6. IOC EXTRACTION — collect indicators, enrich with threat intel
  7. RESPONSE    — propose containment actions, write to DB

Modes:
  - Rule-based (default): Works without LLM API key, deterministic
  - LLM-enhanced: Uses Claude Sonnet 4.5 for reasoning synthesis
"""

import json
import os
import uuid
from datetime import datetime, timezone

import asyncpg
import structlog

from runtime.execution_tracer import ExecutionTracer, StepTimer
from runtime.investigation_tools import (
    check_ip_reputation,
    get_iam_activity,
    query_cloudtrail,
    traverse_blast_radius,
    update_knowledge_graph,
)
from runtime.tools import get_asset_context, get_related_incidents, query_graph, is_llm_available

logger = structlog.get_logger()


# ─── MITRE ATT&CK mapping (extends triage mapping) ──────

ROOT_CAUSE_MITRE = {
    "carding": {
        "technique": "T1530",
        "tactic": "Collection",
        "description": "Stolen payment card data used for fraudulent transactions",
    },
    "brute_force": {
        "technique": "T1110",
        "tactic": "Credential Access",
        "description": "Automated credential guessing against authentication endpoints",
    },
    "credential_stuffing": {
        "technique": "T1110.004",
        "tactic": "Credential Access",
        "description": "Reuse of leaked credentials from external breaches",
    },
    "impossible_travel": {
        "technique": "T1078",
        "tactic": "Defense Evasion",
        "description": "Valid credentials used from geographically impossible locations",
    },
    "privilege_escalation": {
        "technique": "T1078.004",
        "tactic": "Privilege Escalation",
        "description": "Cloud account manipulation for elevated access",
    },
    "api_abuse": {
        "technique": "T1106",
        "tactic": "Execution",
        "description": "Abuse of application APIs for unauthorized operations",
    },
    "prompt_injection": {
        "technique": "AML.T0051",
        "tactic": "Initial Access",
        "description": "Adversarial prompt injection to manipulate AI agent behavior",
    },
    "jailbreak": {
        "technique": "AML.T0054",
        "tactic": "Defense Evasion",
        "description": "Jailbreak attempt to bypass AI agent safety guardrails",
    },
    "data_exfiltration": {
        "technique": "AML.T0024",
        "tactic": "Exfiltration",
        "description": "AI agent exploited to exfiltrate sensitive data",
    },
    "tool_abuse": {
        "technique": "AML.T0043",
        "tactic": "Impact",
        "description": "AI agent tool calls abused for resource exhaustion or loop attacks",
    },
}

# ─── Response action templates ───────────────────────────

RESPONSE_TEMPLATES = {
    "block_ip": {
        "risk_level": "auto",
        "description": "Block malicious IP at firewall/WAF",
        "requires_approval": False,
    },
    "rotate_api_key": {
        "risk_level": "high",
        "description": "Rotate compromised API key and invalidate old one",
        "requires_approval": True,
    },
    "disable_user": {
        "risk_level": "high",
        "description": "Temporarily disable compromised user account",
        "requires_approval": True,
    },
    "revoke_all_sessions": {
        "risk_level": "critical",
        "description": "Revoke all active sessions for affected user",
        "requires_approval": True,
    },
    "enable_enhanced_logging": {
        "risk_level": "auto",
        "description": "Enable verbose logging for affected services",
        "requires_approval": False,
    },
    "notify_affected_users": {
        "risk_level": "high",
        "description": "Send breach notification to affected users",
        "requires_approval": True,
    },
    "notify_security": {
        "risk_level": "auto",
        "description": "Alert security team via notification channel",
        "requires_approval": False,
    },
    "notify_ops": {
        "risk_level": "auto",
        "description": "Alert operations team via notification channel",
        "requires_approval": False,
    },
    "revert_security_group": {
        "risk_level": "high",
        "description": "Revert unauthorized security group modifications",
        "requires_approval": True,
    },
    "disable_iam_user": {
        "risk_level": "critical",
        "description": "Disable compromised IAM user credentials",
        "requires_approval": True,
    },
    "freeze_stripe_payments": {
        "risk_level": "high",
        "description": "Freeze Stripe payouts to prevent further fraud",
        "requires_approval": True,
    },
}


class InvestigationResult:
    """Result of a full investigation."""

    def __init__(
        self,
        incident_id: str,
        incident_created: bool,
        timeline: list[dict],
        blast_radius: dict,
        root_cause: str,
        iocs: list[dict],
        response_actions: list[dict],
        confidence: float,
        requires_critic_review: bool,
        reasoning: str,
    ):
        self.incident_id = incident_id
        self.incident_created = incident_created
        self.timeline = timeline
        self.blast_radius = blast_radius
        self.root_cause = root_cause
        self.iocs = iocs
        self.response_actions = response_actions
        self.confidence = confidence
        self.requires_critic_review = requires_critic_review
        self.reasoning = reasoning

    def to_dict(self) -> dict:
        return {
            "incident_id": self.incident_id,
            "incident_created": self.incident_created,
            "timeline": self.timeline,
            "blast_radius": self.blast_radius,
            "root_cause": self.root_cause,
            "iocs": self.iocs,
            "response_actions": self.response_actions,
            "confidence": self.confidence,
            "requires_critic_review": self.requires_critic_review,
            "reasoning": self.reasoning,
            "investigated_at": datetime.now(timezone.utc).isoformat(),
            "investigation_mode": "llm" if is_llm_available() else "rule_based",
        }


# ─── Step 1: INTAKE ─────────────────────────────────────

def _extract_artifacts(alert: dict, triage_result: dict) -> dict:
    """Extract and deduplicate all artifacts from alert + triage enrichment."""
    artifacts = alert.get("artifacts", [])
    if isinstance(artifacts, str):
        try:
            artifacts = json.loads(artifacts)
        except (json.JSONDecodeError, TypeError):
            artifacts = []

    ips = set()
    emails = set()
    domains = set()
    card_bins = set()
    other = []

    for a in artifacts:
        atype = a.get("type", "")
        aval = a.get("value", "")
        if atype == "ip":
            ips.add(aval)
        elif atype == "email":
            emails.add(aval)
        elif atype == "domain":
            domains.add(aval)
        elif atype == "card_bin":
            card_bins.add(aval)
        else:
            other.append(a)

    # Also pull from triage enrichment
    enrichment = triage_result.get("enrichment", {})
    for ctx in enrichment.get("ip_context", []):
        if ctx.get("found") and ctx.get("properties", {}).get("ip"):
            ips.add(ctx["properties"]["ip"])

    return {
        "ips": list(ips),
        "emails": list(emails),
        "domains": list(domains),
        "card_bins": list(card_bins),
        "other": other,
    }


# ─── Step 2: CORRELATION ────────────────────────────────

async def _correlate(artifacts: dict, alert: dict) -> dict:
    """Query multiple sources for related events and context."""
    correlation = {
        "cloudtrail_events": [],
        "ip_reputations": {},
        "related_alerts": [],
        "iam_activity": [],
        "graph_context": [],
    }

    # CloudTrail — look for events by source user
    raw_payload = alert.get("raw_payload") or {}
    if isinstance(raw_payload, str):
        try:
            raw_payload = json.loads(raw_payload)
        except (json.JSONDecodeError, TypeError):
            raw_payload = {}

    user_name = raw_payload.get("user_name") or raw_payload.get("email")
    if user_name:
        ct_result = await query_cloudtrail(user_name=user_name, hours_back=48)
        correlation["cloudtrail_events"] = ct_result.get("events", [])[:20]

        iam_result = await get_iam_activity(user_name, hours_back=48)
        correlation["iam_activity"] = iam_result.get("events", [])[:20]

    # AbuseIPDB — reputation for each IP
    for ip in artifacts["ips"][:5]:
        rep = await check_ip_reputation(ip)
        correlation["ip_reputations"][ip] = rep

    # Neo4j — related alerts for each IP
    for ip in artifacts["ips"][:3]:
        related = await get_related_incidents("ip", ip, limit=10)
        for a in related.get("related_alerts", []):
            if a not in correlation["related_alerts"]:
                correlation["related_alerts"].append(a)

    # Neo4j — asset context for each entity
    for ip in artifacts["ips"][:3]:
        ctx = await get_asset_context("ip", ip)
        if ctx.get("found"):
            correlation["graph_context"].append({"type": "ip", "value": ip, "context": ctx})

    for email in artifacts["emails"][:3]:
        ctx = await get_asset_context("user", email)
        if ctx.get("found"):
            correlation["graph_context"].append({"type": "user", "value": email, "context": ctx})

    return correlation


# ─── Step 3: TIMELINE ────────────────────────────────────

def _build_timeline(alert: dict, correlation: dict) -> list[dict]:
    """Build chronological event sequence from correlated data."""
    events = []

    # Alert itself
    events.append({
        "timestamp": alert.get("created_at", datetime.now(timezone.utc).isoformat()),
        "type": "alert_triggered",
        "source": alert.get("source", "unknown"),
        "description": alert.get("title", "Alert triggered"),
        "severity": alert.get("severity", "medium"),
    })

    # CloudTrail events
    for ct in correlation.get("cloudtrail_events", []):
        events.append({
            "timestamp": ct.get("timestamp", ct.get("eventTime", "")),
            "type": "cloudtrail",
            "source": "aws_cloudtrail",
            "description": f"{ct.get('eventName', 'unknown')} by {ct.get('userName', 'unknown')}",
            "severity": "info",
        })

    # IAM activity
    for iam in correlation.get("iam_activity", []):
        events.append({
            "timestamp": iam.get("timestamp", ""),
            "type": "iam_activity",
            "source": "aws_iam",
            "description": f"IAM: {iam.get('eventName', 'unknown')}",
            "severity": "info",
        })

    # Related alerts from Neo4j
    for ra in correlation.get("related_alerts", []):
        ts = ra.get("created_at", ra.get("timestamp", ""))
        events.append({
            "timestamp": ts,
            "type": "related_alert",
            "source": ra.get("source", "unknown"),
            "description": ra.get("title", f"Related alert: {ra.get('event_type', 'unknown')}"),
            "severity": ra.get("severity", "medium"),
        })

    # Sort chronologically (empty timestamps go last)
    events.sort(key=lambda e: e.get("timestamp") or "9999")

    return events


# ─── Step 4: BLAST RADIUS ───────────────────────────────

async def _assess_blast_radius(artifacts: dict) -> dict:
    """Traverse Neo4j graph to determine impacted assets, services, users."""
    blast = {
        "affected_ips": [],
        "affected_users": [],
        "affected_services": [],
        "total_entities": 0,
    }

    for ip in artifacts["ips"][:3]:
        result = await traverse_blast_radius("ip", ip, max_hops=3)
        for node in result.get("results", []):
            label = node.get("label", "").lower()
            value = node.get("value") or node.get("name") or "unknown"
            entry = {"value": value, "hops": node.get("hops", 1)}
            if label == "ip" and entry not in blast["affected_ips"]:
                blast["affected_ips"].append(entry)
            elif label == "user" and entry not in blast["affected_users"]:
                blast["affected_users"].append(entry)
            elif label in ("service", "application") and entry not in blast["affected_services"]:
                blast["affected_services"].append(entry)

    for email in artifacts["emails"][:3]:
        result = await traverse_blast_radius("user", email, max_hops=2)
        for node in result.get("results", []):
            label = node.get("label", "").lower()
            value = node.get("value") or node.get("name") or "unknown"
            entry = {"value": value, "hops": node.get("hops", 1)}
            if label == "service" and entry not in blast["affected_services"]:
                blast["affected_services"].append(entry)

    blast["total_entities"] = (
        len(blast["affected_ips"])
        + len(blast["affected_users"])
        + len(blast["affected_services"])
    )

    return blast


# ─── Step 5: ROOT CAUSE ─────────────────────────────────

def _determine_root_cause(alert: dict, timeline: list[dict], correlation: dict) -> str:
    """Trace back to initial attack vector based on event patterns."""
    event_type = alert.get("event_type", "")
    category = event_type.split(".")[0] if "." in event_type else event_type

    # Check for known attack patterns
    if category == "carding":
        high_abuse_ips = [
            ip for ip, rep in correlation.get("ip_reputations", {}).items()
            if rep.get("data", {}).get("abuseConfidenceScore", 0) > 50
            or rep.get("abuse_score", 0) > 50
        ]
        if high_abuse_ips:
            return (
                f"Carding attack originating from known malicious IPs ({', '.join(high_abuse_ips[:3])}). "
                f"Attacker is testing stolen card data using automated tools. "
                f"Attack pattern: {event_type.split('.')[-1] if '.' in event_type else 'unknown'}."
            )
        return (
            f"Carding attack detected via {event_type}. "
            "Source IPs do not have prior abuse history — possible fresh proxy/VPN infrastructure."
        )

    if category == "auth":
        sub_type = event_type.split(".")[-1] if "." in event_type else "unknown"
        related_count = len(correlation.get("related_alerts", []))

        if sub_type == "brute_force":
            return (
                f"Brute-force authentication attack. "
                f"{related_count} related alerts suggest a sustained campaign. "
                "Initial vector: direct password guessing against login endpoint."
            )
        if sub_type == "credential_stuffing":
            return (
                "Credential stuffing attack using leaked credentials from external breach. "
                f"{related_count} related alerts detected across the attack window."
            )
        if sub_type == "impossible_travel":
            return (
                "Account compromise detected via impossible travel. "
                "Legitimate credentials used from geographically impossible locations, "
                "suggesting credential theft or session hijacking."
            )
        if sub_type == "privilege_escalation":
            return (
                "Unauthorized privilege escalation detected. "
                "Attacker has valid credentials and is attempting to elevate access."
            )
        return f"Authentication anomaly: {sub_type}. Further analysis required."

    if category in ("infra", "infrastructure"):
        sub_type = event_type.split(".")[-1] if "." in event_type else "unknown"
        if sub_type == "iam_escalation":
            return (
                "IAM privilege escalation detected. "
                "Attacker created backdoor accounts and attached administrative policies. "
                "Access keys generated for persistent access."
            )
        if sub_type == "security_group_change":
            return (
                "Unauthorized security group modification. "
                "Inbound rules opened to allow unrestricted access (0.0.0.0/0)."
            )
        if sub_type == "s3_unauthorized":
            return (
                "S3 bucket policy changed to allow public access. "
                "Potential data exfiltration or staging for further attacks."
            )
        return (
            f"Infrastructure security event: {event_type}. "
            "Possible misconfiguration exploitation or lateral movement."
        )

    if category == "ai_agent":
        sub_type = event_type.split(".")[-1] if "." in event_type else "unknown"
        if sub_type == "prompt_injection":
            return (
                "Prompt injection attack targeting AI agent. "
                "Adversarial input designed to override system instructions and manipulate agent behavior."
            )
        if sub_type == "jailbreak_attempt":
            return (
                "Jailbreak attempt on AI agent. "
                "Attacker attempting to bypass safety guardrails and extract unauthorized capabilities."
            )
        if sub_type == "data_exfiltration":
            return (
                "Data exfiltration via AI agent output. "
                "Agent manipulated to reveal sensitive information (credentials, PII, API keys)."
            )
        if sub_type in ("tool_call_loop", "excessive_tool_calls", "duplicate_tool_calls"):
            return (
                f"AI agent tool abuse detected ({sub_type}). "
                "Agent stuck in execution loop or making excessive API calls, "
                "indicating either adversarial manipulation or agent malfunction."
            )
        if sub_type == "token_abuse":
            return (
                "AI agent token consumption anomaly. "
                "Excessive LLM token usage detected — possible resource exhaustion attack."
            )
        if sub_type == "guardrail_block":
            return (
                "AI agent guardrail violation. "
                "Safety guardrails blocked an unsafe operation — indicates adversarial probing."
            )
        return f"AI agent security event: {event_type}. Further analysis required."

    return f"Alert type {event_type} detected. Root cause requires further manual analysis."


# ─── Step 6: IOC EXTRACTION ─────────────────────────────

def _extract_iocs(artifacts: dict, correlation: dict) -> list[dict]:
    """Collect all indicators of compromise with enrichment data."""
    iocs = []

    for ip in artifacts["ips"]:
        rep = correlation.get("ip_reputations", {}).get(ip, {})
        abuse_score = (
            rep.get("data", {}).get("abuseConfidenceScore")
            or rep.get("abuse_score")
            or 0
        )
        iocs.append({
            "type": "ip",
            "value": ip,
            "abuse_score": abuse_score,
            "is_tor": rep.get("data", {}).get("isTor", False) or rep.get("is_tor", False),
            "country": rep.get("data", {}).get("countryCode") or rep.get("country", ""),
            "threat_level": "high" if abuse_score > 50 else ("medium" if abuse_score > 20 else "low"),
        })

    for email in artifacts["emails"]:
        iocs.append({
            "type": "email",
            "value": email,
            "threat_level": "medium",
        })

    for domain in artifacts["domains"]:
        iocs.append({
            "type": "domain",
            "value": domain,
            "threat_level": "medium",
        })

    for card_bin in artifacts["card_bins"]:
        iocs.append({
            "type": "card_bin",
            "value": card_bin,
            "threat_level": "high",
        })

    return iocs


# ─── Step 7: RESPONSE ACTIONS ───────────────────────────

async def _propose_response_actions(
    db_pool: asyncpg.Pool,
    tenant_id: str,
    alert_id: str,
    incident_id: str,
    alert: dict,
    iocs: list[dict],
    blast_radius: dict,
) -> list[dict]:
    """Propose containment/remediation actions based on investigation findings."""
    actions = []
    event_type = alert.get("event_type", "")
    category = event_type.split(".")[0] if "." in event_type else event_type

    # Block malicious IPs (auto — no approval needed)
    high_threat_ips = [ioc for ioc in iocs if ioc["type"] == "ip" and ioc.get("threat_level") == "high"]
    for ioc in high_threat_ips:
        actions.append({
            "action_type": "block_ip",
            "parameters": {"ip": ioc["value"], "reason": f"Investigation {incident_id}: abuse score {ioc.get('abuse_score', 'N/A')}"},
            "risk_level": "auto",
        })

    # Carding-specific actions
    if category == "carding":
        actions.append({
            "action_type": "enable_enhanced_logging",
            "parameters": {"service": "stripe", "level": "verbose", "duration_hours": 72},
            "risk_level": "auto",
        })
        if len(high_threat_ips) >= 3:
            actions.append({
                "action_type": "rotate_api_key",
                "parameters": {"service": "stripe", "reason": "Sustained carding campaign detected"},
                "risk_level": "high",
            })

    # Auth-specific actions
    if category == "auth":
        affected_users = blast_radius.get("affected_users", [])
        for user in affected_users[:5]:
            actions.append({
                "action_type": "disable_user",
                "parameters": {"user": user["value"], "reason": f"Compromised via {event_type}"},
                "risk_level": "high",
            })

        sub_type = event_type.split(".")[-1] if "." in event_type else ""
        if sub_type in ("credential_stuffing", "impossible_travel"):
            actions.append({
                "action_type": "revoke_all_sessions",
                "parameters": {"scope": "affected_users", "reason": "Credential compromise confirmed"},
                "risk_level": "critical",
            })

        # Always enhance logging + notify for auth attacks
        actions.append({
            "action_type": "enable_enhanced_logging",
            "parameters": {"service": "auth", "level": "verbose", "duration_hours": 48},
            "risk_level": "auto",
        })
        actions.append({
            "action_type": "notify_security",
            "parameters": {"incident_id": incident_id, "event_type": event_type, "severity": alert.get("severity", "high")},
            "risk_level": "auto",
        })

    # Infrastructure-specific actions
    if category in ("infra", "infrastructure"):
        raw_payload = alert.get("raw_payload") or {}
        if isinstance(raw_payload, str):
            try:
                raw_payload = json.loads(raw_payload)
            except (json.JSONDecodeError, TypeError):
                raw_payload = {}

        sub_type = event_type.split(".")[-1] if "." in event_type else ""

        actions.append({
            "action_type": "enable_enhanced_logging",
            "parameters": {"service": "infrastructure", "level": "verbose", "duration_hours": 72},
            "risk_level": "auto",
        })

        if sub_type == "security_group_change":
            actions.append({
                "action_type": "revert_security_group",
                "parameters": {
                    "security_group_id": raw_payload.get("security_group_id", "unknown"),
                    "reason": f"Unauthorized change detected in incident {incident_id}",
                },
                "risk_level": "high",
            })

        if sub_type == "iam_escalation":
            actions.append({
                "action_type": "disable_iam_user",
                "parameters": {
                    "iam_user": raw_payload.get("user_name", raw_payload.get("userName", "unknown")),
                    "reason": f"Privilege escalation detected in incident {incident_id}",
                },
                "risk_level": "critical",
            })
            actions.append({
                "action_type": "rotate_api_key",
                "parameters": {"service": "aws", "reason": "IAM escalation — keys may be compromised"},
                "risk_level": "high",
            })

        actions.append({
            "action_type": "notify_ops",
            "parameters": {"incident_id": incident_id, "event_type": event_type, "severity": alert.get("severity", "high")},
            "risk_level": "auto",
        })

    # AI Agent-specific actions
    if category == "ai_agent":
        raw_payload = alert.get("raw_payload") or {}
        if isinstance(raw_payload, str):
            try:
                raw_payload = json.loads(raw_payload)
            except (json.JSONDecodeError, TypeError):
                raw_payload = {}

        sub_type = event_type.split(".")[-1] if "." in event_type else ""
        agent_name = raw_payload.get("agent_name", raw_payload.get("agent_id", "unknown_agent"))

        # Always enable enhanced logging for AI agent threats
        actions.append({
            "action_type": "enable_enhanced_logging",
            "parameters": {"service": "ai_agents", "agent": agent_name, "level": "verbose", "duration_hours": 48},
            "risk_level": "auto",
        })

        # High-risk: disable agent for injection, jailbreak, exfiltration
        if sub_type in ("prompt_injection", "jailbreak_attempt", "data_exfiltration"):
            actions.append({
                "action_type": "disable_user",
                "parameters": {"user": agent_name, "reason": f"AI agent threat: {sub_type} in incident {incident_id}"},
                "risk_level": "high",
            })

        # Critical: revoke sessions for data exfiltration (agent may have leaked tokens)
        if sub_type == "data_exfiltration":
            actions.append({
                "action_type": "revoke_all_sessions",
                "parameters": {"scope": "ai_agent", "agent": agent_name, "reason": "Data exfiltration — revoking all agent tokens"},
                "risk_level": "critical",
            })

        # High-risk: rotate API key for token abuse
        if sub_type == "token_abuse":
            actions.append({
                "action_type": "rotate_api_key",
                "parameters": {"service": "ai_agent_llm", "agent": agent_name, "reason": "Token abuse detected"},
                "risk_level": "high",
            })

        # Notify security team
        actions.append({
            "action_type": "notify_security",
            "parameters": {
                "incident_id": incident_id,
                "event_type": event_type,
                "agent": agent_name,
                "severity": alert.get("severity", "high"),
            },
            "risk_level": "auto",
        })

    # Severity-based fallback — ensure HIGH/CRITICAL alerts always get at least one action
    severity = alert.get("severity", "medium")
    if not actions and severity in ("high", "critical"):
        actions.append({
            "action_type": "enable_enhanced_logging",
            "parameters": {"service": category, "level": "verbose", "duration_hours": 48, "reason": f"Automated response for {event_type}"},
            "risk_level": "auto",
        })
        actions.append({
            "action_type": "notify_security",
            "parameters": {"incident_id": incident_id, "event_type": event_type, "severity": severity},
            "risk_level": "auto",
        })

    # Write to response_actions table
    written = []
    async with db_pool.acquire() as conn:
        for action in actions:
            action_id = str(uuid.uuid4())
            template = RESPONSE_TEMPLATES.get(action["action_type"], {})
            await conn.execute(
                """
                INSERT INTO response_actions
                    (id, tenant_id, alert_id, incident_id, action_type,
                     parameters, risk_level, status, proposed_by)
                VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8, $9)
                """,
                action_id,
                tenant_id,
                alert_id,
                incident_id,
                action["action_type"],
                json.dumps(action["parameters"]),
                action["risk_level"],
                "approved" if action["risk_level"] == "auto" else "pending",
                "investigation_agent",
            )
            written.append({
                "id": action_id,
                "action_type": action["action_type"],
                "risk_level": action["risk_level"],
                "status": "approved" if action["risk_level"] == "auto" else "pending",
                "description": template.get("description", action["action_type"]),
                "requires_approval": template.get("requires_approval", True),
            })

    return written


# ─── Incident Creation / Linking ─────────────────────────

async def _find_or_create_incident(
    db_pool: asyncpg.Pool,
    tenant_id: str,
    alert_id: str,
    alert: dict,
    iocs: list[dict],
    timeline: list[dict],
    blast_radius: dict,
    root_cause: str,
) -> tuple[str, bool]:
    """Find an existing incident to link to, or create a new one.

    Returns (incident_id, was_created).
    """
    async with db_pool.acquire() as conn:
        # Check if alert already linked
        existing = await conn.fetchval(
            "SELECT incident_id FROM alerts WHERE id = $1 AND incident_id IS NOT NULL",
            alert_id,
        )
        if existing:
            return str(existing), False

        # Check for open incidents with shared IOCs (2+ matches → link)
        ioc_values = [ioc["value"] for ioc in iocs if ioc.get("value")]
        if ioc_values:
            # Look for incidents that share IOCs via their linked alerts' artifacts
            match = await conn.fetchval(
                """
                SELECT i.id
                FROM incidents i
                JOIN alerts a ON a.incident_id = i.id
                WHERE i.tenant_id = $1
                  AND i.status IN ('open', 'investigating')
                  AND a.artifacts::text LIKE ANY($2::text[])
                ORDER BY i.created_at DESC
                LIMIT 1
                """,
                tenant_id,
                [f"%{v}%" for v in ioc_values[:10]],
            )
            if match:
                # Update existing incident — merge timeline, keep longest root_cause
                await conn.execute(
                    """
                    UPDATE incidents
                    SET timeline = timeline || $1::jsonb,
                        blast_radius = $2::jsonb,
                        root_cause = CASE
                            WHEN LENGTH(COALESCE(root_cause, '')) >= LENGTH($3) THEN root_cause
                            ELSE $3
                        END,
                        status = 'investigating',
                        updated_at = NOW()
                    WHERE id = $4
                    """,
                    json.dumps(timeline[-3:]),  # Append last 3 events
                    json.dumps(blast_radius),
                    root_cause,
                    str(match),
                )
                logger.info("investigation.incident_linked", incident_id=str(match), alert_id=alert_id)
                return str(match), False

        # Create new incident
        incident_id = str(uuid.uuid4())
        severity = alert.get("severity", "high")
        triage_severity = alert.get("triage_result", {})
        if isinstance(triage_severity, str):
            try:
                triage_severity = json.loads(triage_severity)
            except (json.JSONDecodeError, TypeError):
                triage_severity = {}
        severity = triage_severity.get("severity_adjusted", severity)

        await conn.execute(
            """
            INSERT INTO incidents
                (id, tenant_id, title, severity, status,
                 description, timeline, blast_radius, root_cause)
            VALUES ($1, $2, $3, $4, 'investigating', $5, $6::jsonb, $7::jsonb, $8)
            """,
            incident_id,
            tenant_id,
            f"INC: {alert.get('title', 'Security Incident')}",
            severity,
            f"Auto-created by investigation agent from alert {alert_id}. {root_cause}",
            json.dumps(timeline),
            json.dumps(blast_radius),
            root_cause,
        )

        logger.info("investigation.incident_created", incident_id=incident_id, alert_id=alert_id)
        return incident_id, True


# ─── Rule-Based Investigation ────────────────────────────

async def investigate_rule_based(
    alert: dict,
    triage_result: dict,
    db_pool: asyncpg.Pool,
) -> InvestigationResult:
    """7-step rule-based investigation pipeline."""
    tenant_id = alert["tenant_id"]
    alert_id = alert["id"]
    tracer = ExecutionTracer(db_pool, tenant_id, alert_id)

    # Step 1: INTAKE
    with StepTimer() as t:
        artifacts = _extract_artifacts(alert, triage_result)
    await tracer.log_step(
        "intake", input_data={"alert_id": alert_id}, output_data=artifacts, duration_ms=t.duration_ms,
    )
    logger.info("investigation.step.intake", alert_id=alert_id, ips=len(artifacts["ips"]), emails=len(artifacts["emails"]))

    # Step 2: CORRELATION
    with StepTimer() as t:
        correlation = await _correlate(artifacts, alert)
    await tracer.log_step(
        "correlation",
        input_data={"artifact_count": sum(len(v) for v in artifacts.values() if isinstance(v, list))},
        output_data={
            "cloudtrail_events": len(correlation["cloudtrail_events"]),
            "ip_reputations": len(correlation["ip_reputations"]),
            "related_alerts": len(correlation["related_alerts"]),
        },
        tool_calls=["query_cloudtrail", "check_ip_reputation", "get_related_incidents", "get_asset_context"],
        duration_ms=t.duration_ms,
    )
    logger.info("investigation.step.correlation", alert_id=alert_id, related=len(correlation["related_alerts"]))

    # Step 3: TIMELINE
    with StepTimer() as t:
        timeline = _build_timeline(alert, correlation)
    await tracer.log_step(
        "timeline", output_data={"event_count": len(timeline)}, duration_ms=t.duration_ms,
    )

    # Step 4: BLAST RADIUS
    with StepTimer() as t:
        blast_radius = await _assess_blast_radius(artifacts)
    await tracer.log_step(
        "blast_radius",
        output_data=blast_radius,
        tool_calls=["traverse_blast_radius"],
        duration_ms=t.duration_ms,
    )
    logger.info("investigation.step.blast_radius", alert_id=alert_id, total_entities=blast_radius["total_entities"])

    # Step 5: ROOT CAUSE
    with StepTimer() as t:
        root_cause = _determine_root_cause(alert, timeline, correlation)
    await tracer.log_step(
        "root_cause", output_data={"root_cause": root_cause}, duration_ms=t.duration_ms,
    )

    # Step 6: IOC EXTRACTION
    with StepTimer() as t:
        iocs = _extract_iocs(artifacts, correlation)
    await tracer.log_step(
        "ioc_extraction", output_data={"ioc_count": len(iocs), "iocs": iocs}, duration_ms=t.duration_ms,
    )

    # Step 7a: INCIDENT creation / linking
    with StepTimer() as t:
        incident_id, incident_created = await _find_or_create_incident(
            db_pool, tenant_id, alert_id, alert, iocs, timeline, blast_radius, root_cause,
        )
    await tracer.log_step(
        "incident_link",
        output_data={"incident_id": incident_id, "created": incident_created},
        duration_ms=t.duration_ms,
    )

    # Step 7b: RESPONSE actions
    with StepTimer() as t:
        response_actions = await _propose_response_actions(
            db_pool, tenant_id, alert_id, incident_id, alert, iocs, blast_radius,
        )
    requires_critic = any(a["risk_level"] in ("high", "critical") for a in response_actions)
    await tracer.log_step(
        "response_actions",
        output_data={"actions": response_actions, "requires_critic": requires_critic},
        duration_ms=t.duration_ms,
    )

    # Update knowledge graph with IOCs
    for ioc in iocs:
        if ioc.get("threat_level") == "high":
            await update_knowledge_graph(
                operation="create_node",
                entity_type=ioc["type"],
                entity_value=ioc["value"],
                properties={"threat_level": "high", "source": "investigation_agent", "incident_id": incident_id},
            )

    confidence = _calculate_confidence(artifacts, correlation, iocs)

    reasoning = (
        f"Investigation of alert '{alert.get('title')}' completed via rule-based pipeline. "
        f"Found {len(iocs)} IOCs, {len(timeline)} timeline events, "
        f"blast radius covers {blast_radius['total_entities']} entities. "
        f"Root cause: {root_cause[:200]}"
    )

    return InvestigationResult(
        incident_id=incident_id,
        incident_created=incident_created,
        timeline=timeline,
        blast_radius=blast_radius,
        root_cause=root_cause,
        iocs=iocs,
        response_actions=response_actions,
        confidence=confidence,
        requires_critic_review=requires_critic,
        reasoning=reasoning,
    )


def _calculate_confidence(artifacts: dict, correlation: dict, iocs: list[dict]) -> float:
    """Heuristic confidence score for the investigation findings."""
    score = 0.5  # Base

    # More data sources = higher confidence
    if correlation.get("cloudtrail_events"):
        score += 0.1
    if correlation.get("ip_reputations"):
        score += 0.05
    if correlation.get("related_alerts"):
        score += 0.1
    if correlation.get("graph_context"):
        score += 0.05

    # High-threat IOCs increase confidence
    high_threat = sum(1 for ioc in iocs if ioc.get("threat_level") == "high")
    score += min(high_threat * 0.05, 0.15)

    # More artifacts = better picture
    total_artifacts = sum(len(v) for v in artifacts.values() if isinstance(v, list))
    if total_artifacts >= 3:
        score += 0.05

    return min(round(score, 2), 0.99)


# ─── LLM-Enhanced Investigation ─────────────────────────

async def investigate_llm(
    alert: dict,
    triage_result: dict,
    db_pool: asyncpg.Pool,
) -> InvestigationResult:
    """LLM-enhanced investigation — runs rule-based first, then synthesizes with Claude."""
    # Run full rule-based pipeline to gather all data
    rb_result = await investigate_rule_based(alert, triage_result, db_pool)

    try:
        import anthropic
    except ImportError:
        logger.warning("anthropic not installed, returning rule-based result")
        return rb_result

    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        return rb_result

    # Build LLM prompt with all gathered context
    prompt = f"""You are a senior SOC analyst performing a deep investigation on an escalated security alert.
All the raw data has been gathered. Synthesize it into a clear, actionable analysis.

ALERT:
- Type: {alert.get('event_type')}
- Title: {alert.get('title')}
- Severity: {triage_result.get('severity_adjusted', alert.get('severity'))}
- Source: {alert.get('source')}

TRIAGE RESULT:
- Verdict: {triage_result.get('verdict')}
- Reasoning: {triage_result.get('reasoning')}

TIMELINE ({len(rb_result.timeline)} events):
{json.dumps(rb_result.timeline[:10], indent=2, default=str)}

BLAST RADIUS:
{json.dumps(rb_result.blast_radius, indent=2, default=str)}

IOCs ({len(rb_result.iocs)}):
{json.dumps(rb_result.iocs[:10], indent=2, default=str)}

CURRENT ROOT CAUSE ANALYSIS:
{rb_result.root_cause}

PROPOSED RESPONSE ACTIONS:
{json.dumps(rb_result.response_actions, indent=2, default=str)}

Provide your analysis as JSON:
{{
  "root_cause": "refined root cause analysis with attack chain description",
  "confidence": 0.0-1.0,
  "reasoning": "detailed investigation reasoning and conclusions",
  "additional_actions": ["any additional response actions you recommend"],
  "requires_critic_review": true/false
}}"""

    try:
        client = anthropic.Anthropic(api_key=api_key)
        response = client.messages.create(
            model="claude-sonnet-4-5-20250929",
            max_tokens=1500,
            messages=[{"role": "user", "content": prompt}],
        )
        text = response.content[0].text

        start = text.find("{")
        end = text.rfind("}") + 1
        if start >= 0 and end > start:
            llm_data = json.loads(text[start:end])
        else:
            raise ValueError("No JSON found in LLM response")

        # Log LLM step to tracer
        tracer = ExecutionTracer(db_pool, alert["tenant_id"], alert["id"])
        await tracer.log_step(
            "llm_synthesis",
            input_data={"model": "claude-sonnet-4-5-20250929"},
            output_data=llm_data,
            tokens_used=response.usage.input_tokens + response.usage.output_tokens,
        )

        # Merge LLM reasoning with rule-based data
        return InvestigationResult(
            incident_id=rb_result.incident_id,
            incident_created=rb_result.incident_created,
            timeline=rb_result.timeline,
            blast_radius=rb_result.blast_radius,
            root_cause=llm_data.get("root_cause", rb_result.root_cause),
            iocs=rb_result.iocs,
            response_actions=rb_result.response_actions,
            confidence=llm_data.get("confidence", rb_result.confidence),
            requires_critic_review=llm_data.get("requires_critic_review", rb_result.requires_critic_review),
            reasoning=llm_data.get("reasoning", rb_result.reasoning),
        )

    except Exception as e:
        logger.warning("llm.investigation.failed", error=str(e))
        return rb_result


# ─── Main entry point ────────────────────────────────────

async def investigate_alert(
    alert: dict,
    triage_result: dict,
    db_pool: asyncpg.Pool,
) -> InvestigationResult:
    """Investigate an escalated alert — uses LLM if available, otherwise rule-based."""
    logger.info("investigation.triggered", alert_id=alert["id"], event_type=alert.get("event_type"))

    if is_llm_available():
        result = await investigate_llm(alert, triage_result, db_pool)
    else:
        result = await investigate_rule_based(alert, triage_result, db_pool)

    logger.info(
        "investigation.completed",
        alert_id=alert["id"],
        incident_id=result.incident_id,
        incident_created=result.incident_created,
        iocs=len(result.iocs),
        actions=len(result.response_actions),
        confidence=result.confidence,
        requires_critic=result.requires_critic_review,
    )

    return result
