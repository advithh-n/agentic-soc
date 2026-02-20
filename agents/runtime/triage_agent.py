"""Triage Agent — classifies, enriches, and correlates SOC alerts.

Pipeline:
  1. CLASSIFY — determine true_positive / false_positive / needs_investigation
  2. ENRICH  — query Neo4j for asset context, check known threat indicators
  3. CORRELATE — link to related alerts, detect campaigns

Modes:
  - Rule-based (default): Works without LLM API key, uses heuristics
  - LLM-enhanced: Uses Claude Haiku when ANTHROPIC_API_KEY is set
"""

import json
import os
from datetime import datetime, timezone
from enum import Enum

import structlog

from runtime.tools import get_asset_context, get_related_incidents, is_llm_available

logger = structlog.get_logger()


class TriageVerdict(str, Enum):
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    NEEDS_INVESTIGATION = "needs_investigation"


class TriageResult:
    """Result of triage analysis."""

    def __init__(
        self,
        verdict: TriageVerdict,
        confidence: float,
        severity_adjusted: str,
        mitre_techniques: list[str],
        summary: str,
        enrichment: dict,
        recommended_action: str,
        escalate: bool,
        reasoning: str,
    ):
        self.verdict = verdict
        self.confidence = confidence
        self.severity_adjusted = severity_adjusted
        self.mitre_techniques = mitre_techniques
        self.summary = summary
        self.enrichment = enrichment
        self.recommended_action = recommended_action
        self.escalate = escalate
        self.reasoning = reasoning

    def to_dict(self) -> dict:
        return {
            "verdict": self.verdict.value,
            "confidence": self.confidence,
            "severity_adjusted": self.severity_adjusted,
            "mitre_techniques": self.mitre_techniques,
            "summary": self.summary,
            "enrichment": self.enrichment,
            "recommended_action": self.recommended_action,
            "escalate": self.escalate,
            "reasoning": self.reasoning,
            "triaged_at": datetime.now(timezone.utc).isoformat(),
            "triage_mode": "llm" if is_llm_available() else "rule_based",
        }


# ─── MITRE ATT&CK Mapping ────────────────────────────────

EVENT_TYPE_MITRE = {
    "carding.multi_card_velocity": ["T1530"],
    "carding.small_amount_testing": ["T1530"],
    "carding.bin_cycling": ["T1530"],
    "carding.rapid_sequence": ["T1530"],
    "carding.high_failure_rate": ["T1530"],
    "auth.brute_force": ["T1110.001"],
    "auth.credential_stuffing": ["T1110.004"],
    "auth.impossible_travel": ["T1078"],
    "auth.privilege_escalation": ["T1078.004"],
    "auth.session_anomaly": ["T1078"],
}

# ─── Severity escalation rules ───────────────────────────

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _adjust_severity(base: str, threat_context: dict, related_count: int) -> str:
    """Adjust severity based on threat context and correlation."""
    level = SEVERITY_ORDER.get(base, 1)

    # Escalate if IP is a known threat actor
    if threat_context.get("found") and threat_context.get("properties", {}).get("threat_level") == "high":
        level = max(level, 2)  # At least HIGH

    # Escalate if correlated with many other alerts
    if related_count >= 5:
        level = min(level + 1, 3)

    # Map back
    for name, val in SEVERITY_ORDER.items():
        if val == level:
            return name
    return base


# ─── Rule-Based Triage ────────────────────────────────────

async def triage_rule_based(alert: dict) -> TriageResult:
    """Rule-based triage — no LLM needed.

    Enriches with Neo4j context and applies heuristic classification.
    """
    event_type = alert.get("event_type", "")
    severity = alert.get("severity", "medium")
    source = alert.get("source", "")
    confidence = alert.get("confidence", 0.5)

    # Step 1: Extract artifacts for enrichment
    artifacts = alert.get("artifacts", [])
    if isinstance(artifacts, str):
        try:
            artifacts = json.loads(artifacts)
        except (json.JSONDecodeError, TypeError):
            artifacts = []

    ips = [a["value"] for a in artifacts if a.get("type") == "ip"]
    emails = [a["value"] for a in artifacts if a.get("type") == "email"]

    # Step 2: ENRICH — query Neo4j for asset context
    enrichment = {"ip_context": [], "user_context": [], "related_alert_count": 0}

    for ip in ips[:3]:  # Limit to avoid timeout
        ctx = await get_asset_context("ip", ip)
        enrichment["ip_context"].append(ctx)

    for email in emails[:3]:
        ctx = await get_asset_context("user", email)
        enrichment["user_context"].append(ctx)

    # Step 3: Check for related incidents
    related_count = 0
    for ip in ips[:1]:
        related = await get_related_incidents("ip", ip)
        related_count += related.get("count", 0)
    enrichment["related_alert_count"] = related_count

    # Step 4: CLASSIFY — heuristic rules
    is_known_threat = any(
        ctx.get("found") and ctx.get("properties", {}).get("threat_level") == "high"
        for ctx in enrichment["ip_context"]
    )

    is_internal_user = any(
        ctx.get("found") and ctx.get("properties", {}).get("department")
        for ctx in enrichment["user_context"]
    )

    # Classification logic
    if is_known_threat and confidence >= 0.7:
        verdict = TriageVerdict.TRUE_POSITIVE
        reasoning = (
            f"Alert source IP is a known threat actor (Tor exit node / botnet). "
            f"Combined with high detection confidence ({confidence:.0%}), "
            f"this is very likely a true positive."
        )
    elif confidence >= 0.85:
        verdict = TriageVerdict.TRUE_POSITIVE
        reasoning = (
            f"High confidence detection ({confidence:.0%}) from {source} module. "
            f"Multiple detection rules triggered for {event_type}."
        )
    elif confidence >= 0.5:
        verdict = TriageVerdict.NEEDS_INVESTIGATION
        reasoning = (
            f"Moderate confidence ({confidence:.0%}). "
            f"Alert needs human review to confirm true/false positive."
        )
    else:
        verdict = TriageVerdict.FALSE_POSITIVE
        reasoning = (
            f"Low confidence detection ({confidence:.0%}). "
            f"Likely benign activity or noise."
        )

    # Adjust severity
    threat_ctx = enrichment["ip_context"][0] if enrichment["ip_context"] else {}
    severity_adjusted = _adjust_severity(severity, threat_ctx, related_count)

    # MITRE mapping
    mitre = EVENT_TYPE_MITRE.get(event_type, [])

    # Recommended action
    if verdict == TriageVerdict.TRUE_POSITIVE and severity_adjusted in ("high", "critical"):
        action = "escalate_to_incident"
        escalate = True
    elif verdict == TriageVerdict.NEEDS_INVESTIGATION:
        action = "assign_to_analyst"
        escalate = False
    else:
        action = "auto_close"
        escalate = False

    summary = (
        f"[{verdict.value.upper()}] {alert.get('title', 'Unknown alert')} — "
        f"Severity: {severity} → {severity_adjusted}. "
        f"{'Known threat IP. ' if is_known_threat else ''}"
        f"{'Internal user affected. ' if is_internal_user else ''}"
        f"{related_count} related alerts found."
    )

    return TriageResult(
        verdict=verdict,
        confidence=confidence,
        severity_adjusted=severity_adjusted,
        mitre_techniques=mitre,
        summary=summary,
        enrichment=enrichment,
        recommended_action=action,
        escalate=escalate,
        reasoning=reasoning,
    )


# ─── LLM-Enhanced Triage ─────────────────────────────────

async def triage_llm(alert: dict) -> TriageResult:
    """LLM-enhanced triage using Claude Haiku.

    Falls back to rule-based if API call fails.
    """
    try:
        import anthropic
    except ImportError:
        logger.warning("anthropic not installed, falling back to rule-based")
        return await triage_rule_based(alert)

    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        return await triage_rule_based(alert)

    # First, get enrichment (same as rule-based)
    artifacts = alert.get("artifacts", [])
    if isinstance(artifacts, str):
        try:
            artifacts = json.loads(artifacts)
        except (json.JSONDecodeError, TypeError):
            artifacts = []

    ips = [a["value"] for a in artifacts if a.get("type") == "ip"]
    emails = [a["value"] for a in artifacts if a.get("type") == "email"]

    enrichment = {"ip_context": [], "user_context": [], "related_alert_count": 0}
    for ip in ips[:3]:
        enrichment["ip_context"].append(await get_asset_context("ip", ip))
    for email in emails[:3]:
        enrichment["user_context"].append(await get_asset_context("user", email))
    for ip in ips[:1]:
        related = await get_related_incidents("ip", ip)
        enrichment["related_alert_count"] += related.get("count", 0)

    # Build prompt
    prompt = f"""You are a SOC analyst triaging a security alert. Analyze this alert and provide a classification.

ALERT:
- Type: {alert.get('event_type')}
- Source: {alert.get('source')}
- Severity: {alert.get('severity')}
- Confidence: {alert.get('confidence')}
- Title: {alert.get('title')}
- Description: {alert.get('description')}

ENRICHMENT:
- IP Context: {json.dumps(enrichment['ip_context'], default=str)[:500]}
- User Context: {json.dumps(enrichment['user_context'], default=str)[:500]}
- Related Alerts: {enrichment['related_alert_count']}

Respond in this exact JSON format:
{{
  "verdict": "true_positive" | "false_positive" | "needs_investigation",
  "confidence": 0.0-1.0,
  "severity_adjusted": "low" | "medium" | "high" | "critical",
  "reasoning": "brief explanation",
  "recommended_action": "escalate_to_incident" | "assign_to_analyst" | "auto_close",
  "escalate": true | false
}}"""

    try:
        client = anthropic.Anthropic(api_key=api_key)
        response = client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=500,
            messages=[{"role": "user", "content": prompt}],
        )
        text = response.content[0].text

        # Parse JSON from response
        # Find JSON block
        start = text.find("{")
        end = text.rfind("}") + 1
        if start >= 0 and end > start:
            result_data = json.loads(text[start:end])
        else:
            raise ValueError("No JSON found in response")

        return TriageResult(
            verdict=TriageVerdict(result_data["verdict"]),
            confidence=result_data.get("confidence", alert.get("confidence", 0.5)),
            severity_adjusted=result_data.get("severity_adjusted", alert.get("severity", "medium")),
            mitre_techniques=EVENT_TYPE_MITRE.get(alert.get("event_type", ""), []),
            summary=f"[LLM] {result_data.get('reasoning', 'No reasoning provided')}",
            enrichment=enrichment,
            recommended_action=result_data.get("recommended_action", "assign_to_analyst"),
            escalate=result_data.get("escalate", False),
            reasoning=result_data.get("reasoning", "LLM analysis"),
        )

    except Exception as e:
        logger.warning("llm.triage.failed", error=str(e))
        return await triage_rule_based(alert)


# ─── Main entry point ────────────────────────────────────

async def triage_alert(alert: dict) -> TriageResult:
    """Triage an alert — uses LLM if available, otherwise rule-based."""
    if is_llm_available():
        return await triage_llm(alert)
    return await triage_rule_based(alert)
