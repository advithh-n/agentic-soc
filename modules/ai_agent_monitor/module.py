"""AI Agent Monitor Detection Module.

Detects anomalous and malicious AI agent behavior:
- Prompt injection: Known injection patterns in user inputs
- Hallucination indicators: Low confidence, factual inconsistency markers
- Excessive tool calls: Too many tool invocations in a session (loop detection)
- Data exfiltration: Sensitive data patterns in agent outputs (PII, secrets)
- Guardrail violations: NeMo Guardrails block events
- Token abuse: Abnormally high token consumption per session
- Jailbreak attempts: System prompt extraction, role-play attacks
"""

import re
from collections import defaultdict
from datetime import datetime, timedelta

import structlog

from engine.base_module import BaseModule
from engine.models import AlertModel, Artifact, ArtifactType, Severity, StreamEvent

logger = structlog.get_logger()

# ─── Sliding Window State ─────────────────────────────────
# Keyed by agent_id or session_id
_session_tool_calls: dict[str, list[dict]] = defaultdict(list)
_session_tokens: dict[str, list[dict]] = defaultdict(list)
_agent_errors: dict[str, list[dict]] = defaultdict(list)
_WINDOW_SECONDS = 600  # 10 minutes


def _prune_window(store: dict[str, list[dict]], key: str):
    """Remove entries older than the sliding window."""
    cutoff = datetime.utcnow() - timedelta(seconds=_WINDOW_SECONDS)
    store[key] = [e for e in store[key] if e.get("time", datetime.min) > cutoff]


# ─── Prompt Injection Patterns ────────────────────────────
# ATLAS: AML.T0051 — LLM Prompt Injection
_INJECTION_PATTERNS = [
    # Direct injection
    r"ignore\s+(all\s+)?previous\s+instructions",
    r"ignore\s+(all\s+)?above\s+instructions",
    r"disregard\s+(all\s+)?(your\s+)?instructions",
    r"forget\s+(all\s+)?(your\s+)?previous",
    r"new\s+instructions\s*:",
    r"system\s*:\s*you\s+are\s+now",
    r"override\s+(system|safety)\s+prompt",
    # Indirect injection / role-play
    r"pretend\s+you\s+are\s+(a|an|the)",
    r"act\s+as\s+(a|an|the|if)",
    r"you\s+are\s+now\s+in\s+(developer|debug|admin)\s+mode",
    r"developer\s+mode\s+(enabled|activated|on)",
    r"DAN\s+mode",
    # System prompt extraction
    r"(print|show|repeat|reveal|display)\s+(your\s+)?(system|initial)\s+(prompt|instructions)",
    r"what\s+(are|were)\s+your\s+(system|original)\s+instructions",
    r"output\s+your\s+(system|hidden)\s+prompt",
    # Encoding bypass
    r"base64\s*(encode|decode).*ignore",
    r"translate\s+to\s+.*\s+and\s+ignore",
    # Multi-turn manipulation
    r"in\s+our\s+previous\s+conversation\s+you\s+agreed",
    r"you\s+already\s+confirmed\s+you\s+would",
]
_COMPILED_INJECTION = [re.compile(p, re.IGNORECASE) for p in _INJECTION_PATTERNS]

# ─── Data Exfiltration Patterns ───────────────────────────
# ATLAS: AML.T0024 — Exfiltration via AI System
_EXFIL_PATTERNS = [
    r"\b\d{3}-\d{2}-\d{4}\b",                          # SSN
    r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b",    # Credit card
    r"\b[A-Z]{2}\d{2}[\s]?[\dA-Z]{4}[\s]?\d{4}[\s]?\d{4}[\s]?\d{4}[\s]?\d{0,2}\b",  # IBAN
    r"(?:AKIA|ASIA)[A-Z0-9]{16}",                       # AWS access key
    r"(?:sk-|pk_live_|sk_live_|rk_live_)[a-zA-Z0-9]{20,}",  # API keys (Stripe, OpenAI)
    r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----",        # Private keys
    r"ghp_[a-zA-Z0-9]{36}",                             # GitHub PAT
    r"xox[bpas]-[a-zA-Z0-9-]+",                         # Slack tokens
    r"(?:password|passwd|secret)\s*[:=]\s*\S{8,}",      # Leaked credentials
]
_COMPILED_EXFIL = [re.compile(p, re.IGNORECASE) for p in _EXFIL_PATTERNS]

# ─── Jailbreak Patterns ──────────────────────────────────
_JAILBREAK_PATTERNS = [
    r"do\s+anything\s+now",
    r"jailbreak",
    r"no\s+restrictions?\s+mode",
    r"unrestricted\s+mode",
    r"bypass\s+(content|safety)\s+(filter|policy)",
    r"(evil|malicious|unethical)\s+(assistant|mode|AI)",
    r"opposite\s+day",
    r"hypothetical\s+scenario\s+where\s+safety",
]
_COMPILED_JAILBREAK = [re.compile(p, re.IGNORECASE) for p in _JAILBREAK_PATTERNS]

# ─── Thresholds ──────────────────────────────────────────
TOOL_CALL_THRESHOLD = 20       # Max tool calls per session in 10 min
TOKEN_ABUSE_THRESHOLD = 50000  # Max tokens per session in 10 min
ERROR_RATE_THRESHOLD = 0.5     # 50% error rate
RAPID_TOOL_CALLS = 10          # Tool calls in 1 minute = possible loop
DUPLICATE_CALL_THRESHOLD = 5   # Same tool called 5+ times = possible loop


class AiAgentMonitorModule(BaseModule):
    name = "ai_agent_monitor"
    description = "Detects AI agent anomalies: injection, hallucination, tool abuse, data exfiltration"
    streams = ["streams:ai"]

    async def process_event(self, event: StreamEvent) -> list[AlertModel]:
        """Analyze AI agent events for security anomalies."""
        payload = event.raw_payload
        source = event.source
        alerts: list[AlertModel] = []

        if source == "nemo_guardrails":
            alerts.extend(self._check_guardrail_violation(event, payload))
        elif source == "langfuse":
            alerts.extend(self._check_langfuse_trace(event, payload))

        return alerts

    # ─── Guardrail Violation Detection ────────────────────

    def _check_guardrail_violation(self, event: StreamEvent, payload: dict) -> list[AlertModel]:
        """Process NeMo Guardrails block events."""
        alerts: list[AlertModel] = []

        event_type = payload.get("event_type", "")
        rail_name = payload.get("rail_name", "unknown")
        action = payload.get("action", "")
        user_input = payload.get("user_input", "")
        agent_name = payload.get("agent_name", "unknown")
        session_id = payload.get("session_id", "")

        artifacts = []
        if session_id:
            artifacts.append(Artifact(type=ArtifactType.SESSION_ID, value=session_id, context="Agent session"))

        # Rule: Guardrail blocked an action
        if action in ("block", "blocked", "refused"):
            severity = Severity.HIGH
            if "injection" in rail_name.lower() or "injection" in event_type.lower():
                severity = Severity.CRITICAL

            alerts.append(AlertModel(
                tenant_id=event.tenant_id,
                source="nemo_guardrails",
                event_type="ai_agent.guardrail_block",
                severity=severity,
                confidence=0.90,
                title=f"Guardrail blocked: {rail_name} on agent {agent_name}",
                description=(
                    f"NeMo Guardrails blocked action '{action}' via rail '{rail_name}'. "
                    f"Input snippet: {user_input[:200]}..."
                    if len(user_input) > 200 else
                    f"NeMo Guardrails blocked action '{action}' via rail '{rail_name}'. "
                    f"Input: {user_input}"
                ),
                raw_payload=payload,
                artifacts=artifacts,
                atlas_technique="AML.T0051",
                trace_id=event.trace_id,
            ))

        # Also check the user_input for injection patterns
        alerts.extend(self._scan_for_injection(event, user_input, agent_name, session_id, payload))

        return alerts

    # ─── Langfuse Trace Analysis ──────────────────────────

    def _check_langfuse_trace(self, event: StreamEvent, payload: dict) -> list[AlertModel]:
        """Process Langfuse trace events for AI agent anomalies."""
        alerts: list[AlertModel] = []

        trace_type = payload.get("type", "")
        agent_name = payload.get("name", payload.get("agent_name", "unknown"))
        session_id = payload.get("session_id", payload.get("sessionId", ""))
        now = datetime.utcnow()

        # ── Trace-level analysis ──────────────────────────
        if trace_type in ("trace", "generation", "span"):
            input_text = self._extract_text(payload.get("input"))
            output_text = self._extract_text(payload.get("output"))
            tokens = payload.get("usage", {})
            total_tokens = (
                tokens.get("total_tokens", 0)
                or tokens.get("totalTokens", 0)
                or (tokens.get("input", 0) + tokens.get("output", 0))
            )
            model = payload.get("model", "")
            status = payload.get("status", "")
            level = payload.get("level", "DEFAULT")

            # Track tokens per session
            if session_id and total_tokens > 0:
                _session_tokens[session_id].append({"time": now, "tokens": total_tokens})
                _prune_window(_session_tokens, session_id)

            # Track errors per agent
            if status in ("ERROR", "error") or level in ("ERROR", "WARNING"):
                _agent_errors[agent_name].append({"time": now, "status": status, "level": level})
                _prune_window(_agent_errors, agent_name)

            # Rule 1: Prompt injection in input
            alerts.extend(self._scan_for_injection(event, input_text, agent_name, session_id, payload))

            # Rule 2: Jailbreak attempts
            alerts.extend(self._scan_for_jailbreak(event, input_text, agent_name, session_id, payload))

            # Rule 3: Data exfiltration in output
            alerts.extend(self._scan_for_exfiltration(event, output_text, agent_name, session_id, payload))

            # Rule 4: Token abuse
            if session_id:
                session_total = sum(e["tokens"] for e in _session_tokens[session_id])
                if session_total > TOKEN_ABUSE_THRESHOLD:
                    alerts.append(AlertModel(
                        tenant_id=event.tenant_id,
                        source="langfuse",
                        event_type="ai_agent.token_abuse",
                        severity=Severity.HIGH,
                        confidence=min(0.6 + (session_total / TOKEN_ABUSE_THRESHOLD - 1) * 0.2, 0.95),
                        title=f"Token abuse: {session_total:,} tokens in session on {agent_name}",
                        description=(
                            f"Agent '{agent_name}' session '{session_id[:12]}...' consumed "
                            f"{session_total:,} tokens in 10 minutes (threshold: {TOKEN_ABUSE_THRESHOLD:,}). "
                            f"Possible infinite loop, recursive calls, or prompt stuffing attack."
                        ),
                        raw_payload=payload,
                        artifacts=[
                            Artifact(type=ArtifactType.SESSION_ID, value=session_id, context="Abusive session"),
                        ],
                        atlas_technique="AML.T0040",  # Model Extraction
                        trace_id=event.trace_id,
                    ))

            # Rule 5: Hallucination indicators
            if output_text and level in ("WARNING",) and "hallucination" in str(payload.get("metadata", {})).lower():
                alerts.append(AlertModel(
                    tenant_id=event.tenant_id,
                    source="langfuse",
                    event_type="ai_agent.hallucination",
                    severity=Severity.MEDIUM,
                    confidence=0.65,
                    title=f"Hallucination flagged on agent {agent_name}",
                    description=(
                        f"Agent '{agent_name}' produced output flagged for potential hallucination. "
                        f"Output snippet: {output_text[:300]}"
                    ),
                    raw_payload=payload,
                    artifacts=[
                        Artifact(type=ArtifactType.SESSION_ID, value=session_id, context="Session")
                    ] if session_id else [],
                    atlas_technique="AML.T0048",  # AI Supply Chain
                    trace_id=event.trace_id,
                ))

        # ── Tool call analysis ────────────────────────────
        if trace_type in ("tool_call", "span") and payload.get("tool_name"):
            tool_name = payload.get("tool_name", "")
            tool_status = payload.get("status", "success")
            duration_ms = payload.get("duration_ms", 0)
            key = session_id or agent_name

            _session_tool_calls[key].append({
                "time": now,
                "tool": tool_name,
                "status": tool_status,
                "duration_ms": duration_ms,
            })
            _prune_window(_session_tool_calls, key)
            window = _session_tool_calls[key]

            artifacts = []
            if session_id:
                artifacts.append(Artifact(type=ArtifactType.SESSION_ID, value=session_id, context="Session"))

            # Rule 6: Excessive tool calls (loop detection)
            if len(window) >= TOOL_CALL_THRESHOLD:
                alerts.append(AlertModel(
                    tenant_id=event.tenant_id,
                    source="langfuse",
                    event_type="ai_agent.excessive_tool_calls",
                    severity=Severity.HIGH,
                    confidence=min(0.6 + (len(window) - TOOL_CALL_THRESHOLD) * 0.05, 0.95),
                    title=f"Excessive tool calls: {len(window)} calls by {agent_name}",
                    description=(
                        f"Agent '{agent_name}' made {len(window)} tool calls in 10 minutes "
                        f"(threshold: {TOOL_CALL_THRESHOLD}). Top tools: "
                        + ", ".join(f"{t}: {c}" for t, c in self._top_tools(window)[:5])
                    ),
                    raw_payload=payload,
                    artifacts=artifacts,
                    atlas_technique="AML.T0043",  # AI Denial of Service
                    trace_id=event.trace_id,
                ))

            # Rule 7: Rapid tool calls (1 minute window — possible loop)
            recent_1min = [e for e in window if e["time"] > now - timedelta(minutes=1)]
            if len(recent_1min) >= RAPID_TOOL_CALLS:
                alerts.append(AlertModel(
                    tenant_id=event.tenant_id,
                    source="langfuse",
                    event_type="ai_agent.tool_call_loop",
                    severity=Severity.CRITICAL,
                    confidence=0.85,
                    title=f"Tool call loop detected: {len(recent_1min)} calls in 1min by {agent_name}",
                    description=(
                        f"Agent '{agent_name}' is in a possible infinite loop — "
                        f"{len(recent_1min)} tool calls in the last minute. "
                        f"Immediate investigation recommended."
                    ),
                    raw_payload=payload,
                    artifacts=artifacts,
                    atlas_technique="AML.T0043",
                    trace_id=event.trace_id,
                ))

            # Rule 8: Duplicate tool calls (same tool called repeatedly)
            from collections import Counter
            tool_counts = Counter(e["tool"] for e in recent_1min)
            for tn, count in tool_counts.items():
                if count >= DUPLICATE_CALL_THRESHOLD:
                    alerts.append(AlertModel(
                        tenant_id=event.tenant_id,
                        source="langfuse",
                        event_type="ai_agent.duplicate_tool_calls",
                        severity=Severity.HIGH,
                        confidence=min(0.7 + (count - DUPLICATE_CALL_THRESHOLD) * 0.05, 0.95),
                        title=f"Duplicate tool calls: {tn} called {count}x in 1min by {agent_name}",
                        description=(
                            f"Agent '{agent_name}' called tool '{tn}' {count} times in the last "
                            f"minute. This suggests a stuck loop or retry storm."
                        ),
                        raw_payload=payload,
                        artifacts=artifacts,
                        atlas_technique="AML.T0043",
                        trace_id=event.trace_id,
                    ))
                    break  # One alert per event for duplicates

            # Rule 9: High tool error rate
            if len(window) >= 5:
                errors = [e for e in window if e["status"] in ("error", "ERROR", "failed")]
                error_rate = len(errors) / len(window)
                if error_rate > ERROR_RATE_THRESHOLD:
                    alerts.append(AlertModel(
                        tenant_id=event.tenant_id,
                        source="langfuse",
                        event_type="ai_agent.high_tool_error_rate",
                        severity=Severity.HIGH,
                        confidence=0.80,
                        title=f"High tool error rate: {error_rate:.0%} for {agent_name}",
                        description=(
                            f"Agent '{agent_name}' has a {error_rate:.0%} tool call error rate "
                            f"({len(errors)}/{len(window)} calls failed). "
                            f"Possible misconfiguration or cascading failure."
                        ),
                        raw_payload=payload,
                        artifacts=artifacts,
                        atlas_technique="AML.T0043",
                        trace_id=event.trace_id,
                    ))

        return alerts

    # ─── Scanning Helpers ─────────────────────────────────

    def _scan_for_injection(
        self, event: StreamEvent, text: str, agent_name: str, session_id: str, payload: dict,
    ) -> list[AlertModel]:
        """Scan text for prompt injection patterns."""
        if not text:
            return []

        for pattern in _COMPILED_INJECTION:
            match = pattern.search(text)
            if match:
                artifacts = []
                if session_id:
                    artifacts.append(Artifact(type=ArtifactType.SESSION_ID, value=session_id, context="Session"))

                snippet = text[max(0, match.start() - 50):match.end() + 50]
                return [AlertModel(
                    tenant_id=event.tenant_id,
                    source=event.source,
                    event_type="ai_agent.prompt_injection",
                    severity=Severity.CRITICAL,
                    confidence=0.85,
                    title=f"Prompt injection detected on agent {agent_name}",
                    description=(
                        f"Prompt injection pattern detected in input to agent '{agent_name}'. "
                        f"Matched pattern: '{pattern.pattern}'. "
                        f"Context: ...{snippet}..."
                    ),
                    raw_payload=payload,
                    artifacts=artifacts,
                    atlas_technique="AML.T0051",
                    trace_id=event.trace_id,
                )]

        return []

    def _scan_for_jailbreak(
        self, event: StreamEvent, text: str, agent_name: str, session_id: str, payload: dict,
    ) -> list[AlertModel]:
        """Scan text for jailbreak attempt patterns."""
        if not text:
            return []

        for pattern in _COMPILED_JAILBREAK:
            match = pattern.search(text)
            if match:
                artifacts = []
                if session_id:
                    artifacts.append(Artifact(type=ArtifactType.SESSION_ID, value=session_id, context="Session"))

                snippet = text[max(0, match.start() - 50):match.end() + 50]
                return [AlertModel(
                    tenant_id=event.tenant_id,
                    source=event.source,
                    event_type="ai_agent.jailbreak_attempt",
                    severity=Severity.HIGH,
                    confidence=0.75,
                    title=f"Jailbreak attempt on agent {agent_name}",
                    description=(
                        f"Jailbreak pattern detected in input to agent '{agent_name}'. "
                        f"Matched: '{pattern.pattern}'. Context: ...{snippet}..."
                    ),
                    raw_payload=payload,
                    artifacts=artifacts,
                    atlas_technique="AML.T0054",  # LLM Jailbreak
                    trace_id=event.trace_id,
                )]

        return []

    def _scan_for_exfiltration(
        self, event: StreamEvent, text: str, agent_name: str, session_id: str, payload: dict,
    ) -> list[AlertModel]:
        """Scan agent output for sensitive data leakage."""
        if not text:
            return []

        for pattern in _COMPILED_EXFIL:
            match = pattern.search(text)
            if match:
                artifacts = []
                if session_id:
                    artifacts.append(Artifact(type=ArtifactType.SESSION_ID, value=session_id, context="Session"))

                # Don't include the actual sensitive data in the alert
                return [AlertModel(
                    tenant_id=event.tenant_id,
                    source=event.source,
                    event_type="ai_agent.data_exfiltration",
                    severity=Severity.CRITICAL,
                    confidence=0.80,
                    title=f"Data exfiltration: sensitive data in {agent_name} output",
                    description=(
                        f"Agent '{agent_name}' output contains sensitive data matching pattern "
                        f"'{pattern.pattern[:60]}'. This may indicate PII leakage, credential "
                        f"exposure, or data exfiltration via the AI agent."
                    ),
                    raw_payload={"agent_name": agent_name, "session_id": session_id},
                    artifacts=artifacts,
                    atlas_technique="AML.T0024",
                    trace_id=event.trace_id,
                )]

        return []

    # ─── Utilities ────────────────────────────────────────

    @staticmethod
    def _extract_text(data) -> str:
        """Extract text from various Langfuse input/output formats."""
        if data is None:
            return ""
        if isinstance(data, str):
            return data
        if isinstance(data, dict):
            # OpenAI-style message format
            if "messages" in data:
                parts = []
                for msg in data["messages"]:
                    content = msg.get("content", "")
                    if isinstance(content, str):
                        parts.append(content)
                    elif isinstance(content, list):
                        for c in content:
                            if isinstance(c, dict) and c.get("type") == "text":
                                parts.append(c.get("text", ""))
                return " ".join(parts)
            # Simple text field
            return data.get("text", data.get("content", data.get("value", str(data))))
        if isinstance(data, list):
            return " ".join(str(item) for item in data)
        return str(data)

    @staticmethod
    def _top_tools(window: list[dict]) -> list[tuple[str, int]]:
        """Get top tool names by frequency."""
        from collections import Counter
        counts = Counter(e["tool"] for e in window)
        return counts.most_common()
