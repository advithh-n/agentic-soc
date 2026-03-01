"""SOC Analytics API — metrics, stats, MITRE heatmap, system health."""

from datetime import datetime, timezone

import httpx
from fastapi import APIRouter, Depends, Query
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.middleware import get_current_user, set_tenant_context
from app.services.redis_service import redis_client

router = APIRouter()


@router.get("/overview")
async def analytics_overview(
    db: AsyncSession = Depends(set_tenant_context),
    current_user: dict = Depends(get_current_user),
):
    """High-level SOC metrics: alert counts, detection rates, agent stats, response metrics."""
    # Alert metrics
    alerts = await db.execute(text("""
        SELECT
            count(*) as total,
            count(*) FILTER (WHERE status = 'new') as new,
            count(*) FILTER (WHERE status = 'triaged') as triaged,
            count(*) FILTER (WHERE status = 'investigating') as investigating,
            count(*) FILTER (WHERE status = 'false_positive') as false_positive,
            count(*) FILTER (WHERE severity = 'critical') as critical,
            count(*) FILTER (WHERE severity = 'high') as high,
            count(*) FILTER (WHERE severity = 'medium') as medium,
            count(*) FILTER (WHERE severity = 'low') as low,
            count(*) FILTER (WHERE created_at > NOW() - INTERVAL '24 hours') as last_24h,
            count(*) FILTER (WHERE created_at > NOW() - INTERVAL '1 hour') as last_1h
        FROM alerts
    """))
    alert_row = alerts.fetchone()

    # Incident metrics
    incidents = await db.execute(text("""
        SELECT
            count(*) as total,
            count(*) FILTER (WHERE status = 'open') as open,
            count(*) FILTER (WHERE status = 'investigating') as investigating,
            count(*) FILTER (WHERE status = 'resolved') as resolved,
            count(*) FILTER (WHERE status = 'closed') as closed
        FROM incidents
    """))
    inc_row = incidents.fetchone()

    # Response action metrics
    actions = await db.execute(text("""
        SELECT
            count(*) as total,
            count(*) FILTER (WHERE status = 'pending') as pending,
            count(*) FILTER (WHERE status = 'approved') as approved,
            count(*) FILTER (WHERE status = 'executed') as executed,
            count(*) FILTER (WHERE status = 'failed') as failed,
            count(*) FILTER (WHERE status = 'denied') as denied,
            count(*) FILTER (WHERE risk_level = 'auto') as auto_risk,
            count(*) FILTER (WHERE risk_level = 'high') as high_risk,
            count(*) FILTER (WHERE risk_level = 'critical') as critical_risk
        FROM response_actions
    """))
    act_row = actions.fetchone()

    # Execution traces
    traces = await db.execute(text("SELECT count(*) as total FROM execution_traces"))
    trace_row = traces.fetchone()

    # Detection rates by module
    detection_rates = await db.execute(text("""
        SELECT
            CASE
                WHEN event_type LIKE 'carding.%%' THEN 'stripe_carding'
                WHEN event_type LIKE 'auth.%%' THEN 'auth_anomaly'
                WHEN event_type LIKE 'infra.%%' THEN 'infrastructure'
                WHEN event_type LIKE 'ai_agent.%%' THEN 'ai_agent_monitor'
                WHEN event_type LIKE 'recon.%%' THEN 'recon'
                ELSE 'unknown'
            END as module,
            count(*) as alert_count,
            count(DISTINCT event_type) as rule_count
        FROM alerts
        GROUP BY module
        ORDER BY alert_count DESC
    """))
    modules = [dict(r._mapping) for r in detection_rates.fetchall()]

    # MTTR (Mean Time to Resolve)
    mttr_result = await db.execute(text("""
        SELECT
            EXTRACT(EPOCH FROM AVG(updated_at - created_at)) as mttr_seconds
        FROM incidents
        WHERE status IN ('resolved', 'closed')
    """))
    mttr_row = mttr_result.fetchone()
    mttr_seconds = mttr_row.mttr_seconds if mttr_row and mttr_row.mttr_seconds else None

    # MTTD (Mean Time to Detect)
    mttd_result = await db.execute(text("""
        SELECT
            EXTRACT(EPOCH FROM AVG(triaged_at - created_at)) as mttd_seconds
        FROM alerts
        WHERE triaged_at IS NOT NULL
    """))
    mttd_row = mttd_result.fetchone()
    mttd_seconds = mttd_row.mttd_seconds if mttd_row and mttd_row.mttd_seconds else None

    return {
        "alerts": {
            "total": alert_row.total,
            "new": alert_row.new,
            "triaged": alert_row.triaged,
            "investigating": alert_row.investigating,
            "false_positive": alert_row.false_positive,
            "by_severity": {
                "critical": alert_row.critical,
                "high": alert_row.high,
                "medium": alert_row.medium,
                "low": alert_row.low,
            },
            "last_24h": alert_row.last_24h,
            "last_1h": alert_row.last_1h,
        },
        "incidents": {
            "total": inc_row.total,
            "open": inc_row.open,
            "investigating": inc_row.investigating,
            "resolved": inc_row.resolved,
            "closed": inc_row.closed,
        },
        "response_actions": {
            "total": act_row.total,
            "pending": act_row.pending,
            "approved": act_row.approved,
            "executed": act_row.executed,
            "failed": act_row.failed,
            "denied": act_row.denied,
            "by_risk": {
                "auto": act_row.auto_risk,
                "high": act_row.high_risk,
                "critical": act_row.critical_risk,
            },
        },
        "execution_traces": trace_row.total,
        "modules": modules,
        "mttr_seconds": mttr_seconds,
        "mttd_seconds": mttd_seconds,
    }


@router.get("/mitre-heatmap")
async def mitre_heatmap(
    db: AsyncSession = Depends(set_tenant_context),
    current_user: dict = Depends(get_current_user),
):
    """MITRE ATT&CK + ATLAS technique heatmap from detected alerts."""
    result = await db.execute(text("""
        SELECT
            mitre_technique,
            event_type,
            count(*) as hits,
            max(severity) as max_severity,
            max(created_at) as last_seen
        FROM alerts
        WHERE mitre_technique IS NOT NULL AND mitre_technique != ''
        GROUP BY mitre_technique, event_type
        ORDER BY hits DESC
    """))
    rows = result.fetchall()

    techniques = [
        {
            "technique_id": r.mitre_technique,
            "event_type": r.event_type,
            "hits": r.hits,
            "max_severity": r.max_severity,
            "last_seen": r.last_seen.isoformat() if r.last_seen else None,
        }
        for r in rows
    ]

    # ATLAS techniques
    atlas_result = await db.execute(text("""
        SELECT
            atlas_technique,
            event_type,
            count(*) as hits,
            max(severity) as max_severity,
            max(created_at) as last_seen
        FROM alerts
        WHERE atlas_technique IS NOT NULL AND atlas_technique != ''
        GROUP BY atlas_technique, event_type
        ORDER BY hits DESC
    """))
    atlas_rows = atlas_result.fetchall()

    atlas_techniques = [
        {
            "technique_id": r.atlas_technique,
            "event_type": r.event_type,
            "hits": r.hits,
            "max_severity": r.max_severity,
            "last_seen": r.last_seen.isoformat() if r.last_seen else None,
        }
        for r in atlas_rows
    ]

    return {
        "mitre": techniques,
        "atlas": atlas_techniques,
        "total_techniques": len(set(r.mitre_technique for r in rows)) + len(set(r.atlas_technique for r in atlas_rows)),
    }


@router.get("/alert-timeline")
async def alert_timeline(
    hours: int = Query(default=24, ge=1, le=720),
    db: AsyncSession = Depends(set_tenant_context),
    current_user: dict = Depends(get_current_user),
):
    """Alert volume over time, bucketed by hour."""
    result = await db.execute(text("""
        SELECT
            date_trunc('hour', created_at) as bucket,
            count(*) as count,
            count(*) FILTER (WHERE severity = 'critical') as critical,
            count(*) FILTER (WHERE severity = 'high') as high,
            count(*) FILTER (WHERE severity = 'medium') as medium,
            count(*) FILTER (WHERE severity = 'low') as low
        FROM alerts
        WHERE created_at > NOW() - make_interval(hours => :hours)
        GROUP BY bucket
        ORDER BY bucket ASC
    """), {"hours": hours})
    rows = result.fetchall()

    return {
        "hours": hours,
        "buckets": [
            {
                "timestamp": r.bucket.isoformat() if r.bucket else None,
                "total": r.count,
                "critical": r.critical,
                "high": r.high,
                "medium": r.medium,
                "low": r.low,
            }
            for r in rows
        ],
    }


@router.get("/agent-performance")
async def agent_performance(current_user: dict = Depends(get_current_user)):
    """Agent runtime performance stats from the health endpoint."""
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.get("http://agent-runtime:8070/health")
            resp.raise_for_status()
            return resp.json()
    except Exception:
        return {"status": "unreachable", "error": "Could not reach agent-runtime"}


@router.get("/action-breakdown")
async def action_breakdown(
    db: AsyncSession = Depends(set_tenant_context),
    current_user: dict = Depends(get_current_user),
):
    """Response action breakdown by type, adapter, and status."""
    result = await db.execute(text("""
        SELECT
            action_type,
            risk_level,
            status,
            count(*) as count,
            proposed_by,
            min(created_at) as first_seen,
            max(created_at) as last_seen
        FROM response_actions
        GROUP BY action_type, risk_level, status, proposed_by
        ORDER BY count DESC
    """))
    rows = result.fetchall()

    return {
        "actions": [
            {
                "action_type": r.action_type,
                "risk_level": r.risk_level,
                "status": r.status,
                "count": r.count,
                "proposed_by": r.proposed_by,
                "first_seen": r.first_seen.isoformat() if r.first_seen else None,
                "last_seen": r.last_seen.isoformat() if r.last_seen else None,
            }
            for r in rows
        ],
    }


@router.get("/system-health")
async def system_health(current_user: dict = Depends(get_current_user)):
    """Full system health — all services, queue depths, DB stats."""
    services = {}

    # Agent Runtime
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.get("http://agent-runtime:8070/health")
            resp.raise_for_status()
            agent_data = resp.json()
        services["agent_runtime"] = {"status": "healthy", **agent_data}
    except Exception as e:
        services["agent_runtime"] = {"status": "error", "error": str(e)[:100]}

    # Module Engine
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.get("http://module-engine:8060/health")
            resp.raise_for_status()
            module_data = resp.json()
        services["module_engine"] = {"status": "healthy", **module_data}
    except Exception as e:
        services["module_engine"] = {"status": "error", "error": str(e)[:100]}

    # MCP Servers
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.get("http://mcp-servers:8100/health")
            resp.raise_for_status()
        services["mcp_servers"] = {"status": "healthy"}
    except Exception as e:
        services["mcp_servers"] = {"status": "error", "error": str(e)[:100]}

    # Redis
    try:
        await redis_client.ping()
        triage_len = await redis_client.xlen("soc:alerts:triage")
        playbook_len = await redis_client.xlen("soc:playbook:run")
        services["redis"] = {
            "status": "healthy",
            "triage_queue_depth": triage_len,
            "playbook_queue_depth": playbook_len,
        }
    except Exception as e:
        services["redis"] = {"status": "error", "error": str(e)[:100]}

    all_healthy = all(s.get("status") == "healthy" for s in services.values())

    return {
        "overall": "healthy" if all_healthy else "degraded",
        "services": services,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ─── Complete rule → technique mapping for coverage reporting ─────

_RULE_REGISTRY = {
    "carding.multi_card_velocity": {"module": "stripe_carding", "technique": "T1530", "framework": "mitre", "tactic": "Collection"},
    "carding.small_amount_testing": {"module": "stripe_carding", "technique": "T1530", "framework": "mitre", "tactic": "Collection"},
    "carding.bin_cycling": {"module": "stripe_carding", "technique": "T1530", "framework": "mitre", "tactic": "Collection"},
    "carding.rapid_sequence": {"module": "stripe_carding", "technique": "T1530", "framework": "mitre", "tactic": "Collection"},
    "carding.high_failure_rate": {"module": "stripe_carding", "technique": "T1530", "framework": "mitre", "tactic": "Collection"},
    "auth.brute_force": {"module": "auth_anomaly", "technique": "T1110.001", "framework": "mitre", "tactic": "Credential Access"},
    "auth.credential_stuffing": {"module": "auth_anomaly", "technique": "T1110.004", "framework": "mitre", "tactic": "Credential Access"},
    "auth.impossible_travel": {"module": "auth_anomaly", "technique": "T1078", "framework": "mitre", "tactic": "Defense Evasion"},
    "auth.session_anomaly": {"module": "auth_anomaly", "technique": "T1078", "framework": "mitre", "tactic": "Defense Evasion"},
    "auth.privilege_escalation": {"module": "auth_anomaly", "technique": "T1078.004", "framework": "mitre", "tactic": "Privilege Escalation"},
    "infra.iam_escalation": {"module": "infrastructure", "technique": "T1078.004", "framework": "mitre", "tactic": "Privilege Escalation"},
    "infra.s3_unauthorized": {"module": "infrastructure", "technique": "T1530", "framework": "mitre", "tactic": "Collection"},
    "infra.security_group_change": {"module": "infrastructure", "technique": "T1562.007", "framework": "mitre", "tactic": "Defense Evasion"},
    "infra.file_integrity": {"module": "infrastructure", "technique": "T1565.001", "framework": "mitre", "tactic": "Impact"},
    "infra.web_attack": {"module": "infrastructure", "technique": "T1190", "framework": "mitre", "tactic": "Initial Access"},
    "ai_agent.prompt_injection": {"module": "ai_agent_monitor", "technique": "AML.T0051", "framework": "atlas", "tactic": "Initial Access"},
    "ai_agent.jailbreak_attempt": {"module": "ai_agent_monitor", "technique": "AML.T0054", "framework": "atlas", "tactic": "Defense Evasion"},
    "ai_agent.data_exfiltration": {"module": "ai_agent_monitor", "technique": "AML.T0024", "framework": "atlas", "tactic": "Exfiltration"},
    "ai_agent.guardrail_block": {"module": "ai_agent_monitor", "technique": "AML.T0051", "framework": "atlas", "tactic": "Initial Access"},
    "ai_agent.excessive_tool_calls": {"module": "ai_agent_monitor", "technique": "AML.T0043", "framework": "atlas", "tactic": "Impact"},
    "ai_agent.token_abuse": {"module": "ai_agent_monitor", "technique": "AML.T0040", "framework": "atlas", "tactic": "Collection"},
    "ai_agent.hallucination": {"module": "ai_agent_monitor", "technique": "AML.T0048", "framework": "atlas", "tactic": "Impact"},
    "ai_agent.tool_call_loop": {"module": "ai_agent_monitor", "technique": "AML.T0043", "framework": "atlas", "tactic": "Impact"},
    "ai_agent.duplicate_tool_calls": {"module": "ai_agent_monitor", "technique": "AML.T0043", "framework": "atlas", "tactic": "Impact"},
    "ai_agent.high_tool_error_rate": {"module": "ai_agent_monitor", "technique": "AML.T0043", "framework": "atlas", "tactic": "Impact"},
    "recon.port_change_detected": {"module": "recon", "technique": "T1046", "framework": "mitre", "tactic": "Discovery"},
    "recon.new_cve_found": {"module": "recon", "technique": "T1190", "framework": "mitre", "tactic": "Initial Access"},
    "recon.cert_expiry_warning": {"module": "recon", "technique": "T1556", "framework": "mitre", "tactic": "Credential Access"},
    "recon.dns_drift": {"module": "recon", "technique": "T1584.002", "framework": "mitre", "tactic": "Resource Development"},
}


@router.get("/detection-coverage")
async def detection_coverage(
    db: AsyncSession = Depends(set_tenant_context),
    current_user: dict = Depends(get_current_user),
):
    """Detection rule coverage — tested vs theoretical MITRE coverage."""
    # Get all distinct event_types that have actually fired
    result = await db.execute(text("""
        SELECT event_type, count(*) as alert_count
        FROM alerts
        GROUP BY event_type
    """))
    detected_rules = {r.event_type: r.alert_count for r in result.fetchall()}

    # Build per-rule coverage
    rules = []
    for rule_name, info in _RULE_REGISTRY.items():
        fired = rule_name in detected_rules
        rules.append({
            "rule": rule_name,
            "module": info["module"],
            "technique": info["technique"],
            "framework": info["framework"],
            "tactic": info["tactic"],
            "fired": fired,
            "alert_count": detected_rules.get(rule_name, 0),
        })

    # Build per-technique coverage
    techniques: dict[str, dict] = {}
    for rule_name, info in _RULE_REGISTRY.items():
        tid = info["technique"]
        if tid not in techniques:
            techniques[tid] = {
                "technique_id": tid,
                "framework": info["framework"],
                "tactic": info["tactic"],
                "rules_total": 0,
                "rules_fired": 0,
                "alert_count": 0,
            }
        techniques[tid]["rules_total"] += 1
        if rule_name in detected_rules:
            techniques[tid]["rules_fired"] += 1
            techniques[tid]["alert_count"] += detected_rules.get(rule_name, 0)

    technique_list = list(techniques.values())

    # Summary
    total_rules = len(_RULE_REGISTRY)
    fired_count = sum(1 for r in rules if r["fired"])
    techniques_covered = sum(1 for t in technique_list if t["rules_fired"] > 0)

    return {
        "total_rules": total_rules,
        "rules_fired": fired_count,
        "detection_rate_pct": round(fired_count / total_rules * 100, 1) if total_rules else 0,
        "total_techniques": len(technique_list),
        "techniques_covered": techniques_covered,
        "technique_coverage_pct": round(techniques_covered / len(technique_list) * 100, 1) if technique_list else 0,
        "rules": rules,
        "techniques": technique_list,
    }
