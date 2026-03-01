"""Extended MCP tool wrappers for the Investigation Agent.

Provides access to CloudTrail, AbuseIPDB, Neo4j blast-radius traversal,
knowledge-graph updates, Wazuh alerts, Clerk sessions, and Langfuse traces.
All tools call MCP server endpoints with graceful error handling.
"""

import os

import httpx
import structlog

logger = structlog.get_logger()

MCP_BASE = os.getenv("MCP_SERVER_URL", "http://mcp-servers:8100")
_TIMEOUT = 10  # Investigation queries can be heavier than triage


# ─── AWS CloudTrail ──────────────────────────────────────

async def query_cloudtrail(
    event_name: str | None = None,
    user_name: str | None = None,
    hours_back: int = 24,
) -> dict:
    """Query CloudTrail events via MCP server."""
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.post(
                f"{MCP_BASE}/aws/query-cloudtrail",
                json={
                    "event_name": event_name,
                    "user_name": user_name,
                    "hours_back": hours_back,
                },
            )
            resp.raise_for_status()
            return resp.json()
    except Exception as e:
        logger.warning("tool.cloudtrail.failed", error=str(e))
        return {"events": [], "count": 0, "error": str(e)}


async def get_iam_activity(user_name: str, hours_back: int = 24) -> dict:
    """Get IAM activity for a specific user from CloudTrail."""
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.post(
                f"{MCP_BASE}/aws/get-iam-activity",
                json={"user_name": user_name, "hours_back": hours_back},
            )
            resp.raise_for_status()
            return resp.json()
    except Exception as e:
        logger.warning("tool.iam_activity.failed", error=str(e))
        return {"events": [], "count": 0, "error": str(e)}


# ─── AbuseIPDB ───────────────────────────────────────────

async def check_ip_reputation(ip: str) -> dict:
    """Check IP reputation via AbuseIPDB (Redis-cached in MCP server)."""
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.post(
                f"{MCP_BASE}/abuseipdb/check-ip",
                json={"ip": ip},
            )
            resp.raise_for_status()
            return resp.json()
    except Exception as e:
        logger.warning("tool.abuseipdb.failed", ip=ip, error=str(e))
        return {"found": False, "error": str(e)}


# ─── Neo4j — Blast-Radius Traversal ─────────────────────

async def traverse_blast_radius(entity_type: str, entity_value: str, max_hops: int = 3) -> dict:
    """Multi-hop Neo4j traversal to assess blast radius.

    Follows: entity → assets → services → users up to max_hops.
    """
    cypher = """
    MATCH path = (start {value: $entity_value})-[*1..%d]-(connected)
    WHERE labels(start)[0] = $entity_label
    RETURN DISTINCT
        labels(connected)[0] AS label,
        connected.value AS value,
        connected.name AS name,
        length(path) AS hops
    ORDER BY hops
    LIMIT 50
    """ % max_hops

    label_map = {"ip": "IP", "user": "User", "service": "Service", "domain": "Domain"}
    entity_label = label_map.get(entity_type, entity_type.capitalize())

    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.post(
                f"{MCP_BASE}/neo4j/query",
                json={
                    "query": cypher,
                    "parameters": {
                        "entity_value": entity_value,
                        "entity_label": entity_label,
                    },
                },
            )
            resp.raise_for_status()
            return resp.json()
    except Exception as e:
        logger.warning("tool.blast_radius.failed", error=str(e))
        return {"results": [], "count": 0, "error": str(e)}


# ─── Neo4j — Knowledge Graph Update ─────────────────────

async def update_knowledge_graph(
    operation: str,
    entity_type: str,
    entity_value: str,
    properties: dict | None = None,
    relationship: dict | None = None,
) -> dict:
    """Update the knowledge graph (create nodes, relationships, properties).

    Operations: 'create_node', 'update_node', 'create_relationship'
    """
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.post(
                f"{MCP_BASE}/neo4j/update",
                json={
                    "operation": operation,
                    "entity_type": entity_type,
                    "entity_value": entity_value,
                    "properties": properties or {},
                    "relationship": relationship,
                },
            )
            resp.raise_for_status()
            return resp.json()
    except Exception as e:
        logger.warning("tool.kg_update.failed", error=str(e))
        return {"success": False, "error": str(e)}


# ─── Sploitus Exploit Search ─────────────────────────────

async def search_exploits(query: str, search_type: str = "exploits") -> dict:
    """Search Sploitus for known exploits matching a CVE or keyword."""
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.post(
                f"{MCP_BASE}/sploitus/search",
                json={"query": query, "type": search_type, "limit": 5},
            )
            resp.raise_for_status()
            return resp.json()
    except Exception as e:
        logger.warning("tool.sploitus.failed", query=query, error=str(e))
        return {"found": False, "exploits": [], "error": str(e)}


# ─── Threat Actor Attribution ────────────────────────────

async def link_ioc_to_threat_actor(ioc_type: str, ioc_value: str) -> dict:
    """Attempt to attribute an IOC to a known threat actor via graph traversal."""
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.post(
                f"{MCP_BASE}/neo4j/link-ioc-threat-actor",
                json={"ioc_type": ioc_type, "ioc_value": ioc_value},
            )
            resp.raise_for_status()
            return resp.json()
    except Exception as e:
        logger.warning("tool.threat_actor_link.failed", error=str(e))
        return {"attributed": False, "error": str(e)}


async def get_threat_actor_profile(actor_name: str) -> dict:
    """Get full threat actor profile with associated IOCs/campaigns/TTPs."""
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.post(
                f"{MCP_BASE}/neo4j/threat-actor-profile",
                json={"actor_name": actor_name},
            )
            resp.raise_for_status()
            return resp.json()
    except Exception as e:
        logger.warning("tool.threat_actor_profile.failed", error=str(e))
        return {"found": False, "error": str(e)}


# ─── Clerk Sessions ──────────────────────────────────────

async def query_clerk_sessions(user_id: str) -> dict:
    """Query Clerk for active sessions via MCP server."""
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.post(
                f"{MCP_BASE}/clerk/query-sessions",
                json={"user_id": user_id},
            )
            resp.raise_for_status()
            return resp.json()
    except Exception as e:
        logger.warning("tool.clerk_sessions.failed", user_id=user_id, error=str(e))
        return {"sessions": [], "count": 0, "error": str(e)}


# ─── Wazuh Alerts ────────────────────────────────────────

async def query_wazuh_alerts(ip: str | None = None, hostname: str | None = None) -> dict:
    """Query Wazuh for host-level alerts via MCP server."""
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.post(
                f"{MCP_BASE}/wazuh/query-alerts",
                json={"agent_name": hostname, "source_ip": ip},
            )
            resp.raise_for_status()
            return resp.json()
    except Exception as e:
        logger.warning("tool.wazuh_alerts.failed", error=str(e))
        return {"alerts": [], "count": 0, "error": str(e)}


# ─── Langfuse Traces ────────────────────────────────────

async def get_langfuse_traces(trace_id: str) -> dict:
    """Retrieve Langfuse LLM traces via MCP server."""
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.post(
                f"{MCP_BASE}/langfuse/query-traces",
                json={"trace_id": trace_id},
            )
            resp.raise_for_status()
            return resp.json()
    except Exception as e:
        logger.warning("tool.langfuse_traces.failed", trace_id=trace_id, error=str(e))
        return {"traces": [], "count": 0, "error": str(e)}
