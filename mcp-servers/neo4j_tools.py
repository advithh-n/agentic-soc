"""Neo4j Graph Query Tools — MCP tool router.

Provides tools for querying and updating the SOC knowledge graph:
- get_asset_context: Look up context about an IP, user, or service
- get_related_incidents: Find related alerts/incidents for an entity
- query_graph: Run a Cypher query (read-only for triage agent)
- update_graph: Add/update nodes and relationships (investigation agent only)
"""

import os
from contextlib import asynccontextmanager

import structlog
from fastapi import APIRouter, HTTPException
from neo4j import AsyncGraphDatabase
from pydantic import BaseModel

logger = structlog.get_logger()

router = APIRouter(prefix="/neo4j", tags=["neo4j"])

# Neo4j driver (initialized at startup)
_driver = None


async def init_driver():
    global _driver
    uri = os.getenv("NEO4J_URI", "bolt://neo4j:7687")
    password = os.getenv("NEO4J_PASS", "changeme")
    _driver = AsyncGraphDatabase.driver(uri, auth=("neo4j", password))
    # Verify connectivity
    async with _driver.session() as session:
        await session.run("RETURN 1")
    logger.info("neo4j.connected", uri=uri)


async def close_driver():
    global _driver
    if _driver:
        await _driver.close()
        logger.info("neo4j.closed")


async def _get_driver():
    if not _driver:
        await init_driver()
    return _driver


# ─── Request/Response Schemas ────────────────────────────

class AssetContextRequest(BaseModel):
    entity_type: str  # "ip", "user", "service", "domain"
    entity_value: str

class RelatedIncidentsRequest(BaseModel):
    entity_type: str
    entity_value: str
    limit: int = 10

class CypherQueryRequest(BaseModel):
    query: str
    parameters: dict = {}

class GraphUpdateRequest(BaseModel):
    operation: str  # "create_node", "create_relationship", "update_node"
    labels: list[str] = []
    properties: dict = {}
    source_id: str | None = None
    target_id: str | None = None
    relationship_type: str | None = None


# ─── Tool Endpoints ──────────────────────────────────────

@router.post("/asset-context")
async def get_asset_context(req: AssetContextRequest):
    """Get context about an asset from the knowledge graph.

    Returns the node and all its direct relationships (1-hop neighborhood).
    Used by triage agent to understand what an IP/user/service is.
    """
    driver = await _get_driver()

    label_map = {
        "ip": "IP",
        "user": "User",
        "service": "Service",
        "domain": "Domain",
        "host": "Host",
    }
    label = label_map.get(req.entity_type.lower(), "Entity")
    prop_map = {
        "ip": "address",
        "user": "email",
        "service": "name",
        "domain": "name",
        "host": "hostname",
    }
    prop = prop_map.get(req.entity_type.lower(), "id")

    query = f"""
    MATCH (n:{label} {{{prop}: $value}})
    OPTIONAL MATCH (n)-[r]-(m)
    RETURN n, collect(DISTINCT {{
        relationship: type(r),
        direction: CASE WHEN startNode(r) = n THEN 'outgoing' ELSE 'incoming' END,
        node_labels: labels(m),
        node_props: properties(m)
    }}) AS connections
    """

    async with driver.session() as session:
        result = await session.run(query, value=req.entity_value)
        record = await result.single()

    if not record:
        return {
            "found": False,
            "entity_type": req.entity_type,
            "entity_value": req.entity_value,
            "context": "Entity not found in knowledge graph",
        }

    node_props = dict(record["n"])
    connections = [c for c in record["connections"] if c["relationship"]]

    return {
        "found": True,
        "entity_type": req.entity_type,
        "entity_value": req.entity_value,
        "properties": node_props,
        "connections": connections,
        "connection_count": len(connections),
    }


@router.post("/related-incidents")
async def get_related_incidents(req: RelatedIncidentsRequest):
    """Find alerts and incidents related to an entity.

    Traverses the graph to find alerts that reference the same IP, user, etc.
    Used by triage agent for correlation.
    """
    driver = await _get_driver()

    query = """
    MATCH (n {id: $value})-[*1..2]-(a:Alert)
    RETURN a
    ORDER BY a.created_at DESC
    LIMIT $limit
    """

    # Also try by specific property
    label_map = {"ip": "IP", "user": "User", "service": "Service"}
    label = label_map.get(req.entity_type.lower(), "Entity")
    prop_map = {"ip": "address", "user": "email", "service": "name"}
    prop = prop_map.get(req.entity_type.lower(), "id")

    query = f"""
    MATCH (n:{label} {{{prop}: $value}})-[*1..2]-(a:Alert)
    RETURN DISTINCT a
    ORDER BY a.created_at DESC
    LIMIT $limit
    """

    async with driver.session() as session:
        result = await session.run(query, value=req.entity_value, limit=req.limit)
        records = [dict(record["a"]) async for record in result]

    return {
        "entity_type": req.entity_type,
        "entity_value": req.entity_value,
        "related_alerts": records,
        "count": len(records),
    }


@router.post("/query")
async def query_graph(req: CypherQueryRequest):
    """Run a read-only Cypher query against the knowledge graph.

    Used by agents for custom graph traversals.
    Restricted to read-only operations (no CREATE/DELETE/SET).
    """
    # Safety: block write operations
    upper = req.query.upper().strip()
    write_keywords = ["CREATE", "DELETE", "DETACH", "SET", "REMOVE", "MERGE", "DROP"]
    for kw in write_keywords:
        if kw in upper.split():
            raise HTTPException(
                status_code=403,
                detail=f"Write operation '{kw}' not allowed via read-only query endpoint. Use /update instead.",
            )

    driver = await _get_driver()

    async with driver.session() as session:
        result = await session.run(req.query, **req.parameters)
        records = [record.data() async for record in result]

    return {"results": records, "count": len(records)}


@router.post("/update")
async def update_graph(req: GraphUpdateRequest):
    """Update the knowledge graph (create/update nodes and relationships).

    Used by investigation agent to record findings.
    """
    driver = await _get_driver()

    if req.operation == "create_node":
        labels_str = ":".join(req.labels) if req.labels else "Entity"
        props = req.properties
        query = f"CREATE (n:{labels_str} $props) RETURN n"
        async with driver.session() as session:
            result = await session.run(query, props=props)
            record = await result.single()
        return {"created": True, "node": dict(record["n"])}

    elif req.operation == "create_relationship":
        if not all([req.source_id, req.target_id, req.relationship_type]):
            raise HTTPException(400, "source_id, target_id, and relationship_type required")

        query = """
        MATCH (a {id: $source_id}), (b {id: $target_id})
        CREATE (a)-[r:%s $props]->(b)
        RETURN type(r) as rel_type
        """ % req.relationship_type  # Safe: validated below

        # Validate relationship type (alphanumeric + underscore only)
        if not req.relationship_type.replace("_", "").isalnum():
            raise HTTPException(400, "Invalid relationship type")

        async with driver.session() as session:
            result = await session.run(
                query, source_id=req.source_id, target_id=req.target_id,
                props=req.properties,
            )
            record = await result.single()
        return {"created": True, "relationship": record["rel_type"] if record else None}

    elif req.operation == "update_node":
        if not req.properties.get("id"):
            raise HTTPException(400, "properties.id required for update")

        node_id = req.properties.pop("id")
        set_clauses = ", ".join(f"n.{k} = ${k}" for k in req.properties)
        query = f"MATCH (n {{id: $node_id}}) SET {set_clauses} RETURN n"
        params = {"node_id": node_id, **req.properties}

        async with driver.session() as session:
            result = await session.run(query, **params)
            record = await result.single()
        return {"updated": True, "node": dict(record["n"]) if record else None}

    else:
        raise HTTPException(400, f"Unknown operation: {req.operation}")


@router.get("/stats")
async def graph_stats():
    """Get graph statistics."""
    driver = await _get_driver()

    query = """
    CALL apoc.meta.stats() YIELD nodeCount, relCount, labels, relTypes
    RETURN nodeCount, relCount, labels, relTypes
    """

    try:
        async with driver.session() as session:
            result = await session.run(query)
            record = await result.single()

        return {
            "node_count": record["nodeCount"],
            "relationship_count": record["relCount"],
            "labels": record["labels"],
            "relationship_types": record["relTypes"],
        }
    except Exception:
        # Fallback if APOC is not available
        async with driver.session() as session:
            result = await session.run("MATCH (n) RETURN count(n) as cnt")
            record = await result.single()
            node_count = record["cnt"]

            result = await session.run("MATCH ()-[r]->() RETURN count(r) as cnt")
            record = await result.single()
            rel_count = record["cnt"]

        return {
            "node_count": node_count,
            "relationship_count": rel_count,
        }
