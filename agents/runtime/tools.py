"""MCP Tool wrappers — HTTP clients that call the MCP server endpoints.

Used by the triage agent to enrich alerts with context from Neo4j, etc.
"""

import os

import httpx
import structlog

logger = structlog.get_logger()

MCP_BASE = os.getenv("MCP_SERVER_URL", "http://mcp-servers:8100")

# ─── LLM availability check ──────────────────────────────
_PLACEHOLDER_KEYS = {"", "sk-ant-placeholder", "placeholder", "your-api-key-here"}
_llm_available: bool | None = None


def is_llm_available() -> bool:
    """Check if a valid Anthropic API key is configured.

    Caches the result after first check. Returns False for placeholder keys.
    """
    global _llm_available
    if _llm_available is None:
        key = os.getenv("ANTHROPIC_API_KEY", "").strip()
        _llm_available = bool(key) and key not in _PLACEHOLDER_KEYS
        if not _llm_available:
            logger.info("llm.disabled", reason="no valid ANTHROPIC_API_KEY configured — using rule-based mode")
        else:
            logger.info("llm.enabled", key_prefix=key[:10] + "...")
    return _llm_available


# ─── Chain summarization ─────────────────────────────────

async def summarize_context(text: str, max_tokens: int = 500) -> str:
    """Summarize long context using Claude Haiku for cheap summarization.

    Falls back to simple truncation if LLM is unavailable.
    """
    if len(text) <= 3000:
        return text

    if not is_llm_available():
        # Truncation fallback: keep first and last portions
        half = 1400
        return text[:half] + "\n...[truncated]...\n" + text[-half:]

    try:
        import anthropic

        api_key = os.getenv("ANTHROPIC_API_KEY")
        client = anthropic.Anthropic(api_key=api_key)
        response = client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=max_tokens,
            messages=[{
                "role": "user",
                "content": (
                    "Summarize this SOC investigation context concisely, preserving "
                    "all IOCs, IPs, timestamps, MITRE techniques, and key findings:\n\n"
                    + text[:6000]
                ),
            }],
        )
        return response.content[0].text
    except Exception as e:
        logger.warning("summarize.failed", error=str(e))
        half = 1400
        return text[:half] + "\n...[truncated]...\n" + text[-half:]


async def get_asset_context(entity_type: str, entity_value: str) -> dict:
    """Query Neo4j for asset context about an IP, user, or service."""
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.post(
                f"{MCP_BASE}/neo4j/asset-context",
                json={"entity_type": entity_type, "entity_value": entity_value},
            )
            resp.raise_for_status()
            return resp.json()
    except Exception as e:
        logger.warning("tool.asset_context.failed", error=str(e),
                      entity_type=entity_type, entity_value=entity_value)
        return {"found": False, "error": str(e)}


async def get_related_incidents(entity_type: str, entity_value: str, limit: int = 5) -> dict:
    """Query Neo4j for related alerts/incidents."""
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.post(
                f"{MCP_BASE}/neo4j/related-incidents",
                json={"entity_type": entity_type, "entity_value": entity_value, "limit": limit},
            )
            resp.raise_for_status()
            return resp.json()
    except Exception as e:
        logger.warning("tool.related_incidents.failed", error=str(e))
        return {"related_alerts": [], "count": 0, "error": str(e)}


async def query_graph(cypher: str, parameters: dict | None = None) -> dict:
    """Run a read-only Cypher query."""
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.post(
                f"{MCP_BASE}/neo4j/query",
                json={"query": cypher, "parameters": parameters or {}},
            )
            resp.raise_for_status()
            return resp.json()
    except Exception as e:
        logger.warning("tool.query_graph.failed", error=str(e))
        return {"results": [], "count": 0, "error": str(e)}
