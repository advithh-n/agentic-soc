"""Sploitus Exploit Search Tool Router — searches for known exploits and CVEs.

Provides endpoint to search the Sploitus exploit database for vulnerabilities.
Caches results in Redis (TTL 1 hour) to limit external requests.
"""

import json
import os

import httpx
import structlog
from fastapi import APIRouter
from pydantic import BaseModel

logger = structlog.get_logger()

router = APIRouter(prefix="/sploitus", tags=["sploitus"])

SPLOITUS_SEARCH_URL = "https://sploitus.com/search"

# Redis client (injected at startup from server.py)
_redis = None


async def init_redis(redis_client):
    global _redis
    _redis = redis_client
    logger.info("sploitus.redis_connected")


# --- Request/Response Schemas ---

class ExploitSearchRequest(BaseModel):
    query: str  # CVE ID, keyword, or product name
    type: str = "exploits"  # "exploits" or "tools"
    offset: int = 0
    limit: int = 10


# --- Tool Endpoints ---

@router.post("/search")
async def search_exploits(req: ExploitSearchRequest):
    """Search Sploitus for known exploits matching a query.

    Accepts CVE IDs (e.g. CVE-2024-1234), product names, or keywords.
    Results are cached in Redis for 1 hour.
    """
    # Check Redis cache first
    cache_key = f"sploitus:search:{req.query}:{req.type}:{req.offset}"
    if _redis:
        try:
            cached = await _redis.get(cache_key)
            if cached:
                logger.debug("sploitus.cache_hit", query=req.query)
                return json.loads(cached)
        except Exception as e:
            logger.warning("sploitus.cache_error", error=str(e))

    # Call Sploitus API
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(
                SPLOITUS_SEARCH_URL,
                params={
                    "query": req.query,
                    "type": req.type,
                    "offset": req.offset,
                    "title": False,
                },
                headers={
                    "Accept": "application/json",
                },
            )

        if resp.status_code != 200:
            logger.warning("sploitus.api_error", status=resp.status_code,
                           body=resp.text[:200])
            return {
                "found": False,
                "query": req.query,
                "error": f"API returned {resp.status_code}",
                "exploits": [],
            }

        data = resp.json()
        exploits_raw = data.get("exploits", [])

        exploits = []
        for exp in exploits_raw[:req.limit]:
            exploits.append({
                "id": exp.get("id", ""),
                "title": exp.get("title", ""),
                "type": exp.get("type", ""),
                "source": exp.get("source", ""),
                "href": exp.get("href", ""),
                "published": exp.get("published", ""),
                "score": exp.get("score"),
                "cvss_score": exp.get("cvss_score"),
            })

        result = {
            "found": len(exploits) > 0,
            "query": req.query,
            "exploit_count": len(exploits),
            "total_results": data.get("exploits_total", len(exploits)),
            "exploits": exploits,
        }

        # Cache in Redis (TTL 1 hour)
        if _redis:
            try:
                await _redis.set(cache_key, json.dumps(result), ex=3600)
                logger.debug("sploitus.cached", query=req.query)
            except Exception as e:
                logger.warning("sploitus.cache_write_error", error=str(e))

        return result

    except httpx.TimeoutException:
        logger.warning("sploitus.timeout", query=req.query)
        return {
            "found": False,
            "query": req.query,
            "error": "API request timed out",
            "exploits": [],
        }
    except Exception as e:
        logger.error("sploitus.error", query=req.query, error=str(e))
        return {
            "found": False,
            "query": req.query,
            "error": str(e),
            "exploits": [],
        }
