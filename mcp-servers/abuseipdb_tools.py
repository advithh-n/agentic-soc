"""AbuseIPDB Tool Router — IP reputation lookup via AbuseIPDB API.

Provides endpoint to check IP addresses against AbuseIPDB's threat intelligence.
Caches results in Redis (TTL 1 hour) to respect free tier rate limits (1000/day).
"""

import json
import os

import httpx
import structlog
from fastapi import APIRouter
from pydantic import BaseModel

logger = structlog.get_logger()

router = APIRouter(prefix="/abuseipdb", tags=["abuseipdb"])

ABUSEIPDB_API_URL = "https://api.abuseipdb.com/api/v2/check"

# Redis client (injected at startup from server.py)
_redis = None


async def init_redis(redis_client):
    global _redis
    _redis = redis_client
    logger.info("abuseipdb.redis_connected")


# ─── Request/Response Schemas ────────────────────────────

class CheckIPRequest(BaseModel):
    ip: str
    max_age_days: int = 90  # How far back to check reports


# ─── Tool Endpoints ──────────────────────────────────────

@router.post("/check-ip")
async def check_ip(req: CheckIPRequest):
    """Check an IP address against AbuseIPDB for abuse reports.

    Returns abuse confidence score, total reports, country, ISP, etc.
    Results are cached in Redis for 1 hour to respect rate limits.
    """
    api_key = os.getenv("ABUSEIPDB_API_KEY", "")

    # Check Redis cache first
    cache_key = f"abuseipdb:check:{req.ip}"
    if _redis:
        try:
            cached = await _redis.get(cache_key)
            if cached:
                logger.debug("abuseipdb.cache_hit", ip=req.ip)
                return json.loads(cached)
        except Exception as e:
            logger.warning("abuseipdb.cache_error", error=str(e))

    # If no API key configured, return a not-configured response
    if not api_key:
        logger.debug("abuseipdb.no_api_key")
        return {
            "found": False,
            "ip": req.ip,
            "error": "ABUSEIPDB_API_KEY not configured",
            "abuse_confidence_score": None,
        }

    # Call AbuseIPDB API
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(
                ABUSEIPDB_API_URL,
                params={
                    "ipAddress": req.ip,
                    "maxAgeInDays": req.max_age_days,
                    "verbose": "",
                },
                headers={
                    "Key": api_key,
                    "Accept": "application/json",
                },
            )

        if resp.status_code != 200:
            logger.warning("abuseipdb.api_error", status=resp.status_code,
                           body=resp.text[:200])
            return {
                "found": False,
                "ip": req.ip,
                "error": f"API returned {resp.status_code}",
            }

        data = resp.json().get("data", {})

        result = {
            "found": True,
            "ip": req.ip,
            "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
            "total_reports": data.get("totalReports", 0),
            "country_code": data.get("countryCode", ""),
            "isp": data.get("isp", ""),
            "domain": data.get("domain", ""),
            "is_tor": data.get("isTor", False),
            "is_whitelisted": data.get("isWhitelisted", False),
            "usage_type": data.get("usageType", ""),
            "last_reported_at": data.get("lastReportedAt"),
            "num_distinct_users": data.get("numDistinctUsers", 0),
        }

        # Cache in Redis (TTL 1 hour)
        if _redis:
            try:
                await _redis.set(cache_key, json.dumps(result), ex=3600)
                logger.debug("abuseipdb.cached", ip=req.ip)
            except Exception as e:
                logger.warning("abuseipdb.cache_write_error", error=str(e))

        return result

    except httpx.TimeoutException:
        logger.warning("abuseipdb.timeout", ip=req.ip)
        return {
            "found": False,
            "ip": req.ip,
            "error": "API request timed out",
        }
    except Exception as e:
        logger.error("abuseipdb.error", ip=req.ip, error=str(e))
        return {
            "found": False,
            "ip": req.ip,
            "error": str(e),
        }
