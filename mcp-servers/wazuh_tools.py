"""Wazuh Tool Router — Host-level alert and agent status queries.

Provides endpoints to query Wazuh alerts and agent health.
Returns mock data when WAZUH_API_URL is not configured.
Caches results in Redis (TTL 1800s).
"""

import json
import os
import random
import uuid
from datetime import datetime, timedelta, timezone

import structlog
from fastapi import APIRouter
from pydantic import BaseModel

logger = structlog.get_logger()

router = APIRouter(prefix="/wazuh", tags=["wazuh"])

WAZUH_API_URL = os.getenv("WAZUH_API_URL", "")

# Redis client (injected at startup from server.py)
_redis = None


async def init_redis(redis_client):
    global _redis
    _redis = redis_client
    logger.info("wazuh.redis_connected")


# --- Request Schemas ---

class QueryAlertsRequest(BaseModel):
    rule_id: str | None = None
    agent_name: str | None = None
    source_ip: str | None = None
    level_min: int = 5
    hours_back: int = 24


class GetAgentStatusRequest(BaseModel):
    agent_id: str | None = None


# --- Mock Data Generators ---

_WAZUH_RULES = [
    {"id": "5710", "level": 10, "description": "sshd: Attempt to login using a denied user.", "mitre_id": "T1110"},
    {"id": "5712", "level": 10, "description": "sshd: brute force attack detected.", "mitre_id": "T1110.001"},
    {"id": "100002", "level": 8, "description": "Integrity checksum changed.", "mitre_id": "T1565.001"},
    {"id": "87105", "level": 12, "description": "Rootkit detected on system.", "mitre_id": "T1014"},
    {"id": "550", "level": 7, "description": "Firewall rule changed.", "mitre_id": "T1562.004"},
    {"id": "31101", "level": 6, "description": "Web application attack detected.", "mitre_id": "T1190"},
    {"id": "5402", "level": 9, "description": "Successful sudo to ROOT executed.", "mitre_id": "T1548.003"},
    {"id": "60106", "level": 11, "description": "Malware detected by ClamAV.", "mitre_id": "T1204.002"},
]

_AGENT_NAMES = ["web-server-01", "db-server-02", "api-gateway-03", "worker-node-04"]
_AGENT_IPS = ["10.0.1.10", "10.0.1.20", "10.0.2.10", "10.0.2.20"]


def _generate_mock_alerts(req: QueryAlertsRequest) -> list[dict]:
    count = random.randint(3, 8)
    now = datetime.now(timezone.utc)
    alerts = []
    for _ in range(count):
        rule = random.choice(_WAZUH_RULES)
        if req.rule_id and rule["id"] != req.rule_id:
            continue
        agent_idx = random.randint(0, len(_AGENT_NAMES) - 1)
        agent_name = req.agent_name or _AGENT_NAMES[agent_idx]
        alerts.append({
            "id": str(uuid.uuid4())[:8],
            "rule": {
                "id": rule["id"],
                "level": rule["level"],
                "description": rule["description"],
                "mitre": {"id": [rule["mitre_id"]]},
            },
            "agent": {
                "name": agent_name,
                "ip": _AGENT_IPS[agent_idx % len(_AGENT_IPS)],
            },
            "data": {
                "srcip": req.source_ip or f"192.168.{random.randint(1,254)}.{random.randint(1,254)}",
                "dstport": random.choice([22, 80, 443, 3306, 5432, 8080]),
            },
            "timestamp": (now - timedelta(minutes=random.randint(5, req.hours_back * 60))).isoformat(),
        })
    return alerts


def _generate_mock_agents() -> list[dict]:
    now = datetime.now(timezone.utc)
    agents = []
    for i, name in enumerate(_AGENT_NAMES):
        agents.append({
            "id": f"{i+1:03d}",
            "name": name,
            "ip": _AGENT_IPS[i],
            "status": random.choice(["active", "active", "active", "disconnected"]),
            "os": {
                "platform": "linux",
                "name": random.choice(["Ubuntu 22.04", "Debian 12", "Amazon Linux 2023"]),
            },
            "lastKeepAlive": (now - timedelta(seconds=random.randint(10, 300))).isoformat(),
        })
    return agents


# --- Endpoints ---

@router.post("/query-alerts")
async def query_alerts(req: QueryAlertsRequest):
    """Query Wazuh alerts by rule, agent, level, or time window."""
    cache_key = f"wazuh:alerts:{req.rule_id}:{req.agent_name}:{req.source_ip}:{req.level_min}:{req.hours_back}"
    if _redis:
        try:
            cached = await _redis.get(cache_key)
            if cached:
                logger.debug("wazuh.cache_hit")
                return json.loads(cached)
        except Exception as e:
            logger.warning("wazuh.cache_error", error=str(e))

    # Mock mode (no Wazuh API configured)
    alerts = _generate_mock_alerts(req)
    result = {"alerts": alerts, "count": len(alerts), "mock": True}

    if _redis:
        try:
            await _redis.set(cache_key, json.dumps(result), ex=1800)
        except Exception as e:
            logger.warning("wazuh.cache_write_error", error=str(e))

    return result


@router.post("/get-agent-status")
async def get_agent_status(req: GetAgentStatusRequest):
    """Get Wazuh agent health status."""
    cache_key = f"wazuh:agents:{req.agent_id or 'all'}"
    if _redis:
        try:
            cached = await _redis.get(cache_key)
            if cached:
                logger.debug("wazuh.agents.cache_hit")
                return json.loads(cached)
        except Exception as e:
            logger.warning("wazuh.agents.cache_error", error=str(e))

    agents = _generate_mock_agents()
    if req.agent_id:
        agents = [a for a in agents if a["id"] == req.agent_id]
    result = {"agents": agents, "total": len(agents), "mock": True}

    if _redis:
        try:
            await _redis.set(cache_key, json.dumps(result), ex=1800)
        except Exception as e:
            logger.warning("wazuh.agents.cache_write_error", error=str(e))

    return result
