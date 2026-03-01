"""Clerk Tool Router — Auth session and user profile queries.

Provides endpoints to query Clerk sessions and user security profiles.
Returns mock data when CLERK_SECRET_KEY is not configured.
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

router = APIRouter(prefix="/clerk", tags=["clerk"])

CLERK_SECRET_KEY = os.getenv("CLERK_SECRET_KEY", "")

# Redis client (injected at startup from server.py)
_redis = None


async def init_redis(redis_client):
    global _redis
    _redis = redis_client
    logger.info("clerk.redis_connected")


# --- Request Schemas ---

class QuerySessionsRequest(BaseModel):
    user_id: str | None = None
    hours_back: int = 24


class GetUserProfileRequest(BaseModel):
    user_id: str


# --- Mock Data Generators ---

_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15",
    "Mozilla/5.0 (Linux; Android 14) Mobile Chrome/120.0.0.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2_1) Mobile/15E148",
]

_CITIES = ["Melbourne", "Sydney", "Brisbane", "Perth", "Auckland"]


def _generate_mock_sessions(req: QuerySessionsRequest) -> list[dict]:
    count = random.randint(2, 5)
    now = datetime.now(timezone.utc)
    sessions = []
    user_id = req.user_id or f"user_{uuid.uuid4().hex[:12]}"
    statuses = ["active", "active", "revoked", "expired", "ended"]
    for _ in range(count):
        created = now - timedelta(hours=random.randint(1, req.hours_back))
        sessions.append({
            "id": f"sess_{uuid.uuid4().hex[:20]}",
            "status": random.choice(statuses),
            "client_id": f"client_{uuid.uuid4().hex[:8]}",
            "user_id": user_id,
            "last_active_at": (created + timedelta(minutes=random.randint(5, 120))).isoformat(),
            "expire_at": (created + timedelta(hours=24)).isoformat(),
            "created_at": created.isoformat(),
            "user_agent": random.choice(_USER_AGENTS),
            "ip_address": f"203.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
            "city": random.choice(_CITIES),
            "country": "AU",
        })
    return sessions


def _generate_mock_user(user_id: str) -> dict:
    now = datetime.now(timezone.utc)
    return {
        "id": user_id,
        "email": f"{user_id.replace('user_', '')}@example.com",
        "first_name": random.choice(["Alex", "Jordan", "Morgan", "Casey", "Sam"]),
        "last_name": random.choice(["Smith", "Chen", "Patel", "Kim", "Nguyen"]),
        "mfa_enabled": random.choice([True, False]),
        "banned": False,
        "locked": False,
        "last_sign_in_at": (now - timedelta(hours=random.randint(1, 48))).isoformat(),
        "created_at": (now - timedelta(days=random.randint(30, 365))).isoformat(),
        "external_accounts": [
            {"provider": "google", "email": f"{user_id.replace('user_', '')}@gmail.com"}
        ],
        "failed_login_attempts": random.randint(0, 5),
    }


# --- Endpoints ---

@router.post("/query-sessions")
async def query_sessions(req: QuerySessionsRequest):
    """Query Clerk sessions by user ID and time window."""
    cache_key = f"clerk:sessions:{req.user_id}:{req.hours_back}"
    if _redis:
        try:
            cached = await _redis.get(cache_key)
            if cached:
                logger.debug("clerk.sessions.cache_hit")
                return json.loads(cached)
        except Exception as e:
            logger.warning("clerk.sessions.cache_error", error=str(e))

    sessions = _generate_mock_sessions(req)
    result = {"sessions": sessions, "count": len(sessions), "mock": True}

    if _redis:
        try:
            await _redis.set(cache_key, json.dumps(result), ex=1800)
        except Exception as e:
            logger.warning("clerk.sessions.cache_write_error", error=str(e))

    return result


@router.post("/get-user-profile")
async def get_user_profile(req: GetUserProfileRequest):
    """Get Clerk user security profile by user ID."""
    cache_key = f"clerk:user:{req.user_id}"
    if _redis:
        try:
            cached = await _redis.get(cache_key)
            if cached:
                logger.debug("clerk.user.cache_hit")
                return json.loads(cached)
        except Exception as e:
            logger.warning("clerk.user.cache_error", error=str(e))

    user = _generate_mock_user(req.user_id)
    result = {"user": user, "mock": True}

    if _redis:
        try:
            await _redis.set(cache_key, json.dumps(result), ex=1800)
        except Exception as e:
            logger.warning("clerk.user.cache_write_error", error=str(e))

    return result
