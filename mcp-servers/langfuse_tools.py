"""Langfuse Tool Router — LLM observability trace and generation queries.

Provides endpoints to query AI agent traces and generation details.
Returns mock data when LANGFUSE_PUBLIC_KEY is not configured.
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

router = APIRouter(prefix="/langfuse", tags=["langfuse"])

LANGFUSE_PUBLIC_KEY = os.getenv("LANGFUSE_PUBLIC_KEY", "")

# Redis client (injected at startup from server.py)
_redis = None


async def init_redis(redis_client):
    global _redis
    _redis = redis_client
    logger.info("langfuse.redis_connected")


# --- Request Schemas ---

class QueryTracesRequest(BaseModel):
    trace_id: str | None = None
    agent_name: str | None = None
    hours_back: int = 24


class GetGenerationRequest(BaseModel):
    generation_id: str


# --- Mock Data Generators ---

_AGENT_NAMES = ["triage_agent", "investigation_agent", "critic_agent"]
_MODELS = ["claude-3-haiku-20240307", "claude-3-sonnet-20240229", "gpt-4o-mini"]
_STEP_TYPES = ["classification", "enrichment", "investigation", "critique", "action_proposal"]


def _generate_mock_traces(req: QueryTracesRequest) -> list[dict]:
    count = random.randint(3, 6)
    now = datetime.now(timezone.utc)
    traces = []
    for _ in range(count):
        agent = req.agent_name or random.choice(_AGENT_NAMES)
        model = random.choice(_MODELS)
        prompt_tokens = random.randint(200, 2000)
        completion_tokens = random.randint(50, 800)
        trace_id = req.trace_id or f"trace-{uuid.uuid4().hex[:12]}"
        step = random.choice(_STEP_TYPES)
        traces.append({
            "id": f"gen-{uuid.uuid4().hex[:12]}",
            "name": f"{agent}.{step}",
            "input": {"alert_id": f"alert-{uuid.uuid4().hex[:8]}", "step": step},
            "output": {"classification": "true_positive", "confidence": round(random.uniform(0.6, 0.99), 2)},
            "model": model,
            "latency_ms": random.randint(200, 5000),
            "total_tokens": prompt_tokens + completion_tokens,
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "status": random.choice(["success", "success", "success", "error"]),
            "scores": {
                "accuracy": round(random.uniform(0.7, 1.0), 2),
                "relevance": round(random.uniform(0.6, 1.0), 2),
            },
            "metadata": {"agent": agent, "step": step},
            "created_at": (now - timedelta(minutes=random.randint(5, req.hours_back * 60))).isoformat(),
        })
    return traces


def _generate_mock_generation(generation_id: str) -> dict:
    agent = random.choice(_AGENT_NAMES)
    model = random.choice(_MODELS)
    prompt_tokens = random.randint(300, 2500)
    completion_tokens = random.randint(100, 1000)
    total = prompt_tokens + completion_tokens
    cost_per_token = 0.000003 if "haiku" in model else 0.000015
    return {
        "id": generation_id,
        "trace_id": f"trace-{uuid.uuid4().hex[:12]}",
        "model": model,
        "prompt": f"[System] You are {agent}. Analyze the following alert...",
        "completion": "Based on the alert data, this appears to be a true positive incident requiring immediate investigation.",
        "temperature": 0.1,
        "max_tokens": 2048,
        "total_tokens": total,
        "prompt_tokens": prompt_tokens,
        "completion_tokens": completion_tokens,
        "latency_ms": random.randint(300, 4000),
        "cost_usd": round(total * cost_per_token, 6),
        "status": "success",
    }


# --- Endpoints ---

@router.post("/query-traces")
async def query_traces(req: QueryTracesRequest):
    """Query Langfuse traces by trace ID, agent name, or time window."""
    cache_key = f"langfuse:traces:{req.trace_id}:{req.agent_name}:{req.hours_back}"
    if _redis:
        try:
            cached = await _redis.get(cache_key)
            if cached:
                logger.debug("langfuse.traces.cache_hit")
                return json.loads(cached)
        except Exception as e:
            logger.warning("langfuse.traces.cache_error", error=str(e))

    traces = _generate_mock_traces(req)
    result = {"traces": traces, "count": len(traces), "mock": True}

    if _redis:
        try:
            await _redis.set(cache_key, json.dumps(result), ex=1800)
        except Exception as e:
            logger.warning("langfuse.traces.cache_write_error", error=str(e))

    return result


@router.post("/get-generation")
async def get_generation(req: GetGenerationRequest):
    """Get specific LLM generation details by generation ID."""
    cache_key = f"langfuse:gen:{req.generation_id}"
    if _redis:
        try:
            cached = await _redis.get(cache_key)
            if cached:
                logger.debug("langfuse.gen.cache_hit")
                return json.loads(cached)
        except Exception as e:
            logger.warning("langfuse.gen.cache_error", error=str(e))

    generation = _generate_mock_generation(req.generation_id)
    result = {"generation": generation, "mock": True}

    if _redis:
        try:
            await _redis.set(cache_key, json.dumps(result), ex=1800)
        except Exception as e:
            logger.warning("langfuse.gen.cache_write_error", error=str(e))

    return result
