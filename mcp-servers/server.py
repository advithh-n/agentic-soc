"""MCP Server — Multi-router FastAPI server for SOC tool integrations.

All MCP tools run in a single process. Each domain is a FastAPI router.
Exposes REST endpoints that agents call for enrichment and graph queries.
"""

import asyncio
import os
from contextlib import asynccontextmanager

import redis.asyncio as aioredis
import structlog
import uvicorn
from fastapi import FastAPI

from neo4j_tools import router as neo4j_router, init_driver, close_driver
from abuseipdb_tools import router as abuseipdb_router, init_redis as init_abuseipdb_redis
from aws_tools import router as aws_router

logger = structlog.get_logger()

# Redis client for caching (shared across tools)
_redis_client = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup/shutdown lifecycle."""
    global _redis_client
    logger.info("mcp.starting")

    # Initialize Neo4j
    try:
        await init_driver()
    except Exception as e:
        logger.warning("neo4j.init_failed", error=str(e))

    # Initialize Redis for caching
    try:
        redis_url = os.getenv("REDIS_URL", "redis://redis:6379/0")
        _redis_client = aioredis.from_url(
            redis_url, decode_responses=True, max_connections=5,
        )
        await _redis_client.ping()
        await init_abuseipdb_redis(_redis_client)
        logger.info("mcp.redis_connected")
    except Exception as e:
        logger.warning("mcp.redis_failed", error=str(e))

    yield

    # Cleanup
    if _redis_client:
        await _redis_client.close()
    await close_driver()
    logger.info("mcp.stopped")


app = FastAPI(title="Agentic SOC — MCP Tool Servers", lifespan=lifespan)

# Mount tool routers
app.include_router(neo4j_router)
app.include_router(abuseipdb_router)
app.include_router(aws_router)


@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "servers": ["neo4j", "abuseipdb", "aws"],
        "tools_registered": 8,
    }


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8100)
