"""Agentic SOC v5 — FastAPI Application Entry Point."""

from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.routes import alerts, auth, health, ingest, incidents, actions, admin, ai_agents, traces, ws, playbooks, analytics
from app.services.database import engine, async_session
from app.services.redis_service import redis_client

logger = structlog.get_logger()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown events."""
    logger.info("soc.startup", environment=settings.environment)

    # Verify Redis connection
    try:
        await redis_client.ping()
        logger.info("redis.connected")
    except Exception as e:
        logger.error("redis.connection_failed", error=str(e))

    yield

    # Shutdown
    await redis_client.aclose()
    await engine.dispose()
    logger.info("soc.shutdown")


app = FastAPI(
    title="Agentic SOC v5",
    description="Lean Enterprise Security Operations Center",
    version="0.1.0",
    lifespan=lifespan,
    docs_url="/api/v1/docs",
    openapi_url="/api/v1/openapi.json",
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Routes
app.include_router(health.router, prefix="/api/v1", tags=["health"])
app.include_router(auth.router, prefix="/api/v1/auth", tags=["auth"])
app.include_router(alerts.router, prefix="/api/v1/alerts", tags=["alerts"])
app.include_router(incidents.router, prefix="/api/v1/incidents", tags=["incidents"])
app.include_router(actions.router, prefix="/api/v1/actions", tags=["actions"])
app.include_router(ingest.router, prefix="/api/v1/ingest", tags=["ingest"])
app.include_router(ai_agents.router, prefix="/api/v1/ai-agents", tags=["ai-agents"])
app.include_router(admin.router, prefix="/api/v1/admin", tags=["admin"])
app.include_router(traces.router, prefix="/api/v1/traces", tags=["traces"])
app.include_router(playbooks.router, prefix="/api/v1/playbooks", tags=["playbooks"])
app.include_router(analytics.router, prefix="/api/v1/analytics", tags=["analytics"])
app.include_router(ws.router, tags=["websocket"])
