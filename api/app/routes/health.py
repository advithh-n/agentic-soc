"""Health check endpoints."""

from fastapi import APIRouter
from sqlalchemy import text

from app.services.database import async_session
from app.services.redis_service import redis_client

router = APIRouter()


@router.get("/health")
async def health_check():
    """System health check — verifies all critical dependencies."""
    checks = {}

    # PostgreSQL
    try:
        async with async_session() as db:
            result = await db.execute(text("SELECT 1"))
            result.fetchone()
        checks["postgres"] = "ok"
    except Exception as e:
        checks["postgres"] = f"error: {str(e)[:100]}"

    # Redis
    try:
        await redis_client.ping()
        checks["redis"] = "ok"
    except Exception as e:
        checks["redis"] = f"error: {str(e)[:100]}"

    all_ok = all(v == "ok" for v in checks.values())

    return {
        "status": "healthy" if all_ok else "degraded",
        "checks": checks,
        "version": "0.1.0",
    }
