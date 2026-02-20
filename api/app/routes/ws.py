"""WebSocket endpoint for live alert streaming.

Clients connect with a JWT token and receive real-time alerts as they're created.
Uses Redis pub/sub to broadcast alerts from the module engine.
"""

import asyncio
import json

import structlog
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query

from app.auth.jwt import decode_token
from app.services.redis_service import redis_client

logger = structlog.get_logger()
router = APIRouter()

# Active WebSocket connections (per tenant)
_connections: dict[str, set[WebSocket]] = {}


async def _authenticate_ws(websocket: WebSocket, token: str | None) -> dict | None:
    """Validate JWT token for WebSocket connection."""
    if not token:
        return None
    payload = decode_token(token)
    if not payload or payload.get("type") != "access":
        return None
    return {
        "user_id": payload["sub"],
        "tenant_id": payload["tenant_id"],
        "role": payload["role"],
        "email": payload["email"],
    }


@router.websocket("/ws/alerts")
async def alert_stream(
    websocket: WebSocket,
    token: str = Query(None),
):
    """WebSocket endpoint for live alert streaming.

    Connect with: ws://localhost:8050/ws/alerts?token=<JWT>

    Messages sent to client:
    - {"type": "alert", "data": {...}} — new alert created
    - {"type": "triage", "data": {...}} — alert triaged by agent
    - {"type": "ping"} — keepalive every 30s
    """
    user = await _authenticate_ws(websocket, token)
    if not user:
        await websocket.close(code=4001, reason="Invalid or missing token")
        return

    await websocket.accept()
    tenant_id = user["tenant_id"]

    # Register connection
    if tenant_id not in _connections:
        _connections[tenant_id] = set()
    _connections[tenant_id].add(websocket)

    logger.info("ws.connected", tenant_id=tenant_id, email=user["email"])

    try:
        # Subscribe to Redis pub/sub for this tenant's alerts
        pubsub = redis_client.pubsub()
        await pubsub.subscribe(f"soc:{tenant_id}:alerts:live")

        # Run listener and keepalive concurrently
        await asyncio.gather(
            _redis_listener(websocket, pubsub),
            _keepalive(websocket),
            _client_listener(websocket),
        )
    except WebSocketDisconnect:
        logger.info("ws.disconnected", tenant_id=tenant_id, email=user["email"])
    except Exception as e:
        logger.error("ws.error", error=str(e))
    finally:
        _connections[tenant_id].discard(websocket)
        await pubsub.unsubscribe()
        await pubsub.aclose()


async def _redis_listener(websocket: WebSocket, pubsub):
    """Listen to Redis pub/sub and forward alerts to WebSocket."""
    async for message in pubsub.listen():
        if message["type"] == "message":
            try:
                data = json.loads(message["data"])
                await websocket.send_json(data)
            except Exception:
                break


async def _keepalive(websocket: WebSocket):
    """Send ping every 30 seconds to keep connection alive."""
    while True:
        await asyncio.sleep(30)
        try:
            await websocket.send_json({"type": "ping"})
        except Exception:
            break


async def _client_listener(websocket: WebSocket):
    """Listen for client messages (used to detect disconnection)."""
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        raise
    except Exception:
        pass


async def broadcast_alert(tenant_id: str, alert_data: dict):
    """Publish alert to Redis pub/sub for WebSocket broadcast.

    Called from the module engine alert writer or ingest routes.
    """
    message = json.dumps({"type": "alert", "data": alert_data})
    await redis_client.publish(f"soc:{tenant_id}:alerts:live", message)


async def broadcast_triage(tenant_id: str, triage_data: dict):
    """Publish triage result to WebSocket clients."""
    message = json.dumps({"type": "triage", "data": triage_data})
    await redis_client.publish(f"soc:{tenant_id}:alerts:live", message)
