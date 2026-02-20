"""Traefik adapter — mock IP blocking via Traefik middleware.

Handles: block_ip, unblock_ip
In production, this would modify Traefik dynamic config or call the API.
"""

import asyncio
from datetime import datetime, timezone

import structlog

from runtime.integrations.base import BaseAdapter, AdapterResult

logger = structlog.get_logger()

# Simulated blocklist
_blocked_ips: set[str] = set()


class TraefikAdapter(BaseAdapter):
    """Mock Traefik integration for IP blocking."""

    async def execute(self, action_type: str, params: dict) -> AdapterResult:
        ip = params.get("ip") or params.get("source_ip", "unknown")

        if action_type == "block_ip":
            return await self._block_ip(ip)
        elif action_type == "unblock_ip":
            return await self._unblock_ip(ip)

        return AdapterResult(success=False, error=f"Unknown action_type: {action_type}")

    async def rollback(self, action_type: str, params: dict) -> AdapterResult:
        if action_type == "block_ip":
            ip = params.get("ip") or params.get("source_ip", "unknown")
            return await self._unblock_ip(ip)
        return AdapterResult(success=False, error=f"Rollback not supported for {action_type}")

    async def _block_ip(self, ip: str) -> AdapterResult:
        await asyncio.sleep(0.1)  # Simulate API latency
        _blocked_ips.add(ip)
        logger.info("traefik.ip_blocked", ip=ip, total_blocked=len(_blocked_ips))
        return AdapterResult(
            success=True,
            details={
                "action": "block_ip",
                "ip": ip,
                "blocked_at": datetime.now(timezone.utc).isoformat(),
                "middleware": "ip-blocklist",
                "total_blocked": len(_blocked_ips),
            },
            rollback_params={"ip": ip},
        )

    async def _unblock_ip(self, ip: str) -> AdapterResult:
        await asyncio.sleep(0.1)
        _blocked_ips.discard(ip)
        logger.info("traefik.ip_unblocked", ip=ip)
        return AdapterResult(
            success=True,
            details={
                "action": "unblock_ip",
                "ip": ip,
                "unblocked_at": datetime.now(timezone.utc).isoformat(),
            },
        )
