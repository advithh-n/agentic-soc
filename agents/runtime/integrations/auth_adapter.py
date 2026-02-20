"""Auth adapter — mock Clerk-style identity provider operations.

Handles: disable_user, revoke_all_sessions, force_password_reset
In production, this would call Clerk/Auth0/Okta management APIs.
"""

import asyncio
from datetime import datetime, timezone

import structlog

from runtime.integrations.base import BaseAdapter, AdapterResult

logger = structlog.get_logger()

# Simulated state
_disabled_users: set[str] = set()
_revoked_sessions: dict[str, int] = {}  # user_id -> count


class AuthAdapter(BaseAdapter):
    """Mock identity provider integration."""

    async def execute(self, action_type: str, params: dict) -> AdapterResult:
        if action_type == "disable_user":
            return await self._disable_user(params)
        elif action_type == "revoke_all_sessions":
            return await self._revoke_sessions(params)
        elif action_type == "force_password_reset":
            return await self._force_reset(params)

        return AdapterResult(success=False, error=f"Unknown action_type: {action_type}")

    async def rollback(self, action_type: str, params: dict) -> AdapterResult:
        if action_type == "disable_user":
            return await self._enable_user(params)
        return AdapterResult(success=False, error=f"Rollback not supported for {action_type}")

    async def _disable_user(self, params: dict) -> AdapterResult:
        await asyncio.sleep(0.1)
        user_id = params.get("user_id", params.get("username", "unknown"))
        _disabled_users.add(user_id)
        logger.info("auth.user_disabled", user_id=user_id)
        return AdapterResult(
            success=True,
            details={
                "action": "disable_user",
                "user_id": user_id,
                "disabled_at": datetime.now(timezone.utc).isoformat(),
                "provider": "clerk",
            },
            rollback_params={"user_id": user_id},
        )

    async def _enable_user(self, params: dict) -> AdapterResult:
        await asyncio.sleep(0.1)
        user_id = params.get("user_id", "unknown")
        _disabled_users.discard(user_id)
        logger.info("auth.user_enabled", user_id=user_id)
        return AdapterResult(
            success=True,
            details={
                "action": "enable_user",
                "user_id": user_id,
                "enabled_at": datetime.now(timezone.utc).isoformat(),
            },
        )

    async def _revoke_sessions(self, params: dict) -> AdapterResult:
        await asyncio.sleep(0.12)
        user_id = params.get("user_id", params.get("username", "unknown"))
        sessions_revoked = params.get("session_count", 12)
        _revoked_sessions[user_id] = sessions_revoked
        logger.info("auth.sessions_revoked", user_id=user_id, count=sessions_revoked)
        return AdapterResult(
            success=True,
            details={
                "action": "revoke_all_sessions",
                "user_id": user_id,
                "sessions_revoked": sessions_revoked,
                "revoked_at": datetime.now(timezone.utc).isoformat(),
            },
        )

    async def _force_reset(self, params: dict) -> AdapterResult:
        await asyncio.sleep(0.1)
        user_id = params.get("user_id", params.get("username", "unknown"))
        logger.info("auth.password_reset_forced", user_id=user_id)
        return AdapterResult(
            success=True,
            details={
                "action": "force_password_reset",
                "user_id": user_id,
                "reset_email_sent": True,
                "forced_at": datetime.now(timezone.utc).isoformat(),
            },
        )
