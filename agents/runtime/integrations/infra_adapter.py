"""Infrastructure adapter — mock AWS security operations.

Handles: revert_security_group, disable_iam_user, enable_enhanced_logging
In production, this would call AWS boto3 APIs.
"""

import asyncio
from datetime import datetime, timezone

import structlog

from runtime.integrations.base import BaseAdapter, AdapterResult

logger = structlog.get_logger()


class InfraAdapter(BaseAdapter):
    """Mock AWS infrastructure integration."""

    async def execute(self, action_type: str, params: dict) -> AdapterResult:
        if action_type == "revert_security_group":
            return await self._revert_sg(params)
        elif action_type == "disable_iam_user":
            return await self._disable_iam(params)
        elif action_type == "enable_enhanced_logging":
            return await self._enable_logging(params)

        return AdapterResult(success=False, error=f"Unknown action_type: {action_type}")

    async def rollback(self, action_type: str, params: dict) -> AdapterResult:
        if action_type == "disable_iam_user":
            return await self._enable_iam(params)
        return AdapterResult(success=False, error=f"Rollback not supported for {action_type}")

    async def _revert_sg(self, params: dict) -> AdapterResult:
        await asyncio.sleep(0.15)
        sg_id = params.get("security_group_id", "sg-unknown")
        logger.info("infra.sg_reverted", sg_id=sg_id)
        return AdapterResult(
            success=True,
            details={
                "action": "revert_security_group",
                "security_group_id": sg_id,
                "rules_removed": params.get("rules_to_remove", 1),
                "reverted_at": datetime.now(timezone.utc).isoformat(),
                "region": params.get("region", "ap-southeast-2"),
            },
        )

    async def _disable_iam(self, params: dict) -> AdapterResult:
        await asyncio.sleep(0.12)
        iam_user = params.get("iam_user", params.get("username", "unknown"))
        logger.info("infra.iam_disabled", iam_user=iam_user)
        return AdapterResult(
            success=True,
            details={
                "action": "disable_iam_user",
                "iam_user": iam_user,
                "access_keys_deactivated": 2,
                "disabled_at": datetime.now(timezone.utc).isoformat(),
            },
            rollback_params={"iam_user": iam_user},
        )

    async def _enable_iam(self, params: dict) -> AdapterResult:
        await asyncio.sleep(0.1)
        iam_user = params.get("iam_user", "unknown")
        logger.info("infra.iam_enabled", iam_user=iam_user)
        return AdapterResult(
            success=True,
            details={
                "action": "enable_iam_user",
                "iam_user": iam_user,
                "enabled_at": datetime.now(timezone.utc).isoformat(),
            },
        )

    async def _enable_logging(self, params: dict) -> AdapterResult:
        await asyncio.sleep(0.1)
        services = params.get("services", ["cloudtrail", "vpc-flow-logs"])
        logger.info("infra.enhanced_logging_enabled", services=services)
        return AdapterResult(
            success=True,
            details={
                "action": "enable_enhanced_logging",
                "services": services,
                "log_level": "verbose",
                "retention_days": 90,
                "enabled_at": datetime.now(timezone.utc).isoformat(),
            },
        )
