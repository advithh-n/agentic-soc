"""Base adapter class and registry for integration adapters."""

from __future__ import annotations

import abc
from dataclasses import dataclass, field

import structlog

logger = structlog.get_logger()


@dataclass
class AdapterResult:
    """Result of an adapter execution."""
    success: bool
    details: dict = field(default_factory=dict)
    rollback_params: dict | None = None
    error: str | None = None


class BaseAdapter(abc.ABC):
    """Abstract base for integration adapters.

    Each adapter handles one or more action_types (e.g. block_ip, disable_user).
    Production implementations would call real APIs; these are mocks that
    simulate the operation with a short delay.
    """

    @abc.abstractmethod
    async def execute(self, action_type: str, params: dict) -> AdapterResult:
        """Execute an action. Returns AdapterResult with success/failure."""
        ...

    async def rollback(self, action_type: str, params: dict) -> AdapterResult:
        """Rollback a previously executed action. Default: not supported."""
        return AdapterResult(
            success=False,
            error=f"Rollback not supported for {action_type}",
        )


# ─── Global adapter registry ─────────────────────────────

_ADAPTER_REGISTRY: dict[str, BaseAdapter] = {}


def register_adapter(action_type: str, adapter: BaseAdapter) -> None:
    """Register an adapter instance for a specific action_type."""
    _ADAPTER_REGISTRY[action_type] = adapter
    logger.debug("adapter.registered", action_type=action_type, adapter=type(adapter).__name__)


def get_adapter(action_type: str) -> BaseAdapter | None:
    """Look up the adapter for a given action_type."""
    return _ADAPTER_REGISTRY.get(action_type)
