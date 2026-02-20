"""Module registry — discovers and loads detection modules."""

import structlog

from engine.base_module import BaseModule

logger = structlog.get_logger()


class ModuleRegistry:
    """Registry of active detection modules."""

    def __init__(self):
        self._modules: dict[str, BaseModule] = {}

    def register(self, module: BaseModule):
        """Register a module instance."""
        if module.name in self._modules:
            logger.warning("module.duplicate", name=module.name)
            return
        self._modules[module.name] = module
        logger.info("module.registered", name=module.name, streams=module.streams)

    def get(self, name: str) -> BaseModule | None:
        return self._modules.get(name)

    @property
    def modules(self) -> list[BaseModule]:
        return list(self._modules.values())

    @property
    def all_streams(self) -> set[str]:
        """All unique stream suffixes across all modules."""
        streams = set()
        for module in self._modules.values():
            streams.update(module.streams)
        return streams

    def get_modules_for_stream(self, stream_suffix: str) -> list[BaseModule]:
        """Get all modules that subscribe to a given stream suffix."""
        return [m for m in self._modules.values() if stream_suffix in m.streams]


def build_registry() -> ModuleRegistry:
    """Discover and register all available modules."""
    registry = ModuleRegistry()

    # Import and register modules
    from stripe_carding.module import StripeCardingModule
    registry.register(StripeCardingModule())

    from auth_anomaly.module import AuthAnomalyModule
    registry.register(AuthAnomalyModule())

    from infrastructure.module import InfrastructureModule
    registry.register(InfrastructureModule())

    from ai_agent_monitor.module import AiAgentMonitorModule
    registry.register(AiAgentMonitorModule())

    logger.info("registry.built", module_count=len(registry.modules))
    return registry
