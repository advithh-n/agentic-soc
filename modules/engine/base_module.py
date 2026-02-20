"""Base class for all detection modules."""

from abc import ABC, abstractmethod

import structlog

from engine.models import AlertModel, StreamEvent

logger = structlog.get_logger()


class BaseModule(ABC):
    """Base detection module. All modules inherit from this.

    Each module:
    - Subscribes to one or more Redis Streams
    - Processes events through detection rules
    - Emits AlertModel instances when threats are detected
    """

    # Override in subclass
    name: str = "base"
    description: str = ""
    streams: list[str] = []  # Stream suffixes to subscribe to (e.g., ["streams:stripe"])

    def __init__(self):
        self.alert_count = 0
        self.event_count = 0
        self.error_count = 0
        self._log = logger.bind(module=self.name)

    @abstractmethod
    async def process_event(self, event: StreamEvent) -> list[AlertModel]:
        """Process a single event and return zero or more alerts.

        This is the core detection logic. Implementations should:
        1. Parse the raw_payload for relevant fields
        2. Apply detection rules
        3. Return AlertModel instances for detected threats
        4. Return an empty list for benign events
        """
        ...

    async def on_startup(self):
        """Called when the module engine starts. Override for initialization."""
        self._log.info("module.started")

    async def on_shutdown(self):
        """Called when the module engine stops. Override for cleanup."""
        self._log.info("module.stopped")

    def get_stream_keys(self, tenant_id: str) -> list[str]:
        """Get the full Redis Stream keys for a tenant."""
        return [f"{tenant_id}:{stream}" for stream in self.streams]

    @property
    def stats(self) -> dict:
        return {
            "module": self.name,
            "events_processed": self.event_count,
            "alerts_generated": self.alert_count,
            "errors": self.error_count,
        }
