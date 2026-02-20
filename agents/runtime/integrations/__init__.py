"""Integration adapters — mock service connectors for response automation."""

from runtime.integrations.base import BaseAdapter, AdapterResult, get_adapter, register_adapter
from runtime.integrations.registry import register_all_adapters

__all__ = ["BaseAdapter", "AdapterResult", "get_adapter", "register_adapter", "register_all_adapters"]
