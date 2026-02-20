"""Adapter registry — maps all action_types to adapter instances."""

import structlog

from runtime.integrations.base import register_adapter
from runtime.integrations.traefik_adapter import TraefikAdapter
from runtime.integrations.stripe_adapter import StripeAdapter
from runtime.integrations.auth_adapter import AuthAdapter
from runtime.integrations.infra_adapter import InfraAdapter
from runtime.integrations.notification_adapter import NotificationAdapter

logger = structlog.get_logger()


def register_all_adapters() -> None:
    """Register all integration adapters in the global registry."""
    traefik = TraefikAdapter()
    register_adapter("block_ip", traefik)
    register_adapter("unblock_ip", traefik)

    stripe = StripeAdapter()
    register_adapter("rotate_api_key", stripe)
    register_adapter("freeze_stripe_payments", stripe)

    auth = AuthAdapter()
    register_adapter("disable_user", auth)
    register_adapter("revoke_all_sessions", auth)
    register_adapter("force_password_reset", auth)

    infra = InfraAdapter()
    register_adapter("revert_security_group", infra)
    register_adapter("disable_iam_user", infra)
    register_adapter("enable_enhanced_logging", infra)

    notif = NotificationAdapter()
    register_adapter("notify_fraud_team", notif)
    register_adapter("notify_security", notif)
    register_adapter("notify_ops", notif)

    logger.info("adapters.registered", count=13)
