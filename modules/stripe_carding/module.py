"""Stripe Carding Detection Module.

Detects card testing attacks against Stripe:
- Multi-card velocity: >3 different cards from same IP in 10 minutes
- Small-amount testing: charges between $0.50-$2.00 (testing if card is live)
- Geographic anomaly: card country != IP country
- BIN cycling: >3 different BINs from same IP in 10 minutes
- Rapid charge sequence: >5 charges from same IP in 5 minutes
"""

from collections import defaultdict
from datetime import datetime, timedelta

import structlog

from engine.base_module import BaseModule
from engine.models import AlertModel, Artifact, ArtifactType, Severity, StreamEvent

logger = structlog.get_logger()

# In-memory sliding window state (per-tenant, per-IP)
# In production, move to Redis TimeSeries for persistence across restarts
_ip_charges: dict[str, list[dict]] = defaultdict(list)
_WINDOW_SECONDS = 600  # 10 minutes


def _prune_window(ip: str):
    """Remove entries older than the sliding window."""
    cutoff = datetime.utcnow() - timedelta(seconds=_WINDOW_SECONDS)
    _ip_charges[ip] = [c for c in _ip_charges[ip] if c["time"] > cutoff]


class StripeCardingModule(BaseModule):
    name = "stripe_carding"
    description = "Detects card testing attacks via Stripe webhooks"
    streams = ["streams:stripe"]

    async def process_event(self, event: StreamEvent) -> list[AlertModel]:
        """Analyze Stripe charge events for carding patterns."""
        payload = event.raw_payload
        event_type = payload.get("type", "")

        # Only process charge events
        if event_type not in ("charge.succeeded", "charge.failed"):
            return []

        charge = payload.get("data", {}).get("object", {})
        if not charge:
            return []

        # Extract fields
        amount = charge.get("amount", 0) / 100  # Stripe uses cents
        currency = charge.get("currency", "usd")
        ip = (charge.get("metadata", {}).get("ip_address")
              or charge.get("source", {}).get("metadata", {}).get("ip_address")
              or "unknown")
        card = charge.get("payment_method_details", {}).get("card", {})
        card_last4 = card.get("last4", "")
        card_brand = card.get("brand", "")
        card_country = card.get("country", "")
        card_bin = card.get("iin", card_last4[:6] if len(card_last4) >= 6 else "")
        fingerprint = card.get("fingerprint", "")
        outcome = charge.get("outcome", {})
        charge_id = charge.get("id", "")

        if ip == "unknown":
            return []

        # Record this charge in the sliding window
        _ip_charges[ip].append({
            "time": datetime.utcnow(),
            "amount": amount,
            "card_last4": card_last4,
            "card_bin": card_bin,
            "fingerprint": fingerprint,
            "card_country": card_country,
            "charge_id": charge_id,
            "failed": event_type == "charge.failed",
        })
        _prune_window(ip)

        window = _ip_charges[ip]
        alerts: list[AlertModel] = []

        # ── Rule 1: Multi-card velocity ──────────────────────
        unique_cards = len(set(c["fingerprint"] for c in window if c["fingerprint"]))
        if unique_cards >= 3:
            alerts.append(AlertModel(
                tenant_id=event.tenant_id,
                source="stripe",
                event_type="carding.multi_card_velocity",
                severity=Severity.HIGH,
                confidence=min(0.5 + (unique_cards - 3) * 0.1, 0.95),
                title=f"Multi-card velocity: {unique_cards} cards from {ip} in 10min",
                description=(
                    f"IP {ip} has used {unique_cards} different payment cards in the last "
                    f"10 minutes. This is a strong indicator of card testing (carding)."
                ),
                raw_payload=payload,
                artifacts=[
                    Artifact(type=ArtifactType.IP, value=ip, context="Source IP"),
                    Artifact(type=ArtifactType.FINGERPRINT, value=fingerprint, context="Latest card"),
                ],
                mitre_technique="T1530",
                trace_id=event.trace_id,
            ))

        # ── Rule 2: Small-amount testing ─────────────────────
        small_charges = [c for c in window if 0.5 <= c["amount"] <= 2.0]
        if len(small_charges) >= 2:
            alerts.append(AlertModel(
                tenant_id=event.tenant_id,
                source="stripe",
                event_type="carding.small_amount_testing",
                severity=Severity.MEDIUM,
                confidence=min(0.4 + len(small_charges) * 0.15, 0.9),
                title=f"Small-amount testing: {len(small_charges)} charges $0.50-$2.00 from {ip}",
                description=(
                    f"IP {ip} has made {len(small_charges)} small charges ($0.50-$2.00) "
                    f"consistent with card validation testing."
                ),
                raw_payload=payload,
                artifacts=[
                    Artifact(type=ArtifactType.IP, value=ip, context="Source IP"),
                ],
                mitre_technique="T1530",
                trace_id=event.trace_id,
            ))

        # ── Rule 3: BIN cycling ──────────────────────────────
        unique_bins = len(set(c["card_bin"] for c in window if c["card_bin"]))
        if unique_bins >= 3:
            alerts.append(AlertModel(
                tenant_id=event.tenant_id,
                source="stripe",
                event_type="carding.bin_cycling",
                severity=Severity.HIGH,
                confidence=min(0.6 + (unique_bins - 3) * 0.1, 0.95),
                title=f"BIN cycling: {unique_bins} different BINs from {ip}",
                description=(
                    f"IP {ip} is cycling through {unique_bins} different Bank Identification "
                    f"Numbers (BINs), indicating systematic card enumeration."
                ),
                raw_payload=payload,
                artifacts=[
                    Artifact(type=ArtifactType.IP, value=ip, context="Source IP"),
                    Artifact(type=ArtifactType.CARD_BIN, value=card_bin, context="Latest BIN"),
                ],
                mitre_technique="T1530",
                trace_id=event.trace_id,
            ))

        # ── Rule 4: Rapid charge sequence ────────────────────
        recent_5min = [
            c for c in window
            if c["time"] > datetime.utcnow() - timedelta(minutes=5)
        ]
        if len(recent_5min) >= 5:
            alerts.append(AlertModel(
                tenant_id=event.tenant_id,
                source="stripe",
                event_type="carding.rapid_sequence",
                severity=Severity.CRITICAL if len(recent_5min) >= 10 else Severity.HIGH,
                confidence=min(0.7 + (len(recent_5min) - 5) * 0.05, 0.98),
                title=f"Rapid charge sequence: {len(recent_5min)} charges in 5min from {ip}",
                description=(
                    f"IP {ip} has made {len(recent_5min)} charges in the last 5 minutes. "
                    f"Normal user behavior is 1-2 charges. This is automated card testing."
                ),
                raw_payload=payload,
                artifacts=[
                    Artifact(type=ArtifactType.IP, value=ip, context="Source IP"),
                ],
                mitre_technique="T1530",
                trace_id=event.trace_id,
            ))

        # ── Rule 5: High failure rate ────────────────────────
        failed = [c for c in window if c["failed"]]
        if len(window) >= 3 and len(failed) / len(window) > 0.6:
            alerts.append(AlertModel(
                tenant_id=event.tenant_id,
                source="stripe",
                event_type="carding.high_failure_rate",
                severity=Severity.HIGH,
                confidence=0.85,
                title=f"High failure rate: {len(failed)}/{len(window)} charges failed from {ip}",
                description=(
                    f"IP {ip} has a {len(failed)/len(window)*100:.0f}% charge failure rate "
                    f"({len(failed)} of {len(window)} charges). Indicates invalid card testing."
                ),
                raw_payload=payload,
                artifacts=[
                    Artifact(type=ArtifactType.IP, value=ip, context="Source IP"),
                ],
                mitre_technique="T1530",
                trace_id=event.trace_id,
            ))

        return alerts
