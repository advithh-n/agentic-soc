"""Stripe Carding Attack Simulator.

Generates realistic Stripe webhook payloads that simulate a card testing attack.
Sends them to the SOC API's /ingest/stripe endpoint.

Attack Pattern:
  1. Attacker obtains a list of stolen card numbers
  2. Tests each card with a small charge ($0.50-$2.00)
  3. Uses the same IP address
  4. Rapid sequence of charges
  5. Mix of successes and failures (most cards are expired/invalid)

Expected detections:
  - multi_card_velocity (3+ different cards from same IP)
  - small_amount_testing ($0.50-$2.00 charges)
  - rapid_sequence (5+ charges in 5 min)
  - high_failure_rate (>60% failures)
  - bin_cycling (3+ different BINs)
"""

import asyncio
import random
import time
from uuid import uuid4

import httpx


API_URL = "http://localhost:8050/api/v1/ingest/stripe"

# Simulated stolen card data
STOLEN_CARDS = [
    {"last4": "4242", "brand": "visa", "country": "US", "iin": "424242", "fingerprint": f"fp_{uuid4().hex[:12]}"},
    {"last4": "5556", "brand": "mastercard", "country": "GB", "iin": "555566", "fingerprint": f"fp_{uuid4().hex[:12]}"},
    {"last4": "3782", "brand": "amex", "country": "CA", "iin": "378282", "fingerprint": f"fp_{uuid4().hex[:12]}"},
    {"last4": "6011", "brand": "discover", "country": "US", "iin": "601111", "fingerprint": f"fp_{uuid4().hex[:12]}"},
    {"last4": "3566", "brand": "jcb", "country": "JP", "iin": "356600", "fingerprint": f"fp_{uuid4().hex[:12]}"},
    {"last4": "4000", "brand": "visa", "country": "AU", "iin": "400012", "fingerprint": f"fp_{uuid4().hex[:12]}"},
    {"last4": "5200", "brand": "mastercard", "country": "DE", "iin": "520082", "fingerprint": f"fp_{uuid4().hex[:12]}"},
    {"last4": "4111", "brand": "visa", "country": "FR", "iin": "411111", "fingerprint": f"fp_{uuid4().hex[:12]}"},
]

ATTACKER_IP = "185.220.101.42"  # Known Tor exit node


def _make_charge_payload(card: dict, amount_cents: int, failed: bool) -> dict:
    """Build a realistic Stripe charge webhook payload."""
    charge_id = f"ch_{uuid4().hex[:24]}"
    return {
        "id": f"evt_{uuid4().hex[:24]}",
        "type": "charge.failed" if failed else "charge.succeeded",
        "data": {
            "object": {
                "id": charge_id,
                "object": "charge",
                "amount": amount_cents,
                "currency": "aud",
                "status": "failed" if failed else "succeeded",
                "metadata": {
                    "ip_address": ATTACKER_IP,
                },
                "payment_method_details": {
                    "card": {
                        "last4": card["last4"],
                        "brand": card["brand"],
                        "country": card["country"],
                        "iin": card["iin"],
                        "fingerprint": card["fingerprint"],
                        "exp_month": 12,
                        "exp_year": 2027,
                    },
                    "type": "card",
                },
                "outcome": {
                    "network_status": "declined_by_network" if failed else "approved_by_network",
                    "reason": "generic_decline" if failed else None,
                    "type": "issuer_declined" if failed else "authorized",
                },
                "created": int(time.time()),
            }
        },
    }


async def run_carding_attack(
    api_url: str = API_URL,
    num_charges: int = 12,
    delay_seconds: float = 0.5,
) -> dict:
    """Execute a simulated carding attack.

    Returns stats about the simulation.
    """
    results = {
        "total_sent": 0,
        "successful_ingests": 0,
        "failed_ingests": 0,
        "trace_ids": [],
        "cards_used": 0,
        "attack_ip": ATTACKER_IP,
    }

    cards_used = set()

    async with httpx.AsyncClient(timeout=10) as client:
        for i in range(num_charges):
            # Pick a random card
            card = random.choice(STOLEN_CARDS)
            cards_used.add(card["fingerprint"])

            # Most card tests fail (70% failure rate)
            failed = random.random() < 0.7

            # Small test amounts ($0.50-$2.00)
            amount_cents = random.choice([50, 75, 100, 125, 150, 175, 200])

            payload = _make_charge_payload(card, amount_cents, failed)

            try:
                resp = await client.post(api_url, json=payload)
                if resp.status_code == 200:
                    data = resp.json()
                    results["successful_ingests"] += 1
                    results["trace_ids"].append(data.get("trace_id"))
                else:
                    results["failed_ingests"] += 1
                    print(f"  [{i+1}/{num_charges}] FAILED: {resp.status_code} {resp.text[:100]}")
            except Exception as e:
                results["failed_ingests"] += 1
                print(f"  [{i+1}/{num_charges}] ERROR: {e}")

            results["total_sent"] += 1
            status = "FAIL" if failed else "OK"
            print(f"  [{i+1}/{num_charges}] Card {card['last4']} ${amount_cents/100:.2f} {status} -> ingested")

            # Small delay between charges (attacker uses automation)
            await asyncio.sleep(delay_seconds)

    results["cards_used"] = len(cards_used)
    return results


async def main():
    print("=" * 60)
    print("  STRIPE CARDING ATTACK SIMULATION")
    print("=" * 60)
    print(f"  Target: {API_URL}")
    print(f"  Attacker IP: {ATTACKER_IP}")
    print(f"  Cards in pool: {len(STOLEN_CARDS)}")
    print("=" * 60)
    print()

    results = await run_carding_attack(num_charges=12, delay_seconds=0.3)

    print()
    print("=" * 60)
    print("  SIMULATION RESULTS")
    print("=" * 60)
    print(f"  Total webhooks sent:  {results['total_sent']}")
    print(f"  Successfully ingested: {results['successful_ingests']}")
    print(f"  Failed to ingest:     {results['failed_ingests']}")
    print(f"  Unique cards used:    {results['cards_used']}")
    print(f"  Attacker IP:          {results['attack_ip']}")
    print()
    print("  Expected alerts triggered:")
    print("    - carding.multi_card_velocity (3+ cards from same IP)")
    print("    - carding.small_amount_testing ($0.50-$2.00)")
    print("    - carding.rapid_sequence (5+ charges in 5 min)")
    print("    - carding.high_failure_rate (>60% failures)")
    print("    - carding.bin_cycling (3+ BINs)")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
