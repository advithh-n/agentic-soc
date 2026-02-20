"""False Positive Simulator — benign activity that looks suspicious.

Generates realistic Stripe and Clerk events that should trigger detection
rules but ultimately be classified as FALSE POSITIVE or LOW confidence
by the triage agent.

Scenarios:
  1. Legitimate SaaS company testing their own payment flow
     - Multiple small charges with same IP (company office)
     - All succeed, using company test cards
     - Different amounts, not the classic $0.50-$2.00 pattern

  2. Normal user traveling for business
     - Login from Melbourne, then Sydney 1.5 hours later (plausible)
     - Different devices (phone + laptop) but same user

  3. QA team running automated test suite
     - Rapid sequence of charges (test harness)
     - All from internal IP
     - Mixed success/failure (testing edge cases)

Expected: Alerts triggered but triage should mark as false_positive
          or needs_investigation with low confidence.
"""

import asyncio
import random
import time
from uuid import uuid4

import httpx

STRIPE_URL = "http://localhost:8050/api/v1/ingest/stripe"
CLERK_URL = "http://localhost:8050/api/v1/ingest/clerk"

# Legitimate company office IP (internal, not on any threat list)
OFFICE_IP = "203.17.88.100"  # Australian ISP, clean IP


def _make_legit_charge(amount_cents: int, succeeded: bool, card_idx: int) -> dict:
    """Build a legitimate-looking Stripe charge — company testing their own flow."""
    # Company uses 2-3 test cards (not 8+ like an attacker)
    cards = [
        {"last4": "1234", "brand": "visa", "country": "AU", "iin": "456712",
         "fingerprint": "fp_legit_company_01"},
        {"last4": "5678", "brand": "mastercard", "country": "AU", "iin": "520012",
         "fingerprint": "fp_legit_company_02"},
        {"last4": "9012", "brand": "visa", "country": "AU", "iin": "456712",
         "fingerprint": "fp_legit_company_03"},
    ]
    card = cards[card_idx % len(cards)]

    return {
        "id": f"evt_{uuid4().hex[:24]}",
        "type": "charge.succeeded" if succeeded else "charge.failed",
        "data": {
            "object": {
                "id": f"ch_{uuid4().hex[:24]}",
                "object": "charge",
                "amount": amount_cents,
                "currency": "aud",
                "status": "succeeded" if succeeded else "failed",
                "metadata": {
                    "ip_address": OFFICE_IP,
                    "test_mode": "true",
                    "internal_ref": f"QA-{random.randint(1000, 9999)}",
                },
                "payment_method_details": {
                    "card": {
                        "last4": card["last4"],
                        "brand": card["brand"],
                        "country": card["country"],
                        "iin": card["iin"],
                        "fingerprint": card["fingerprint"],
                        "exp_month": 6,
                        "exp_year": 2028,
                    },
                    "type": "card",
                },
                "outcome": {
                    "network_status": "approved_by_network" if succeeded else "declined_by_network",
                    "reason": None if succeeded else "insufficient_funds",
                    "type": "authorized" if succeeded else "issuer_declined",
                },
                "created": int(time.time()),
            }
        },
    }


def _make_travel_login(
    user_id: str, email: str, city: str, country: str, ip: str, device: str
) -> dict:
    """Build a plausible business travel login event."""
    return {
        "type": "session.created",
        "data": {
            "id": f"sess_{uuid4().hex[:24]}",
            "user_id": user_id,
            "status": "active",
            "created_at": int(time.time() * 1000),
            "client_id": f"client_{uuid4().hex[:12]}",
            "last_active_at": int(time.time() * 1000),
        },
        "object": "event",
        "metadata": {
            "ip_address": ip,
            "city": city,
            "country": country,
            "user_email": email,
            "device_type": device,
            "user_agent": (
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"
                if device == "laptop"
                else "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0)"
            ),
        },
    }


async def run_false_positive_scenario(
    delay_seconds: float = 0.5,
) -> dict:
    """Execute false positive scenarios.

    Returns stats about the simulation.
    """
    results = {
        "total_sent": 0,
        "successful_ingests": 0,
        "failed_ingests": 0,
        "scenarios": [],
    }

    async with httpx.AsyncClient(timeout=10) as client:

        # ── Scenario 1: QA team testing payment flow ─────────
        print("\n  Scenario 1: QA team testing payment flow")
        print("  " + "-" * 50)
        qa_charges = [
            (4999, True, 0),   # $49.99 — real product price
            (4999, True, 1),   # Same price, different card
            (9999, True, 0),   # $99.99 — premium tier
            (4999, False, 2),  # Testing decline handling
            (1999, True, 0),   # $19.99 — basic tier
            (4999, True, 1),   # Repeat test
        ]

        for i, (amount, succeeded, card_idx) in enumerate(qa_charges):
            payload = _make_legit_charge(amount, succeeded, card_idx)
            try:
                resp = await client.post(STRIPE_URL, json=payload)
                if resp.status_code == 200:
                    results["successful_ingests"] += 1
                else:
                    results["failed_ingests"] += 1
            except Exception as e:
                results["failed_ingests"] += 1
                print(f"    ERROR: {e}")

            results["total_sent"] += 1
            status = "OK" if succeeded else "DECLINE"
            print(f"    [{i+1}/6] ${amount/100:.2f} {status} card#{card_idx} from {OFFICE_IP}")
            await asyncio.sleep(delay_seconds)

        results["scenarios"].append("qa_payment_testing")

        # ── Scenario 2: Business travel (Melbourne -> Sydney) ──
        print("\n  Scenario 2: Business travel (Melbourne -> Sydney)")
        print("  " + "-" * 50)
        user_id = f"user_{uuid4().hex[:16]}"
        email = "sarah.chen@heya.au"

        travel_logins = [
            ("Melbourne", "AU", "103.4.16.22", "laptop"),     # Office login
            ("Melbourne", "AU", "103.4.16.22", "phone"),      # Phone at same office
            ("Sydney", "AU", "203.45.128.10", "phone"),       # 1.5hr later, plausible flight
            ("Sydney", "AU", "103.78.200.5", "laptop"),       # Hotel wifi
        ]

        for i, (city, country, ip, device) in enumerate(travel_logins):
            payload = _make_travel_login(user_id, email, city, country, ip, device)
            try:
                resp = await client.post(CLERK_URL, json=payload)
                if resp.status_code == 200:
                    results["successful_ingests"] += 1
                else:
                    results["failed_ingests"] += 1
            except Exception as e:
                results["failed_ingests"] += 1
                print(f"    ERROR: {e}")

            results["total_sent"] += 1
            print(f"    [{i+1}/4] Login from {city} ({ip}) on {device}")
            await asyncio.sleep(delay_seconds * 2)  # Slower — real user pace

        results["scenarios"].append("business_travel")

        # ── Scenario 3: Legitimate user password reset ─────────
        print("\n  Scenario 3: User resets password (multiple attempts)")
        print("  " + "-" * 50)
        reset_user_id = f"user_{uuid4().hex[:16]}"
        reset_email = "james.nguyen@heya.au"
        reset_ip = "110.175.32.88"  # Australian residential IP

        # User forgets password, tries 3 times, then resets
        reset_events = [
            ("session.created", "failed", "wrong_password"),
            ("session.created", "failed", "wrong_password"),
            ("session.created", "failed", "wrong_password"),
            ("session.created", "active", None),  # Success after reset
        ]

        for i, (event_type, status, reason) in enumerate(reset_events):
            payload = {
                "type": event_type,
                "data": {
                    "id": f"sess_{uuid4().hex[:24]}",
                    "user_id": reset_user_id,
                    "status": status,
                    "created_at": int(time.time() * 1000),
                    "client_id": f"client_{uuid4().hex[:12]}",
                    "last_active_at": int(time.time() * 1000),
                },
                "object": "event",
                "metadata": {
                    "ip_address": reset_ip,
                    "city": "Melbourne",
                    "country": "AU",
                    "user_email": reset_email,
                    "device_type": "laptop",
                    "failure_reason": reason,
                },
            }
            try:
                resp = await client.post(CLERK_URL, json=payload)
                if resp.status_code == 200:
                    results["successful_ingests"] += 1
                else:
                    results["failed_ingests"] += 1
            except Exception as e:
                results["failed_ingests"] += 1

            results["total_sent"] += 1
            label = f"FAIL ({reason})" if reason else "SUCCESS"
            print(f"    [{i+1}/4] {label} from {reset_ip}")
            await asyncio.sleep(delay_seconds)

        results["scenarios"].append("password_reset")

    return results


async def main():
    print("=" * 60)
    print("  FALSE POSITIVE SIMULATION")
    print("  Benign activity that may trigger detection rules")
    print("=" * 60)
    print(f"  Office IP: {OFFICE_IP}")
    print("=" * 60)

    results = await run_false_positive_scenario(delay_seconds=0.3)

    print()
    print("=" * 60)
    print("  SIMULATION RESULTS")
    print("=" * 60)
    print(f"  Total events sent:     {results['total_sent']}")
    print(f"  Successfully ingested: {results['successful_ingests']}")
    print(f"  Failed to ingest:      {results['failed_ingests']}")
    print(f"  Scenarios run:         {', '.join(results['scenarios'])}")
    print()
    print("  EXPECTED OUTCOMES:")
    print("    - Some alerts may trigger (multi-card, session anomaly)")
    print("    - Triage should classify as FALSE POSITIVE or LOW confidence")
    print("    - IP is NOT on any threat list (clean Australian IP)")
    print("    - Charges are realistic amounts ($19.99-$99.99)")
    print("    - Travel is plausible (Melbourne -> Sydney, same country)")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
