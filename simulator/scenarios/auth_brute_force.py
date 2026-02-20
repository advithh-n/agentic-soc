"""Auth Brute Force & Credential Stuffing Attack Simulator.

Generates realistic Clerk-style authentication webhook payloads that simulate:
1. Brute force attack: Many failed logins from one IP targeting one account
2. Credential stuffing: One IP tries many different username/password combos
3. Impossible travel: Same user logs in from two distant countries rapidly

Sends events to the SOC API's /ingest/clerk endpoint.

Expected detections:
  - auth.brute_force (5+ failed logins from same IP)
  - auth.credential_stuffing (3+ different accounts from same IP)
  - auth.impossible_travel (same user from different countries in 5min)
  - auth.session_anomaly (successful logins from 3+ IPs)
"""

import asyncio
import random
from uuid import uuid4

import httpx

API_URL = "http://localhost:8050/api/v1/ingest/clerk"

ATTACKER_IP = "91.240.118.172"  # Known botnet IP

# Target accounts for brute force
TARGET_EMAILS = [
    "admin@heya.au",
    "john@heya.au",
    "sarah@heya.au",
    "ops@heya.au",
    "finance@heya.au",
    "dev@heya.au",
    "ceo@heya.au",
    "support@heya.au",
]

# IPs for impossible travel
TRAVEL_IPS = {
    "AU": "103.4.16.22",
    "RU": "185.100.87.41",
    "BR": "177.54.128.99",
}


def _make_login_payload(email: str, ip: str, success: bool, country: str = "") -> dict:
    """Build a Clerk-style session webhook payload."""
    return {
        "type": "login.failed" if not success else "session.created",
        "data": {
            "object": {
                "id": f"sess_{uuid4().hex[:20]}",
                "user_id": f"user_{uuid4().hex[:16]}",
                "email_address": email,
                "client_ip": ip,
                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "country": country,
                "city": "",
                "status": "active" if success else "failed",
            }
        },
    }


async def run_brute_force(api_url: str = API_URL, target: str = "admin@heya.au", attempts: int = 8):
    """Simulate brute force attack — many failed logins targeting one account."""
    print(f"\n--- Phase 1: Brute Force on {target} ---")
    async with httpx.AsyncClient(timeout=10) as client:
        for i in range(attempts):
            success = i == attempts - 1 and random.random() < 0.3  # Maybe succeed on last try
            payload = _make_login_payload(target, ATTACKER_IP, success, "RU")

            resp = await client.post(api_url, json=payload)
            status = "OK" if success else "FAIL"
            print(f"  [{i+1}/{attempts}] {target} from {ATTACKER_IP} {status} -> {resp.status_code}")
            await asyncio.sleep(0.2)


async def run_credential_stuffing(api_url: str = API_URL, num_accounts: int = 6):
    """Simulate credential stuffing — try many accounts from one IP."""
    print(f"\n--- Phase 2: Credential Stuffing ({num_accounts} accounts) ---")
    async with httpx.AsyncClient(timeout=10) as client:
        for i in range(num_accounts):
            email = TARGET_EMAILS[i % len(TARGET_EMAILS)]
            success = random.random() < 0.15  # ~15% success rate (leaked passwords)
            payload = _make_login_payload(email, ATTACKER_IP, success, "RU")

            resp = await client.post(api_url, json=payload)
            status = "OK" if success else "FAIL"
            print(f"  [{i+1}/{num_accounts}] {email} from {ATTACKER_IP} {status} -> {resp.status_code}")
            await asyncio.sleep(0.2)


async def run_impossible_travel(api_url: str = API_URL, target: str = "sarah@heya.au"):
    """Simulate impossible travel — same user from AU then RU within seconds."""
    print(f"\n--- Phase 3: Impossible Travel for {target} ---")
    async with httpx.AsyncClient(timeout=10) as client:
        for country, ip in TRAVEL_IPS.items():
            payload = _make_login_payload(target, ip, True, country)
            resp = await client.post(api_url, json=payload)
            print(f"  {target} from {country} ({ip}) -> {resp.status_code}")
            await asyncio.sleep(0.3)


async def main():
    print("=" * 60)
    print("  AUTH ATTACK SIMULATION")
    print("=" * 60)
    print(f"  Target: {API_URL}")
    print(f"  Attacker IP: {ATTACKER_IP}")
    print("=" * 60)

    await run_brute_force()
    await run_credential_stuffing()
    await run_impossible_travel()

    print()
    print("=" * 60)
    print("  SIMULATION COMPLETE")
    print("=" * 60)
    print("  Expected alerts:")
    print("    - auth.brute_force (5+ failed logins from same IP)")
    print("    - auth.credential_stuffing (3+ accounts from same IP)")
    print("    - auth.impossible_travel (same user from AU, RU, BR)")
    print("    - auth.session_anomaly (3+ IPs for same user)")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
