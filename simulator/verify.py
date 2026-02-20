"""Verification script — checks the SOC after a simulation.

1. Logs in as admin
2. Queries alerts
3. Reports what was detected
"""

import asyncio
import sys

import httpx

API_BASE = "http://localhost:8050/api/v1"


async def main():
    async with httpx.AsyncClient(timeout=10) as client:
        # Step 1: Login
        print("Logging in as admin@heya.au ...")
        resp = await client.post(f"{API_BASE}/auth/login", json={
            "email": "admin@heya.au",
            "password": "changeme",
            "tenant_slug": "heya",
        })
        if resp.status_code != 200:
            print(f"LOGIN FAILED: {resp.status_code} {resp.text}")
            sys.exit(1)

        token = resp.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        print(f"  Token obtained (expires in {resp.json()['expires_in']}s)")

        # Step 2: Health check
        print("\nHealth check ...")
        resp = await client.get(f"{API_BASE}/health")
        health = resp.json()
        print(f"  Status: {health['status']}")
        for svc, status in health["checks"].items():
            print(f"    {svc}: {status}")

        # Step 3: Get alerts
        print("\nQuerying alerts ...")
        resp = await client.get(f"{API_BASE}/alerts", headers=headers)
        if resp.status_code != 200:
            print(f"ALERT QUERY FAILED: {resp.status_code} {resp.text}")
            sys.exit(1)

        data = resp.json()
        print(f"  Total alerts: {data['total']}")

        if data["total"] == 0:
            print("\n  No alerts yet. Did you run the simulator and wait for processing?")
            print("  Try: python -m scenarios.stripe_carding")
            return

        print("\n  ALERTS DETECTED:")
        print("  " + "-" * 70)
        for alert in data["alerts"]:
            sev = alert["severity"].upper()
            color = {"LOW": "", "MEDIUM": "", "HIGH": "!", "CRITICAL": "!!"}
            marker = color.get(sev, "")
            print(f"  {marker:>2} [{sev:8}] {alert['event_type']:35} conf={alert.get('confidence', 'N/A')}")
            print(f"     {alert['title'][:80]}")
        print("  " + "-" * 70)

        # Step 4: Summary by event_type
        types = {}
        for a in data["alerts"]:
            types[a["event_type"]] = types.get(a["event_type"], 0) + 1

        print("\n  DETECTION SUMMARY:")
        for et, count in sorted(types.items()):
            print(f"    {et}: {count} alerts")

        # Step 5: Check audit log
        print("\nQuerying audit log ...")
        resp = await client.get(f"{API_BASE}/admin/audit-log", headers=headers)
        if resp.status_code == 200:
            audit = resp.json()
            print(f"  Audit entries: {len(audit['entries'])}")
            for entry in audit["entries"][:5]:
                print(f"    [{entry['action']}] {entry['resource_type']} by {entry['actor_type']}:{entry['actor_id'][:12]}...")
        else:
            print(f"  Audit log query: {resp.status_code}")


if __name__ == "__main__":
    asyncio.run(main())
