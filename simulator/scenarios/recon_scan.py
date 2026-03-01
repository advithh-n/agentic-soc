"""Recon Scan Simulator — pushes infrastructure scan results to trigger recon module.

Simulates results from an infrastructure scanner that checks:
- Open ports (port change detection)
- CVE vulnerabilities (new CVE found)
- TLS certificate expiry (cert expiry warning)
- DNS record drift (DNS drift detection)

Sends events to the SOC API's /ingest/webhook endpoint as recon scan results.

Expected detections:
  - recon.port_change_detected (new dangerous ports opened)
  - recon.new_cve_found (CVSS >= 7.0 vulnerability)
  - recon.cert_expiry_warning (cert expires in <= 30 days)
  - recon.dns_drift (DNS record mismatch)
"""

import asyncio
import time
from uuid import uuid4

import httpx

API_URL = "http://localhost:8050/api/v1/ingest/webhook"

# Scanned hosts
TARGET_HOST = "10.0.1.50"
TARGET_DOMAIN = "api.heya.au"


def build_scan_events() -> list[dict]:
    """Build a sequence of recon scan result events."""
    events = []
    trace_id = f"recon-{uuid4().hex[:8]}"

    # Event 1: Port scan baseline (first scan — no alert expected)
    events.append({
        "source": "recon_scanner",
        "event_type": "recon.port_scan",
        "severity_hint": "info",
        "payload": {
            "scan_type": "port_scan",
            "host": TARGET_HOST,
            "open_ports": [22, 80, 443],
            "scan_time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        },
        "trace_id": trace_id,
    })

    # Event 2: Port scan with new dangerous ports (alert expected)
    events.append({
        "source": "recon_scanner",
        "event_type": "recon.port_scan",
        "severity_hint": "high",
        "payload": {
            "scan_type": "port_scan",
            "host": TARGET_HOST,
            "open_ports": [22, 80, 443, 3389, 6379, 27017],
            "scan_time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        },
        "trace_id": trace_id,
    })

    # Event 3: Critical CVE found
    events.append({
        "source": "recon_scanner",
        "event_type": "recon.vuln_scan",
        "severity_hint": "critical",
        "payload": {
            "scan_type": "vuln_scan",
            "host": TARGET_HOST,
            "vulnerabilities": [
                {
                    "cve_id": "CVE-2024-3094",
                    "cvss_score": 10.0,
                    "product": "xz-utils",
                    "version": "5.6.0",
                    "description": "Backdoor in xz/liblzma library allowing unauthorized SSH access",
                },
                {
                    "cve_id": "CVE-2024-21762",
                    "cvss_score": 9.6,
                    "product": "FortiOS",
                    "version": "7.4.2",
                    "description": "Out-of-bounds write enabling remote code execution",
                },
            ],
            "scan_time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        },
        "trace_id": trace_id,
    })

    # Event 4: Certificate expiring in 5 days
    events.append({
        "source": "recon_scanner",
        "event_type": "recon.cert_check",
        "severity_hint": "high",
        "payload": {
            "scan_type": "cert_check",
            "host": TARGET_DOMAIN,
            "domain": TARGET_DOMAIN,
            "cert_cn": "*.heya.au",
            "days_until_expiry": 5,
            "cert_expiry": "2026-03-04T00:00:00Z",
            "issuer": "Let's Encrypt Authority X3",
        },
        "trace_id": trace_id,
    })

    # Event 5: DNS drift — first scan (baseline, no alert)
    events.append({
        "source": "recon_scanner",
        "event_type": "recon.dns_check",
        "severity_hint": "info",
        "payload": {
            "scan_type": "dns_check",
            "domain": TARGET_DOMAIN,
            "record_type": "A",
            "dns_record": "13.55.123.45",
        },
        "trace_id": trace_id,
    })

    # Event 6: DNS drift — record changed (alert expected)
    events.append({
        "source": "recon_scanner",
        "event_type": "recon.dns_check",
        "severity_hint": "high",
        "payload": {
            "scan_type": "dns_check",
            "domain": TARGET_DOMAIN,
            "record_type": "A",
            "dns_record": "91.240.118.172",
            "expected_value": "13.55.123.45",
        },
        "trace_id": trace_id,
    })

    return events


async def run_recon_scan(
    api_url: str = API_URL,
    delay_seconds: float = 0.3,
) -> dict:
    """Execute a simulated recon scan sequence.

    Returns stats about the simulation.
    """
    results = {
        "total_sent": 0,
        "successful_ingests": 0,
        "failed_ingests": 0,
        "trace_ids": [],
        "target_host": TARGET_HOST,
        "target_domain": TARGET_DOMAIN,
    }

    events = build_scan_events()
    step_names = [
        "Port scan baseline (first scan)",
        "Port scan — new dangerous ports (3389, 6379, 27017)",
        "Vuln scan — CVE-2024-3094 (CVSS 10.0) + CVE-2024-21762 (CVSS 9.6)",
        "Cert check — *.heya.au expires in 5 days",
        "DNS check baseline (first scan)",
        "DNS drift — api.heya.au A record changed to botnet IP",
    ]

    async with httpx.AsyncClient(timeout=10) as client:
        for i, (event, step_name) in enumerate(zip(events, step_names)):
            try:
                resp = await client.post(api_url, json=event)
                if resp.status_code == 200:
                    data = resp.json()
                    results["successful_ingests"] += 1
                    results["trace_ids"].append(data.get("trace_id"))
                    print(f"  [{i+1}/{len(events)}] {step_name} -> ingested")
                else:
                    results["failed_ingests"] += 1
                    print(f"  [{i+1}/{len(events)}] {step_name} -> FAILED: {resp.status_code}")
            except Exception as e:
                results["failed_ingests"] += 1
                print(f"  [{i+1}/{len(events)}] {step_name} -> ERROR: {e}")

            results["total_sent"] += 1
            await asyncio.sleep(delay_seconds)

    return results


async def main():
    print("=" * 60)
    print("  INFRASTRUCTURE RECON SCAN SIMULATION")
    print("=" * 60)
    print(f"  Target host: {TARGET_HOST}")
    print(f"  Target domain: {TARGET_DOMAIN}")
    print("=" * 60)
    print()

    results = await run_recon_scan(delay_seconds=0.3)

    print()
    print("=" * 60)
    print("  SIMULATION RESULTS")
    print("=" * 60)
    print(f"  Total events sent:     {results['total_sent']}")
    print(f"  Successfully ingested: {results['successful_ingests']}")
    print(f"  Failed to ingest:      {results['failed_ingests']}")
    print()
    print("  Expected alerts triggered:")
    print("    - recon.port_change_detected (new dangerous ports)")
    print("    - recon.new_cve_found (2x critical CVEs)")
    print("    - recon.cert_expiry_warning (cert expires in 5 days)")
    print("    - recon.dns_drift (A record changed to botnet IP)")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
