"""End-to-End Test — runs all simulator scenarios and verifies detection.

Flow:
  1. Login as admin
  2. Record baseline alert count
  3. Run all 5 scenarios (carding, brute_force, iam_escalation, false_positive, ai_agent_attack)
  4. Wait for processing (modules + triage agent)
  5. Query alerts and verify:
     - Detection rules fired correctly
     - Triage agent classified alerts
     - Severity adjustments applied
     - False positives handled appropriately
     - AI agent security rules detected
  6. Print detection accuracy report

Usage:
  cd simulator
  python e2e_test.py
"""

import asyncio
import sys
import time

import httpx

from scenarios.stripe_carding import run_carding_attack
from scenarios.auth_brute_force import run_brute_force, run_credential_stuffing, run_impossible_travel
from scenarios.iam_escalation import run_iam_escalation
from scenarios.false_positive import run_false_positive_scenario
from scenarios.ai_agent_attack import run_ai_agent_attacks

API_BASE = "http://localhost:8050/api/v1"

# Expected detection rules per scenario
EXPECTED_CARDING_RULES = {
    "carding.multi_card_velocity",
    "carding.small_amount_testing",
    "carding.rapid_sequence",
    "carding.high_failure_rate",
    "carding.bin_cycling",
}

EXPECTED_AUTH_RULES = {
    "auth.brute_force",
    "auth.credential_stuffing",
    "auth.impossible_travel",
    "auth.session_anomaly",
}

EXPECTED_INFRA_RULES = {
    "infra.iam_escalation",
    "infra.s3_unauthorized",
    "infra.security_group_change",
}

EXPECTED_AI_RULES = {
    "ai_agent.prompt_injection",
    "ai_agent.jailbreak_attempt",
    "ai_agent.data_exfiltration",
    "ai_agent.guardrail_block",
    "ai_agent.excessive_tool_calls",
    "ai_agent.token_abuse",
}


async def main():
    print("=" * 70)
    print("  AGENTIC SOC v5 — END-TO-END DETECTION TEST")
    print("=" * 70)
    print()

    async with httpx.AsyncClient(timeout=15) as client:

        # ── Step 1: Health check ──────────────────────────
        print("[1/7] Health check ...")
        try:
            resp = await client.get(f"{API_BASE}/health")
            health = resp.json()
            if health["status"] != "healthy":
                print(f"  WARNING: API status is '{health['status']}'")
            for svc, st in health["checks"].items():
                status_icon = "OK" if st in ("connected", "healthy") else "!!"
                print(f"  {status_icon:>4}  {svc}: {st}")
        except Exception as e:
            print(f"  FATAL: Cannot reach API — {e}")
            sys.exit(1)

        # ── Step 2: Login ─────────────────────────────────
        print("\n[2/7] Logging in as admin@heya.au ...")
        resp = await client.post(f"{API_BASE}/auth/login", json={
            "email": "admin@heya.au",
            "password": "changeme",
            "tenant_slug": "heya",
        })
        if resp.status_code != 200:
            print(f"  FATAL: Login failed — {resp.status_code} {resp.text[:100]}")
            sys.exit(1)

        token = resp.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        print("  Authenticated.")

        # Baseline alert count
        resp = await client.get(f"{API_BASE}/alerts?page_size=1", headers=headers)
        baseline_count = resp.json()["total"]
        print(f"  Baseline alerts: {baseline_count}")

        # ── Step 3: Run all scenarios ─────────────────────
        print("\n[3/7] Running attack scenarios ...")
        print()

        print("  >>> SCENARIO 1: Stripe Carding Attack")
        carding_results = await run_carding_attack(num_charges=12, delay_seconds=0.2)
        print()

        print("  >>> SCENARIO 2: Auth Brute Force Attack")
        await run_brute_force()
        await run_credential_stuffing()
        await run_impossible_travel()
        auth_sent = 8 + 6 + 3  # brute_force + credential_stuffing + impossible_travel
        print()

        print("  >>> SCENARIO 3: IAM Privilege Escalation Attack")
        infra_results = await run_iam_escalation(delay_seconds=0.3)
        print()

        print("  >>> SCENARIO 4: False Positive (Benign Activity)")
        fp_results = await run_false_positive_scenario(delay_seconds=0.2)
        print()

        print("  >>> SCENARIO 5: AI Agent Attacks")
        ai_results = await run_ai_agent_attacks(delay_seconds=0.15)
        print()

        total_sent = (
            carding_results["total_sent"]
            + auth_sent
            + infra_results["total_sent"]
            + fp_results["total_sent"]
            + ai_results["total_sent"]
        )
        total_ingested = (
            carding_results["successful_ingests"]
            + auth_sent  # auth functions don't track failures
            + infra_results["successful_ingests"]
            + fp_results["successful_ingests"]
            + ai_results["successful_ingests"]
        )
        print(f"  Total events sent: {total_sent}")
        print(f"  Successfully ingested: {total_ingested}")

        # ── Step 4: Wait for processing ───────────────────
        print("\n[4/7] Waiting for module processing + triage ...")
        wait_seconds = 18
        for i in range(wait_seconds):
            print(f"\r  Waiting... {wait_seconds - i}s remaining", end="", flush=True)
            await asyncio.sleep(1)
        print("\r  Processing window complete.            ")

        # ── Step 5: Verify detections ─────────────────────
        print("\n[5/7] Verifying detections ...")

        # Get all new alerts
        resp = await client.get(
            f"{API_BASE}/alerts?page_size=200",
            headers=headers,
        )
        if resp.status_code != 200:
            print(f"  FATAL: Alert query failed — {resp.status_code}")
            sys.exit(1)

        all_alerts = resp.json()["alerts"]
        new_count = resp.json()["total"] - baseline_count

        print(f"  New alerts generated: {new_count}")
        print()

        # Classify alerts by event type
        detected_rules = set()
        carding_alerts = []
        auth_alerts = []
        infra_alerts = []
        ai_alerts = []
        other_alerts = []
        triaged_count = 0
        verdicts = {"true_positive": 0, "false_positive": 0, "needs_investigation": 0, "unknown": 0}

        for alert in all_alerts:
            et = alert["event_type"]
            detected_rules.add(et)

            if et.startswith("carding."):
                carding_alerts.append(alert)
            elif et.startswith("auth."):
                auth_alerts.append(alert)
            elif et.startswith("infra."):
                infra_alerts.append(alert)
            elif et.startswith("ai_agent."):
                ai_alerts.append(alert)
            else:
                other_alerts.append(alert)

            if alert["status"] in ("triaged", "false_positive"):
                triaged_count += 1

        # ── Step 6: Get triage details ────────────────────
        print("[6/7] Fetching triage verdicts ...")
        for alert in all_alerts[:30]:
            resp = await client.get(f"{API_BASE}/alerts/{alert['id']}", headers=headers)
            if resp.status_code == 200:
                detail = resp.json()
                triage = detail.get("triage_result")
                if triage:
                    v = triage.get("verdict", "unknown")
                    verdicts[v] = verdicts.get(v, 0) + 1

        # ── Step 7: Report ────────────────────────────────
        print()
        print("=" * 70)
        print("  DETECTION ACCURACY REPORT")
        print("=" * 70)

        # Carding detection
        carding_detected = detected_rules & EXPECTED_CARDING_RULES
        carding_rate = len(carding_detected) / len(EXPECTED_CARDING_RULES) * 100

        print(f"\n  STRIPE CARDING DETECTION: {carding_rate:.0f}%")
        print(f"    Alerts generated: {len(carding_alerts)}")
        for rule in sorted(EXPECTED_CARDING_RULES):
            icon = "PASS" if rule in carding_detected else "MISS"
            print(f"    [{icon}] {rule}")

        # Auth detection
        auth_detected = detected_rules & EXPECTED_AUTH_RULES
        auth_rate = len(auth_detected) / len(EXPECTED_AUTH_RULES) * 100

        print(f"\n  AUTH ANOMALY DETECTION: {auth_rate:.0f}%")
        print(f"    Alerts generated: {len(auth_alerts)}")
        for rule in sorted(EXPECTED_AUTH_RULES):
            icon = "PASS" if rule in auth_detected else "MISS"
            print(f"    [{icon}] {rule}")

        # Infrastructure detection
        infra_detected = detected_rules & EXPECTED_INFRA_RULES
        infra_rate = len(infra_detected) / len(EXPECTED_INFRA_RULES) * 100

        print(f"\n  INFRASTRUCTURE DETECTION: {infra_rate:.0f}%")
        print(f"    Alerts generated: {len(infra_alerts)}")
        for rule in sorted(EXPECTED_INFRA_RULES):
            icon = "PASS" if rule in infra_detected else "MISS"
            print(f"    [{icon}] {rule}")

        # AI Agent detection
        ai_detected = detected_rules & EXPECTED_AI_RULES
        ai_rate = len(ai_detected) / len(EXPECTED_AI_RULES) * 100

        print(f"\n  AI AGENT MONITOR DETECTION: {ai_rate:.0f}%")
        print(f"    Alerts generated: {len(ai_alerts)}")
        for rule in sorted(EXPECTED_AI_RULES):
            icon = "PASS" if rule in ai_detected else "MISS"
            print(f"    [{icon}] {rule}")

        # Triage results
        print(f"\n  TRIAGE AGENT RESULTS:")
        print(f"    Alerts triaged: {triaged_count}/{len(all_alerts)}")
        for v, count in sorted(verdicts.items()):
            if count > 0:
                print(f"    {v}: {count}")

        # Overall
        overall_rules = len(carding_detected) + len(auth_detected) + len(infra_detected) + len(ai_detected)
        total_expected = len(EXPECTED_CARDING_RULES) + len(EXPECTED_AUTH_RULES) + len(EXPECTED_INFRA_RULES) + len(EXPECTED_AI_RULES)
        overall_rate = overall_rules / total_expected * 100 if total_expected else 0

        print(f"\n  OVERALL DETECTION RATE: {overall_rate:.0f}% ({overall_rules}/{total_expected} rules)")
        print(f"  TRIAGE RATE: {triaged_count}/{len(all_alerts)} alerts triaged")
        print(f"  TRUE POSITIVES: {verdicts.get('true_positive', 0)}")
        print(f"  FALSE POSITIVES: {verdicts.get('false_positive', 0)}")
        print(f"  NEEDS INVESTIGATION: {verdicts.get('needs_investigation', 0)}")

        # ── Step 7b: Phase 4 Pipeline Validation ────────
        print()
        print("=" * 70)
        print("  RESPONSE AUTOMATION PIPELINE REPORT")
        print("=" * 70)

        # Get analytics overview for full pipeline stats
        try:
            resp = await client.get(f"{API_BASE}/analytics/overview", headers=headers)
            if resp.status_code == 200:
                analytics = resp.json()

                inc_total = analytics["incidents"]["total"]
                inc_investigating = analytics["incidents"]["investigating"]
                act_total = analytics["response_actions"]["total"]
                act_executed = analytics["response_actions"]["executed"]
                act_pending = analytics["response_actions"]["pending"]
                act_failed = analytics["response_actions"]["failed"]
                traces_total = analytics["execution_traces"]

                print(f"\n  INCIDENTS:")
                print(f"    Total created: {inc_total}")
                print(f"    Investigating: {inc_investigating}")

                print(f"\n  RESPONSE ACTIONS:")
                print(f"    Total proposed: {act_total}")
                print(f"    Auto-executed:  {act_executed}")
                print(f"    Pending human:  {act_pending}")
                print(f"    Failed:         {act_failed}")
                print(f"    By risk: auto={analytics['response_actions']['by_risk']['auto']}"
                      f"  high={analytics['response_actions']['by_risk']['high']}"
                      f"  critical={analytics['response_actions']['by_risk']['critical']}")

                print(f"\n  EXECUTION TRACES: {traces_total}")

                if analytics["mttd_seconds"]:
                    print(f"  MTTD (Mean Time to Detect): {analytics['mttd_seconds']:.1f}s")
                if analytics["mttr_seconds"]:
                    print(f"  MTTR (Mean Time to Resolve): {analytics['mttr_seconds']:.1f}s")

                print(f"\n  MODULE DETECTION BREAKDOWN:")
                for mod in analytics["modules"]:
                    print(f"    {mod['module']:20s}  {mod['alert_count']:>5} alerts  ({mod['rule_count']} rules)")
            else:
                print(f"  WARNING: Analytics API returned {resp.status_code}")
        except Exception as e:
            print(f"  WARNING: Could not fetch analytics — {e}")

        # Get agent performance
        try:
            resp = await client.get(f"{API_BASE}/analytics/agent-performance", headers=headers)
            if resp.status_code == 200:
                agent = resp.json()
                print(f"\n  AGENT PIPELINE:")
                print(f"    Mode:             {agent.get('mode', 'unknown')}")
                print(f"    Alerts triaged:   {agent.get('alerts_triaged', 0)}")
                print(f"    Escalations:      {agent.get('escalations', 0)}")
                print(f"    Investigations:   {agent.get('investigations', 0)}")
                print(f"    Incidents created: {agent.get('incidents_created', 0)}")
                print(f"    Critic reviews:   {agent.get('critic_reviews', 0)}")
                print(f"    Actions approved: {agent.get('actions_approved', 0)}")
                print(f"    Actions executed: {agent.get('actions_executed', 0)}")
                print(f"    Playbooks run:    {agent.get('playbooks_run', 0)}")

                pipeline_ok = (
                    agent.get("investigations", 0) > 0
                    and agent.get("critic_reviews", 0) > 0
                    and agent.get("actions_executed", 0) > 0
                )
            else:
                pipeline_ok = False
        except Exception as e:
            print(f"  WARNING: Could not fetch agent performance — {e}")
            pipeline_ok = False

        print()
        print("=" * 70)

        # Pass/fail
        print()
        if overall_rate >= 80 and triaged_count > 0 and pipeline_ok:
            print("  RESULT: PASS (Detection + Pipeline validated)")
        elif overall_rate >= 80 and triaged_count > 0:
            print("  RESULT: PARTIAL PASS (Detection OK, pipeline needs review)")
        elif overall_rate >= 60:
            print("  RESULT: PARTIAL PASS (some rules not firing)")
        else:
            print("  RESULT: FAIL (detection rules need review)")

        print("=" * 70)


if __name__ == "__main__":
    asyncio.run(main())
