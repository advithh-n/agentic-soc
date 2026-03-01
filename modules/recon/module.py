"""Recon Detection Module — infrastructure scanning and drift detection.

Detects suspicious changes from infrastructure reconnaissance scans:
- port_change_detected: New open ports compared to baseline
- new_cve_found: Vulnerability with CVSS >= 7.0 found on an asset
- cert_expiry_warning: TLS certificate expiring within 30 days
- dns_drift: DNS record changed from expected value

Consumes events from `streams:recon` pushed by external scanners
or the built-in recon_scan simulator.
"""

from collections import defaultdict
from datetime import datetime, timedelta

import structlog

from engine.base_module import BaseModule
from engine.models import AlertModel, Artifact, ArtifactType, Severity, StreamEvent

logger = structlog.get_logger()

# Baseline port profiles (in production: loaded from DB or Neo4j)
_PORT_BASELINES: dict[str, set[int]] = defaultdict(lambda: set())

# DNS record baselines
_DNS_BASELINES: dict[str, str] = {}


class ReconModule(BaseModule):
    name = "recon"
    description = "Detects infrastructure drift from reconnaissance scans (ports, CVEs, certs, DNS)"
    streams = ["streams:recon"]

    async def process_event(self, event: StreamEvent) -> list[AlertModel]:
        """Route recon scan results to detection rules."""
        payload = event.raw_payload
        scan_type = payload.get("scan_type", "")
        alerts: list[AlertModel] = []

        if scan_type == "port_scan":
            alerts.extend(self._check_port_changes(event, payload))
        elif scan_type == "vuln_scan":
            alerts.extend(self._check_cve(event, payload))
        elif scan_type == "cert_check":
            alerts.extend(self._check_cert_expiry(event, payload))
        elif scan_type == "dns_check":
            alerts.extend(self._check_dns_drift(event, payload))
        else:
            # Try to detect scan type from payload structure
            if "open_ports" in payload:
                alerts.extend(self._check_port_changes(event, payload))
            if "cve_id" in payload or "vulnerabilities" in payload:
                alerts.extend(self._check_cve(event, payload))
            if "cert_expiry" in payload or "days_until_expiry" in payload:
                alerts.extend(self._check_cert_expiry(event, payload))
            if "dns_record" in payload:
                alerts.extend(self._check_dns_drift(event, payload))

        return alerts

    def _check_port_changes(self, event: StreamEvent, payload: dict) -> list[AlertModel]:
        """Rule 1: Port change detected — new open ports vs baseline."""
        alerts: list[AlertModel] = []
        host = payload.get("host", payload.get("target", "unknown"))
        open_ports = set(payload.get("open_ports", []))

        if not open_ports:
            return []

        baseline = _PORT_BASELINES[host]
        new_ports = open_ports - baseline if baseline else set()

        # Update baseline
        _PORT_BASELINES[host] = open_ports

        # If no baseline existed, record and skip (first scan)
        if not baseline:
            return []

        if not new_ports:
            return []

        # Critical if new ports include dangerous services
        dangerous_ports = {22, 23, 3389, 445, 3306, 5432, 6379, 27017}
        has_dangerous = bool(new_ports & dangerous_ports)
        severity = Severity.HIGH if has_dangerous else Severity.MEDIUM
        confidence = 0.85 if has_dangerous else 0.7

        alerts.append(AlertModel(
            tenant_id=event.tenant_id,
            source="recon_scanner",
            event_type="recon.port_change_detected",
            severity=severity,
            confidence=confidence,
            title=f"New ports detected on {host}: {', '.join(str(p) for p in sorted(new_ports))}",
            description=(
                f"Infrastructure scan detected {len(new_ports)} new open port(s) on '{host}' "
                f"compared to baseline. New ports: {sorted(new_ports)}. "
                f"Previous baseline: {sorted(baseline)}. "
                f"{'DANGEROUS PORTS EXPOSED. ' if has_dangerous else ''}"
                f"Verify these ports were intentionally opened."
            ),
            raw_payload=payload,
            artifacts=[
                Artifact(type=ArtifactType.IP, value=host, context="Scanned host"),
            ],
            mitre_technique="T1046",
            trace_id=event.trace_id,
        ))

        return alerts

    def _check_cve(self, event: StreamEvent, payload: dict) -> list[AlertModel]:
        """Rule 2: New CVE found with CVSS >= 7.0."""
        alerts: list[AlertModel] = []
        host = payload.get("host", payload.get("target", "unknown"))

        vulns = payload.get("vulnerabilities", [])
        if not vulns and payload.get("cve_id"):
            vulns = [payload]

        for vuln in vulns:
            cve_id = vuln.get("cve_id", "")
            cvss = vuln.get("cvss_score", vuln.get("cvss", 0))
            product = vuln.get("product", vuln.get("service", "unknown"))
            description = vuln.get("description", "")

            if cvss < 7.0:
                continue

            severity = Severity.CRITICAL if cvss >= 9.0 else Severity.HIGH
            confidence = min(0.5 + cvss * 0.05, 0.95)

            alerts.append(AlertModel(
                tenant_id=event.tenant_id,
                source="recon_scanner",
                event_type="recon.new_cve_found",
                severity=severity,
                confidence=confidence,
                title=f"{cve_id} (CVSS {cvss}) found on {host} ({product})",
                description=(
                    f"Vulnerability scan detected {cve_id} (CVSS {cvss}) on host '{host}'. "
                    f"Affected product: {product}. {description[:300]}"
                ),
                raw_payload=payload,
                artifacts=[
                    Artifact(type=ArtifactType.IP, value=host, context="Vulnerable host"),
                ],
                mitre_technique="T1190",
                trace_id=event.trace_id,
            ))

        return alerts

    def _check_cert_expiry(self, event: StreamEvent, payload: dict) -> list[AlertModel]:
        """Rule 3: TLS certificate expiring within 30 days."""
        alerts: list[AlertModel] = []
        host = payload.get("host", payload.get("domain", "unknown"))
        days = payload.get("days_until_expiry", 999)
        cert_cn = payload.get("cert_cn", payload.get("subject", host))

        if days > 30:
            return []

        severity = Severity.HIGH if days <= 7 else Severity.MEDIUM
        confidence = 0.95

        alerts.append(AlertModel(
            tenant_id=event.tenant_id,
            source="recon_scanner",
            event_type="recon.cert_expiry_warning",
            severity=severity,
            confidence=confidence,
            title=f"TLS certificate expires in {days} days: {cert_cn}",
            description=(
                f"TLS certificate for '{cert_cn}' on host '{host}' "
                f"expires in {days} day(s). "
                f"{'URGENT: Certificate expires within 7 days! ' if days <= 7 else ''}"
                f"Renew immediately to avoid service disruption."
            ),
            raw_payload=payload,
            artifacts=[
                Artifact(type=ArtifactType.DOMAIN, value=host, context="Certificate host"),
            ],
            mitre_technique="T1556",
            trace_id=event.trace_id,
        ))

        return alerts

    def _check_dns_drift(self, event: StreamEvent, payload: dict) -> list[AlertModel]:
        """Rule 4: DNS record mismatch from expected value."""
        alerts: list[AlertModel] = []
        domain = payload.get("domain", "unknown")
        record_type = payload.get("record_type", "A")
        current_value = payload.get("dns_record", payload.get("current_value", ""))
        expected_value = payload.get("expected_value", "")

        # Use baseline if no expected provided
        if not expected_value:
            key = f"{domain}:{record_type}"
            if key in _DNS_BASELINES:
                expected_value = _DNS_BASELINES[key]
            else:
                # Record first-seen baseline
                _DNS_BASELINES[key] = current_value
                return []

        if current_value == expected_value:
            return []

        # Update baseline to current
        _DNS_BASELINES[f"{domain}:{record_type}"] = current_value

        severity = Severity.HIGH
        confidence = 0.9

        alerts.append(AlertModel(
            tenant_id=event.tenant_id,
            source="recon_scanner",
            event_type="recon.dns_drift",
            severity=severity,
            confidence=confidence,
            title=f"DNS drift: {domain} {record_type} changed to {current_value}",
            description=(
                f"DNS record for '{domain}' ({record_type}) changed from "
                f"'{expected_value}' to '{current_value}'. "
                f"This could indicate DNS hijacking, misconfiguration, or "
                f"unauthorized infrastructure changes."
            ),
            raw_payload=payload,
            artifacts=[
                Artifact(type=ArtifactType.DOMAIN, value=domain, context="Domain with DNS drift"),
            ],
            mitre_technique="T1584.002",
            trace_id=event.trace_id,
        ))

        return alerts
