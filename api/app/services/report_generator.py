"""PDF Incident Report Generator — produces professional incident reports.

Uses fpdf2 to generate PDF reports with sections:
- Executive Summary
- Root Cause Analysis
- Timeline
- MITRE ATT&CK Mapping
- IOCs
- Blast Radius
- Response Actions
- Evidence Chain
"""

import io
import os
from datetime import datetime, timezone

import structlog
from fpdf import FPDF

logger = structlog.get_logger()


class IncidentReportPDF(FPDF):
    """Custom PDF class for SOC incident reports."""

    def __init__(self):
        super().__init__()
        self.set_auto_page_break(auto=True, margin=20)

    def header(self):
        self.set_font("Helvetica", "B", 10)
        self.set_text_color(100, 100, 100)
        self.cell(0, 8, "Agentic SOC — Incident Report", align="L")
        self.cell(0, 8, datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"), align="R", new_x="LMARGIN", new_y="NEXT")
        self.set_draw_color(200, 200, 200)
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(5)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(150, 150, 150)
        self.cell(0, 10, f"Page {self.page_no()}/{{nb}}", align="C")

    def section_title(self, title: str):
        self.set_font("Helvetica", "B", 13)
        self.set_text_color(30, 30, 30)
        self.ln(4)
        self.cell(0, 10, title, new_x="LMARGIN", new_y="NEXT")
        self.set_draw_color(60, 130, 200)
        self.set_line_width(0.5)
        self.line(10, self.get_y(), 80, self.get_y())
        self.ln(3)
        self.set_line_width(0.2)

    def key_value(self, key: str, value: str):
        self.set_font("Helvetica", "B", 9)
        self.set_text_color(80, 80, 80)
        self.cell(45, 6, key + ":", align="L")
        self.set_font("Helvetica", "", 9)
        self.set_text_color(30, 30, 30)
        self.multi_cell(0, 6, str(value)[:300])

    def body_text(self, text: str):
        self.set_font("Helvetica", "", 9)
        self.set_text_color(40, 40, 40)
        self.multi_cell(0, 5, str(text)[:2000])
        self.ln(2)


def generate_incident_pdf(report_data: dict) -> bytes:
    """Generate a PDF from the incident report JSON data.

    Returns the PDF as bytes.
    """
    pdf = IncidentReportPDF()
    pdf.alias_nb_pages()
    pdf.add_page()

    incident = report_data.get("incident", {})
    alerts = report_data.get("alerts", [])
    actions = report_data.get("response_actions", [])
    timeline = report_data.get("timeline", [])
    summary = report_data.get("summary", {})

    # --- Title ---
    pdf.set_font("Helvetica", "B", 18)
    pdf.set_text_color(20, 20, 20)
    pdf.cell(0, 12, "Incident Report", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 11)
    pdf.set_text_color(60, 60, 60)
    pdf.cell(0, 8, incident.get("title", "Untitled Incident"), new_x="LMARGIN", new_y="NEXT")
    pdf.ln(4)

    # --- Executive Summary ---
    pdf.section_title("1. Executive Summary")
    pdf.key_value("Incident ID", incident.get("id", "N/A"))
    pdf.key_value("Severity", incident.get("severity", "N/A").upper())
    pdf.key_value("Status", incident.get("status", "N/A"))
    pdf.key_value("Created", incident.get("created_at", "N/A"))
    pdf.key_value("Resolved", incident.get("resolved_at", "N/A") or "Ongoing")
    pdf.key_value("Alert Count", str(summary.get("alert_count", len(alerts))))
    pdf.key_value("Action Count", str(summary.get("action_count", len(actions))))
    pdf.key_value("Actions Executed", str(summary.get("actions_executed", 0)))
    pdf.key_value("Actions Pending", str(summary.get("actions_pending", 0)))

    if incident.get("description"):
        pdf.ln(2)
        pdf.body_text(incident["description"])

    # --- Root Cause Analysis ---
    pdf.section_title("2. Root Cause Analysis")
    root_cause = incident.get("root_cause", "Root cause analysis pending.")
    pdf.body_text(root_cause)

    # --- MITRE ATT&CK Mapping ---
    mitre_techniques = set()
    for alert in alerts:
        tech = alert.get("mitre_technique")
        if tech:
            mitre_techniques.add(tech)

    if mitre_techniques:
        pdf.section_title("3. MITRE ATT&CK Mapping")
        for tech in sorted(mitre_techniques):
            pdf.set_font("Helvetica", "B", 9)
            pdf.cell(0, 6, f"  {tech}", new_x="LMARGIN", new_y="NEXT")

    # --- Timeline ---
    if timeline:
        pdf.section_title("4. Timeline")
        for i, event in enumerate(timeline[:20]):
            ts = event.get("timestamp", "")[:19]
            desc = event.get("description", "")
            sev = event.get("severity", "info")
            prefix = f"[{ts}] [{sev.upper()}]"
            pdf.set_font("Helvetica", "B", 8)
            pdf.set_text_color(100, 100, 100)
            pdf.cell(0, 5, prefix, new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("Helvetica", "", 8)
            pdf.set_text_color(40, 40, 40)
            pdf.multi_cell(0, 4, desc[:200])
            pdf.ln(1)

    # --- IOCs ---
    # Extract from alerts' artifacts
    pdf.section_title("5. Indicators of Compromise (IOCs)")
    ioc_seen = set()
    for alert in alerts:
        source = alert.get("source", "")
        event_type = alert.get("event_type", "")
        pdf.set_font("Helvetica", "", 8)
        # We don't have direct IOC data in report_data, but note the alert sources
    if not alerts:
        pdf.body_text("No IOC data available in report.")
    else:
        unique_sources = summary.get("unique_sources", [])
        sev_dist = summary.get("severity_distribution", {})
        pdf.key_value("Unique Sources", ", ".join(unique_sources) if unique_sources else "N/A")
        pdf.key_value("Severity Distribution", str(sev_dist))

    # --- Blast Radius ---
    blast = incident.get("blast_radius")
    if blast:
        pdf.section_title("6. Blast Radius")
        affected_ips = blast.get("affected_ips", [])
        affected_users = blast.get("affected_users", [])
        affected_services = blast.get("affected_services", [])
        total = blast.get("total_entities", 0)

        pdf.key_value("Total Entities Affected", str(total))
        if affected_ips:
            ip_list = ", ".join(ip.get("value", str(ip)) if isinstance(ip, dict) else str(ip) for ip in affected_ips[:10])
            pdf.key_value("Affected IPs", ip_list)
        if affected_users:
            user_list = ", ".join(u.get("value", str(u)) if isinstance(u, dict) else str(u) for u in affected_users[:10])
            pdf.key_value("Affected Users", user_list)
        if affected_services:
            svc_list = ", ".join(s.get("value", str(s)) if isinstance(s, dict) else str(s) for s in affected_services[:10])
            pdf.key_value("Affected Services", svc_list)

    # --- Response Actions ---
    if actions:
        pdf.section_title("7. Response Actions")
        for action in actions[:20]:
            status_marker = {
                "executed": "[DONE]",
                "approved": "[APPROVED]",
                "pending": "[PENDING]",
                "denied": "[DENIED]",
                "failed": "[FAILED]",
            }.get(action.get("status", ""), "[?]")

            pdf.set_font("Helvetica", "B", 9)
            pdf.cell(0, 6,
                     f"  {status_marker} {action.get('action_type', 'unknown')} "
                     f"(risk: {action.get('risk_level', 'N/A')})",
                     new_x="LMARGIN", new_y="NEXT")
            if action.get("executed_at"):
                pdf.set_font("Helvetica", "", 8)
                pdf.set_text_color(100, 100, 100)
                pdf.cell(0, 5, f"    Executed: {action['executed_at']}", new_x="LMARGIN", new_y="NEXT")
                pdf.set_text_color(40, 40, 40)

    # --- Evidence Chain (Alerts) ---
    if alerts:
        pdf.section_title("8. Evidence Chain (Linked Alerts)")
        for alert in alerts[:15]:
            pdf.set_font("Helvetica", "B", 8)
            pdf.cell(0, 5,
                     f"  [{alert.get('severity', '').upper()}] {alert.get('title', 'N/A')[:80]}",
                     new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("Helvetica", "", 8)
            pdf.set_text_color(100, 100, 100)
            pdf.cell(0, 4,
                     f"    Type: {alert.get('event_type', '')} | "
                     f"Source: {alert.get('source', '')} | "
                     f"Status: {alert.get('status', '')} | "
                     f"Created: {alert.get('created_at', '')[:19]}",
                     new_x="LMARGIN", new_y="NEXT")
            pdf.set_text_color(40, 40, 40)
            pdf.ln(1)

    return pdf.output()


async def store_report_in_minio(pdf_bytes: bytes, incident_id: str) -> str:
    """Store the PDF report in MinIO and return the object path."""
    try:
        from minio import Minio

        endpoint = os.getenv("MINIO_ENDPOINT", "minio:9000")
        access_key = os.getenv("MINIO_ACCESS_KEY", "")
        secret_key = os.getenv("MINIO_SECRET_KEY", "")

        client = Minio(endpoint, access_key=access_key, secret_key=secret_key, secure=False)

        bucket = "reports"
        if not client.bucket_exists(bucket):
            client.make_bucket(bucket)

        object_name = f"incidents/{incident_id}/report_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.pdf"
        client.put_object(
            bucket,
            object_name,
            io.BytesIO(pdf_bytes),
            length=len(pdf_bytes),
            content_type="application/pdf",
        )

        logger.info("report.stored_minio", object_name=object_name)
        return f"{bucket}/{object_name}"
    except Exception as e:
        logger.warning("report.minio_store_failed", error=str(e))
        return ""
