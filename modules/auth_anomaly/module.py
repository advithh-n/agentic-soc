"""Authentication Anomaly Detection Module.

Detects suspicious authentication patterns:
- Brute force login: >5 failed logins from same IP in 5 minutes
- Credential stuffing: >3 different usernames from same IP in 5 minutes
- Impossible travel: same user from distant IPs within impossible timeframe
- Privilege escalation: role/permission changes on sensitive accounts
- Session anomaly: concurrent sessions from multiple distinct IPs
"""

from collections import defaultdict
from datetime import datetime, timedelta

import structlog

from engine.base_module import BaseModule
from engine.models import AlertModel, Artifact, ArtifactType, Severity, StreamEvent

logger = structlog.get_logger()

# Sliding window state (in-memory; move to Redis for persistence in production)
_ip_logins: dict[str, list[dict]] = defaultdict(list)
_user_logins: dict[str, list[dict]] = defaultdict(list)
_WINDOW_SECONDS = 300  # 5 minutes


def _prune_ip(ip: str):
    cutoff = datetime.utcnow() - timedelta(seconds=_WINDOW_SECONDS)
    _ip_logins[ip] = [e for e in _ip_logins[ip] if e["time"] > cutoff]


def _prune_user(user: str):
    cutoff = datetime.utcnow() - timedelta(seconds=_WINDOW_SECONDS)
    _user_logins[user] = [e for e in _user_logins[user] if e["time"] > cutoff]


class AuthAnomalyModule(BaseModule):
    name = "auth_anomaly"
    description = "Detects suspicious authentication patterns (brute force, credential stuffing, impossible travel)"
    streams = ["streams:auth"]

    async def process_event(self, event: StreamEvent) -> list[AlertModel]:
        """Analyze auth events for anomalous patterns."""
        payload = event.raw_payload
        event_type = payload.get("type", event.event_type)

        # Route to appropriate handler
        if event_type in ("session.created", "user.signed_in", "login.succeeded", "login.failed"):
            return self._check_login(event, payload)
        elif event_type in ("user.updated", "role.changed", "permission.changed"):
            return self._check_privilege_change(event, payload)
        elif event_type in ("session.revoked", "session.ended"):
            return []  # Informational only

        return []

    def _extract_login_fields(self, payload: dict) -> dict:
        """Extract normalized fields from various auth provider payloads."""
        data = payload.get("data", {})
        # Support Clerk, generic, and custom auth webhook formats
        user_obj = data.get("object", data)

        return {
            "user_id": (user_obj.get("user_id")
                       or user_obj.get("id")
                       or data.get("user_id")
                       or "unknown"),
            "email": (user_obj.get("email_address")
                     or user_obj.get("email")
                     or data.get("email")
                     or "unknown"),
            "ip": (user_obj.get("client_ip")
                  or data.get("ip_address")
                  or payload.get("ip_address")
                  or "unknown"),
            "user_agent": (user_obj.get("user_agent")
                          or data.get("user_agent")
                          or ""),
            "country": (user_obj.get("country")
                       or data.get("country")
                       or ""),
            "city": (user_obj.get("city")
                    or data.get("city")
                    or ""),
            "success": payload.get("type", "") not in ("login.failed",),
        }

    def _check_login(self, event: StreamEvent, payload: dict) -> list[AlertModel]:
        """Check login events for brute force, credential stuffing, and impossible travel."""
        fields = self._extract_login_fields(payload)
        ip = fields["ip"]
        email = fields["email"]
        now = datetime.utcnow()
        alerts: list[AlertModel] = []

        if ip == "unknown":
            return []

        # Record in IP window
        _ip_logins[ip].append({
            "time": now,
            "email": email,
            "user_id": fields["user_id"],
            "success": fields["success"],
            "country": fields["country"],
            "city": fields["city"],
        })
        _prune_ip(ip)

        # Record in user window
        if email != "unknown":
            _user_logins[email].append({
                "time": now,
                "ip": ip,
                "success": fields["success"],
                "country": fields["country"],
                "city": fields["city"],
            })
            _prune_user(email)

        ip_window = _ip_logins[ip]

        # ── Rule 1: Brute force — many failed logins from same IP ──
        failed_logins = [e for e in ip_window if not e["success"]]
        if len(failed_logins) >= 5:
            alerts.append(AlertModel(
                tenant_id=event.tenant_id,
                source="auth",
                event_type="auth.brute_force",
                severity=Severity.HIGH if len(failed_logins) >= 10 else Severity.MEDIUM,
                confidence=min(0.6 + len(failed_logins) * 0.04, 0.95),
                title=f"Brute force: {len(failed_logins)} failed logins from {ip} in 5min",
                description=(
                    f"IP {ip} has {len(failed_logins)} failed login attempts in the last "
                    f"5 minutes targeting {len(set(e['email'] for e in failed_logins))} "
                    f"account(s). This is consistent with a brute force attack."
                ),
                raw_payload=payload,
                artifacts=[
                    Artifact(type=ArtifactType.IP, value=ip, context="Source IP"),
                    Artifact(type=ArtifactType.EMAIL, value=email, context="Target account"),
                ],
                mitre_technique="T1110.001",
                trace_id=event.trace_id,
            ))

        # ── Rule 2: Credential stuffing — many different users from same IP ──
        unique_users = set(e["email"] for e in ip_window if e["email"] != "unknown")
        if len(unique_users) >= 3:
            fail_rate = len(failed_logins) / len(ip_window) if ip_window else 0
            alerts.append(AlertModel(
                tenant_id=event.tenant_id,
                source="auth",
                event_type="auth.credential_stuffing",
                severity=Severity.HIGH,
                confidence=min(0.5 + len(unique_users) * 0.1, 0.95),
                title=f"Credential stuffing: {len(unique_users)} accounts from {ip} in 5min",
                description=(
                    f"IP {ip} has attempted login to {len(unique_users)} different accounts "
                    f"in the last 5 minutes with a {fail_rate*100:.0f}% failure rate. "
                    f"This is consistent with credential stuffing."
                ),
                raw_payload=payload,
                artifacts=[
                    Artifact(type=ArtifactType.IP, value=ip, context="Source IP"),
                    *[Artifact(type=ArtifactType.EMAIL, value=u, context="Target account")
                      for u in list(unique_users)[:5]],
                ],
                mitre_technique="T1110.004",
                trace_id=event.trace_id,
            ))

        # ── Rule 3: Impossible travel — same user from distant locations ──
        if email != "unknown" and len(_user_logins[email]) >= 2:
            user_window = _user_logins[email]
            unique_countries = set(e["country"] for e in user_window if e["country"])
            unique_ips = set(e["ip"] for e in user_window)

            if len(unique_countries) >= 2 and len(unique_ips) >= 2:
                # Two different countries within 5 minutes = impossible travel
                countries_str = ", ".join(sorted(unique_countries))
                alerts.append(AlertModel(
                    tenant_id=event.tenant_id,
                    source="auth",
                    event_type="auth.impossible_travel",
                    severity=Severity.HIGH,
                    confidence=0.85,
                    title=f"Impossible travel: {email} from {countries_str} in 5min",
                    description=(
                        f"User {email} logged in from {len(unique_countries)} different "
                        f"countries ({countries_str}) within 5 minutes using "
                        f"{len(unique_ips)} different IPs. This indicates compromised "
                        f"credentials or session hijacking."
                    ),
                    raw_payload=payload,
                    artifacts=[
                        Artifact(type=ArtifactType.EMAIL, value=email, context="Compromised account"),
                        *[Artifact(type=ArtifactType.IP, value=uip, context=f"Login IP")
                          for uip in list(unique_ips)[:5]],
                    ],
                    mitre_technique="T1078",
                    trace_id=event.trace_id,
                ))

        # ── Rule 4: Session anomaly — concurrent sessions from multiple IPs ──
        if email != "unknown":
            user_window = _user_logins[email]
            successful = [e for e in user_window if e["success"]]
            unique_success_ips = set(e["ip"] for e in successful)

            if len(unique_success_ips) >= 3:
                alerts.append(AlertModel(
                    tenant_id=event.tenant_id,
                    source="auth",
                    event_type="auth.session_anomaly",
                    severity=Severity.MEDIUM,
                    confidence=0.7,
                    title=f"Session anomaly: {email} active from {len(unique_success_ips)} IPs",
                    description=(
                        f"User {email} has successful logins from "
                        f"{len(unique_success_ips)} different IPs within 5 minutes. "
                        f"This may indicate shared credentials or session tokens being "
                        f"reused across multiple locations."
                    ),
                    raw_payload=payload,
                    artifacts=[
                        Artifact(type=ArtifactType.EMAIL, value=email, context="Account"),
                        *[Artifact(type=ArtifactType.IP, value=uip, context="Session IP")
                          for uip in list(unique_success_ips)[:5]],
                    ],
                    mitre_technique="T1078",
                    trace_id=event.trace_id,
                ))

        return alerts

    def _check_privilege_change(self, event: StreamEvent, payload: dict) -> list[AlertModel]:
        """Check for suspicious privilege escalation."""
        data = payload.get("data", {})
        user_obj = data.get("object", data)
        target_user = user_obj.get("email", user_obj.get("id", "unknown"))
        new_role = user_obj.get("new_role", user_obj.get("role", "unknown"))
        old_role = user_obj.get("old_role", user_obj.get("previous_role", "unknown"))
        changed_by = payload.get("actor", {}).get("email", "system")

        privileged_roles = {"owner", "admin", "superadmin", "root"}
        is_escalation = new_role.lower() in privileged_roles and old_role.lower() not in privileged_roles

        if not is_escalation:
            return []

        return [AlertModel(
            tenant_id=event.tenant_id,
            source="auth",
            event_type="auth.privilege_escalation",
            severity=Severity.HIGH,
            confidence=0.75,
            title=f"Privilege escalation: {target_user} → {new_role}",
            description=(
                f"User {target_user} was elevated from '{old_role}' to '{new_role}' "
                f"by {changed_by}. Verify this change was authorized."
            ),
            raw_payload=payload,
            artifacts=[
                Artifact(type=ArtifactType.EMAIL, value=target_user, context="Escalated user"),
            ],
            mitre_technique="T1078.004",
            trace_id=event.trace_id,
        )]
