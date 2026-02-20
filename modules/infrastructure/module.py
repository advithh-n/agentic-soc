"""Infrastructure Alert Detection Module.

Detects suspicious infrastructure events from AWS CloudTrail and Wazuh:
- IAM privilege escalation: CreateUser + AttachUserPolicy + CreateAccessKey by non-admin
- Unauthorized S3 access: GetObject/PutObject on sensitive buckets from unusual roles
- Security group changes: Opening 0.0.0.0/0 ingress or creating wide-open groups
- File integrity violation: Wazuh syscheck alerts on critical files (level >= 10)
- Web attack patterns: SQLi, XSS, path traversal from Wazuh or Traefik logs
"""

from collections import defaultdict
from datetime import datetime, timedelta

import structlog

from engine.base_module import BaseModule
from engine.models import AlertModel, Artifact, ArtifactType, Severity, StreamEvent

logger = structlog.get_logger()

# Sliding window state (in-memory; move to Redis TimeSeries for production)
_iam_actions: dict[str, list[dict]] = defaultdict(list)
_WINDOW_SECONDS = 600  # 10 minutes for IAM escalation correlation

# Sensitive S3 bucket keywords
_SENSITIVE_BUCKET_KEYWORDS = {
    "secret", "credential", "backup", "config", "key", "private",
    "password", "token", "cert", "pii", "financial", "compliance",
}

# Known admin IAM users/roles (in production: pull from Neo4j)
_ADMIN_PRINCIPALS = {
    "root", "admin", "Administrator", "soc-admin", "SecurityAudit",
}

# IAM escalation action sequence
_IAM_ESCALATION_ACTIONS = {
    "CreateUser", "AttachUserPolicy", "PutUserPolicy",
    "AttachRolePolicy", "PutRolePolicy", "CreateAccessKey",
    "CreateLoginProfile", "AddUserToGroup",
}

# Dangerous admin policies
_DANGEROUS_POLICIES = {
    "AdministratorAccess", "IAMFullAccess", "PowerUserAccess",
    "arn:aws:iam::aws:policy/AdministratorAccess",
    "arn:aws:iam::aws:policy/IAMFullAccess",
}

# Web attack patterns (simple string matching; production: use regex or WAF rules)
_SQLI_PATTERNS = [
    "' OR ", "' AND ", "UNION SELECT", "1=1", "DROP TABLE",
    "'; --", "\" OR ", "WAITFOR DELAY", "BENCHMARK(",
]
_XSS_PATTERNS = [
    "<script>", "javascript:", "onerror=", "onload=", "eval(",
    "<img src=", "<svg onload", "document.cookie",
]
_PATH_TRAVERSAL_PATTERNS = [
    "../", "..\\", "%2e%2e", "/etc/passwd", "/etc/shadow",
    "..%2f", "..%5c",
]


def _prune_iam(user: str):
    cutoff = datetime.utcnow() - timedelta(seconds=_WINDOW_SECONDS)
    _iam_actions[user] = [e for e in _iam_actions[user] if e["time"] > cutoff]


class InfrastructureModule(BaseModule):
    name = "infrastructure"
    description = "Detects infrastructure anomalies (AWS CloudTrail, Wazuh, security group changes)"
    streams = ["streams:infra"]

    async def process_event(self, event: StreamEvent) -> list[AlertModel]:
        """Analyze infrastructure events for security threats."""
        payload = event.raw_payload
        source = event.source or payload.get("source", "")

        if source == "aws":
            return self._process_aws_event(event, payload)
        elif source == "wazuh":
            return self._process_wazuh_event(event, payload)
        else:
            # Try to auto-detect based on payload structure
            if "eventName" in payload or "userIdentity" in payload:
                return self._process_aws_event(event, payload)
            elif "rule" in payload and "agent" in payload:
                return self._process_wazuh_event(event, payload)

        return []

    # ──────────────────────────────────────────────────────────────
    # AWS CloudTrail Event Processing
    # ──────────────────────────────────────────────────────────────

    def _extract_aws_fields(self, payload: dict) -> dict:
        """Extract normalized fields from CloudTrail event JSON."""
        user_identity = payload.get("userIdentity", {})
        return {
            "event_name": payload.get("eventName", ""),
            "event_source": payload.get("eventSource", ""),
            "source_ip": payload.get("sourceIPAddress", "unknown"),
            "user_agent": payload.get("userAgent", ""),
            "principal_id": user_identity.get("principalId", ""),
            "arn": user_identity.get("arn", ""),
            "account_id": user_identity.get("accountId", ""),
            "user_type": user_identity.get("type", ""),
            "user_name": (
                user_identity.get("userName", "")
                or user_identity.get("sessionContext", {})
                .get("sessionIssuer", {}).get("userName", "")
                or "unknown"
            ),
            "request_params": payload.get("requestParameters", {}),
            "response_elements": payload.get("responseElements", {}),
            "error_code": payload.get("errorCode"),
            "error_message": payload.get("errorMessage"),
            "aws_region": payload.get("awsRegion", ""),
        }

    def _process_aws_event(self, event: StreamEvent, payload: dict) -> list[AlertModel]:
        """Route AWS CloudTrail events to detection rules."""
        fields = self._extract_aws_fields(payload)
        event_name = fields["event_name"]
        alerts: list[AlertModel] = []

        # Rule 1: IAM privilege escalation
        if event_name in _IAM_ESCALATION_ACTIONS:
            alerts.extend(self._check_iam_escalation(event, payload, fields))

        # Rule 2: Unauthorized S3 access
        if event_name in ("GetObject", "PutObject", "DeleteObject",
                          "ListBuckets", "GetBucketPolicy", "PutBucketPolicy",
                          "PutBucketAcl", "DeleteBucket"):
            alerts.extend(self._check_s3_access(event, payload, fields))

        # Rule 3: Security group changes
        if event_name in ("AuthorizeSecurityGroupIngress",
                          "AuthorizeSecurityGroupEgress",
                          "CreateSecurityGroup",
                          "RevokeSecurityGroupIngress",
                          "ModifySecurityGroupRules"):
            alerts.extend(self._check_security_group(event, payload, fields))

        return alerts

    def _check_iam_escalation(self, event: StreamEvent, payload: dict,
                               fields: dict) -> list[AlertModel]:
        """Rule 1: IAM privilege escalation — CreateUser + AttachUserPolicy + CreateAccessKey."""
        user = fields["user_name"]
        now = datetime.utcnow()
        alerts: list[AlertModel] = []

        # Skip if action was performed by known admin
        if user in _ADMIN_PRINCIPALS:
            return []

        # Record IAM action in sliding window
        _iam_actions[user].append({
            "time": now,
            "action": fields["event_name"],
            "target": (
                fields["request_params"].get("userName", "")
                or fields["request_params"].get("roleName", "")
                or ""
            ),
            "policy": (
                fields["request_params"].get("policyArn", "")
                or fields["request_params"].get("policyName", "")
                or ""
            ),
        })
        _prune_iam(user)

        window = _iam_actions[user]
        actions_in_window = {e["action"] for e in window}

        # Detect escalation sequence: user creation + policy attachment
        has_create = actions_in_window & {"CreateUser", "CreateLoginProfile"}
        has_policy = actions_in_window & {"AttachUserPolicy", "PutUserPolicy",
                                          "AttachRolePolicy", "PutRolePolicy"}
        has_creds = actions_in_window & {"CreateAccessKey", "CreateLoginProfile"}

        escalation_score = len(has_create) + len(has_policy) + len(has_creds)

        if escalation_score >= 2:
            # Check if dangerous policy was attached
            policies_used = {e["policy"] for e in window if e["policy"]}
            dangerous = policies_used & _DANGEROUS_POLICIES
            severity = Severity.CRITICAL if dangerous else Severity.HIGH
            confidence = min(0.6 + escalation_score * 0.1, 0.95)

            targets = {e["target"] for e in window if e["target"]}
            actions_list = sorted(actions_in_window & _IAM_ESCALATION_ACTIONS)

            alerts.append(AlertModel(
                tenant_id=event.tenant_id,
                source="aws",
                event_type="infra.iam_escalation",
                severity=severity,
                confidence=confidence,
                title=f"IAM escalation: {user} performed {', '.join(actions_list)} in 10min",
                description=(
                    f"IAM user '{user}' performed {len(actions_list)} privileged "
                    f"IAM actions in the last 10 minutes: {', '.join(actions_list)}. "
                    f"Target entities: {', '.join(targets) or 'unknown'}. "
                    f"{'DANGEROUS POLICIES attached: ' + ', '.join(dangerous) + '. ' if dangerous else ''}"
                    f"This pattern is consistent with IAM privilege escalation."
                ),
                raw_payload=payload,
                artifacts=[
                    Artifact(type=ArtifactType.IP, value=fields["source_ip"],
                             context="Source IP"),
                    Artifact(type=ArtifactType.USER_ID, value=user,
                             context="IAM user performing escalation"),
                    *[Artifact(type=ArtifactType.USER_ID, value=t,
                               context="Target entity")
                      for t in list(targets)[:3]],
                ],
                mitre_technique="T1078.004",
                trace_id=event.trace_id,
            ))

        return alerts

    def _check_s3_access(self, event: StreamEvent, payload: dict,
                          fields: dict) -> list[AlertModel]:
        """Rule 2: Unauthorized S3 access — sensitive bucket access from unusual roles."""
        alerts: list[AlertModel] = []
        params = fields["request_params"]
        bucket = params.get("bucketName", "")
        key = params.get("key", "")
        event_name = fields["event_name"]

        # Check if accessing a sensitive bucket
        is_sensitive = any(kw in bucket.lower() for kw in _SENSITIVE_BUCKET_KEYWORDS)

        # Public access modification is always suspicious
        is_public_access = False
        if event_name in ("PutBucketPolicy", "PutBucketAcl"):
            policy_str = str(params)
            if '"*"' in policy_str or "'*'" in policy_str or "public" in policy_str.lower():
                is_public_access = True

        if not is_sensitive and not is_public_access:
            return []

        if is_public_access:
            severity = Severity.HIGH
            confidence = 0.85
            title = f"S3 bucket public access: {event_name} on {bucket}"
            description = (
                f"User '{fields['user_name']}' modified access policy on bucket "
                f"'{bucket}' to allow public access. Event: {event_name}. "
                f"Source IP: {fields['source_ip']}. This may expose sensitive data."
            )
        else:
            severity = Severity.MEDIUM if event_name in ("GetObject", "ListBuckets") else Severity.HIGH
            confidence = 0.7
            title = f"Sensitive S3 access: {event_name} on {bucket}/{key}"
            description = (
                f"User '{fields['user_name']}' accessed sensitive bucket '{bucket}' "
                f"(key: '{key or 'N/A'}'). Event: {event_name}. "
                f"Source IP: {fields['source_ip']}. Verify this access was authorized."
            )

        alerts.append(AlertModel(
            tenant_id=event.tenant_id,
            source="aws",
            event_type="infra.s3_unauthorized",
            severity=severity,
            confidence=confidence,
            title=title,
            description=description,
            raw_payload=payload,
            artifacts=[
                Artifact(type=ArtifactType.IP, value=fields["source_ip"],
                         context="Source IP"),
                Artifact(type=ArtifactType.USER_ID, value=fields["user_name"],
                         context="IAM user"),
            ],
            mitre_technique="T1530",
            trace_id=event.trace_id,
        ))

        return alerts

    def _check_security_group(self, event: StreamEvent, payload: dict,
                                fields: dict) -> list[AlertModel]:
        """Rule 3: Security group changes — opening 0.0.0.0/0 or wide-open rules."""
        alerts: list[AlertModel] = []
        params = fields["request_params"]
        event_name = fields["event_name"]

        # Check for wide-open ingress rules
        is_wide_open = False
        opened_ports = []

        # AuthorizeSecurityGroupIngress has ipPermissions
        ip_permissions = params.get("ipPermissions", {})
        if isinstance(ip_permissions, dict):
            ip_permissions = ip_permissions.get("items", [])
        elif isinstance(ip_permissions, list):
            pass
        else:
            ip_permissions = []

        for perm in ip_permissions:
            ip_ranges = perm.get("ipRanges", {})
            if isinstance(ip_ranges, dict):
                ip_ranges = ip_ranges.get("items", [])
            elif isinstance(ip_ranges, list):
                pass
            else:
                ip_ranges = []

            for ip_range in ip_ranges:
                cidr = ip_range.get("cidrIp", "")
                if cidr in ("0.0.0.0/0", "::/0"):
                    is_wide_open = True
                    from_port = perm.get("fromPort", "any")
                    to_port = perm.get("toPort", "any")
                    opened_ports.append(f"{from_port}-{to_port}")

        # Also check flat structure (simulator format)
        if not is_wide_open:
            cidr = params.get("cidrIp", "")
            if cidr in ("0.0.0.0/0", "::/0"):
                is_wide_open = True
                from_port = params.get("fromPort", "any")
                to_port = params.get("toPort", "any")
                opened_ports.append(f"{from_port}-{to_port}")

        if not is_wide_open and event_name != "CreateSecurityGroup":
            return []

        group_id = params.get("groupId", params.get("groupName", "unknown"))

        if is_wide_open:
            # Critical if opening SSH (22), RDP (3389), or all ports
            critical_ports = {"22", "3389", "any"}
            is_critical = any(
                p.split("-")[0] in critical_ports for p in opened_ports
            )
            severity = Severity.CRITICAL if is_critical else Severity.HIGH
            confidence = 0.9

            title = (
                f"Security group opened to internet: {group_id} "
                f"ports {', '.join(opened_ports)}"
            )
            description = (
                f"User '{fields['user_name']}' modified security group '{group_id}' "
                f"to allow ingress from 0.0.0.0/0 on ports {', '.join(opened_ports)}. "
                f"Event: {event_name}. Source IP: {fields['source_ip']}. "
                f"This exposes resources directly to the internet."
            )
        else:
            severity = Severity.MEDIUM
            confidence = 0.5
            title = f"New security group created: {group_id}"
            description = (
                f"User '{fields['user_name']}' created security group '{group_id}'. "
                f"Event: {event_name}. Source IP: {fields['source_ip']}. "
                f"Review the group rules for overly permissive access."
            )

        alerts.append(AlertModel(
            tenant_id=event.tenant_id,
            source="aws",
            event_type="infra.security_group_change",
            severity=severity,
            confidence=confidence,
            title=title,
            description=description,
            raw_payload=payload,
            artifacts=[
                Artifact(type=ArtifactType.IP, value=fields["source_ip"],
                         context="Source IP"),
                Artifact(type=ArtifactType.USER_ID, value=fields["user_name"],
                         context="IAM user"),
            ],
            mitre_technique="T1562.007",
            trace_id=event.trace_id,
        ))

        return alerts

    # ──────────────────────────────────────────────────────────────
    # Wazuh Event Processing
    # ──────────────────────────────────────────────────────────────

    def _process_wazuh_event(self, event: StreamEvent, payload: dict) -> list[AlertModel]:
        """Route Wazuh events to detection rules."""
        rule = payload.get("rule", {})
        rule_id = str(rule.get("id", ""))
        rule_level = rule.get("level", 0)
        alerts: list[AlertModel] = []

        # Rule 4: File integrity violation — syscheck alerts level >= 10
        syscheck = payload.get("syscheck", {})
        if syscheck or rule_id.startswith("55"):  # Wazuh syscheck rule IDs 550-559
            integrity_alert = self._check_file_integrity(event, payload, rule, syscheck)
            if integrity_alert:
                alerts.extend(integrity_alert)

        # Rule 5: Web attack patterns
        web_alert = self._check_web_attacks(event, payload, rule)
        if web_alert:
            alerts.extend(web_alert)

        return alerts

    def _check_file_integrity(self, event: StreamEvent, payload: dict,
                                rule: dict, syscheck: dict) -> list[AlertModel]:
        """Rule 4: File integrity violation — Wazuh syscheck on critical files."""
        rule_level = rule.get("level", 0)
        if rule_level < 10 and not syscheck:
            return []

        alerts: list[AlertModel] = []
        changed_file = syscheck.get("path", "")
        change_type = syscheck.get("event", "modified")  # added, modified, deleted
        agent_name = payload.get("agent", {}).get("name", "unknown")
        agent_ip = payload.get("agent", {}).get("ip", "unknown")

        # Critical system files
        critical_paths = [
            "/etc/passwd", "/etc/shadow", "/etc/sudoers",
            "/etc/ssh/sshd_config", "/etc/pam.d/",
            "/root/.ssh/authorized_keys", "/boot/",
            "/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/",
        ]
        is_critical = any(changed_file.startswith(p) for p in critical_paths)

        if not is_critical and rule_level < 10:
            return []

        severity = Severity.CRITICAL if is_critical else Severity.HIGH
        confidence = min(0.5 + rule_level * 0.04, 0.95)

        alerts.append(AlertModel(
            tenant_id=event.tenant_id,
            source="wazuh",
            event_type="infra.file_integrity",
            severity=severity,
            confidence=confidence,
            title=f"File integrity: {change_type} {changed_file} on {agent_name}",
            description=(
                f"Wazuh syscheck detected {change_type} on '{changed_file}' "
                f"on agent '{agent_name}' ({agent_ip}). "
                f"Rule: {rule.get('description', 'N/A')} (level {rule_level}). "
                f"{'CRITICAL SYSTEM FILE — immediate investigation required.' if is_critical else 'Review for unauthorized changes.'}"
            ),
            raw_payload=payload,
            artifacts=[
                Artifact(type=ArtifactType.IP, value=agent_ip,
                         context=f"Agent: {agent_name}"),
            ],
            mitre_technique="T1565.001",
            trace_id=event.trace_id,
        ))

        return alerts

    def _check_web_attacks(self, event: StreamEvent, payload: dict,
                            rule: dict) -> list[AlertModel]:
        """Rule 5: Web attack patterns — SQLi, XSS, path traversal."""
        rule_desc = rule.get("description", "").lower()
        rule_groups = rule.get("groups", [])
        full_log = payload.get("full_log", "")
        data = payload.get("data", {})
        url = data.get("url", "") or data.get("uri", "") or ""
        src_ip = (
            data.get("srcip", "")
            or data.get("src_ip", "")
            or payload.get("agent", {}).get("ip", "unknown")
        )

        # Check Wazuh web attack rule groups
        web_groups = {"web", "attack", "sqli", "xss", "web_scan", "web-attacks"}
        is_web_rule = bool(set(rule_groups) & web_groups)

        # Check for attack patterns in URL or log
        check_text = (url + " " + full_log).upper()
        attack_type = None

        for pattern in _SQLI_PATTERNS:
            if pattern.upper() in check_text:
                attack_type = "SQL Injection"
                break

        if not attack_type:
            for pattern in _XSS_PATTERNS:
                if pattern.upper() in check_text:
                    attack_type = "Cross-Site Scripting (XSS)"
                    break

        if not attack_type:
            for pattern in _PATH_TRAVERSAL_PATTERNS:
                if pattern.upper() in check_text:
                    attack_type = "Path Traversal"
                    break

        # Also trigger on Wazuh's own web attack classifications
        if not attack_type and is_web_rule:
            if "sqli" in rule_desc or "sql injection" in rule_desc:
                attack_type = "SQL Injection"
            elif "xss" in rule_desc or "cross-site" in rule_desc:
                attack_type = "Cross-Site Scripting (XSS)"
            elif "traversal" in rule_desc or "directory" in rule_desc:
                attack_type = "Path Traversal"
            elif "scan" in rule_desc or "nikto" in rule_desc:
                attack_type = "Web Scanner"
            else:
                attack_type = "Web Attack"

        if not attack_type:
            return []

        rule_level = rule.get("level", 5)
        severity = Severity.HIGH if rule_level >= 10 else Severity.MEDIUM
        confidence = min(0.5 + rule_level * 0.04, 0.9)

        return [AlertModel(
            tenant_id=event.tenant_id,
            source="wazuh",
            event_type="infra.web_attack",
            severity=severity,
            confidence=confidence,
            title=f"{attack_type} detected from {src_ip}",
            description=(
                f"Wazuh detected a {attack_type} attempt from {src_ip}. "
                f"URL: {url or 'N/A'}. "
                f"Rule: {rule.get('description', 'N/A')} (ID {rule.get('id', 'N/A')}, "
                f"level {rule_level}). "
                f"Groups: {', '.join(rule_groups) if rule_groups else 'N/A'}."
            ),
            raw_payload=payload,
            artifacts=[
                Artifact(type=ArtifactType.IP, value=src_ip,
                         context="Attacker IP"),
                *([Artifact(type=ArtifactType.URL, value=url,
                            context="Target URL")] if url else []),
            ],
            mitre_technique="T1190",
            trace_id=event.trace_id,
        )]
