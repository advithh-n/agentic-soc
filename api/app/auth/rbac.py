"""Role-Based Access Control — permission checking."""

from enum import Enum
from functools import wraps

from fastapi import HTTPException, status


class Role(str, Enum):
    OWNER = "owner"
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"
    API_ONLY = "api_only"


# Permission matrix: role -> set of allowed actions
PERMISSIONS: dict[str, set[str]] = {
    Role.OWNER: {
        "view_dashboard", "view_alerts", "investigate", "approve_actions",
        "configure_modules", "manage_users", "manage_api_keys",
        "view_audit_log", "export_evidence", "manage_tenants",
    },
    Role.ADMIN: {
        "view_dashboard", "view_alerts", "investigate", "approve_actions",
        "configure_modules", "manage_users", "manage_api_keys",
        "view_audit_log", "export_evidence",
    },
    Role.ANALYST: {
        "view_dashboard", "view_alerts", "investigate",
        "approve_low_risk_actions", "view_audit_log", "export_evidence",
    },
    Role.VIEWER: {
        "view_dashboard", "view_alerts",
    },
    Role.API_ONLY: {
        "view_alerts", "export_evidence",
    },
}


def has_permission(role: str, permission: str) -> bool:
    """Check if a role has a specific permission."""
    role_perms = PERMISSIONS.get(role, set())

    # Analysts can approve low-risk actions
    if permission == "approve_actions" and "approve_low_risk_actions" in role_perms:
        return True  # Caller must also check risk level

    return permission in role_perms


def require_permission(permission: str):
    """Dependency factory — raises 403 if the current user lacks the permission."""

    def checker(current_user: dict):
        if not has_permission(current_user["role"], permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{current_user['role']}' lacks permission: {permission}",
            )
        return current_user

    return checker
