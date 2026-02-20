"""Hash-chained immutable audit log service."""

import hashlib
import json
from datetime import datetime
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.services.redis_service import UUIDEncoder


async def write_audit_log(
    db: AsyncSession,
    tenant_id: UUID,
    actor_type: str,
    actor_id: str,
    action: str,
    resource_type: str,
    resource_id: str,
    details: dict | None = None,
    ip_address: str | None = None,
) -> int:
    """Write a hash-chained audit log entry.

    Each row's hash is computed from:
        SHA-256(tenant_id + timestamp + actor_type + actor_id + action + previous_hash)

    This creates a tamper-evident chain — any modification breaks the chain.
    """
    now = datetime.utcnow()

    # Get previous hash (or genesis hash for first entry)
    result = await db.execute(
        text("SELECT row_hash FROM audit_log WHERE tenant_id = :tid ORDER BY id DESC LIMIT 1"),
        {"tid": str(tenant_id)},
    )
    row = result.fetchone()
    previous_hash = row[0] if row else "GENESIS"

    # Compute row hash
    hash_input = f"{tenant_id}|{now.isoformat()}|{actor_type}|{actor_id}|{action}|{previous_hash}"
    row_hash = hashlib.sha256(hash_input.encode()).hexdigest()

    # Insert (no ORM — direct SQL for audit_log to ensure immutability)
    await db.execute(
        text("""
            INSERT INTO audit_log
                (tenant_id, timestamp, actor_type, actor_id, action,
                 resource_type, resource_id, details, ip_address,
                 previous_hash, row_hash)
            VALUES
                (:tenant_id, :timestamp, :actor_type, :actor_id, :action,
                 :resource_type, :resource_id, :details, :ip_address,
                 :previous_hash, :row_hash)
            RETURNING id
        """),
        {
            "tenant_id": str(tenant_id),
            "timestamp": now,
            "actor_type": actor_type,
            "actor_id": actor_id,
            "action": action,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "details": json.dumps(details, cls=UUIDEncoder) if details else None,
            "ip_address": ip_address,
            "previous_hash": previous_hash,
            "row_hash": row_hash,
        },
    )
    await db.commit()

    return row_hash


async def verify_audit_chain(db: AsyncSession, tenant_id: UUID) -> dict:
    """Verify the integrity of the audit log hash chain for a tenant.

    Returns {"valid": bool, "checked": int, "broken_at": int | None}
    """
    result = await db.execute(
        text("""
            SELECT id, tenant_id, timestamp, actor_type, actor_id, action,
                   previous_hash, row_hash
            FROM audit_log
            WHERE tenant_id = :tid
            ORDER BY id ASC
        """),
        {"tid": str(tenant_id)},
    )
    rows = result.fetchall()

    if not rows:
        return {"valid": True, "checked": 0, "broken_at": None}

    expected_previous = "GENESIS"
    for row in rows:
        # Verify chain linkage
        if row.previous_hash != expected_previous:
            return {"valid": False, "checked": row.id, "broken_at": row.id}

        # Verify row hash
        hash_input = (
            f"{row.tenant_id}|{row.timestamp.isoformat()}|"
            f"{row.actor_type}|{row.actor_id}|{row.action}|{row.previous_hash}"
        )
        computed = hashlib.sha256(hash_input.encode()).hexdigest()
        if computed != row.row_hash:
            return {"valid": False, "checked": row.id, "broken_at": row.id}

        expected_previous = row.row_hash

    return {"valid": True, "checked": len(rows), "broken_at": None}
