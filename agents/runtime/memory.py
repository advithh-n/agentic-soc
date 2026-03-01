"""Agent Memory — learn from past investigations.

Uses the existing `agent_memory` table (fact/pattern/preference/lesson) and
`alert_embeddings` table (384-dim pgvector with IVFFlat index).

Embedding strategy: keyword-based 384-dim vectors using hash trigrams into
buckets, L2-normalized. This matches the existing IVFFlat index and avoids
requiring an external embedding model.
"""

import hashlib
import json
import math
import uuid
from datetime import datetime, timezone

import asyncpg
import structlog

logger = structlog.get_logger()

EMBEDDING_DIM = 384


# --- Keyword-based embedding (no external model needed) ---

def _text_to_embedding(text: str) -> list[float]:
    """Convert text to a 384-dim vector using hash-based trigram bucketing.

    This produces deterministic embeddings that work with the existing
    IVFFlat cosine index. Similar texts get similar vectors.
    """
    text = text.lower().strip()
    vec = [0.0] * EMBEDDING_DIM

    # Hash each word and character trigram into buckets
    words = text.split()
    for word in words:
        h = int(hashlib.sha256(word.encode()).hexdigest(), 16)
        bucket = h % EMBEDDING_DIM
        vec[bucket] += 1.0

        # Also hash character trigrams for substring matching
        for i in range(len(word) - 2):
            trigram = word[i : i + 3]
            h = int(hashlib.md5(trigram.encode()).hexdigest(), 16)
            bucket = h % EMBEDDING_DIM
            vec[bucket] += 0.5

    # L2-normalize
    magnitude = math.sqrt(sum(v * v for v in vec))
    if magnitude > 0:
        vec = [v / magnitude for v in vec]

    return vec


# --- Memory Storage ---

async def store_investigation_memory(
    db_pool: asyncpg.Pool,
    tenant_id: str,
    agent_name: str,
    memory_type: str,
    content: str,
    confidence: float = 1.0,
    source_incident: str | None = None,
):
    """Store an investigation finding as a memory fact/pattern/lesson.

    memory_type: 'fact', 'pattern', 'preference', or 'lesson'
    """
    try:
        async with db_pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO agent_memory
                    (id, tenant_id, agent_name, memory_type, content,
                     confidence, source_incident, created_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
                """,
                str(uuid.uuid4()),
                tenant_id,
                agent_name,
                memory_type,
                content,
                confidence,
                source_incident,
            )
        logger.debug("memory.stored", agent=agent_name, type=memory_type,
                     content_len=len(content))
    except Exception as e:
        logger.warning("memory.store_failed", error=str(e))


async def recall_similar_investigations(
    db_pool: asyncpg.Pool,
    tenant_id: str,
    event_type: str,
    ioc_summary: str,
    limit: int = 5,
) -> list[dict]:
    """Recall past investigation memories relevant to the current alert.

    Uses keyword matching on event_type and IOC values.
    """
    try:
        search_terms = [event_type]
        # Extract category (e.g., "carding" from "carding.multi_card_velocity")
        if "." in event_type:
            search_terms.append(event_type.split(".")[0])
            search_terms.append(event_type.split(".")[-1])

        # Build LIKE patterns from IOC summary
        for term in ioc_summary.split()[:10]:
            if len(term) > 3:
                search_terms.append(term)

        like_patterns = [f"%{t}%" for t in search_terms[:8]]

        async with db_pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT id, agent_name, memory_type, content, confidence,
                       source_incident, access_count, created_at
                FROM agent_memory
                WHERE tenant_id = $1
                  AND content LIKE ANY($2::text[])
                ORDER BY confidence DESC, created_at DESC
                LIMIT $3
                """,
                tenant_id,
                like_patterns,
                limit,
            )

            # Update access counts
            if rows:
                ids = [str(r["id"]) for r in rows]
                await conn.execute(
                    """
                    UPDATE agent_memory
                    SET access_count = access_count + 1,
                        last_accessed = NOW()
                    WHERE id = ANY($1::uuid[])
                    """,
                    ids,
                )

        memories = [
            {
                "id": str(r["id"]),
                "type": r["memory_type"],
                "content": r["content"],
                "confidence": r["confidence"],
                "source_incident": str(r["source_incident"]) if r["source_incident"] else None,
                "access_count": r["access_count"],
                "created_at": r["created_at"].isoformat() if r["created_at"] else None,
            }
            for r in rows
        ]
        logger.debug("memory.recalled", count=len(memories), event_type=event_type)
        return memories

    except Exception as e:
        logger.warning("memory.recall_failed", error=str(e))
        return []


# --- Alert Embedding Storage ---

async def store_alert_embedding(
    db_pool: asyncpg.Pool,
    tenant_id: str,
    alert_id: str,
    alert_text: str,
):
    """Store a 384-dim embedding for an alert to enable similarity search."""
    try:
        embedding = _text_to_embedding(alert_text)
        embedding_str = "[" + ",".join(str(v) for v in embedding) + "]"

        async with db_pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO alert_embeddings (id, alert_id, tenant_id, embedding)
                VALUES ($1, $2, $3, $4::vector)
                ON CONFLICT DO NOTHING
                """,
                str(uuid.uuid4()),
                alert_id,
                tenant_id,
                embedding_str,
            )
        logger.debug("memory.embedding_stored", alert_id=alert_id)
    except Exception as e:
        logger.warning("memory.embedding_store_failed", alert_id=alert_id, error=str(e))


async def find_similar_alerts(
    db_pool: asyncpg.Pool,
    tenant_id: str,
    alert_text: str,
    limit: int = 5,
    threshold: float = 0.3,
) -> list[dict]:
    """Find similar past alerts using vector cosine similarity."""
    try:
        embedding = _text_to_embedding(alert_text)
        embedding_str = "[" + ",".join(str(v) for v in embedding) + "]"

        async with db_pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT ae.alert_id,
                       1 - (ae.embedding <=> $1::vector) AS similarity,
                       a.title, a.event_type, a.severity, a.status
                FROM alert_embeddings ae
                JOIN alerts a ON a.id = ae.alert_id
                WHERE ae.tenant_id = $2
                  AND 1 - (ae.embedding <=> $1::vector) > $3
                ORDER BY ae.embedding <=> $1::vector
                LIMIT $4
                """,
                embedding_str,
                tenant_id,
                threshold,
                limit,
            )

        return [
            {
                "alert_id": str(r["alert_id"]),
                "similarity": round(r["similarity"], 3),
                "title": r["title"],
                "event_type": r["event_type"],
                "severity": r["severity"],
                "status": r["status"],
            }
            for r in rows
        ]
    except Exception as e:
        logger.warning("memory.similar_alerts_failed", error=str(e))
        return []
