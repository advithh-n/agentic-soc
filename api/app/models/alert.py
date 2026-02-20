"""Alert and Incident SQLAlchemy models."""

from sqlalchemy import Column, DateTime, Float, ForeignKey, Text, text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import relationship

from app.models.base import Base, TimestampMixin


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    source = Column(Text, nullable=False)
    event_type = Column(Text, nullable=False)
    severity = Column(Text, nullable=False)
    confidence = Column(Float)
    status = Column(Text, nullable=False, server_default="open")
    title = Column(Text, nullable=False)
    description = Column(Text)
    raw_payload = Column(JSONB)
    enrichment = Column(JSONB)
    artifacts = Column(JSONB, server_default="[]")
    mitre_technique = Column(Text)
    atlas_technique = Column(Text)
    triage_result = Column(JSONB)
    resolved_by = Column(Text)
    resolution = Column(Text)
    incident_id = Column(UUID(as_uuid=True), ForeignKey("incidents.id"))
    trace_id = Column(Text)
    created_at = Column(DateTime(timezone=True), server_default=text("NOW()"))
    triaged_at = Column(DateTime(timezone=True))
    resolved_at = Column(DateTime(timezone=True))

    incident = relationship("Incident", back_populates="alerts")
    evidence = relationship("Evidence", back_populates="alert")
    response_actions = relationship("ResponseAction", back_populates="alert")


class Incident(Base, TimestampMixin):
    __tablename__ = "incidents"

    id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    title = Column(Text, nullable=False)
    severity = Column(Text, nullable=False)
    status = Column(Text, nullable=False, server_default="open")
    description = Column(Text)
    timeline = Column(JSONB, server_default="[]")
    blast_radius = Column(JSONB)
    root_cause = Column(Text)
    assignee_id = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    resolved_at = Column(DateTime(timezone=True))
    closed_at = Column(DateTime(timezone=True))

    alerts = relationship("Alert", back_populates="incident")
    evidence = relationship("Evidence", back_populates="incident")
    response_actions = relationship("ResponseAction", back_populates="incident")


class Evidence(Base):
    __tablename__ = "evidence"

    id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    incident_id = Column(UUID(as_uuid=True), ForeignKey("incidents.id"))
    alert_id = Column(UUID(as_uuid=True), ForeignKey("alerts.id"))
    content_type = Column(Text, nullable=False)
    storage_path = Column(Text, nullable=False)
    content_hash = Column(Text, nullable=False)
    size_bytes = Column(Text)
    collected_by = Column(Text, nullable=False)
    chain_of_custody = Column(JSONB, server_default="[]")
    metadata_ = Column("metadata", JSONB, server_default="{}")
    created_at = Column(DateTime(timezone=True), server_default=text("NOW()"))

    incident = relationship("Incident", back_populates="evidence")
    alert = relationship("Alert", back_populates="evidence")


class ResponseAction(Base):
    __tablename__ = "response_actions"

    id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    alert_id = Column(UUID(as_uuid=True), ForeignKey("alerts.id"))
    incident_id = Column(UUID(as_uuid=True), ForeignKey("incidents.id"))
    action_type = Column(Text, nullable=False)
    parameters = Column(JSONB, nullable=False)
    risk_level = Column(Text, nullable=False)
    status = Column(Text, nullable=False, server_default="pending")
    proposed_by = Column(Text, nullable=False)
    critic_review = Column(JSONB)
    approved_by = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    executed_at = Column(DateTime(timezone=True))
    outcome = Column(JSONB)
    evidence_hash = Column(Text)
    rollback_action = Column(JSONB)
    created_at = Column(DateTime(timezone=True), server_default=text("NOW()"))

    alert = relationship("Alert", back_populates="response_actions")
    incident = relationship("Incident", back_populates="response_actions")
