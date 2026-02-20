"""AI Agent monitoring models (Mode B)."""

from sqlalchemy import Boolean, Column, DateTime, Float, ForeignKey, Integer, Text, text
from sqlalchemy.dialects.postgresql import ARRAY, INET, JSONB, UUID
from sqlalchemy.orm import relationship

from app.models.base import Base, TimestampMixin


class AiAgent(Base, TimestampMixin):
    __tablename__ = "ai_agents"

    id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    name = Column(Text, nullable=False)
    platform = Column(Text, nullable=False)
    model = Column(Text)
    environment = Column(Text, server_default="production")
    status = Column(Text, server_default="active")
    tool_permissions = Column(JSONB, server_default="[]")
    baseline_config = Column(JSONB, server_default="{}")

    sessions = relationship("AiAgentSession", back_populates="agent", cascade="all, delete-orphan")


class AiAgentSession(Base):
    __tablename__ = "ai_agent_sessions"

    id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    agent_id = Column(UUID(as_uuid=True), ForeignKey("ai_agents.id", ondelete="CASCADE"), nullable=False)
    user_identifier = Column(Text)
    started_at = Column(DateTime(timezone=True), server_default=text("NOW()"))
    ended_at = Column(DateTime(timezone=True))
    total_tokens = Column(Integer, server_default="0")
    total_cost = Column(Float, server_default="0")
    tool_calls = Column(Integer, server_default="0")
    anomaly_flags = Column(ARRAY(Text), server_default="{}")
    metadata_ = Column("metadata", JSONB, server_default="{}")

    agent = relationship("AiAgent", back_populates="sessions")
    tool_call_logs = relationship("AiToolCallLog", back_populates="session", cascade="all, delete-orphan")


class AiToolCallLog(Base):
    __tablename__ = "ai_tool_call_log"

    id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    session_id = Column(UUID(as_uuid=True), ForeignKey("ai_agent_sessions.id", ondelete="CASCADE"), nullable=False)
    agent_id = Column(UUID(as_uuid=True), ForeignKey("ai_agents.id", ondelete="CASCADE"), nullable=False)
    tool_name = Column(Text, nullable=False)
    arguments = Column(JSONB)
    result_summary = Column(Text)
    duration_ms = Column(Integer)
    was_anomalous = Column(Boolean, server_default="false")
    anomaly_reason = Column(Text)
    timestamp = Column(DateTime(timezone=True), server_default=text("NOW()"))

    session = relationship("AiAgentSession", back_populates="tool_call_logs")


class PromptInjectionLog(Base):
    __tablename__ = "prompt_injection_log"

    id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    agent_id = Column(UUID(as_uuid=True), ForeignKey("ai_agents.id"))
    session_id = Column(UUID(as_uuid=True), ForeignKey("ai_agent_sessions.id"))
    detection_layer = Column(Text, nullable=False)
    injection_type = Column(Text)
    injection_score = Column(Float)
    prompt_snippet = Column(Text)
    was_blocked = Column(Boolean, server_default="false")
    source_ip = Column(INET)
    user_identifier = Column(Text)
    timestamp = Column(DateTime(timezone=True), server_default=text("NOW()"))
