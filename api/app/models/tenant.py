"""Tenant and User SQLAlchemy models."""

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, String, Text, text
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import relationship

from app.models.base import Base, TimestampMixin


class Tenant(Base, TimestampMixin):
    __tablename__ = "tenants"

    id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    name = Column(Text, nullable=False)
    slug = Column(Text, unique=True, nullable=False)
    plan = Column(Text, nullable=False, server_default="starter")
    settings = Column(JSONB, server_default="{}")
    is_active = Column(Boolean, server_default="true")

    users = relationship("User", back_populates="tenant", cascade="all, delete-orphan")
    api_keys = relationship("ApiKey", back_populates="tenant", cascade="all, delete-orphan")


class User(Base, TimestampMixin):
    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    email = Column(Text, nullable=False)
    password_hash = Column(Text, nullable=False)
    role = Column(Text, nullable=False, server_default="viewer")
    is_active = Column(Boolean, server_default="true")
    last_login = Column(DateTime(timezone=True))

    tenant = relationship("Tenant", back_populates="users")


class ApiKey(Base):
    __tablename__ = "api_keys"

    id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    name = Column(Text, nullable=False)
    key_hash = Column(Text, nullable=False)
    prefix = Column(Text, nullable=False)
    role = Column(Text, nullable=False, server_default="api_only")
    scopes = Column(ARRAY(Text), server_default="{}")
    is_active = Column(Boolean, server_default="true")
    expires_at = Column(DateTime(timezone=True))
    last_used_at = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), server_default=text("NOW()"))

    tenant = relationship("Tenant", back_populates="api_keys")
