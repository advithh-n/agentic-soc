-- ============================================================
-- Agentic SOC v5 — PostgreSQL Schema
-- Initialized on first docker compose up
-- ============================================================

-- Extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "vector";

-- ============================================================
-- MULTI-TENANCY
-- ============================================================

CREATE TABLE tenants (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            TEXT NOT NULL,
    slug            TEXT UNIQUE NOT NULL,
    plan            TEXT NOT NULL DEFAULT 'starter'
                    CHECK (plan IN ('starter', 'professional', 'enterprise')),
    settings        JSONB DEFAULT '{}',
    is_active       BOOLEAN DEFAULT true,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE users (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    email           TEXT NOT NULL,
    password_hash   TEXT NOT NULL,
    role            TEXT NOT NULL DEFAULT 'viewer'
                    CHECK (role IN ('owner', 'admin', 'analyst', 'viewer', 'api_only')),
    is_active       BOOLEAN DEFAULT true,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW(),
    last_login      TIMESTAMPTZ,
    UNIQUE(tenant_id, email)
);

CREATE TABLE api_keys (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    created_by      UUID NOT NULL REFERENCES users(id),
    name            TEXT NOT NULL,
    key_hash        TEXT NOT NULL,
    prefix          TEXT NOT NULL,
    role            TEXT NOT NULL DEFAULT 'api_only'
                    CHECK (role IN ('api_only', 'analyst', 'admin')),
    scopes          TEXT[] DEFAULT '{}',
    is_active       BOOLEAN DEFAULT true,
    expires_at      TIMESTAMPTZ,
    last_used_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

-- ============================================================
-- SOC CORE
-- ============================================================

CREATE TABLE incidents (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    title           TEXT NOT NULL,
    severity        TEXT NOT NULL
                    CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    status          TEXT NOT NULL DEFAULT 'open'
                    CHECK (status IN ('open', 'investigating', 'contained', 'resolved', 'closed')),
    description     TEXT,
    timeline        JSONB DEFAULT '[]',
    blast_radius    JSONB,
    root_cause      TEXT,
    assignee_id     UUID REFERENCES users(id),
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW(),
    resolved_at     TIMESTAMPTZ,
    closed_at       TIMESTAMPTZ
);

CREATE TABLE alerts (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    source          TEXT NOT NULL,
    event_type      TEXT NOT NULL,
    severity        TEXT NOT NULL
                    CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    confidence      FLOAT CHECK (confidence >= 0 AND confidence <= 1),
    status          TEXT NOT NULL DEFAULT 'open'
                    CHECK (status IN ('open', 'triaged', 'investigating', 'resolved', 'false_positive')),
    title           TEXT NOT NULL,
    description     TEXT,
    raw_payload     JSONB,
    enrichment      JSONB,
    artifacts       JSONB DEFAULT '[]',
    mitre_technique TEXT,
    atlas_technique TEXT,
    triage_result   JSONB,
    resolved_by     TEXT,
    resolution      TEXT,
    incident_id     UUID REFERENCES incidents(id),
    trace_id        TEXT,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    triaged_at      TIMESTAMPTZ,
    resolved_at     TIMESTAMPTZ
);

CREATE TABLE evidence (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    incident_id     UUID REFERENCES incidents(id),
    alert_id        UUID REFERENCES alerts(id),
    content_type    TEXT NOT NULL,
    storage_path    TEXT NOT NULL,
    content_hash    TEXT NOT NULL,
    size_bytes      BIGINT,
    collected_by    TEXT NOT NULL,
    chain_of_custody JSONB DEFAULT '[]',
    metadata        JSONB DEFAULT '{}',
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE response_actions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    alert_id        UUID REFERENCES alerts(id),
    incident_id     UUID REFERENCES incidents(id),
    action_type     TEXT NOT NULL,
    parameters      JSONB NOT NULL,
    risk_level      TEXT NOT NULL
                    CHECK (risk_level IN ('auto', 'low', 'high', 'critical')),
    status          TEXT NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'approved', 'denied', 'executing', 'executed', 'failed', 'rolled_back')),
    proposed_by     TEXT NOT NULL,
    critic_review   JSONB,
    approved_by     UUID REFERENCES users(id),
    executed_at     TIMESTAMPTZ,
    outcome         JSONB,
    evidence_hash   TEXT,
    rollback_action JSONB,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

-- ============================================================
-- AI AGENT MONITORING (Mode B)
-- ============================================================

CREATE TABLE ai_agents (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    platform        TEXT NOT NULL,
    model           TEXT,
    environment     TEXT DEFAULT 'production',
    status          TEXT DEFAULT 'active'
                    CHECK (status IN ('active', 'disabled', 'quarantined')),
    tool_permissions JSONB DEFAULT '[]',
    baseline_config JSONB DEFAULT '{}',
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE ai_agent_sessions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    agent_id        UUID NOT NULL REFERENCES ai_agents(id) ON DELETE CASCADE,
    user_identifier TEXT,
    started_at      TIMESTAMPTZ DEFAULT NOW(),
    ended_at        TIMESTAMPTZ,
    total_tokens    INTEGER DEFAULT 0,
    total_cost      DECIMAL(10,4) DEFAULT 0,
    tool_calls      INTEGER DEFAULT 0,
    anomaly_flags   TEXT[] DEFAULT '{}',
    metadata        JSONB DEFAULT '{}'
);

CREATE TABLE ai_tool_call_log (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    session_id      UUID NOT NULL REFERENCES ai_agent_sessions(id) ON DELETE CASCADE,
    agent_id        UUID NOT NULL REFERENCES ai_agents(id) ON DELETE CASCADE,
    tool_name       TEXT NOT NULL,
    arguments       JSONB,
    result_summary  TEXT,
    duration_ms     INTEGER,
    was_anomalous   BOOLEAN DEFAULT false,
    anomaly_reason  TEXT,
    timestamp       TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE prompt_injection_log (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    agent_id        UUID REFERENCES ai_agents(id),
    session_id      UUID REFERENCES ai_agent_sessions(id),
    detection_layer TEXT NOT NULL,
    injection_type  TEXT,
    injection_score FLOAT CHECK (injection_score >= 0 AND injection_score <= 1),
    prompt_snippet  TEXT,
    was_blocked     BOOLEAN DEFAULT false,
    source_ip       INET,
    user_identifier TEXT,
    timestamp       TIMESTAMPTZ DEFAULT NOW()
);

-- ============================================================
-- VECTOR SEARCH (pgvector)
-- ============================================================

CREATE TABLE alert_embeddings (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    alert_id        UUID NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    embedding       vector(384),
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE injection_pattern_embeddings (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    pattern_name    TEXT NOT NULL,
    category        TEXT NOT NULL,
    example_text    TEXT NOT NULL,
    embedding       vector(384),
    severity        TEXT DEFAULT 'high',
    source          TEXT,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

-- ============================================================
-- AGENT MEMORY (replaces Mem0)
-- ============================================================

CREATE TABLE agent_memory (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    agent_name      TEXT NOT NULL,
    memory_type     TEXT NOT NULL
                    CHECK (memory_type IN ('fact', 'pattern', 'preference', 'lesson')),
    content         TEXT NOT NULL,
    confidence      FLOAT DEFAULT 1.0,
    source_incident UUID REFERENCES incidents(id),
    access_count    INTEGER DEFAULT 0,
    last_accessed   TIMESTAMPTZ,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    expires_at      TIMESTAMPTZ
);

-- ============================================================
-- AGENT EXECUTION TRACES
-- ============================================================

CREATE TABLE execution_traces (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    alert_id        UUID REFERENCES alerts(id),
    agent_name      TEXT NOT NULL,
    trace_id        TEXT NOT NULL,
    step_number     INTEGER NOT NULL,
    step_type       TEXT NOT NULL,
    input_data      JSONB,
    output_data     JSONB,
    tool_calls      JSONB DEFAULT '[]',
    tokens_used     INTEGER DEFAULT 0,
    duration_ms     INTEGER,
    timestamp       TIMESTAMPTZ DEFAULT NOW()
);

-- ============================================================
-- MODULE CONFIGURATION
-- ============================================================

CREATE TABLE module_configs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    module_name     TEXT NOT NULL,
    is_enabled      BOOLEAN DEFAULT true,
    thresholds      JSONB DEFAULT '{}',
    custom_rules    JSONB DEFAULT '[]',
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(tenant_id, module_name)
);

-- ============================================================
-- AUDIT LOG (immutable, hash-chained)
-- ============================================================

CREATE TABLE audit_log (
    id              BIGSERIAL PRIMARY KEY,
    tenant_id       UUID NOT NULL,
    timestamp       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    actor_type      TEXT NOT NULL
                    CHECK (actor_type IN ('user', 'agent', 'module', 'system')),
    actor_id        TEXT NOT NULL,
    action          TEXT NOT NULL,
    resource_type   TEXT NOT NULL,
    resource_id     TEXT NOT NULL,
    details         JSONB,
    ip_address      INET,
    previous_hash   TEXT NOT NULL,
    row_hash        TEXT NOT NULL
);

-- Revoke UPDATE and DELETE on audit_log from application role
-- (enforced at app level since we use the superuser during init)

-- ============================================================
-- ROW-LEVEL SECURITY
-- ============================================================

ALTER TABLE tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE alerts ENABLE ROW LEVEL SECURITY;
ALTER TABLE incidents ENABLE ROW LEVEL SECURITY;
ALTER TABLE evidence ENABLE ROW LEVEL SECURITY;
ALTER TABLE response_actions ENABLE ROW LEVEL SECURITY;
ALTER TABLE ai_agents ENABLE ROW LEVEL SECURITY;
ALTER TABLE ai_agent_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE ai_tool_call_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE prompt_injection_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE alert_embeddings ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_memory ENABLE ROW LEVEL SECURITY;
ALTER TABLE execution_traces ENABLE ROW LEVEL SECURITY;
ALTER TABLE module_configs ENABLE ROW LEVEL SECURITY;

-- RLS policies (applied when app sets app.current_tenant)
CREATE POLICY tenant_isolation ON alerts
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);
CREATE POLICY tenant_isolation ON incidents
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);
CREATE POLICY tenant_isolation ON evidence
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);
CREATE POLICY tenant_isolation ON response_actions
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);
CREATE POLICY tenant_isolation ON ai_agents
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);
CREATE POLICY tenant_isolation ON ai_agent_sessions
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);
CREATE POLICY tenant_isolation ON ai_tool_call_log
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);
CREATE POLICY tenant_isolation ON prompt_injection_log
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);
CREATE POLICY tenant_isolation ON alert_embeddings
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);
CREATE POLICY tenant_isolation ON agent_memory
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);
CREATE POLICY tenant_isolation ON execution_traces
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);
CREATE POLICY tenant_isolation ON module_configs
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);
CREATE POLICY tenant_isolation ON users
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);
CREATE POLICY tenant_isolation ON api_keys
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- ============================================================
-- INDEXES
-- ============================================================

-- Alerts
CREATE INDEX idx_alerts_tenant_status ON alerts(tenant_id, status);
CREATE INDEX idx_alerts_tenant_severity ON alerts(tenant_id, severity);
CREATE INDEX idx_alerts_tenant_source ON alerts(tenant_id, source);
CREATE INDEX idx_alerts_created ON alerts(created_at DESC);
CREATE INDEX idx_alerts_trace ON alerts(trace_id) WHERE trace_id IS NOT NULL;

-- Incidents
CREATE INDEX idx_incidents_tenant_status ON incidents(tenant_id, status);
CREATE INDEX idx_incidents_created ON incidents(created_at DESC);

-- Response Actions
CREATE INDEX idx_actions_tenant_status ON response_actions(tenant_id, status);
CREATE INDEX idx_actions_pending ON response_actions(status, created_at)
    WHERE status = 'pending';

-- AI Agent Monitoring
CREATE INDEX idx_ai_sessions_agent ON ai_agent_sessions(agent_id, started_at DESC);
CREATE INDEX idx_ai_tool_calls_session ON ai_tool_call_log(session_id, timestamp);
CREATE INDEX idx_ai_tool_calls_anomalous ON ai_tool_call_log(tenant_id, was_anomalous)
    WHERE was_anomalous = true;
CREATE INDEX idx_injection_log_tenant ON prompt_injection_log(tenant_id, timestamp DESC);

-- Audit Log
CREATE INDEX idx_audit_tenant_timestamp ON audit_log(tenant_id, timestamp DESC);
CREATE INDEX idx_audit_action ON audit_log(action, timestamp DESC);

-- Agent Memory
CREATE INDEX idx_memory_agent ON agent_memory(tenant_id, agent_name);
CREATE INDEX idx_memory_type ON agent_memory(tenant_id, memory_type);

-- Execution Traces
CREATE INDEX idx_traces_alert ON execution_traces(alert_id, step_number);
CREATE INDEX idx_traces_trace_id ON execution_traces(trace_id);

-- Vector Indexes
CREATE INDEX idx_alert_embeddings ON alert_embeddings
    USING ivfflat (embedding vector_cosine_ops) WITH (lists = 100);
CREATE INDEX idx_injection_embeddings ON injection_pattern_embeddings
    USING ivfflat (embedding vector_cosine_ops) WITH (lists = 50);

-- ============================================================
-- SEED: Default tenant for development
-- ============================================================

INSERT INTO tenants (id, name, slug, plan) VALUES
    ('a0000000-0000-0000-0000-000000000001', 'Heya Enterprises', 'heya', 'enterprise');

-- Default admin user (password: "changeme" — bcrypt hash)
-- In production, create via API with proper password
INSERT INTO users (id, tenant_id, email, password_hash, role) VALUES
    ('b0000000-0000-0000-0000-000000000001',
     'a0000000-0000-0000-0000-000000000001',
     'admin@heya.au',
     '$2b$12$BuaJBMgutDP1p6Bohc.A1eSI9Q3RnXIZV0eJg0M7o/7it6Uwm2uMq',
     'owner');
