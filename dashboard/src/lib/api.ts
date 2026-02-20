const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8050";

interface FetchOptions extends RequestInit {
  skipAuth?: boolean;
}

let accessToken: string | null = null;
let refreshToken: string | null = null;
let onAuthError: (() => void) | null = null;

export function setTokens(access: string, refresh: string) {
  accessToken = access;
  refreshToken = refresh;
  if (typeof window !== "undefined") {
    localStorage.setItem("soc_refresh_token", refresh);
  }
}

export function clearTokens() {
  accessToken = null;
  refreshToken = null;
  if (typeof window !== "undefined") {
    localStorage.removeItem("soc_refresh_token");
  }
}

export function getAccessToken() {
  return accessToken;
}

export function setOnAuthError(fn: () => void) {
  onAuthError = fn;
}

export function loadStoredRefreshToken(): string | null {
  if (typeof window !== "undefined") {
    return localStorage.getItem("soc_refresh_token");
  }
  return null;
}

async function refreshAccessToken(): Promise<boolean> {
  const stored = refreshToken || loadStoredRefreshToken();
  if (!stored) return false;

  try {
    const res = await fetch(`${API_URL}/api/v1/auth/refresh`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ refresh_token: stored }),
    });
    if (!res.ok) return false;
    const data = await res.json();
    setTokens(data.access_token, data.refresh_token);
    return true;
  } catch {
    return false;
  }
}

export async function apiFetch<T = unknown>(
  path: string,
  options: FetchOptions = {}
): Promise<T> {
  const { skipAuth, ...fetchOpts } = options;
  const headers = new Headers(fetchOpts.headers);

  if (!skipAuth && accessToken) {
    headers.set("Authorization", `Bearer ${accessToken}`);
  }
  if (!headers.has("Content-Type") && fetchOpts.body) {
    headers.set("Content-Type", "application/json");
  }

  let res = await fetch(`${API_URL}${path}`, { ...fetchOpts, headers });

  if (res.status === 401 && !skipAuth) {
    const refreshed = await refreshAccessToken();
    if (refreshed) {
      headers.set("Authorization", `Bearer ${accessToken}`);
      res = await fetch(`${API_URL}${path}`, { ...fetchOpts, headers });
    } else {
      clearTokens();
      onAuthError?.();
      throw new Error("Session expired");
    }
  }

  if (!res.ok) {
    const body = await res.text();
    throw new Error(`API error ${res.status}: ${body}`);
  }

  return res.json();
}

// Auth endpoints
export async function login(email: string, password: string, tenantSlug: string) {
  const data = await apiFetch<{
    access_token: string;
    refresh_token: string;
    token_type: string;
    expires_in: number;
  }>("/api/v1/auth/login", {
    method: "POST",
    skipAuth: true,
    body: JSON.stringify({ email, password, tenant_slug: tenantSlug }),
  });
  setTokens(data.access_token, data.refresh_token);
  return data;
}

export async function getMe() {
  return apiFetch<{
    user_id: string;
    tenant_id: string;
    role: string;
    email: string;
  }>("/api/v1/auth/me");
}

// Alert endpoints
export interface Alert {
  id: string;
  source: string;
  event_type: string;
  severity: string;
  confidence: number | null;
  status: string;
  title: string;
  description: string | null;
  mitre_technique: string | null;
  atlas_technique: string | null;
  trace_id: string;
  created_at: string;
  triaged_at: string | null;
}

export interface AlertDetail extends Alert {
  raw_payload: Record<string, unknown> | null;
  enrichment: Record<string, unknown> | null;
  artifacts: Array<{ type: string; value: string }>;
  triage_result: {
    classification: string;
    confidence: number;
    severity: string;
    reasoning: string;
    recommended_action: string;
    mitre_technique?: string;
    enrichment_summary?: string;
    steps?: Array<{ step: string; result: string }>;
  } | null;
  resolved_by: string | null;
  resolution: string | null;
  resolved_at: string | null;
  incident_id: string | null;
}

export interface AlertListResponse {
  alerts: Alert[];
  total: number;
  page: number;
  page_size: number;
}

export async function getAlerts(params?: {
  status?: string;
  severity?: string;
  source?: string;
  page?: number;
  page_size?: number;
}) {
  const query = new URLSearchParams();
  if (params?.status) query.set("status", params.status);
  if (params?.severity) query.set("severity", params.severity);
  if (params?.source) query.set("source", params.source);
  if (params?.page) query.set("page", String(params.page));
  if (params?.page_size) query.set("page_size", String(params.page_size));
  const qs = query.toString();
  return apiFetch<AlertListResponse>(`/api/v1/alerts${qs ? `?${qs}` : ""}`);
}

export async function getAlertDetail(id: string) {
  return apiFetch<AlertDetail>(`/api/v1/alerts/${id}`);
}

export async function escalateAlert(id: string, reason?: string) {
  return apiFetch(`/api/v1/alerts/${id}/escalate`, {
    method: "POST",
    body: JSON.stringify({ reason: reason || null }),
  });
}

export async function closeAlert(id: string, resolution: string) {
  return apiFetch(`/api/v1/alerts/${id}/close`, {
    method: "POST",
    body: JSON.stringify({ resolution, status: "resolved" }),
  });
}

// Incident endpoints
export interface Incident {
  id: string;
  title: string;
  severity: string;
  status: string;
  description: string | null;
  blast_radius: Record<string, unknown> | null;
  root_cause: string | null;
  created_at: string;
}

export interface LinkedAlert {
  id: string;
  title: string;
  event_type: string;
  severity: string;
  status: string;
  confidence: number | null;
  created_at: string;
}

export interface LinkedAction {
  id: string;
  action_type: string;
  risk_level: string;
  status: string;
  proposed_by: string;
  critic_review: Record<string, unknown> | null;
  created_at: string;
}

export interface IncidentDetail extends Incident {
  timeline: Array<Record<string, unknown>> | null;
  alerts: LinkedAlert[];
  response_actions: LinkedAction[];
  alert_count: number;
}

export async function getIncidents(params?: { status?: string; page?: number }) {
  const query = new URLSearchParams();
  if (params?.status) query.set("status", params.status);
  if (params?.page) query.set("page", String(params.page));
  const qs = query.toString();
  return apiFetch<{ incidents: Incident[]; total: number }>(
    `/api/v1/incidents${qs ? `?${qs}` : ""}`
  );
}

export async function getIncidentDetail(id: string) {
  return apiFetch<IncidentDetail>(`/api/v1/incidents/${id}`);
}

// Execution trace endpoints
export interface TraceStep {
  id: string;
  agent_name: string;
  trace_id: string;
  step_number: number;
  step_type: string;
  input_data: Record<string, unknown> | null;
  output_data: Record<string, unknown> | null;
  tool_calls: string[] | null;
  tokens_used: number;
  duration_ms: number | null;
  timestamp: string;
}

export async function getTraces(params: { alert_id?: string; agent_name?: string }) {
  const query = new URLSearchParams();
  if (params.alert_id) query.set("alert_id", params.alert_id);
  if (params.agent_name) query.set("agent_name", params.agent_name);
  const qs = query.toString();
  return apiFetch<{ steps: TraceStep[]; total: number }>(
    `/api/v1/traces${qs ? `?${qs}` : ""}`
  );
}

// Action endpoints
export interface ResponseAction {
  id: string;
  action_type: string;
  parameters: Record<string, unknown>;
  risk_level: string;
  status: string;
  proposed_by: string;
  critic_review: Record<string, unknown> | null;
  created_at: string;
}

export async function getPendingActions() {
  return apiFetch<ResponseAction[]>("/api/v1/actions/pending");
}

export async function approveAction(id: string) {
  return apiFetch(`/api/v1/actions/${id}/approve`, { method: "POST" });
}

export async function denyAction(id: string, reason: string) {
  return apiFetch(`/api/v1/actions/${id}/deny`, {
    method: "POST",
    body: JSON.stringify({ reason }),
  });
}

export async function executeAction(id: string) {
  return apiFetch(`/api/v1/actions/${id}/execute`, { method: "POST" });
}

export interface ActionHistoryItem {
  id: string;
  action_type: string;
  parameters: Record<string, unknown>;
  risk_level: string;
  status: string;
  proposed_by: string;
  critic_review: Record<string, unknown> | null;
  outcome: Record<string, unknown> | null;
  executed_at: string | null;
  created_at: string;
}

export async function getActionHistory(params?: {
  status?: string;
  page?: number;
  page_size?: number;
}) {
  const query = new URLSearchParams();
  if (params?.status) query.set("status", params.status);
  if (params?.page) query.set("page", String(params.page));
  if (params?.page_size) query.set("page_size", String(params.page_size));
  const qs = query.toString();
  return apiFetch<{ actions: ActionHistoryItem[]; total: number }>(
    `/api/v1/actions/history${qs ? `?${qs}` : ""}`
  );
}

// Playbook endpoints
export interface Playbook {
  name: string;
  description: string;
  event_types: string[];
  severity_min: string;
  action_count: number;
  actions: Array<{
    action_type: string;
    risk_level: string;
    description: string;
  }>;
}

export async function getPlaybooks() {
  return apiFetch<Playbook[]>("/api/v1/playbooks");
}

export async function runPlaybook(
  name: string,
  incidentId: string,
  context?: Record<string, unknown>
) {
  return apiFetch<{ status: string; playbook: string; message: string }>(
    `/api/v1/playbooks/${name}/run`,
    {
      method: "POST",
      body: JSON.stringify({ incident_id: incidentId, context: context || {} }),
    }
  );
}

// Health
export async function getHealth() {
  return apiFetch<{
    status: string;
    checks: Record<string, string>;
    version: string;
  }>("/api/v1/health", { skipAuth: true });
}

// Analytics endpoints
export interface AnalyticsOverview {
  alerts: {
    total: number;
    new: number;
    triaged: number;
    investigating: number;
    false_positive: number;
    by_severity: { critical: number; high: number; medium: number; low: number };
    last_24h: number;
    last_1h: number;
  };
  incidents: {
    total: number;
    open: number;
    investigating: number;
    resolved: number;
    closed: number;
  };
  response_actions: {
    total: number;
    pending: number;
    approved: number;
    executed: number;
    failed: number;
    denied: number;
    by_risk: { auto: number; high: number; critical: number };
  };
  execution_traces: number;
  modules: Array<{ module: string; alert_count: number; rule_count: number }>;
  mttr_seconds: number | null;
  mttd_seconds: number | null;
}

export interface MitreHeatmap {
  mitre: Array<{
    technique_id: string;
    event_type: string;
    hits: number;
    max_severity: string;
    last_seen: string | null;
  }>;
  atlas: Array<{
    technique_id: string;
    event_type: string;
    hits: number;
    max_severity: string;
    last_seen: string | null;
  }>;
  total_techniques: number;
}

export interface AlertTimeline {
  hours: number;
  buckets: Array<{
    timestamp: string;
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
  }>;
}

export interface AgentPerformance {
  status: string;
  alerts_triaged: number;
  verdicts: Record<string, number>;
  escalations: number;
  investigations: number;
  incidents_created: number;
  critic_reviews: number;
  actions_approved: number;
  actions_denied: number;
  actions_escalated: number;
  actions_executed: number;
  actions_failed: number;
  playbooks_run: number;
  mode: string;
}

export interface SystemHealth {
  overall: string;
  services: Record<string, { status: string; [key: string]: unknown }>;
  timestamp: string;
}

export interface ActionBreakdown {
  actions: Array<{
    action_type: string;
    risk_level: string;
    status: string;
    count: number;
    proposed_by: string;
    first_seen: string | null;
    last_seen: string | null;
  }>;
}

export async function getAnalyticsOverview() {
  return apiFetch<AnalyticsOverview>("/api/v1/analytics/overview");
}

export async function getMitreHeatmap() {
  return apiFetch<MitreHeatmap>("/api/v1/analytics/mitre-heatmap");
}

export async function getAlertTimeline(hours = 24) {
  return apiFetch<AlertTimeline>(`/api/v1/analytics/alert-timeline?hours=${hours}`);
}

export async function getAgentPerformance() {
  return apiFetch<AgentPerformance>("/api/v1/analytics/agent-performance");
}

export async function getSystemHealth() {
  return apiFetch<SystemHealth>("/api/v1/analytics/system-health");
}

export async function getActionBreakdown() {
  return apiFetch<ActionBreakdown>("/api/v1/analytics/action-breakdown");
}

// ─── Admin: User Management ─────────────────────────────

export interface AdminUser {
  id: string;
  email: string;
  role: string;
  is_active: boolean;
  last_login: string | null;
}

export async function getAdminUsers() {
  return apiFetch<AdminUser[]>("/api/v1/admin/users");
}

export async function createAdminUser(email: string, password: string, role: string) {
  return apiFetch<AdminUser>("/api/v1/admin/users", {
    method: "POST",
    body: JSON.stringify({ email, password, role }),
  });
}

export async function updateAdminUser(id: string, data: { role?: string; is_active?: boolean }) {
  return apiFetch<AdminUser>(`/api/v1/admin/users/${id}`, {
    method: "PUT",
    body: JSON.stringify(data),
  });
}

export async function deactivateAdminUser(id: string) {
  return apiFetch(`/api/v1/admin/users/${id}`, { method: "DELETE" });
}

// ─── Admin: Module Config ───────────────────────────────

export interface ModuleConfig {
  module_name: string;
  is_enabled: boolean;
  thresholds: Record<string, number>;
}

export async function getModuleConfigs() {
  return apiFetch<ModuleConfig[]>("/api/v1/admin/modules");
}

export async function updateModuleConfig(name: string, data: { is_enabled?: boolean; thresholds?: Record<string, number> }) {
  return apiFetch<ModuleConfig>(`/api/v1/admin/modules/${name}`, {
    method: "PUT",
    body: JSON.stringify(data),
  });
}

// ─── Admin: API Keys ────────────────────────────────────

export interface ApiKeyInfo {
  id: string;
  name: string;
  prefix: string;
  role: string;
  scopes: string[];
  is_active: boolean;
  created_at: string;
}

export interface ApiKeyCreated extends ApiKeyInfo {
  key: string;
}

export async function getApiKeys() {
  return apiFetch<ApiKeyInfo[]>("/api/v1/admin/api-keys");
}

export async function createApiKey(name: string, role?: string, scopes?: string[]) {
  return apiFetch<ApiKeyCreated>("/api/v1/admin/api-keys", {
    method: "POST",
    body: JSON.stringify({ name, role: role || "api_only", scopes: scopes || [] }),
  });
}

export async function revokeApiKey(id: string) {
  return apiFetch(`/api/v1/admin/api-keys/${id}`, { method: "DELETE" });
}

// ─── Admin: Notification Settings ───────────────────────

export interface NotificationSettings {
  slack_webhook_url: string | null;
  email_enabled: boolean;
  email_recipients: string[];
  severity_filter: string[];
}

export async function getNotificationSettings() {
  return apiFetch<NotificationSettings>("/api/v1/admin/notifications");
}

export async function updateNotificationSettings(data: NotificationSettings) {
  return apiFetch<NotificationSettings>("/api/v1/admin/notifications", {
    method: "PUT",
    body: JSON.stringify(data),
  });
}

export async function testNotification() {
  return apiFetch<{ status: string; message: string }>("/api/v1/admin/notifications/test", {
    method: "POST",
  });
}

// ─── Admin: Audit Log ───────────────────────────────────

export interface AuditLogEntry {
  id: number;
  timestamp: string;
  actor_type: string;
  actor_id: string;
  action: string;
  resource_type: string;
  resource_id: string;
  details: Record<string, unknown> | null;
  row_hash: string;
}

export interface AuditLogResponse {
  entries: AuditLogEntry[];
  total: number;
  page: number;
  page_size: number;
}

export async function getAuditLog(params?: {
  action?: string;
  resource_type?: string;
  page?: number;
  page_size?: number;
}) {
  const query = new URLSearchParams();
  if (params?.action) query.set("action", params.action);
  if (params?.resource_type) query.set("resource_type", params.resource_type);
  if (params?.page) query.set("page", String(params.page));
  if (params?.page_size) query.set("page_size", String(params.page_size));
  const qs = query.toString();
  return apiFetch<AuditLogResponse>(`/api/v1/admin/audit-log${qs ? `?${qs}` : ""}`);
}

export async function verifyAuditChain() {
  return apiFetch<{ valid: boolean; checked: number; broken_at: number | null }>(
    "/api/v1/admin/audit-log/verify"
  );
}

// ─── Export & Reports ───────────────────────────────────

export function getAlertExportUrl(params?: { status?: string; severity?: string; source?: string }) {
  const query = new URLSearchParams();
  if (params?.status) query.set("status", params.status);
  if (params?.severity) query.set("severity", params.severity);
  if (params?.source) query.set("source", params.source);
  const qs = query.toString();
  return `${API_URL}/api/v1/alerts/export${qs ? `?${qs}` : ""}`;
}

export async function getIncidentReport(id: string) {
  return apiFetch<{ report: Record<string, unknown> }>(`/api/v1/incidents/${id}/report`);
}
