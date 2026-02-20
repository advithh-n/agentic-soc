"use client";

import { useCallback, useEffect, useState } from "react";
import {
  Settings,
  Users,
  Puzzle,
  Key,
  Bell,
  Plus,
  Trash2,
  Copy,
  Check,
  X,
  Eye,
  EyeOff,
} from "lucide-react";
import { clsx } from "clsx";
import { Header } from "@/components/header";
import { useAuth } from "@/lib/auth";
import {
  getAdminUsers,
  createAdminUser,
  updateAdminUser,
  deactivateAdminUser,
  getModuleConfigs,
  updateModuleConfig,
  getApiKeys,
  createApiKey,
  revokeApiKey,
  getNotificationSettings,
  updateNotificationSettings,
  testNotification,
  type AdminUser,
  type ModuleConfig,
  type ApiKeyInfo,
  type NotificationSettings,
} from "@/lib/api";

type Tab = "account" | "users" | "modules" | "api-keys" | "notifications";

const TABS: { key: Tab; label: string; icon: typeof Settings }[] = [
  { key: "account", label: "Account", icon: Settings },
  { key: "users", label: "Users", icon: Users },
  { key: "modules", label: "Modules", icon: Puzzle },
  { key: "api-keys", label: "API Keys", icon: Key },
  { key: "notifications", label: "Notifications", icon: Bell },
];

const ROLES = ["owner", "admin", "analyst", "viewer", "api_only"];

const MODULE_DESCRIPTIONS: Record<string, string> = {
  stripe_carding: "Detects card testing and payment fraud patterns from Stripe webhooks",
  auth_anomaly: "Monitors authentication anomalies including brute force and credential stuffing",
  infrastructure: "Detects port scans, unauthorized access, and infrastructure-level threats",
  ai_agent_monitor: "Monitors AI agent behavior for prompt injection, hallucination, and abuse",
};

export default function SettingsPage() {
  const { user } = useAuth();
  const [activeTab, setActiveTab] = useState<Tab>("account");

  return (
    <div>
      <Header title="Settings" />
      <div className="p-6">
        {/* Tab Navigation */}
        <div className="flex gap-1 border-b border-soc-border mb-6">
          {TABS.map((tab) => (
            <button
              key={tab.key}
              onClick={() => setActiveTab(tab.key)}
              className={clsx(
                "flex items-center gap-2 px-4 py-2.5 text-sm font-medium transition-colors",
                activeTab === tab.key
                  ? "text-soc-accent border-b-2 border-soc-accent"
                  : "text-gray-400 hover:text-white"
              )}
            >
              <tab.icon className="w-4 h-4" />
              {tab.label}
            </button>
          ))}
        </div>

        {/* Tab Content */}
        {activeTab === "account" && <AccountTab user={user} />}
        {activeTab === "users" && <UsersTab />}
        {activeTab === "modules" && <ModulesTab />}
        {activeTab === "api-keys" && <ApiKeysTab />}
        {activeTab === "notifications" && <NotificationsTab />}
      </div>
    </div>
  );
}

// ─── Account Tab ─────────────────────────────────────────

function AccountTab({ user }: { user: { email: string; role: string; tenant_id: string } | null }) {
  return (
    <div className="card p-6 max-w-2xl">
      <h2 className="text-base font-semibold text-white mb-4">Account Information</h2>
      <div className="space-y-4">
        <SettingsRow label="Email" value={user?.email || "-"} />
        <SettingsRow label="Role" value={user?.role || "-"} />
        <SettingsRow label="Tenant ID" value={user?.tenant_id || "-"} mono />
      </div>
    </div>
  );
}

// ─── Users Tab ───────────────────────────────────────────

function UsersTab() {
  const [users, setUsers] = useState<AdminUser[]>([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [newEmail, setNewEmail] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [newRole, setNewRole] = useState("viewer");
  const [saving, setSaving] = useState(false);

  const load = useCallback(async () => {
    try {
      const data = await getAdminUsers();
      setUsers(data);
    } catch (err) {
      console.error("Failed to load users:", err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const handleCreate = async () => {
    if (!newEmail || !newPassword) return;
    setSaving(true);
    try {
      await createAdminUser(newEmail, newPassword, newRole);
      setShowForm(false);
      setNewEmail("");
      setNewPassword("");
      setNewRole("viewer");
      await load();
    } catch (err) {
      console.error("Create user failed:", err);
    } finally {
      setSaving(false);
    }
  };

  const handleRoleChange = async (userId: string, role: string) => {
    try {
      await updateAdminUser(userId, { role });
      await load();
    } catch (err) {
      console.error("Update role failed:", err);
    }
  };

  const handleDeactivate = async (userId: string) => {
    try {
      await deactivateAdminUser(userId);
      await load();
    } catch (err) {
      console.error("Deactivate failed:", err);
    }
  };

  if (loading) return <Spinner />;

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-base font-semibold text-white">
          Users ({users.length})
        </h2>
        <button
          onClick={() => setShowForm(!showForm)}
          className="flex items-center gap-2 px-3 py-1.5 bg-soc-accent/20 text-soc-accent rounded-lg text-xs font-medium hover:bg-soc-accent/30 transition-colors"
        >
          <Plus className="w-3.5 h-3.5" />
          Add User
        </button>
      </div>

      {showForm && (
        <div className="card p-4 space-y-3">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            <input
              type="email"
              placeholder="Email"
              value={newEmail}
              onChange={(e) => setNewEmail(e.target.value)}
              className="bg-soc-bg border border-soc-border rounded px-3 py-2 text-sm text-white placeholder-gray-500"
            />
            <input
              type="password"
              placeholder="Password"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              className="bg-soc-bg border border-soc-border rounded px-3 py-2 text-sm text-white placeholder-gray-500"
            />
            <select
              value={newRole}
              onChange={(e) => setNewRole(e.target.value)}
              className="bg-soc-bg border border-soc-border rounded px-3 py-2 text-sm text-white"
            >
              {ROLES.map((r) => (
                <option key={r} value={r}>{r}</option>
              ))}
            </select>
          </div>
          <div className="flex gap-2">
            <button
              onClick={handleCreate}
              disabled={saving}
              className="px-4 py-1.5 bg-soc-accent text-white rounded text-xs font-medium hover:bg-soc-accent/80 disabled:opacity-50"
            >
              {saving ? "Creating..." : "Create User"}
            </button>
            <button
              onClick={() => setShowForm(false)}
              className="px-4 py-1.5 bg-soc-surface text-gray-400 rounded text-xs hover:text-white"
            >
              Cancel
            </button>
          </div>
        </div>
      )}

      <div className="card overflow-hidden">
        <table className="w-full">
          <thead>
            <tr className="border-b border-soc-border text-left text-xs text-gray-500">
              <th className="px-4 py-3">Email</th>
              <th className="px-4 py-3">Role</th>
              <th className="px-4 py-3">Status</th>
              <th className="px-4 py-3">Last Login</th>
              <th className="px-4 py-3 w-20">Actions</th>
            </tr>
          </thead>
          <tbody>
            {users.map((u) => (
              <tr key={u.id} className="border-b border-soc-border/50">
                <td className="px-4 py-3 text-sm text-gray-200">{u.email}</td>
                <td className="px-4 py-3">
                  <select
                    value={u.role}
                    onChange={(e) => handleRoleChange(u.id, e.target.value)}
                    className="bg-soc-bg border border-soc-border rounded px-2 py-1 text-xs text-gray-200"
                  >
                    {ROLES.map((r) => (
                      <option key={r} value={r}>{r}</option>
                    ))}
                  </select>
                </td>
                <td className="px-4 py-3">
                  <span className={clsx(
                    "text-xs px-2 py-0.5 rounded",
                    u.is_active
                      ? "bg-green-400/10 text-green-400"
                      : "bg-red-400/10 text-red-400"
                  )}>
                    {u.is_active ? "Active" : "Inactive"}
                  </span>
                </td>
                <td className="px-4 py-3 text-xs text-gray-500">
                  {u.last_login ? new Date(u.last_login).toLocaleString() : "Never"}
                </td>
                <td className="px-4 py-3">
                  {u.is_active && (
                    <button
                      onClick={() => handleDeactivate(u.id)}
                      className="p-1 text-red-400/60 hover:text-red-400 transition-colors"
                      title="Deactivate"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ─── Modules Tab ─────────────────────────────────────────

function ModulesTab() {
  const [modules, setModules] = useState<ModuleConfig[]>([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const data = await getModuleConfigs();
      setModules(data);
    } catch (err) {
      console.error("Failed to load modules:", err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const handleToggle = async (name: string, enabled: boolean) => {
    setSaving(name);
    try {
      await updateModuleConfig(name, { is_enabled: enabled });
      await load();
    } catch (err) {
      console.error("Toggle failed:", err);
    } finally {
      setSaving(null);
    }
  };

  const handleThresholdChange = async (name: string, thresholds: Record<string, number>) => {
    setSaving(name);
    try {
      await updateModuleConfig(name, { thresholds });
      await load();
    } catch (err) {
      console.error("Threshold update failed:", err);
    } finally {
      setSaving(null);
    }
  };

  if (loading) return <Spinner />;

  return (
    <div className="space-y-4">
      <h2 className="text-base font-semibold text-white">
        Detection Modules ({modules.length})
      </h2>
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {modules.map((mod) => (
          <div key={mod.module_name} className="card p-5">
            <div className="flex items-start justify-between mb-3">
              <div>
                <h3 className="text-sm font-semibold text-white">
                  {mod.module_name.replace(/_/g, " ")}
                </h3>
                <p className="text-xs text-gray-500 mt-0.5">
                  {MODULE_DESCRIPTIONS[mod.module_name] || "Detection module"}
                </p>
              </div>
              <button
                onClick={() => handleToggle(mod.module_name, !mod.is_enabled)}
                disabled={saving === mod.module_name}
                className={clsx(
                  "relative inline-flex h-6 w-11 items-center rounded-full transition-colors",
                  mod.is_enabled ? "bg-soc-accent" : "bg-gray-600"
                )}
              >
                <span
                  className={clsx(
                    "inline-block h-4 w-4 rounded-full bg-white transition-transform",
                    mod.is_enabled ? "translate-x-6" : "translate-x-1"
                  )}
                />
              </button>
            </div>
            {mod.is_enabled && (
              <div className="space-y-2 mt-3 pt-3 border-t border-soc-border">
                <span className="text-[10px] text-gray-500 uppercase">Thresholds</span>
                {Object.entries(mod.thresholds).map(([key, value]) => (
                  <div key={key} className="flex items-center justify-between">
                    <span className="text-xs text-gray-400">
                      {key.replace(/_/g, " ")}
                    </span>
                    <input
                      type="number"
                      defaultValue={value}
                      onBlur={(e) => {
                        const newVal = parseFloat(e.target.value);
                        if (!isNaN(newVal) && newVal !== value) {
                          handleThresholdChange(mod.module_name, {
                            ...mod.thresholds,
                            [key]: newVal,
                          });
                        }
                      }}
                      className="w-24 bg-soc-bg border border-soc-border rounded px-2 py-1 text-xs text-white text-right"
                    />
                  </div>
                ))}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

// ─── API Keys Tab ────────────────────────────────────────

function ApiKeysTab() {
  const [keys, setKeys] = useState<ApiKeyInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [newName, setNewName] = useState("");
  const [saving, setSaving] = useState(false);
  const [newKey, setNewKey] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  const load = useCallback(async () => {
    try {
      const data = await getApiKeys();
      setKeys(data);
    } catch (err) {
      console.error("Failed to load API keys:", err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const handleCreate = async () => {
    if (!newName) return;
    setSaving(true);
    try {
      const result = await createApiKey(newName);
      setNewKey(result.key);
      setShowForm(false);
      setNewName("");
      await load();
    } catch (err) {
      console.error("Create key failed:", err);
    } finally {
      setSaving(false);
    }
  };

  const handleRevoke = async (keyId: string) => {
    try {
      await revokeApiKey(keyId);
      await load();
    } catch (err) {
      console.error("Revoke failed:", err);
    }
  };

  const handleCopy = () => {
    if (newKey) {
      navigator.clipboard.writeText(newKey);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  if (loading) return <Spinner />;

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-base font-semibold text-white">
          API Keys ({keys.length})
        </h2>
        <button
          onClick={() => { setShowForm(!showForm); setNewKey(null); }}
          className="flex items-center gap-2 px-3 py-1.5 bg-soc-accent/20 text-soc-accent rounded-lg text-xs font-medium hover:bg-soc-accent/30 transition-colors"
        >
          <Plus className="w-3.5 h-3.5" />
          Create Key
        </button>
      </div>

      {/* New key display (one-time) */}
      {newKey && (
        <div className="card p-4 border-2 border-yellow-500/30 bg-yellow-500/5">
          <div className="flex items-center gap-2 text-yellow-400 text-xs font-medium mb-2">
            <Key className="w-3.5 h-3.5" />
            Copy this key now - it will not be shown again
          </div>
          <div className="flex items-center gap-2">
            <code className="flex-1 bg-soc-bg rounded px-3 py-2 text-xs text-white font-mono break-all">
              {newKey}
            </code>
            <button
              onClick={handleCopy}
              className="p-2 text-gray-400 hover:text-white transition-colors"
            >
              {copied ? <Check className="w-4 h-4 text-green-400" /> : <Copy className="w-4 h-4" />}
            </button>
          </div>
          <button
            onClick={() => setNewKey(null)}
            className="mt-2 text-xs text-gray-500 hover:text-gray-300"
          >
            Dismiss
          </button>
        </div>
      )}

      {showForm && (
        <div className="card p-4 flex items-center gap-3">
          <input
            type="text"
            placeholder="Key name (e.g. CI/CD Pipeline)"
            value={newName}
            onChange={(e) => setNewName(e.target.value)}
            className="flex-1 bg-soc-bg border border-soc-border rounded px-3 py-2 text-sm text-white placeholder-gray-500"
          />
          <button
            onClick={handleCreate}
            disabled={saving || !newName}
            className="px-4 py-2 bg-soc-accent text-white rounded text-xs font-medium hover:bg-soc-accent/80 disabled:opacity-50"
          >
            {saving ? "Creating..." : "Create"}
          </button>
          <button
            onClick={() => setShowForm(false)}
            className="px-4 py-2 bg-soc-surface text-gray-400 rounded text-xs hover:text-white"
          >
            Cancel
          </button>
        </div>
      )}

      <div className="card overflow-hidden">
        <table className="w-full">
          <thead>
            <tr className="border-b border-soc-border text-left text-xs text-gray-500">
              <th className="px-4 py-3">Name</th>
              <th className="px-4 py-3">Prefix</th>
              <th className="px-4 py-3">Role</th>
              <th className="px-4 py-3">Status</th>
              <th className="px-4 py-3">Created</th>
              <th className="px-4 py-3 w-20">Actions</th>
            </tr>
          </thead>
          <tbody>
            {keys.map((k) => (
              <tr key={k.id} className="border-b border-soc-border/50">
                <td className="px-4 py-3 text-sm text-gray-200">{k.name}</td>
                <td className="px-4 py-3 text-xs font-mono text-gray-400">{k.prefix}...</td>
                <td className="px-4 py-3 text-xs text-gray-400">{k.role}</td>
                <td className="px-4 py-3">
                  <span className={clsx(
                    "text-xs px-2 py-0.5 rounded",
                    k.is_active
                      ? "bg-green-400/10 text-green-400"
                      : "bg-red-400/10 text-red-400"
                  )}>
                    {k.is_active ? "Active" : "Revoked"}
                  </span>
                </td>
                <td className="px-4 py-3 text-xs text-gray-500">
                  {k.created_at ? new Date(k.created_at).toLocaleDateString() : "-"}
                </td>
                <td className="px-4 py-3">
                  {k.is_active && (
                    <button
                      onClick={() => handleRevoke(k.id)}
                      className="p-1 text-red-400/60 hover:text-red-400 transition-colors"
                      title="Revoke"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {keys.length === 0 && (
          <div className="text-center py-8 text-gray-500 text-sm">
            No API keys created yet.
          </div>
        )}
      </div>
    </div>
  );
}

// ─── Notifications Tab ───────────────────────────────────

function NotificationsTab() {
  const [settings, setSettings] = useState<NotificationSettings | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<string | null>(null);
  const [showWebhook, setShowWebhook] = useState(false);

  useEffect(() => {
    (async () => {
      try {
        const data = await getNotificationSettings();
        setSettings(data);
      } catch (err) {
        console.error("Failed to load notifications:", err);
      } finally {
        setLoading(false);
      }
    })();
  }, []);

  const handleSave = async () => {
    if (!settings) return;
    setSaving(true);
    try {
      await updateNotificationSettings(settings);
    } catch (err) {
      console.error("Save failed:", err);
    } finally {
      setSaving(false);
    }
  };

  const handleTest = async () => {
    setTesting(true);
    setTestResult(null);
    try {
      const result = await testNotification();
      setTestResult(result.message);
    } catch (err) {
      setTestResult(`Failed: ${err}`);
    } finally {
      setTesting(false);
    }
  };

  if (loading || !settings) return <Spinner />;

  const severities = ["critical", "high", "medium", "low"];

  return (
    <div className="space-y-6 max-w-2xl">
      <h2 className="text-base font-semibold text-white">Notification Settings</h2>

      {/* Slack Webhook */}
      <div className="card p-5 space-y-3">
        <h3 className="text-sm font-medium text-gray-300">Slack Integration</h3>
        <div className="flex items-center gap-2">
          <div className="relative flex-1">
            <input
              type={showWebhook ? "text" : "password"}
              placeholder="https://hooks.slack.com/services/..."
              value={settings.slack_webhook_url || ""}
              onChange={(e) =>
                setSettings({ ...settings, slack_webhook_url: e.target.value || null })
              }
              className="w-full bg-soc-bg border border-soc-border rounded px-3 py-2 text-sm text-white placeholder-gray-500 pr-10"
            />
            <button
              onClick={() => setShowWebhook(!showWebhook)}
              className="absolute right-2 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-300"
            >
              {showWebhook ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
            </button>
          </div>
          <button
            onClick={handleTest}
            disabled={testing || !settings.slack_webhook_url}
            className="px-3 py-2 bg-soc-surface border border-soc-border rounded text-xs text-gray-300 hover:text-white disabled:opacity-50"
          >
            {testing ? "Sending..." : "Test"}
          </button>
        </div>
        {testResult && (
          <p className={clsx(
            "text-xs",
            testResult.includes("Failed") ? "text-red-400" : "text-green-400"
          )}>
            {testResult}
          </p>
        )}
      </div>

      {/* Email */}
      <div className="card p-5 space-y-3">
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-medium text-gray-300">Email Notifications</h3>
          <button
            onClick={() =>
              setSettings({ ...settings, email_enabled: !settings.email_enabled })
            }
            className={clsx(
              "relative inline-flex h-6 w-11 items-center rounded-full transition-colors",
              settings.email_enabled ? "bg-soc-accent" : "bg-gray-600"
            )}
          >
            <span
              className={clsx(
                "inline-block h-4 w-4 rounded-full bg-white transition-transform",
                settings.email_enabled ? "translate-x-6" : "translate-x-1"
              )}
            />
          </button>
        </div>
        {settings.email_enabled && (
          <input
            type="text"
            placeholder="Recipients (comma-separated)"
            value={settings.email_recipients.join(", ")}
            onChange={(e) =>
              setSettings({
                ...settings,
                email_recipients: e.target.value
                  .split(",")
                  .map((s) => s.trim())
                  .filter(Boolean),
              })
            }
            className="w-full bg-soc-bg border border-soc-border rounded px-3 py-2 text-sm text-white placeholder-gray-500"
          />
        )}
      </div>

      {/* Severity Filter */}
      <div className="card p-5 space-y-3">
        <h3 className="text-sm font-medium text-gray-300">Severity Filter</h3>
        <p className="text-xs text-gray-500">
          Only send notifications for selected severity levels.
        </p>
        <div className="flex gap-2">
          {severities.map((sev) => {
            const active = settings.severity_filter.includes(sev);
            return (
              <button
                key={sev}
                onClick={() => {
                  const next = active
                    ? settings.severity_filter.filter((s) => s !== sev)
                    : [...settings.severity_filter, sev];
                  setSettings({ ...settings, severity_filter: next });
                }}
                className={clsx(
                  "px-3 py-1.5 rounded text-xs font-medium transition-colors border",
                  active
                    ? sev === "critical"
                      ? "bg-red-400/20 text-red-400 border-red-400/30"
                      : sev === "high"
                      ? "bg-orange-400/20 text-orange-400 border-orange-400/30"
                      : sev === "medium"
                      ? "bg-yellow-400/20 text-yellow-400 border-yellow-400/30"
                      : "bg-blue-400/20 text-blue-400 border-blue-400/30"
                    : "bg-soc-surface text-gray-500 border-soc-border"
                )}
              >
                {sev}
              </button>
            );
          })}
        </div>
      </div>

      {/* Save Button */}
      <button
        onClick={handleSave}
        disabled={saving}
        className="px-6 py-2.5 bg-soc-accent text-white rounded-lg text-sm font-medium hover:bg-soc-accent/80 disabled:opacity-50 transition-colors"
      >
        {saving ? "Saving..." : "Save Notification Settings"}
      </button>
    </div>
  );
}

// ─── Shared Components ───────────────────────────────────

function SettingsRow({
  label,
  value,
  mono,
}: {
  label: string;
  value: string;
  mono?: boolean;
}) {
  return (
    <div className="flex items-center justify-between py-2">
      <span className="text-sm text-gray-400">{label}</span>
      <span
        className={`text-sm text-gray-200 ${mono ? "font-mono text-xs" : ""}`}
      >
        {value}
      </span>
    </div>
  );
}

function Spinner() {
  return (
    <div className="flex items-center justify-center py-16">
      <div className="w-6 h-6 border-2 border-soc-accent border-t-transparent rounded-full animate-spin" />
    </div>
  );
}
