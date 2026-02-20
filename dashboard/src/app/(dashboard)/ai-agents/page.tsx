"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { formatDistanceToNow } from "date-fns";
import {
  Bot,
  ShieldCheck,
  AlertTriangle,
  Shield,
  Zap,
  Brain,
  Lock,
  Activity,
} from "lucide-react";
import { clsx } from "clsx";
import { Header } from "@/components/header";
import { SeverityBadge } from "@/components/severity-badge";
import { apiFetch, type Alert } from "@/lib/api";

interface AiAgent {
  id: string;
  name: string;
  platform: string;
  model: string | null;
  status: string;
  environment: string;
}

interface ScorecardItem {
  id: string;
  risk: string;
  max_score: number;
  score: number;
  status: string;
}

interface Scorecard {
  tenant_id: string;
  scorecard: ScorecardItem[];
  overall_score: number;
}

const AI_EVENT_TYPES = [
  "ai_agent.prompt_injection",
  "ai_agent.jailbreak_attempt",
  "ai_agent.data_exfiltration",
  "ai_agent.guardrail_block",
  "ai_agent.token_abuse",
  "ai_agent.excessive_tool_calls",
  "ai_agent.tool_call_loop",
  "ai_agent.duplicate_tool_calls",
  "ai_agent.high_tool_error_rate",
  "ai_agent.hallucination",
];

const EVENT_TYPE_ICONS: Record<string, { icon: typeof Shield; color: string }> = {
  "ai_agent.prompt_injection": { icon: Lock, color: "text-red-400" },
  "ai_agent.jailbreak_attempt": { icon: AlertTriangle, color: "text-orange-400" },
  "ai_agent.data_exfiltration": { icon: Shield, color: "text-red-400" },
  "ai_agent.guardrail_block": { icon: ShieldCheck, color: "text-yellow-400" },
  "ai_agent.token_abuse": { icon: Zap, color: "text-purple-400" },
  "ai_agent.excessive_tool_calls": { icon: Activity, color: "text-blue-400" },
  "ai_agent.tool_call_loop": { icon: Activity, color: "text-red-400" },
  "ai_agent.duplicate_tool_calls": { icon: Activity, color: "text-yellow-400" },
  "ai_agent.high_tool_error_rate": { icon: AlertTriangle, color: "text-orange-400" },
  "ai_agent.hallucination": { icon: Brain, color: "text-pink-400" },
};

type TabKey = "overview" | "alerts" | "scorecard";

export default function AiAgentsPage() {
  const router = useRouter();
  const [agents, setAgents] = useState<AiAgent[]>([]);
  const [scorecard, setScorecard] = useState<Scorecard | null>(null);
  const [aiAlerts, setAiAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<TabKey>("overview");

  useEffect(() => {
    (async () => {
      try {
        const [agentData, scorecardData, alertData] = await Promise.all([
          apiFetch<AiAgent[]>("/api/v1/ai-agents"),
          apiFetch<Scorecard>("/api/v1/ai-agents/scorecard"),
          apiFetch<{ alerts: Alert[]; total: number }>(
            "/api/v1/alerts?source=langfuse&page_size=50"
          ).catch(() => ({ alerts: [], total: 0 })),
        ]);
        setAgents(agentData);
        setScorecard(scorecardData);

        // Also fetch nemo_guardrails alerts
        const grAlerts = await apiFetch<{ alerts: Alert[]; total: number }>(
          "/api/v1/alerts?source=nemo_guardrails&page_size=50"
        ).catch(() => ({ alerts: [], total: 0 }));

        // Merge and sort by created_at descending
        const allAiAlerts = [...alertData.alerts, ...grAlerts.alerts]
          .filter((a) => a.event_type.startsWith("ai_agent."))
          .sort(
            (a, b) =>
              new Date(b.created_at).getTime() - new Date(a.created_at).getTime()
          );
        setAiAlerts(allAiAlerts);
      } catch (err) {
        console.error("Failed to load AI agents:", err);
      } finally {
        setLoading(false);
      }
    })();
  }, []);

  if (loading) {
    return (
      <div>
        <Header title="AI Agent Monitor" />
        <div className="flex items-center justify-center py-32">
          <div className="w-6 h-6 border-2 border-soc-accent border-t-transparent rounded-full animate-spin" />
        </div>
      </div>
    );
  }

  // Compute stats
  const injectionCount = aiAlerts.filter(
    (a) => a.event_type === "ai_agent.prompt_injection"
  ).length;
  const jailbreakCount = aiAlerts.filter(
    (a) => a.event_type === "ai_agent.jailbreak_attempt"
  ).length;
  const exfilCount = aiAlerts.filter(
    (a) => a.event_type === "ai_agent.data_exfiltration"
  ).length;
  const guardrailCount = aiAlerts.filter(
    (a) => a.event_type === "ai_agent.guardrail_block"
  ).length;
  const toolAbuseCount = aiAlerts.filter((a) =>
    ["ai_agent.excessive_tool_calls", "ai_agent.tool_call_loop", "ai_agent.duplicate_tool_calls"].includes(
      a.event_type
    )
  ).length;
  const criticalCount = aiAlerts.filter((a) => a.severity === "critical").length;

  const TABS: { key: TabKey; label: string }[] = [
    { key: "overview", label: "Overview" },
    { key: "alerts", label: `Alerts (${aiAlerts.length})` },
    { key: "scorecard", label: "OWASP Scorecard" },
  ];

  return (
    <div>
      <Header title="AI Agent Monitor" />

      <div className="p-6 space-y-6">
        {/* KPI Row */}
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
          <KpiCard label="Injections" value={injectionCount} color="red" />
          <KpiCard label="Jailbreaks" value={jailbreakCount} color="orange" />
          <KpiCard label="Exfiltration" value={exfilCount} color="red" />
          <KpiCard label="Guardrail Blocks" value={guardrailCount} color="yellow" />
          <KpiCard label="Tool Abuse" value={toolAbuseCount} color="blue" />
          <KpiCard label="Critical" value={criticalCount} color="red" />
        </div>

        {/* Tab Navigation */}
        <div className="flex gap-1 border-b border-soc-border">
          {TABS.map((tab) => (
            <button
              key={tab.key}
              onClick={() => setActiveTab(tab.key)}
              className={clsx(
                "px-4 py-2 text-xs font-medium transition-colors border-b-2 -mb-px",
                activeTab === tab.key
                  ? "border-soc-accent text-white"
                  : "border-transparent text-gray-500 hover:text-gray-300"
              )}
            >
              {tab.label}
            </button>
          ))}
        </div>

        {/* Tab Content */}
        {activeTab === "overview" && (
          <div className="space-y-6">
            {/* Monitored Agents */}
            <div className="card">
              <div className="flex items-center gap-2 px-5 py-4 border-b border-soc-border">
                <Bot className="w-4 h-4 text-purple-400" />
                <h3 className="text-sm font-semibold text-white">Monitored Agents</h3>
                <span className="text-xs text-gray-500">({agents.length})</span>
              </div>
              <div className="p-5">
                {agents.length === 0 ? (
                  <p className="text-sm text-gray-500 text-center py-12">
                    No AI agents registered yet. Agents will appear here when
                    monitoring is configured via Langfuse or NeMo Guardrails webhooks.
                  </p>
                ) : (
                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                    {agents.map((agent) => (
                      <div
                        key={agent.id}
                        className="bg-soc-bg border border-soc-border rounded-lg p-4"
                      >
                        <div className="flex items-center gap-2 mb-2">
                          <span
                            className={clsx(
                              "w-2 h-2 rounded-full",
                              agent.status === "active" ? "bg-green-500" : "bg-gray-600"
                            )}
                          />
                          <span className="text-sm font-medium text-white">{agent.name}</span>
                        </div>
                        <div className="space-y-1 text-xs text-gray-400">
                          <div>
                            Platform: <span className="text-gray-300">{agent.platform}</span>
                          </div>
                          {agent.model && (
                            <div>
                              Model:{" "}
                              <span className="text-gray-300 font-mono">{agent.model}</span>
                            </div>
                          )}
                          <div>
                            Env: <span className="text-gray-300">{agent.environment}</span>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>

            {/* Recent AI Security Alerts */}
            <div className="card">
              <div className="flex items-center gap-2 px-5 py-4 border-b border-soc-border">
                <AlertTriangle className="w-4 h-4 text-yellow-400" />
                <h3 className="text-sm font-semibold text-white">Recent AI Security Alerts</h3>
                <span className="text-xs text-gray-500">
                  (latest {Math.min(aiAlerts.length, 10)})
                </span>
              </div>
              {aiAlerts.length === 0 ? (
                <div className="text-center py-16 px-5">
                  <Brain className="h-10 w-10 text-gray-600 mx-auto mb-3" />
                  <p className="text-sm text-gray-500">
                    No AI agent security alerts yet. Alerts will appear when the AI
                    Agent Monitor detects prompt injection, tool abuse, or other anomalies.
                  </p>
                </div>
              ) : (
                <div className="divide-y divide-soc-border/50">
                  {aiAlerts.slice(0, 10).map((alert) => {
                    const typeInfo = EVENT_TYPE_ICONS[alert.event_type] || {
                      icon: Shield,
                      color: "text-gray-400",
                    };
                    const Icon = typeInfo.icon;
                    return (
                      <div
                        key={alert.id}
                        onClick={() => router.push(`/alerts/${alert.id}`)}
                        className="px-5 py-4 hover:bg-soc-surface/50 cursor-pointer transition-colors flex items-center gap-4"
                      >
                        <Icon className={clsx("w-4 h-4 shrink-0", typeInfo.color)} />
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 mb-1">
                            <SeverityBadge severity={alert.severity} />
                            <span className="text-[10px] font-mono text-gray-500">
                              {alert.event_type.replace("ai_agent.", "")}
                            </span>
                          </div>
                          <h4 className="text-sm text-white truncate">{alert.title}</h4>
                        </div>
                        <span className="text-xs text-gray-500 whitespace-nowrap shrink-0">
                          {formatDistanceToNow(new Date(alert.created_at), {
                            addSuffix: true,
                          })}
                        </span>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>

            {/* Detection Coverage */}
            <div className="card">
              <div className="flex items-center gap-2 px-5 py-4 border-b border-soc-border">
                <Shield className="w-4 h-4 text-green-400" />
                <h3 className="text-sm font-semibold text-white">Detection Rules</h3>
              </div>
              <div className="p-5 grid grid-cols-1 md:grid-cols-2 gap-3">
                {AI_EVENT_TYPES.map((et) => {
                  const typeInfo = EVENT_TYPE_ICONS[et] || {
                    icon: Shield,
                    color: "text-gray-400",
                  };
                  const Icon = typeInfo.icon;
                  const count = aiAlerts.filter((a) => a.event_type === et).length;
                  return (
                    <div
                      key={et}
                      className="flex items-center gap-3 bg-soc-bg rounded-lg px-4 py-3 border border-soc-border"
                    >
                      <Icon className={clsx("w-4 h-4 shrink-0", typeInfo.color)} />
                      <div className="flex-1 min-w-0">
                        <span className="text-xs text-gray-300">
                          {et.replace("ai_agent.", "").replace(/_/g, " ")}
                        </span>
                      </div>
                      <span
                        className={clsx(
                          "text-xs font-mono",
                          count > 0 ? "text-white" : "text-gray-600"
                        )}
                      >
                        {count}
                      </span>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        )}

        {activeTab === "alerts" && (
          <div className="card">
            <div className="flex items-center gap-2 px-5 py-4 border-b border-soc-border">
              <AlertTriangle className="w-4 h-4 text-yellow-400" />
              <h3 className="text-sm font-semibold text-white">All AI Agent Alerts</h3>
              <span className="text-xs text-gray-500">({aiAlerts.length})</span>
            </div>
            {aiAlerts.length === 0 ? (
              <div className="text-center py-16 px-5">
                <Brain className="h-10 w-10 text-gray-600 mx-auto mb-3" />
                <p className="text-sm text-gray-500">No AI agent alerts detected yet.</p>
              </div>
            ) : (
              <div className="divide-y divide-soc-border/50">
                {aiAlerts.map((alert) => {
                  const typeInfo = EVENT_TYPE_ICONS[alert.event_type] || {
                    icon: Shield,
                    color: "text-gray-400",
                  };
                  const Icon = typeInfo.icon;
                  return (
                    <div
                      key={alert.id}
                      onClick={() => router.push(`/alerts/${alert.id}`)}
                      className="px-5 py-4 hover:bg-soc-surface/50 cursor-pointer transition-colors"
                    >
                      <div className="flex items-center gap-3">
                        <Icon className={clsx("w-4 h-4 shrink-0", typeInfo.color)} />
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 mb-1">
                            <SeverityBadge severity={alert.severity} />
                            <span className="text-[10px] font-mono text-gray-500 uppercase">
                              {alert.event_type.replace("ai_agent.", "")}
                            </span>
                            <span className="text-[10px] text-gray-600">
                              {alert.source}
                            </span>
                          </div>
                          <h4 className="text-sm text-white truncate">{alert.title}</h4>
                          {alert.description && (
                            <p className="text-xs text-gray-400 mt-1 truncate max-w-3xl">
                              {alert.description}
                            </p>
                          )}
                        </div>
                        <span className="text-xs text-gray-500 whitespace-nowrap shrink-0">
                          {formatDistanceToNow(new Date(alert.created_at), {
                            addSuffix: true,
                          })}
                        </span>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        )}

        {activeTab === "scorecard" && scorecard && (
          <div className="card">
            <div className="flex items-center justify-between px-5 py-4 border-b border-soc-border">
              <div className="flex items-center gap-2">
                <ShieldCheck className="w-4 h-4 text-green-400" />
                <h3 className="text-sm font-semibold text-white">
                  OWASP Agentic Top 10 Scorecard
                </h3>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-2xl font-bold text-white">
                  {scorecard.overall_score}
                </span>
                <span className="text-xs text-gray-500">/ 100</span>
              </div>
            </div>
            <div className="p-5">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {scorecard.scorecard.map((item) => (
                  <div
                    key={item.id}
                    className="flex items-center gap-3 bg-soc-bg rounded-lg px-4 py-3 border border-soc-border"
                  >
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-mono text-gray-500">{item.id}</span>
                        <StatusIndicator status={item.status} />
                      </div>
                      <div className="text-sm text-gray-300 truncate mt-0.5">
                        {item.risk}
                      </div>
                    </div>
                    <div className="text-right">
                      <div className="text-sm font-mono text-white">
                        {item.score}/{item.max_score}
                      </div>
                      <div className="w-20 h-1.5 bg-soc-border rounded-full mt-1 overflow-hidden">
                        <div
                          className={clsx(
                            "h-full rounded-full transition-all",
                            item.score / item.max_score > 0.7
                              ? "bg-green-500"
                              : item.score / item.max_score > 0.4
                                ? "bg-yellow-500"
                                : "bg-red-500"
                          )}
                          style={{
                            width: `${(item.score / item.max_score) * 100}%`,
                          }}
                        />
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

function KpiCard({
  label,
  value,
  color,
}: {
  label: string;
  value: number;
  color: string;
}) {
  const colorMap: Record<string, string> = {
    red: "text-red-400",
    orange: "text-orange-400",
    yellow: "text-yellow-400",
    blue: "text-blue-400",
    green: "text-green-400",
    purple: "text-purple-400",
  };
  return (
    <div className="card p-4">
      <p className="text-xs text-gray-500 uppercase tracking-wider">{label}</p>
      <p className={clsx("text-2xl font-bold mt-1", value > 0 ? colorMap[color] : "text-gray-600")}>
        {value}
      </p>
    </div>
  );
}

function StatusIndicator({ status }: { status: string }) {
  const colors: Record<string, string> = {
    ACTIVE: "bg-green-500/20 text-green-400",
    PARTIAL: "bg-yellow-500/20 text-yellow-400",
    PLANNED: "bg-gray-500/20 text-gray-400",
    LOGGING: "bg-blue-500/20 text-blue-400",
  };
  return (
    <span
      className={clsx(
        "px-1.5 py-0.5 rounded text-[10px] font-medium uppercase",
        colors[status] || colors.PLANNED
      )}
    >
      {status}
    </span>
  );
}
