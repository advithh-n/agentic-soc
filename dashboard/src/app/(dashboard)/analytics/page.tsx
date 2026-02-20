"use client";

import { useEffect, useState } from "react";
import {
  BarChart3,
  Clock,
  Zap,
  Target,
  Shield,
  AlertTriangle,
  Activity,
  TrendingUp,
  Eye,
  Bot,
} from "lucide-react";
import { Header } from "@/components/header";
import { StatsCard } from "@/components/stats-card";
import {
  getAnalyticsOverview,
  getMitreHeatmap,
  getAlertTimeline,
  getAgentPerformance,
  getActionBreakdown,
  type AnalyticsOverview,
  type MitreHeatmap,
  type AlertTimeline,
  type AgentPerformance,
  type ActionBreakdown,
} from "@/lib/api";

// MITRE technique labels
const TECHNIQUE_NAMES: Record<string, string> = {
  "T1110": "Brute Force",
  "T1110.004": "Credential Stuffing",
  "T1078": "Valid Accounts",
  "T1078.004": "Cloud Accounts",
  "T1530": "Data from Cloud Storage",
  "T1106": "Native API",
  "AML.T0051": "Prompt Injection",
  "AML.T0054": "Jailbreak",
  "AML.T0024": "Data Exfiltration",
  "AML.T0040": "Model Extraction",
  "AML.T0043": "Denial of Service",
};

const SEVERITY_COLORS: Record<string, string> = {
  critical: "bg-red-500",
  high: "bg-orange-500",
  medium: "bg-yellow-500",
  low: "bg-blue-500",
};

function formatDuration(seconds: number | null): string {
  if (!seconds) return "N/A";
  if (seconds < 60) return `${Math.round(seconds)}s`;
  if (seconds < 3600) return `${Math.round(seconds / 60)}m`;
  return `${(seconds / 3600).toFixed(1)}h`;
}

export default function AnalyticsPage() {
  const [overview, setOverview] = useState<AnalyticsOverview | null>(null);
  const [mitre, setMitre] = useState<MitreHeatmap | null>(null);
  const [timeline, setTimeline] = useState<AlertTimeline | null>(null);
  const [agent, setAgent] = useState<AgentPerformance | null>(null);
  const [actionBreakdown, setActionBreakdown] = useState<ActionBreakdown | null>(null);
  const [loading, setLoading] = useState(true);
  const [tab, setTab] = useState<"overview" | "mitre" | "agents" | "actions">("overview");

  useEffect(() => {
    async function load() {
      try {
        const [o, m, t, a, ab] = await Promise.all([
          getAnalyticsOverview(),
          getMitreHeatmap(),
          getAlertTimeline(48),
          getAgentPerformance(),
          getActionBreakdown(),
        ]);
        setOverview(o);
        setMitre(m);
        setTimeline(t);
        setAgent(a);
        setActionBreakdown(ab);
      } catch (err) {
        console.error("Failed to load analytics:", err);
      } finally {
        setLoading(false);
      }
    }
    load();
    const interval = setInterval(load, 30000);
    return () => clearInterval(interval);
  }, []);

  if (loading) {
    return (
      <div className="p-6">
        <Header title="SOC Analytics" subtitle="Loading metrics..." />
        <div className="mt-8 flex items-center justify-center">
          <div className="animate-spin rounded-full h-8 w-8 border-t-2 border-soc-accent" />
        </div>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      <Header title="SOC Analytics" subtitle="Detection rates, agent performance, response automation metrics" />

      {/* Tab bar */}
      <div className="flex gap-1 bg-soc-surface rounded-lg p-1 w-fit">
        {(["overview", "mitre", "agents", "actions"] as const).map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`px-4 py-2 rounded-md text-sm font-medium transition-colors ${
              tab === t ? "bg-soc-accent text-white" : "text-gray-400 hover:text-white"
            }`}
          >
            {t === "overview" ? "Overview" : t === "mitre" ? "MITRE Heatmap" : t === "agents" ? "Agent Performance" : "Response Actions"}
          </button>
        ))}
      </div>

      {/* Overview Tab */}
      {tab === "overview" && overview && (
        <>
          {/* KPI Row 1: Alert Metrics */}
          <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-4">
            <StatsCard label="Total Alerts" value={overview.alerts.total} icon={<AlertTriangle className="w-5 h-5" />} />
            <StatsCard label="Last 24h" value={overview.alerts.last_24h} icon={<Clock className="w-5 h-5" />} accentColor="bg-blue-500" />
            <StatsCard label="Last Hour" value={overview.alerts.last_1h} icon={<Zap className="w-5 h-5" />} accentColor="bg-yellow-500" />
            <StatsCard label="MTTD" value={formatDuration(overview.mttd_seconds)} icon={<Eye className="w-5 h-5" />} accentColor="bg-green-500" />
            <StatsCard label="MTTR" value={formatDuration(overview.mttr_seconds)} icon={<Target className="w-5 h-5" />} accentColor="bg-purple-500" />
            <StatsCard label="Incidents" value={overview.incidents.total} icon={<Shield className="w-5 h-5" />} accentColor="bg-red-500" />
          </div>

          {/* KPI Row 2: Response Automation */}
          <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-5 gap-4">
            <StatsCard label="Actions Executed" value={overview.response_actions.executed} icon={<Activity className="w-5 h-5" />} accentColor="bg-green-500" />
            <StatsCard label="Pending Approval" value={overview.response_actions.pending} icon={<Clock className="w-5 h-5" />} accentColor="bg-yellow-500" />
            <StatsCard label="Failed" value={overview.response_actions.failed} icon={<AlertTriangle className="w-5 h-5" />} accentColor="bg-red-500" />
            <StatsCard label="Execution Traces" value={overview.execution_traces.toLocaleString()} icon={<BarChart3 className="w-5 h-5" />} accentColor="bg-blue-500" />
            <StatsCard label="Auto-Risk" value={overview.response_actions.by_risk.auto} icon={<Zap className="w-5 h-5" />} accentColor="bg-cyan-500" />
          </div>

          {/* Severity Distribution + Module Performance */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Severity Distribution */}
            <div className="card p-6">
              <h3 className="text-sm font-medium text-gray-400 uppercase tracking-wider mb-4">Alert Severity Distribution</h3>
              <div className="space-y-3">
                {Object.entries(overview.alerts.by_severity).map(([sev, count]) => {
                  const pct = overview.alerts.total > 0 ? (count / overview.alerts.total) * 100 : 0;
                  return (
                    <div key={sev} className="flex items-center gap-3">
                      <span className="text-xs text-gray-400 uppercase w-16">{sev}</span>
                      <div className="flex-1 h-6 bg-gray-800 rounded overflow-hidden">
                        <div
                          className={`h-full ${SEVERITY_COLORS[sev]} rounded transition-all`}
                          style={{ width: `${pct}%` }}
                        />
                      </div>
                      <span className="text-sm text-white font-mono w-16 text-right">{count}</span>
                      <span className="text-xs text-gray-500 w-12 text-right">{pct.toFixed(1)}%</span>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Module Performance */}
            <div className="card p-6">
              <h3 className="text-sm font-medium text-gray-400 uppercase tracking-wider mb-4">Detection Module Performance</h3>
              <div className="space-y-3">
                {overview.modules.map((mod) => (
                  <div key={mod.module} className="flex items-center justify-between py-2 border-b border-gray-800 last:border-0">
                    <div>
                      <span className="text-sm text-white font-medium">{mod.module.replace("_", " ").replace(/\b\w/g, (l) => l.toUpperCase())}</span>
                      <span className="text-xs text-gray-500 ml-2">{mod.rule_count} rules</span>
                    </div>
                    <span className="text-lg font-bold text-soc-accent">{mod.alert_count}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Alert Timeline */}
          {timeline && timeline.buckets.length > 0 && (
            <div className="card p-6">
              <h3 className="text-sm font-medium text-gray-400 uppercase tracking-wider mb-4">Alert Volume (Last 48h)</h3>
              <div className="flex items-end gap-1 h-40">
                {timeline.buckets.map((bucket, i) => {
                  const maxVal = Math.max(...timeline.buckets.map((b) => b.total), 1);
                  const height = (bucket.total / maxVal) * 100;
                  return (
                    <div
                      key={i}
                      className="flex-1 flex flex-col items-center gap-1 group relative"
                    >
                      <div
                        className="w-full bg-soc-accent/80 rounded-t hover:bg-soc-accent transition-colors cursor-pointer"
                        style={{ height: `${Math.max(height, 2)}%` }}
                        title={`${new Date(bucket.timestamp).toLocaleString()}: ${bucket.total} alerts (C:${bucket.critical} H:${bucket.high} M:${bucket.medium} L:${bucket.low})`}
                      />
                    </div>
                  );
                })}
              </div>
              <div className="flex justify-between mt-2 text-[10px] text-gray-600">
                <span>{timeline.buckets[0] ? new Date(timeline.buckets[0].timestamp).toLocaleDateString() : ""}</span>
                <span>Now</span>
              </div>
            </div>
          )}
        </>
      )}

      {/* MITRE Heatmap Tab */}
      {tab === "mitre" && mitre && (
        <div className="space-y-6">
          <StatsCard
            label="Total Techniques Detected"
            value={mitre.total_techniques}
            icon={<Target className="w-5 h-5" />}
            accentColor="bg-red-500"
          />

          {/* MITRE ATT&CK */}
          {mitre.mitre.length > 0 && (
            <div className="card p-6">
              <h3 className="text-sm font-medium text-gray-400 uppercase tracking-wider mb-4">MITRE ATT&CK Techniques</h3>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                {mitre.mitre.map((t, i) => {
                  const intensity = Math.min(t.hits / 50, 1);
                  return (
                    <div
                      key={i}
                      className="p-4 rounded-lg border border-gray-800 hover:border-gray-600 transition-colors"
                      style={{
                        background: `rgba(239, 68, 68, ${0.05 + intensity * 0.2})`,
                      }}
                    >
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-mono text-red-400">{t.technique_id}</span>
                        <span className={`text-xs px-2 py-0.5 rounded ${SEVERITY_COLORS[t.max_severity]}/20 text-${t.max_severity === "critical" ? "red" : t.max_severity === "high" ? "orange" : "yellow"}-400`}>
                          {t.max_severity}
                        </span>
                      </div>
                      <div className="text-sm text-white mt-1">{TECHNIQUE_NAMES[t.technique_id] || t.event_type}</div>
                      <div className="flex items-center justify-between mt-2">
                        <span className="text-xs text-gray-500">{t.event_type}</span>
                        <span className="text-lg font-bold text-red-400">{t.hits}</span>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* MITRE ATLAS */}
          {mitre.atlas.length > 0 && (
            <div className="card p-6">
              <h3 className="text-sm font-medium text-gray-400 uppercase tracking-wider mb-4">MITRE ATLAS (AI Security) Techniques</h3>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                {mitre.atlas.map((t, i) => {
                  const intensity = Math.min(t.hits / 30, 1);
                  return (
                    <div
                      key={i}
                      className="p-4 rounded-lg border border-gray-800 hover:border-gray-600 transition-colors"
                      style={{
                        background: `rgba(168, 85, 247, ${0.05 + intensity * 0.2})`,
                      }}
                    >
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-mono text-purple-400">{t.technique_id}</span>
                        <span className="text-xs text-gray-500">{t.max_severity}</span>
                      </div>
                      <div className="text-sm text-white mt-1">{TECHNIQUE_NAMES[t.technique_id] || t.event_type}</div>
                      <div className="flex items-center justify-between mt-2">
                        <span className="text-xs text-gray-500">{t.event_type}</span>
                        <span className="text-lg font-bold text-purple-400">{t.hits}</span>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {mitre.mitre.length === 0 && mitre.atlas.length === 0 && (
            <div className="card p-12 text-center text-gray-500">
              No MITRE technique data available yet. Run attack simulations to populate.
            </div>
          )}
        </div>
      )}

      {/* Agent Performance Tab */}
      {tab === "agents" && agent && (
        <div className="space-y-6">
          <div className="flex items-center gap-3 mb-2">
            <span className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-medium ${
              agent.status === "running" ? "bg-green-500/15 text-green-400" : "bg-red-500/15 text-red-400"
            }`}>
              <span className={`w-2 h-2 rounded-full ${agent.status === "running" ? "bg-green-400 animate-pulse" : "bg-red-400"}`} />
              {agent.status}
            </span>
            <span className="text-xs text-gray-500">Mode: {agent.mode}</span>
          </div>

          <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-5 gap-4">
            <StatsCard label="Alerts Triaged" value={agent.alerts_triaged} icon={<Eye className="w-5 h-5" />} />
            <StatsCard label="Escalations" value={agent.escalations} icon={<TrendingUp className="w-5 h-5" />} accentColor="bg-orange-500" />
            <StatsCard label="Investigations" value={agent.investigations} icon={<Shield className="w-5 h-5" />} accentColor="bg-blue-500" />
            <StatsCard label="Incidents Created" value={agent.incidents_created} icon={<AlertTriangle className="w-5 h-5" />} accentColor="bg-red-500" />
            <StatsCard label="Critic Reviews" value={agent.critic_reviews} icon={<Bot className="w-5 h-5" />} accentColor="bg-purple-500" />
          </div>

          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <StatsCard label="Actions Approved" value={agent.actions_approved} icon={<Activity className="w-5 h-5" />} accentColor="bg-green-500" />
            <StatsCard label="Actions Denied" value={agent.actions_denied} icon={<AlertTriangle className="w-5 h-5" />} accentColor="bg-red-500" />
            <StatsCard label="Actions Escalated" value={agent.actions_escalated} icon={<TrendingUp className="w-5 h-5" />} accentColor="bg-yellow-500" />
            <StatsCard label="Playbooks Run" value={agent.playbooks_run} icon={<Zap className="w-5 h-5" />} accentColor="bg-cyan-500" />
          </div>

          {/* Triage Verdicts */}
          <div className="card p-6">
            <h3 className="text-sm font-medium text-gray-400 uppercase tracking-wider mb-4">Triage Verdict Distribution</h3>
            <div className="grid grid-cols-3 gap-4">
              {Object.entries(agent.verdicts).map(([verdict, count]) => (
                <div key={verdict} className="text-center p-4 rounded-lg bg-gray-800/50">
                  <div className="text-2xl font-bold text-white">{count}</div>
                  <div className="text-xs text-gray-400 mt-1">{verdict.replace("_", " ")}</div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Response Actions Tab */}
      {tab === "actions" && actionBreakdown && (
        <div className="space-y-6">
          {overview && (
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <StatsCard label="Total Actions" value={overview.response_actions.total} icon={<Activity className="w-5 h-5" />} />
              <StatsCard label="Executed" value={overview.response_actions.executed} icon={<Zap className="w-5 h-5" />} accentColor="bg-green-500" />
              <StatsCard label="Pending" value={overview.response_actions.pending} icon={<Clock className="w-5 h-5" />} accentColor="bg-yellow-500" />
              <StatsCard label="Failed" value={overview.response_actions.failed} icon={<AlertTriangle className="w-5 h-5" />} accentColor="bg-red-500" />
            </div>
          )}

          <div className="card overflow-hidden">
            <div className="p-4 border-b border-gray-800">
              <h3 className="text-sm font-medium text-gray-400 uppercase tracking-wider">Action Breakdown by Type</h3>
            </div>
            <table className="w-full">
              <thead>
                <tr className="border-b border-gray-800 text-xs text-gray-500 uppercase">
                  <th className="text-left px-4 py-3">Action Type</th>
                  <th className="text-left px-4 py-3">Risk Level</th>
                  <th className="text-left px-4 py-3">Status</th>
                  <th className="text-right px-4 py-3">Count</th>
                  <th className="text-left px-4 py-3">Source</th>
                </tr>
              </thead>
              <tbody>
                {actionBreakdown.actions.map((a, i) => (
                  <tr key={i} className="border-b border-gray-800/50 hover:bg-white/[0.02]">
                    <td className="px-4 py-3 text-sm text-white font-mono">{a.action_type}</td>
                    <td className="px-4 py-3">
                      <span className={`text-xs px-2 py-0.5 rounded ${
                        a.risk_level === "auto" ? "bg-green-500/15 text-green-400" :
                        a.risk_level === "high" ? "bg-orange-500/15 text-orange-400" :
                        "bg-red-500/15 text-red-400"
                      }`}>
                        {a.risk_level}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <span className={`text-xs px-2 py-0.5 rounded ${
                        a.status === "executed" ? "bg-green-500/15 text-green-400" :
                        a.status === "pending" ? "bg-yellow-500/15 text-yellow-400" :
                        a.status === "failed" ? "bg-red-500/15 text-red-400" :
                        "bg-gray-500/15 text-gray-400"
                      }`}>
                        {a.status}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-right text-sm font-bold text-white">{a.count}</td>
                    <td className="px-4 py-3 text-xs text-gray-500">{a.proposed_by}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
