"use client";

import { useEffect, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import {
  ArrowLeft,
  Shield,
  Clock,
  Target,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Activity,
  ChevronDown,
  ChevronRight,
  PlayCircle,
  BookOpen,
  FileText,
} from "lucide-react";
import { format } from "date-fns";
import { SeverityBadge, StatusBadge } from "@/components/severity-badge";
import {
  getIncidentDetail,
  getTraces,
  getPlaybooks,
  runPlaybook,
  getIncidentReport,
  type IncidentDetail,
  type TraceStep,
  type Playbook,
} from "@/lib/api";

const RISK_COLORS: Record<string, string> = {
  auto: "text-green-400 bg-green-400/10 border-green-400/30",
  low: "text-blue-400 bg-blue-400/10 border-blue-400/30",
  high: "text-orange-400 bg-orange-400/10 border-orange-400/30",
  critical: "text-red-400 bg-red-400/10 border-red-400/30",
};

const STATUS_ICONS: Record<string, typeof CheckCircle> = {
  approved: CheckCircle,
  executed: CheckCircle,
  denied: XCircle,
  pending: Clock,
};

const STATUS_COLORS: Record<string, string> = {
  approved: "text-green-400",
  executed: "text-green-400",
  denied: "text-red-400",
  pending: "text-yellow-400",
};

export default function IncidentDetailPage() {
  const params = useParams();
  const router = useRouter();
  const id = params.id as string;

  const [incident, setIncident] = useState<IncidentDetail | null>(null);
  const [traces, setTraces] = useState<TraceStep[]>([]);
  const [loading, setLoading] = useState(true);
  const [expandedTrace, setExpandedTrace] = useState<string | null>(null);
  const [playbooks, setPlaybooks] = useState<Playbook[]>([]);
  const [playbookRunning, setPlaybookRunning] = useState<string | null>(null);
  const [playbookMessage, setPlaybookMessage] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<"overview" | "alerts" | "actions" | "timeline" | "traces" | "playbooks" | "report">("overview");
  const [reportData, setReportData] = useState<Record<string, unknown> | null>(null);
  const [reportLoading, setReportLoading] = useState(false);

  useEffect(() => {
    async function load() {
      try {
        const inc = await getIncidentDetail(id);
        setIncident(inc);

        // Load traces from first linked alert
        if (inc.alerts.length > 0) {
          const traceData = await getTraces({ alert_id: inc.alerts[0].id });
          setTraces(traceData.steps);
        }

        // Load playbooks
        try {
          const pbs = await getPlaybooks();
          setPlaybooks(pbs);
        } catch {
          // Playbook API may not be available yet
        }
      } catch (e) {
        console.error("Failed to load incident", e);
      } finally {
        setLoading(false);
      }
    }
    load();
  }, [id]);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin h-8 w-8 border-2 border-soc-accent border-t-transparent rounded-full" />
      </div>
    );
  }

  if (!incident) {
    return (
      <div className="text-center py-16 text-gray-400">
        Incident not found.
      </div>
    );
  }

  const blastRadius = incident.blast_radius || {};
  const affectedIps = (blastRadius.affected_ips as Array<{ value: string }>) || [];
  const affectedUsers = (blastRadius.affected_users as Array<{ value: string }>) || [];
  const affectedServices = (blastRadius.affected_services as Array<{ value: string }>) || [];
  const totalEntities = (blastRadius.total_entities as number) || 0;

  const tabs = [
    { key: "overview", label: "Overview" },
    { key: "alerts", label: `Alerts (${incident.alert_count})` },
    { key: "actions", label: `Actions (${incident.response_actions.length})` },
    { key: "timeline", label: "Timeline" },
    { key: "traces", label: "Agent Traces" },
    { key: "playbooks", label: "Playbooks" },
    { key: "report", label: "Report" },
  ] as const;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start gap-4">
        <button
          onClick={() => router.push("/incidents")}
          className="mt-1 p-2 rounded-lg hover:bg-soc-surface transition-colors text-gray-400 hover:text-white"
        >
          <ArrowLeft className="h-5 w-5" />
        </button>
        <div className="flex-1">
          <div className="flex items-center gap-3 mb-2">
            <SeverityBadge severity={incident.severity} />
            <StatusBadge status={incident.status} />
          </div>
          <h1 className="text-2xl font-bold text-white">{incident.title}</h1>
          {incident.description && (
            <p className="text-gray-400 mt-1 text-sm max-w-3xl">
              {incident.description.slice(0, 200)}
            </p>
          )}
          <p className="text-gray-500 text-xs mt-2">
            Created {format(new Date(incident.created_at), "PPpp")}
          </p>
        </div>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="card p-4">
          <div className="flex items-center gap-2 text-gray-400 text-xs mb-1">
            <AlertTriangle className="h-3.5 w-3.5" />
            Linked Alerts
          </div>
          <div className="text-2xl font-bold text-white">{incident.alert_count}</div>
        </div>
        <div className="card p-4">
          <div className="flex items-center gap-2 text-gray-400 text-xs mb-1">
            <Shield className="h-3.5 w-3.5" />
            Response Actions
          </div>
          <div className="text-2xl font-bold text-white">{incident.response_actions.length}</div>
        </div>
        <div className="card p-4">
          <div className="flex items-center gap-2 text-gray-400 text-xs mb-1">
            <Target className="h-3.5 w-3.5" />
            Blast Radius
          </div>
          <div className="text-2xl font-bold text-white">{totalEntities} entities</div>
        </div>
        <div className="card p-4">
          <div className="flex items-center gap-2 text-gray-400 text-xs mb-1">
            <Activity className="h-3.5 w-3.5" />
            Agent Steps
          </div>
          <div className="text-2xl font-bold text-white">{traces.length}</div>
        </div>
      </div>

      {/* Tab Navigation */}
      <div className="flex gap-1 border-b border-soc-border">
        {tabs.map((tab) => (
          <button
            key={tab.key}
            onClick={() => setActiveTab(tab.key)}
            className={`px-4 py-2 text-sm font-medium transition-colors ${
              activeTab === tab.key
                ? "text-soc-accent border-b-2 border-soc-accent"
                : "text-gray-400 hover:text-white"
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* Tab Content */}
      {activeTab === "overview" && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Root Cause */}
          <div className="card p-5">
            <h3 className="text-sm font-semibold text-gray-300 mb-3 flex items-center gap-2">
              <Target className="h-4 w-4 text-red-400" />
              Root Cause Analysis
            </h3>
            <p className="text-gray-300 text-sm leading-relaxed whitespace-pre-line">
              {incident.root_cause
                ? incident.root_cause.split("\n").filter((line, i, arr) =>
                    arr.indexOf(line) === i
                  ).slice(0, 5).join("\n")
                : "Root cause pending analysis."}
            </p>
          </div>

          {/* Blast Radius */}
          <div className="card p-5">
            <h3 className="text-sm font-semibold text-gray-300 mb-3 flex items-center gap-2">
              <Shield className="h-4 w-4 text-orange-400" />
              Blast Radius
            </h3>
            {totalEntities > 0 ? (
              <div className="space-y-3">
                {affectedIps.length > 0 && (
                  <div>
                    <span className="text-xs text-gray-500">IPs</span>
                    <div className="flex flex-wrap gap-1.5 mt-1">
                      {affectedIps.slice(0, 10).map((ip, i) => (
                        <span key={i} className="px-2 py-0.5 bg-red-400/10 text-red-300 rounded text-xs font-mono">
                          {ip.value}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
                {affectedUsers.length > 0 && (
                  <div>
                    <span className="text-xs text-gray-500">Users</span>
                    <div className="flex flex-wrap gap-1.5 mt-1">
                      {affectedUsers.slice(0, 10).map((u, i) => (
                        <span key={i} className="px-2 py-0.5 bg-blue-400/10 text-blue-300 rounded text-xs font-mono">
                          {u.value}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
                {affectedServices.length > 0 && (
                  <div>
                    <span className="text-xs text-gray-500">Services</span>
                    <div className="flex flex-wrap gap-1.5 mt-1">
                      {affectedServices.slice(0, 10).map((s, i) => (
                        <span key={i} className="px-2 py-0.5 bg-purple-400/10 text-purple-300 rounded text-xs font-mono">
                          {s.value}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            ) : (
              <p className="text-gray-500 text-sm">No blast radius data available.</p>
            )}
          </div>
        </div>
      )}

      {activeTab === "alerts" && (
        <div className="card overflow-hidden">
          <table className="w-full">
            <thead>
              <tr className="border-b border-soc-border text-left text-xs text-gray-500">
                <th className="px-4 py-3">Severity</th>
                <th className="px-4 py-3">Title</th>
                <th className="px-4 py-3">Type</th>
                <th className="px-4 py-3">Status</th>
                <th className="px-4 py-3">Confidence</th>
                <th className="px-4 py-3">Created</th>
              </tr>
            </thead>
            <tbody>
              {incident.alerts.map((alert) => (
                <tr
                  key={alert.id}
                  onClick={() => router.push(`/alerts/${alert.id}`)}
                  className="border-b border-soc-border/50 hover:bg-soc-surface/50 cursor-pointer transition-colors"
                >
                  <td className="px-4 py-3">
                    <SeverityBadge severity={alert.severity} />
                  </td>
                  <td className="px-4 py-3 text-sm text-gray-200 max-w-xs truncate">
                    {alert.title}
                  </td>
                  <td className="px-4 py-3">
                    <span className="text-xs font-mono text-gray-400">{alert.event_type}</span>
                  </td>
                  <td className="px-4 py-3">
                    <StatusBadge status={alert.status} />
                  </td>
                  <td className="px-4 py-3 text-sm text-gray-400">
                    {alert.confidence != null ? `${(alert.confidence * 100).toFixed(0)}%` : "—"}
                  </td>
                  <td className="px-4 py-3 text-xs text-gray-500">
                    {format(new Date(alert.created_at), "MMM d, HH:mm")}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {incident.alerts.length === 0 && (
            <div className="text-center py-8 text-gray-500">No alerts linked.</div>
          )}
        </div>
      )}

      {activeTab === "actions" && (
        <div className="space-y-3">
          {incident.response_actions.map((action) => {
            const StatusIcon = STATUS_ICONS[action.status] || Clock;
            const statusColor = STATUS_COLORS[action.status] || "text-gray-400";
            const criticDecision = action.critic_review
              ? (action.critic_review as Record<string, string>).decision
              : null;

            return (
              <div key={action.id} className="card p-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <span className={`px-2 py-0.5 rounded border text-xs font-medium ${RISK_COLORS[action.risk_level] || RISK_COLORS.high}`}>
                      {action.risk_level.toUpperCase()}
                    </span>
                    <span className="text-sm text-white font-medium">
                      {action.action_type.replace(/_/g, " ")}
                    </span>
                    <span className="text-xs text-purple-400">
                      by {action.proposed_by}
                    </span>
                  </div>
                  <div className="flex items-center gap-2">
                    <StatusIcon className={`h-4 w-4 ${statusColor}`} />
                    <span className={`text-xs font-medium ${statusColor}`}>
                      {action.status}
                    </span>
                  </div>
                </div>
                {criticDecision && (
                  <div className="mt-2 px-3 py-2 bg-purple-500/10 rounded text-xs text-purple-300 border border-purple-500/20">
                    Critic: {criticDecision} — {(action.critic_review as Record<string, string>).reasoning}
                  </div>
                )}
              </div>
            );
          })}
          {incident.response_actions.length === 0 && (
            <div className="text-center py-8 text-gray-500 card">No response actions proposed.</div>
          )}
        </div>
      )}

      {activeTab === "timeline" && (
        <div className="card p-5">
          <div className="relative">
            {(incident.timeline || []).slice(0, 30).map((event: Record<string, unknown>, i: number) => {
              const ts = event.timestamp as string;
              const evType = event.type as string;
              const desc = event.description as string;
              const sev = event.severity as string;

              return (
                <div key={i} className="flex gap-4 pb-4">
                  <div className="flex flex-col items-center">
                    <div className={`w-2.5 h-2.5 rounded-full mt-1.5 ${
                      sev === "critical" ? "bg-red-400" :
                      sev === "high" ? "bg-orange-400" :
                      sev === "info" ? "bg-blue-400" : "bg-gray-400"
                    }`} />
                    {i < (incident.timeline || []).length - 1 && (
                      <div className="w-px flex-1 bg-soc-border mt-1" />
                    )}
                  </div>
                  <div className="flex-1 min-w-0 pb-2">
                    <div className="flex items-center gap-2">
                      <span className="text-xs text-gray-500">
                        {ts ? format(new Date(ts), "HH:mm:ss") : "—"}
                      </span>
                      <span className="text-xs px-1.5 py-0.5 rounded bg-soc-surface text-gray-400">
                        {evType}
                      </span>
                    </div>
                    <p className="text-sm text-gray-300 mt-0.5">{desc}</p>
                  </div>
                </div>
              );
            })}
            {(!incident.timeline || incident.timeline.length === 0) && (
              <div className="text-center py-8 text-gray-500">No timeline events recorded.</div>
            )}
          </div>
        </div>
      )}

      {activeTab === "traces" && (
        <div className="space-y-2">
          {traces.map((step) => {
            const isExpanded = expandedTrace === step.id;
            return (
              <div key={step.id} className="card">
                <button
                  onClick={() => setExpandedTrace(isExpanded ? null : step.id)}
                  className="w-full px-4 py-3 flex items-center justify-between hover:bg-soc-surface/50 transition-colors"
                >
                  <div className="flex items-center gap-3">
                    <span className="text-xs font-mono text-gray-500 w-6">#{step.step_number}</span>
                    <span className="px-2 py-0.5 rounded bg-soc-accent/20 text-soc-accent text-xs font-medium">
                      {step.agent_name}
                    </span>
                    <span className="text-sm text-gray-200">{step.step_type.replace(/_/g, " ")}</span>
                    {step.duration_ms != null && (
                      <span className="text-xs text-gray-500">{step.duration_ms}ms</span>
                    )}
                  </div>
                  {isExpanded ? (
                    <ChevronDown className="h-4 w-4 text-gray-500" />
                  ) : (
                    <ChevronRight className="h-4 w-4 text-gray-500" />
                  )}
                </button>
                {isExpanded && (
                  <div className="px-4 pb-4 border-t border-soc-border/50">
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-3">
                      {step.input_data && Object.keys(step.input_data).length > 0 && (
                        <div>
                          <span className="text-xs text-gray-500 block mb-1">Input</span>
                          <pre className="text-xs text-gray-300 bg-soc-bg rounded p-2 overflow-auto max-h-40 font-mono">
                            {JSON.stringify(step.input_data, null, 2)}
                          </pre>
                        </div>
                      )}
                      {step.output_data && Object.keys(step.output_data).length > 0 && (
                        <div>
                          <span className="text-xs text-gray-500 block mb-1">Output</span>
                          <pre className="text-xs text-gray-300 bg-soc-bg rounded p-2 overflow-auto max-h-40 font-mono">
                            {JSON.stringify(step.output_data, null, 2)}
                          </pre>
                        </div>
                      )}
                    </div>
                    {step.tool_calls && step.tool_calls.length > 0 && (
                      <div className="mt-2">
                        <span className="text-xs text-gray-500 block mb-1">Tool Calls</span>
                        <div className="flex flex-wrap gap-1.5">
                          {step.tool_calls.map((tc, i) => (
                            <span key={i} className="px-2 py-0.5 bg-yellow-400/10 text-yellow-300 rounded text-xs font-mono">
                              {typeof tc === "string" ? tc : JSON.stringify(tc)}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })}
          {traces.length === 0 && (
            <div className="text-center py-8 text-gray-500 card">
              No execution traces found. Traces are generated when the investigation agent processes alerts.
            </div>
          )}
        </div>
      )}

      {activeTab === "playbooks" && (
        <div className="space-y-4">
          {playbookMessage && (
            <div className="bg-green-500/10 border border-green-500/30 rounded-lg p-3 text-sm text-green-300">
              {playbookMessage}
            </div>
          )}
          {playbooks.length === 0 ? (
            <div className="text-center py-8 text-gray-500 card">
              No playbooks available.
            </div>
          ) : (
            playbooks.map((pb) => (
              <div key={pb.name} className="card p-5">
                <div className="flex items-start justify-between">
                  <div className="flex-1">
                    <div className="flex items-center gap-2 mb-1">
                      <BookOpen className="h-4 w-4 text-purple-400" />
                      <h4 className="text-sm font-semibold text-white">
                        {pb.name.replace(/_/g, " ")}
                      </h4>
                    </div>
                    <p className="text-xs text-gray-400 mb-3">{pb.description}</p>
                    <div className="flex flex-wrap gap-1.5 mb-3">
                      {pb.event_types.map((et) => (
                        <span
                          key={et}
                          className="px-2 py-0.5 bg-soc-surface text-gray-400 rounded text-xs font-mono"
                        >
                          {et}
                        </span>
                      ))}
                    </div>
                    <div className="space-y-1">
                      {pb.actions.map((action, i) => {
                        const riskColor =
                          action.risk_level === "auto"
                            ? "text-green-400 bg-green-400/10 border-green-400/30"
                            : action.risk_level === "high"
                            ? "text-orange-400 bg-orange-400/10 border-orange-400/30"
                            : "text-red-400 bg-red-400/10 border-red-400/30";
                        return (
                          <div key={i} className="flex items-center gap-2 text-xs">
                            <span className="text-gray-600 w-4">{i + 1}.</span>
                            <span className={`px-1.5 py-0.5 rounded border text-[10px] font-medium ${riskColor}`}>
                              {action.risk_level}
                            </span>
                            <span className="text-gray-300">
                              {action.action_type.replace(/_/g, " ")}
                            </span>
                            <span className="text-gray-600">— {action.description}</span>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                  <button
                    onClick={async () => {
                      setPlaybookRunning(pb.name);
                      setPlaybookMessage(null);
                      try {
                        const res = await runPlaybook(pb.name, id);
                        setPlaybookMessage(res.message);
                      } catch (e) {
                        setPlaybookMessage(`Failed: ${e}`);
                      } finally {
                        setPlaybookRunning(null);
                      }
                    }}
                    disabled={playbookRunning === pb.name}
                    className="ml-4 px-4 py-2 bg-purple-500/20 text-purple-300 border border-purple-500/30 rounded-lg text-xs font-medium hover:bg-purple-500/30 transition-colors disabled:opacity-50 flex items-center gap-2"
                  >
                    <PlayCircle className="h-4 w-4" />
                    {playbookRunning === pb.name ? "Running..." : "Run"}
                  </button>
                </div>
              </div>
            ))
          )}
        </div>
      )}

      {activeTab === "report" && (
        <div className="space-y-4">
          <div className="flex items-center gap-3">
            <button
              onClick={async () => {
                setReportLoading(true);
                try {
                  const res = await getIncidentReport(id);
                  setReportData(res.report);
                } catch (e) {
                  console.error("Report generation failed:", e);
                } finally {
                  setReportLoading(false);
                }
              }}
              disabled={reportLoading}
              className="flex items-center gap-2 px-4 py-2 bg-soc-accent/20 text-soc-accent border border-soc-accent/30 rounded-lg text-xs font-medium hover:bg-soc-accent/30 disabled:opacity-50"
            >
              <FileText className="h-4 w-4" />
              {reportLoading ? "Generating..." : "Generate Report"}
            </button>
            {reportData && (
              <button
                onClick={() => window.print()}
                className="px-4 py-2 bg-soc-surface border border-soc-border rounded-lg text-xs text-gray-300 hover:text-white"
              >
                Print / Save PDF
              </button>
            )}
          </div>
          {reportData && (
            <div className="card p-6 print:shadow-none print:border-none" id="incident-report">
              <div className="space-y-6">
                <div>
                  <h2 className="text-lg font-bold text-white">Incident Report</h2>
                  <p className="text-xs text-gray-500 mt-1">
                    Generated: {(reportData as Record<string, string>).generated_at
                      ? new Date((reportData as Record<string, string>).generated_at).toLocaleString()
                      : "—"}
                  </p>
                </div>
                <pre className="text-xs text-gray-300 bg-soc-bg rounded p-4 overflow-auto max-h-[600px] font-mono whitespace-pre-wrap">
                  {JSON.stringify(reportData, null, 2)}
                </pre>
              </div>
            </div>
          )}
          {!reportData && !reportLoading && (
            <div className="text-center py-8 text-gray-500 card">
              Click &quot;Generate Report&quot; to create a structured incident report.
            </div>
          )}
        </div>
      )}
    </div>
  );
}
