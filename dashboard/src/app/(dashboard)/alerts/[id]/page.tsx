"use client";

import { useCallback, useEffect, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import {
  ArrowLeft,
  Brain,
  Clock,
  ExternalLink,
  FileCode,
  Fingerprint,
  Shield,
  Target,
} from "lucide-react";
import { formatDistanceToNow, format } from "date-fns";
import { clsx } from "clsx";
import { Header } from "@/components/header";
import {
  SeverityBadge,
  StatusBadge,
  SourceBadge,
} from "@/components/severity-badge";
import {
  getAlertDetail,
  escalateAlert,
  closeAlert,
  type AlertDetail,
} from "@/lib/api";

export default function AlertDetailPage() {
  const { id } = useParams<{ id: string }>();
  const router = useRouter();
  const [alert, setAlert] = useState<AlertDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [actionLoading, setActionLoading] = useState(false);
  const [showCloseModal, setShowCloseModal] = useState(false);
  const [resolution, setResolution] = useState("");

  const load = useCallback(async () => {
    try {
      const data = await getAlertDetail(id);
      setAlert(data);
    } catch (err) {
      console.error("Failed to load alert:", err);
    } finally {
      setLoading(false);
    }
  }, [id]);

  useEffect(() => {
    load();
  }, [load]);

  async function handleEscalate() {
    setActionLoading(true);
    try {
      await escalateAlert(id);
      await load();
    } catch (err) {
      console.error("Escalation failed:", err);
    } finally {
      setActionLoading(false);
    }
  }

  async function handleClose() {
    if (!resolution.trim()) return;
    setActionLoading(true);
    try {
      await closeAlert(id, resolution);
      await load();
      setShowCloseModal(false);
    } catch (err) {
      console.error("Close failed:", err);
    } finally {
      setActionLoading(false);
    }
  }

  if (loading) {
    return (
      <div>
        <Header title="Alert Detail" />
        <div className="flex items-center justify-center py-32">
          <div className="w-6 h-6 border-2 border-soc-accent border-t-transparent rounded-full animate-spin" />
        </div>
      </div>
    );
  }

  if (!alert) {
    return (
      <div>
        <Header title="Alert Detail" />
        <div className="p-6 text-center text-gray-500">Alert not found</div>
      </div>
    );
  }

  return (
    <div>
      <Header title="Alert Detail" />

      <div className="p-6 space-y-6">
        {/* Breadcrumb + Actions */}
        <div className="flex items-center justify-between">
          <button
            onClick={() => router.back()}
            className="flex items-center gap-1 text-sm text-gray-400 hover:text-gray-200 transition-colors"
          >
            <ArrowLeft className="w-4 h-4" />
            Back to Alerts
          </button>
          <div className="flex items-center gap-2">
            {alert.status === "open" && (
              <button
                onClick={handleEscalate}
                disabled={actionLoading}
                className="px-3 py-1.5 text-xs bg-severity-high/20 text-severity-high border border-severity-high/30 rounded-lg hover:bg-severity-high/30 disabled:opacity-50 transition-colors"
              >
                Escalate
              </button>
            )}
            {alert.status !== "resolved" && (
              <button
                onClick={() => setShowCloseModal(true)}
                disabled={actionLoading}
                className="px-3 py-1.5 text-xs bg-green-500/20 text-green-400 border border-green-500/30 rounded-lg hover:bg-green-500/30 disabled:opacity-50 transition-colors"
              >
                Resolve
              </button>
            )}
          </div>
        </div>

        {/* Alert Header */}
        <div className="card p-6">
          <div className="flex items-start gap-4">
            <div className="flex-1">
              <div className="flex items-center gap-3 mb-2">
                <SeverityBadge severity={alert.severity} />
                <StatusBadge status={alert.status} />
                <SourceBadge source={alert.source} />
              </div>
              <h2 className="text-lg font-bold text-white mb-1">{alert.title}</h2>
              <p className="text-sm text-gray-400">{alert.description}</p>
              <div className="flex items-center gap-4 mt-3 text-xs text-gray-500">
                <span className="flex items-center gap-1">
                  <Clock className="w-3 h-3" />
                  Created{" "}
                  {formatDistanceToNow(new Date(alert.created_at), {
                    addSuffix: true,
                  })}
                </span>
                {alert.triaged_at && (
                  <span className="flex items-center gap-1">
                    <Brain className="w-3 h-3" />
                    Triaged{" "}
                    {formatDistanceToNow(new Date(alert.triaged_at), {
                      addSuffix: true,
                    })}
                  </span>
                )}
                {alert.mitre_technique && (
                  <span className="flex items-center gap-1 font-mono text-orange-400">
                    <Target className="w-3 h-3" />
                    {alert.mitre_technique}
                  </span>
                )}
                {alert.confidence !== null && (
                  <span>
                    Confidence:{" "}
                    <span className="text-white font-mono">
                      {(alert.confidence * 100).toFixed(0)}%
                    </span>
                  </span>
                )}
              </div>
            </div>
          </div>
        </div>

        <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
          {/* Agent Reasoning Trace */}
          {alert.triage_result && (
            <div className="card xl:col-span-2">
              <div className="flex items-center gap-2 px-5 py-4 border-b border-soc-border">
                <Brain className="w-4 h-4 text-purple-400" />
                <h3 className="text-sm font-semibold text-white">
                  Agent Reasoning Trace
                </h3>
              </div>
              <div className="p-5 space-y-4">
                {/* Classification */}
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <ReasoningField
                    label="Classification"
                    value={alert.triage_result.classification}
                    highlight
                  />
                  <ReasoningField
                    label="Confidence"
                    value={`${(alert.triage_result.confidence * 100).toFixed(0)}%`}
                  />
                  <ReasoningField
                    label="Severity Assessment"
                    value={alert.triage_result.severity}
                  />
                </div>

                {/* Reasoning */}
                <div>
                  <span className="text-xs text-gray-500 uppercase tracking-wider">
                    Reasoning
                  </span>
                  <p className="mt-1 text-sm text-gray-300 leading-relaxed bg-soc-bg rounded-lg p-4 border border-soc-border">
                    {alert.triage_result.reasoning}
                  </p>
                </div>

                {/* Recommended Action */}
                <div>
                  <span className="text-xs text-gray-500 uppercase tracking-wider">
                    Recommended Action
                  </span>
                  <p className="mt-1 text-sm text-soc-accent bg-soc-accent/5 rounded-lg p-4 border border-soc-accent/20">
                    {alert.triage_result.recommended_action}
                  </p>
                </div>

                {/* Steps */}
                {alert.triage_result.steps && alert.triage_result.steps.length > 0 && (
                  <div>
                    <span className="text-xs text-gray-500 uppercase tracking-wider">
                      Investigation Steps
                    </span>
                    <div className="mt-2 space-y-2">
                      {alert.triage_result.steps.map((step, i) => (
                        <div
                          key={i}
                          className="flex items-start gap-3 bg-soc-bg rounded-lg p-3 border border-soc-border"
                        >
                          <div className="w-6 h-6 rounded-full bg-purple-500/20 text-purple-400 flex items-center justify-center text-xs font-bold flex-shrink-0">
                            {i + 1}
                          </div>
                          <div className="min-w-0">
                            <div className="text-sm font-medium text-gray-200">
                              {step.step}
                            </div>
                            <div className="text-xs text-gray-400 mt-0.5">
                              {step.result}
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Enrichment Summary */}
                {alert.triage_result.enrichment_summary && (
                  <div>
                    <span className="text-xs text-gray-500 uppercase tracking-wider">
                      Enrichment Summary
                    </span>
                    <p className="mt-1 text-sm text-gray-300 bg-soc-bg rounded-lg p-4 border border-soc-border">
                      {alert.triage_result.enrichment_summary}
                    </p>
                  </div>
                )}

                {/* MITRE Technique */}
                {alert.triage_result.mitre_technique && (
                  <div className="flex items-center gap-2">
                    <Target className="w-4 h-4 text-orange-400" />
                    <span className="text-sm font-mono text-orange-400">
                      {alert.triage_result.mitre_technique}
                    </span>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Artifacts / IOCs */}
          {alert.artifacts && alert.artifacts.length > 0 && (
            <div className="card">
              <div className="flex items-center gap-2 px-5 py-4 border-b border-soc-border">
                <Fingerprint className="w-4 h-4 text-cyan-400" />
                <h3 className="text-sm font-semibold text-white">
                  Artifacts / IOCs
                </h3>
              </div>
              <div className="p-5">
                <div className="space-y-2">
                  {alert.artifacts.map((artifact, i) => (
                    <div
                      key={i}
                      className="flex items-center gap-3 bg-soc-bg rounded-lg px-4 py-2.5 border border-soc-border"
                    >
                      <span className="text-[10px] text-gray-500 uppercase tracking-widest w-20">
                        {artifact.type}
                      </span>
                      <code className="text-sm text-cyan-300 font-mono">
                        {artifact.value}
                      </code>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* Enrichment Data */}
          {alert.enrichment && Object.keys(alert.enrichment).length > 0 && (
            <div className="card">
              <div className="flex items-center gap-2 px-5 py-4 border-b border-soc-border">
                <Shield className="w-4 h-4 text-green-400" />
                <h3 className="text-sm font-semibold text-white">
                  Enrichment Data
                </h3>
              </div>
              <div className="p-5">
                <pre className="text-xs text-gray-300 bg-soc-bg rounded-lg p-4 border border-soc-border overflow-x-auto">
                  {JSON.stringify(alert.enrichment, null, 2)}
                </pre>
              </div>
            </div>
          )}

          {/* Raw Payload */}
          {alert.raw_payload && (
            <div className="card xl:col-span-2">
              <div className="flex items-center gap-2 px-5 py-4 border-b border-soc-border">
                <FileCode className="w-4 h-4 text-gray-400" />
                <h3 className="text-sm font-semibold text-white">Raw Payload</h3>
              </div>
              <div className="p-5">
                <pre className="text-xs text-gray-400 bg-soc-bg rounded-lg p-4 border border-soc-border overflow-x-auto max-h-96">
                  {JSON.stringify(alert.raw_payload, null, 2)}
                </pre>
              </div>
            </div>
          )}
        </div>

        {/* Timeline */}
        <div className="card">
          <div className="flex items-center gap-2 px-5 py-4 border-b border-soc-border">
            <Clock className="w-4 h-4 text-gray-400" />
            <h3 className="text-sm font-semibold text-white">Timeline</h3>
          </div>
          <div className="p-5">
            <div className="space-y-4">
              <TimelineEvent
                time={alert.created_at}
                label="Alert created"
                detail={`${alert.source} — ${alert.event_type}`}
                color="blue"
              />
              {alert.triaged_at && (
                <TimelineEvent
                  time={alert.triaged_at}
                  label="Triage completed"
                  detail={
                    alert.triage_result
                      ? `${alert.triage_result.classification} (${(alert.triage_result.confidence * 100).toFixed(0)}% confidence)`
                      : "Agent classified"
                  }
                  color="purple"
                />
              )}
              {alert.resolved_at && (
                <TimelineEvent
                  time={alert.resolved_at}
                  label="Resolved"
                  detail={`By ${alert.resolved_by || "system"}: ${alert.resolution || ""}`}
                  color="green"
                />
              )}
            </div>
          </div>
        </div>

        {/* Close Modal */}
        {showCloseModal && (
          <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4">
            <div className="card w-full max-w-md p-6 space-y-4">
              <h3 className="text-base font-semibold text-white">Resolve Alert</h3>
              <textarea
                value={resolution}
                onChange={(e) => setResolution(e.target.value)}
                placeholder="Describe the resolution..."
                rows={4}
                className="w-full px-3 py-2.5 bg-soc-bg border border-soc-border rounded-lg text-sm text-white placeholder-gray-600 focus:outline-none focus:border-soc-accent"
              />
              <div className="flex justify-end gap-2">
                <button
                  onClick={() => setShowCloseModal(false)}
                  className="px-3 py-1.5 text-xs text-gray-400 hover:text-gray-200 transition-colors"
                >
                  Cancel
                </button>
                <button
                  onClick={handleClose}
                  disabled={actionLoading || !resolution.trim()}
                  className="px-3 py-1.5 text-xs bg-green-500/20 text-green-400 border border-green-500/30 rounded-lg hover:bg-green-500/30 disabled:opacity-50 transition-colors"
                >
                  {actionLoading ? "Resolving..." : "Resolve"}
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

function ReasoningField({
  label,
  value,
  highlight,
}: {
  label: string;
  value: string;
  highlight?: boolean;
}) {
  return (
    <div className="bg-soc-bg rounded-lg p-3 border border-soc-border">
      <span className="text-[10px] text-gray-500 uppercase tracking-widest">
        {label}
      </span>
      <p
        className={clsx(
          "mt-1 text-sm font-medium",
          highlight ? "text-purple-400" : "text-gray-200"
        )}
      >
        {value}
      </p>
    </div>
  );
}

function TimelineEvent({
  time,
  label,
  detail,
  color,
}: {
  time: string;
  label: string;
  detail: string;
  color: "blue" | "purple" | "green" | "red";
}) {
  const colors = {
    blue: "bg-blue-500",
    purple: "bg-purple-500",
    green: "bg-green-500",
    red: "bg-red-500",
  };

  return (
    <div className="flex items-start gap-3">
      <div className="flex flex-col items-center">
        <div className={clsx("w-2.5 h-2.5 rounded-full mt-1.5", colors[color])} />
        <div className="w-px h-full bg-soc-border" />
      </div>
      <div className="pb-4">
        <div className="text-sm text-gray-200">{label}</div>
        <div className="text-xs text-gray-500 mt-0.5">{detail}</div>
        <div className="text-[10px] text-gray-600 mt-0.5 font-mono">
          {format(new Date(time), "yyyy-MM-dd HH:mm:ss")}
        </div>
      </div>
    </div>
  );
}
