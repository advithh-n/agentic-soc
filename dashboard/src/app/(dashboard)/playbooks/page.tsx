"use client";

import { useEffect, useState } from "react";
import {
  BookOpen,
  Play,
  ChevronDown,
  ChevronUp,
  AlertTriangle,
  X,
} from "lucide-react";
import { clsx } from "clsx";
import { Header } from "@/components/header";
import { getPlaybooks, runPlaybook, type Playbook } from "@/lib/api";

const RISK_COLORS: Record<string, string> = {
  auto: "bg-green-500/15 text-green-400 border-green-500/30",
  high: "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
  critical: "bg-red-500/15 text-red-400 border-red-500/30",
};

export default function PlaybooksPage() {
  const [playbooks, setPlaybooks] = useState<Playbook[]>([]);
  const [loading, setLoading] = useState(true);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [runTarget, setRunTarget] = useState<string | null>(null);
  const [incidentId, setIncidentId] = useState("");
  const [runLoading, setRunLoading] = useState(false);
  const [feedback, setFeedback] = useState<{
    type: "success" | "error";
    message: string;
  } | null>(null);

  async function load() {
    try {
      const data = await getPlaybooks();
      setPlaybooks(data);
    } catch (err) {
      console.error("Failed to load playbooks:", err);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    load();
  }, []);

  function toggleExpand(name: string) {
    setExpanded((prev) => (prev === name ? null : name));
  }

  async function handleRun() {
    if (!runTarget || !incidentId.trim()) return;
    setRunLoading(true);
    setFeedback(null);
    try {
      const result = await runPlaybook(runTarget, incidentId.trim());
      setFeedback({
        type: "success",
        message: result.message || `Playbook "${runTarget}" executed successfully.`,
      });
      setRunTarget(null);
      setIncidentId("");
    } catch (err) {
      setFeedback({
        type: "error",
        message: err instanceof Error ? err.message : "Failed to run playbook",
      });
    } finally {
      setRunLoading(false);
    }
  }

  return (
    <div>
      <Header title="Playbooks" />
      <div className="p-6">
        <p className="text-sm text-gray-400 mb-6">
          Automated response workflows triggered by incidents and alert patterns.
        </p>

        {/* Feedback toast */}
        {feedback && (
          <div
            className={clsx(
              "mb-4 px-4 py-3 rounded-lg border text-sm flex items-center justify-between",
              feedback.type === "success"
                ? "bg-green-500/10 border-green-500/30 text-green-400"
                : "bg-red-500/10 border-red-500/30 text-red-400"
            )}
          >
            <span>{feedback.message}</span>
            <button
              onClick={() => setFeedback(null)}
              className="ml-3 hover:opacity-70"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        )}

        {loading ? (
          <div className="flex items-center justify-center py-16">
            <div className="w-6 h-6 border-2 border-soc-accent border-t-transparent rounded-full animate-spin" />
          </div>
        ) : playbooks.length === 0 ? (
          <div className="text-center py-16">
            <BookOpen className="w-10 h-10 text-gray-600 mx-auto mb-3" />
            <p className="text-sm text-gray-500">No playbooks configured</p>
          </div>
        ) : (
          <div className="grid gap-4">
            {playbooks.map((pb) => (
              <div
                key={pb.name}
                className="card overflow-hidden"
              >
                {/* Card Header */}
                <div className="px-5 py-4 flex items-start justify-between">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-3 mb-1">
                      <BookOpen className="w-4 h-4 text-soc-accent flex-shrink-0" />
                      <h3 className="text-sm font-semibold text-white truncate">
                        {pb.name.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase())}
                      </h3>
                      <span className="text-[10px] px-2 py-0.5 rounded-full bg-soc-accent/15 text-soc-accent border border-soc-accent/30 flex-shrink-0">
                        {pb.action_count} actions
                      </span>
                    </div>
                    <p className="text-xs text-gray-400 ml-7">{pb.description}</p>
                    <div className="flex items-center gap-2 mt-2 ml-7">
                      <span className="text-[10px] text-gray-500 uppercase">
                        Severity: {pb.severity_min}+
                      </span>
                      <span className="text-gray-700">|</span>
                      <div className="flex gap-1 flex-wrap">
                        {pb.event_types.map((et) => (
                          <span
                            key={et}
                            className="text-[10px] px-1.5 py-0.5 rounded bg-white/5 text-gray-400 border border-soc-border"
                          >
                            {et}
                          </span>
                        ))}
                      </div>
                    </div>
                  </div>
                  <div className="flex items-center gap-2 ml-4 flex-shrink-0">
                    <button
                      onClick={() => setRunTarget(pb.name)}
                      className="flex items-center gap-1.5 px-3 py-1.5 text-xs bg-soc-accent/15 text-soc-accent border border-soc-accent/30 rounded-lg hover:bg-soc-accent/25 transition-colors"
                    >
                      <Play className="w-3 h-3" />
                      Run
                    </button>
                    <button
                      onClick={() => toggleExpand(pb.name)}
                      className="p-1.5 text-gray-500 hover:text-gray-300 transition-colors"
                      title="Toggle actions"
                    >
                      {expanded === pb.name ? (
                        <ChevronUp className="w-4 h-4" />
                      ) : (
                        <ChevronDown className="w-4 h-4" />
                      )}
                    </button>
                  </div>
                </div>

                {/* Expandable Actions */}
                {expanded === pb.name && (
                  <div className="border-t border-soc-border px-5 py-4">
                    <h4 className="text-xs font-semibold text-gray-400 uppercase mb-3">
                      Actions
                    </h4>
                    <div className="space-y-2">
                      {pb.actions.map((action, idx) => (
                        <div
                          key={idx}
                          className="bg-soc-bg border border-soc-border rounded-lg p-3 flex items-center justify-between"
                        >
                          <div className="flex items-center gap-3">
                            <span className="text-[10px] text-gray-600 font-mono w-5">
                              #{idx + 1}
                            </span>
                            <div>
                              <span className="text-xs font-mono text-gray-300 uppercase">
                                {action.action_type.replace(/_/g, " ")}
                              </span>
                              <p className="text-[10px] text-gray-500 mt-0.5">
                                {action.description}
                              </p>
                            </div>
                          </div>
                          <span
                            className={clsx(
                              "text-[10px] px-2 py-0.5 rounded-full border",
                              RISK_COLORS[action.risk_level] || "bg-gray-500/15 text-gray-400 border-gray-500/30"
                            )}
                          >
                            {action.risk_level}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>
        )}

        {/* Run Playbook Modal */}
        {runTarget && (
          <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4">
            <div className="card w-full max-w-md p-6 space-y-4">
              <div className="flex items-center gap-2">
                <Play className="w-4 h-4 text-soc-accent" />
                <h3 className="text-base font-semibold text-white">
                  Run Playbook
                </h3>
              </div>
              <p className="text-xs text-gray-400">
                Execute{" "}
                <span className="text-white font-medium">
                  {runTarget.replace(/_/g, " ")}
                </span>{" "}
                on an incident.
              </p>
              <div>
                <label className="block text-xs text-gray-500 mb-1.5">
                  Incident ID
                </label>
                <input
                  type="text"
                  value={incidentId}
                  onChange={(e) => setIncidentId(e.target.value)}
                  placeholder="e.g. inc-abc123..."
                  className="w-full px-3 py-2.5 bg-soc-bg border border-soc-border rounded-lg text-sm text-white placeholder-gray-600 focus:outline-none focus:border-soc-accent"
                />
              </div>
              {feedback?.type === "error" && (
                <div className="flex items-center gap-2 text-xs text-red-400">
                  <AlertTriangle className="w-3 h-3" />
                  {feedback.message}
                </div>
              )}
              <div className="flex justify-end gap-2">
                <button
                  onClick={() => {
                    setRunTarget(null);
                    setIncidentId("");
                    setFeedback(null);
                  }}
                  className="px-3 py-1.5 text-xs text-gray-400 hover:text-gray-200 transition-colors"
                >
                  Cancel
                </button>
                <button
                  onClick={handleRun}
                  disabled={!incidentId.trim() || runLoading}
                  className="px-4 py-1.5 text-xs bg-soc-accent/20 text-soc-accent border border-soc-accent/30 rounded-lg hover:bg-soc-accent/30 disabled:opacity-50 transition-colors flex items-center gap-1.5"
                >
                  {runLoading ? (
                    <div className="w-3 h-3 border border-soc-accent border-t-transparent rounded-full animate-spin" />
                  ) : (
                    <Play className="w-3 h-3" />
                  )}
                  Execute
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
