"use client";

import { useEffect, useState } from "react";
import { formatDistanceToNow } from "date-fns";
import {
  CheckCircle,
  XCircle,
  Clock,
  AlertTriangle,
  PlayCircle,
  History,
} from "lucide-react";
import { clsx } from "clsx";
import { Header } from "@/components/header";
import { SeverityBadge } from "@/components/severity-badge";
import {
  getPendingActions,
  approveAction,
  denyAction,
  executeAction,
  getActionHistory,
  type ResponseAction,
  type ActionHistoryItem,
} from "@/lib/api";

export default function ApprovalsPage() {
  const [actions, setActions] = useState<ResponseAction[]>([]);
  const [history, setHistory] = useState<ActionHistoryItem[]>([]);
  const [historyTotal, setHistoryTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [actionLoading, setActionLoading] = useState<string | null>(null);
  const [denyId, setDenyId] = useState<string | null>(null);
  const [denyReason, setDenyReason] = useState("");

  async function load() {
    try {
      const [pendingData, historyData] = await Promise.all([
        getPendingActions(),
        getActionHistory({ page_size: 10 }),
      ]);
      setActions(pendingData);
      setHistory(historyData.actions);
      setHistoryTotal(historyData.total);
    } catch (err) {
      console.error("Failed to load actions:", err);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    load();
    const interval = setInterval(load, 15000);
    return () => clearInterval(interval);
  }, []);

  async function handleApprove(id: string) {
    setActionLoading(id);
    try {
      await approveAction(id);
      await load();
    } finally {
      setActionLoading(null);
    }
  }

  async function handleExecute(id: string) {
    setActionLoading(id);
    try {
      await executeAction(id);
      await load();
    } finally {
      setActionLoading(null);
    }
  }

  async function handleDeny() {
    if (!denyId || !denyReason.trim()) return;
    setActionLoading(denyId);
    try {
      await denyAction(denyId, denyReason);
      await load();
      setDenyId(null);
      setDenyReason("");
    } finally {
      setActionLoading(null);
    }
  }

  return (
    <div>
      <Header title="Approval Queue" />
      <div className="p-6">
        <div className="card">
          <div className="flex items-center gap-2 px-5 py-4 border-b border-soc-border">
            <Clock className="w-4 h-4 text-yellow-400" />
            <h3 className="text-sm font-semibold text-white">
              Pending Approvals
            </h3>
            <span className="text-xs text-gray-500">({actions.length})</span>
          </div>
          <div className="p-5">
            {loading ? (
              <div className="flex items-center justify-center py-16">
                <div className="w-6 h-6 border-2 border-soc-accent border-t-transparent rounded-full animate-spin" />
              </div>
            ) : actions.length === 0 ? (
              <div className="text-center py-12">
                <CheckCircle className="w-10 h-10 text-green-500/30 mx-auto mb-3" />
                <p className="text-sm text-gray-500">No pending approvals</p>
              </div>
            ) : (
              <div className="space-y-3">
                {actions.map((action) => (
                  <div
                    key={action.id}
                    className="bg-soc-bg border border-soc-border rounded-lg p-4"
                  >
                    <div className="flex items-start justify-between">
                      <div className="flex-1">
                        <div className="flex items-center gap-2 mb-1">
                          <SeverityBadge severity={action.risk_level} />
                          <span className="text-xs text-gray-500 uppercase font-mono">
                            {action.action_type.replace(/_/g, " ")}
                          </span>
                        </div>
                        <div className="text-sm text-gray-300 mt-1">
                          Proposed by:{" "}
                          <span className="text-purple-400">{action.proposed_by}</span>
                        </div>
                        <pre className="text-xs text-gray-500 bg-soc-surface rounded p-2 mt-2 overflow-x-auto">
                          {JSON.stringify(action.parameters, null, 2)}
                        </pre>
                        {action.critic_review && (
                          <div className="mt-2 text-xs text-gray-400 bg-purple-500/5 border border-purple-500/20 rounded p-2">
                            Critic: {JSON.stringify(action.critic_review)}
                          </div>
                        )}
                      </div>
                      <div className="flex items-center gap-2 ml-4">
                        <button
                          onClick={() => handleApprove(action.id)}
                          disabled={actionLoading === action.id}
                          className="p-2 text-green-400 hover:bg-green-500/10 rounded-lg transition-colors disabled:opacity-50"
                          title="Approve"
                        >
                          <CheckCircle className="w-5 h-5" />
                        </button>
                        <button
                          onClick={() => handleExecute(action.id)}
                          disabled={actionLoading === action.id}
                          className="p-2 text-blue-400 hover:bg-blue-500/10 rounded-lg transition-colors disabled:opacity-50"
                          title="Approve & Execute"
                        >
                          <PlayCircle className="w-5 h-5" />
                        </button>
                        <button
                          onClick={() => setDenyId(action.id)}
                          disabled={actionLoading === action.id}
                          className="p-2 text-red-400 hover:bg-red-500/10 rounded-lg transition-colors disabled:opacity-50"
                          title="Deny"
                        >
                          <XCircle className="w-5 h-5" />
                        </button>
                      </div>
                    </div>
                    <div className="text-[10px] text-gray-600 mt-2 font-mono">
                      {formatDistanceToNow(new Date(action.created_at), {
                        addSuffix: true,
                      })}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Action History */}
        <div className="card mt-6">
          <div className="flex items-center gap-2 px-5 py-4 border-b border-soc-border">
            <History className="w-4 h-4 text-blue-400" />
            <h3 className="text-sm font-semibold text-white">
              Action History
            </h3>
            <span className="text-xs text-gray-500">({historyTotal})</span>
          </div>
          <div className="p-5">
            {history.length === 0 ? (
              <div className="text-center py-8 text-gray-500 text-sm">
                No executed actions yet.
              </div>
            ) : (
              <div className="space-y-2">
                {history.map((item) => {
                  const statusColor =
                    item.status === "executed"
                      ? "text-green-400"
                      : item.status === "failed"
                      ? "text-red-400"
                      : item.status === "rolled_back"
                      ? "text-yellow-400"
                      : "text-gray-400";
                  return (
                    <div
                      key={item.id}
                      className="bg-soc-bg border border-soc-border rounded-lg p-3 flex items-center justify-between"
                    >
                      <div className="flex-1">
                        <div className="flex items-center gap-2">
                          <SeverityBadge severity={item.risk_level} />
                          <span className="text-xs font-mono text-gray-400 uppercase">
                            {item.action_type.replace(/_/g, " ")}
                          </span>
                          <span className={`text-xs font-medium ${statusColor}`}>
                            {item.status}
                          </span>
                        </div>
                        {item.outcome && (
                          <div className="mt-1 text-xs text-gray-500 truncate max-w-md">
                            {item.outcome.error
                              ? `Error: ${item.outcome.error}`
                              : item.outcome.details
                              ? JSON.stringify(item.outcome.details).slice(0, 80)
                              : ""}
                          </div>
                        )}
                      </div>
                      <div className="text-[10px] text-gray-600 font-mono ml-4">
                        {item.executed_at
                          ? formatDistanceToNow(new Date(item.executed_at), {
                              addSuffix: true,
                            })
                          : formatDistanceToNow(new Date(item.created_at), {
                              addSuffix: true,
                            })}
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </div>

        {/* Deny modal */}
        {denyId && (
          <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4">
            <div className="card w-full max-w-md p-6 space-y-4">
              <h3 className="text-base font-semibold text-white">Deny Action</h3>
              <textarea
                value={denyReason}
                onChange={(e) => setDenyReason(e.target.value)}
                placeholder="Reason for denial..."
                rows={3}
                className="w-full px-3 py-2.5 bg-soc-bg border border-soc-border rounded-lg text-sm text-white placeholder-gray-600 focus:outline-none focus:border-soc-accent"
              />
              <div className="flex justify-end gap-2">
                <button
                  onClick={() => { setDenyId(null); setDenyReason(""); }}
                  className="px-3 py-1.5 text-xs text-gray-400 hover:text-gray-200 transition-colors"
                >
                  Cancel
                </button>
                <button
                  onClick={handleDeny}
                  disabled={!denyReason.trim()}
                  className="px-3 py-1.5 text-xs bg-red-500/20 text-red-400 border border-red-500/30 rounded-lg hover:bg-red-500/30 disabled:opacity-50 transition-colors"
                >
                  Deny
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
