"use client";

import { useCallback, useEffect, useState } from "react";
import {
  FileText,
  Shield,
  ChevronLeft,
  ChevronRight,
  ChevronDown,
  ChevronUp,
  RefreshCw,
  CheckCircle,
  XCircle,
  Clock,
} from "lucide-react";
import { Header } from "@/components/header";
import {
  getAuditLog,
  verifyAuditChain,
  type AuditLogEntry,
} from "@/lib/api";

const ACTION_OPTIONS = [
  "all",
  "user.created",
  "user.updated",
  "user.deactivated",
  "alert.escalated",
  "alert.closed",
  "incident.created",
  "module.updated",
  "api_key.created",
  "api_key.revoked",
  "notifications.updated",
];

const RESOURCE_OPTIONS = [
  "all",
  "user",
  "alert",
  "incident",
  "module",
  "api_key",
  "tenant",
];

export default function AuditLogPage() {
  const [entries, setEntries] = useState<AuditLogEntry[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [pageSize] = useState(25);
  const [actionFilter, setActionFilter] = useState("all");
  const [resourceFilter, setResourceFilter] = useState("all");
  const [loading, setLoading] = useState(true);
  const [expandedId, setExpandedId] = useState<number | null>(null);
  const [chainStatus, setChainStatus] = useState<{
    valid: boolean;
    checked: number;
  } | null>(null);
  const [verifying, setVerifying] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const res = await getAuditLog({
        action: actionFilter === "all" ? undefined : actionFilter,
        resource_type: resourceFilter === "all" ? undefined : resourceFilter,
        page,
        page_size: pageSize,
      });
      setEntries(res.entries);
      setTotal(res.total);
    } catch (err) {
      console.error("Failed to load audit log:", err);
    } finally {
      setLoading(false);
    }
  }, [actionFilter, resourceFilter, page, pageSize]);

  useEffect(() => {
    load();
  }, [load]);

  const handleVerify = async () => {
    setVerifying(true);
    try {
      const result = await verifyAuditChain();
      setChainStatus(result);
    } catch (err) {
      console.error("Verify failed:", err);
    } finally {
      setVerifying(false);
    }
  };

  const totalPages = Math.ceil(total / pageSize);

  // Count last 24h entries from loaded data (approximate)
  const now = Date.now();
  const last24h = entries.filter(
    (e) => now - new Date(e.timestamp).getTime() < 86400000
  ).length;

  return (
    <div>
      <Header title="Audit Log" />

      <div className="p-6 space-y-4">
        {/* KPI Cards */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="card p-4">
            <div className="flex items-center gap-2 text-gray-400 text-xs mb-1">
              <FileText className="h-3.5 w-3.5" />
              Total Entries
            </div>
            <div className="text-2xl font-bold text-white">{total}</div>
          </div>
          <div className="card p-4">
            <div className="flex items-center gap-2 text-gray-400 text-xs mb-1">
              <Clock className="h-3.5 w-3.5" />
              Last 24h (this page)
            </div>
            <div className="text-2xl font-bold text-white">{last24h}</div>
          </div>
          <div className="card p-4">
            <div className="flex items-center gap-2 text-gray-400 text-xs mb-1">
              <Shield className="h-3.5 w-3.5" />
              Chain Integrity
            </div>
            <div className="flex items-center gap-2">
              {chainStatus === null ? (
                <span className="text-sm text-gray-500">Not verified</span>
              ) : chainStatus.valid ? (
                <>
                  <CheckCircle className="h-5 w-5 text-green-400" />
                  <span className="text-sm text-green-400">
                    Valid ({chainStatus.checked} entries)
                  </span>
                </>
              ) : (
                <>
                  <XCircle className="h-5 w-5 text-red-400" />
                  <span className="text-sm text-red-400">Chain broken</span>
                </>
              )}
            </div>
            <button
              onClick={handleVerify}
              disabled={verifying}
              className="mt-2 px-3 py-1 text-xs bg-soc-accent/20 text-soc-accent rounded hover:bg-soc-accent/30 transition-colors disabled:opacity-50"
            >
              {verifying ? "Verifying..." : "Verify Chain"}
            </button>
          </div>
        </div>

        {/* Filters */}
        <div className="card p-4">
          <div className="flex flex-wrap items-center gap-4">
            <div className="flex items-center gap-2">
              <span className="text-xs text-gray-500">Action:</span>
              <select
                value={actionFilter}
                onChange={(e) => {
                  setActionFilter(e.target.value);
                  setPage(1);
                }}
                className="bg-soc-surface border border-soc-border rounded px-2 py-1 text-xs text-gray-200"
              >
                {ACTION_OPTIONS.map((opt) => (
                  <option key={opt} value={opt}>
                    {opt === "all" ? "All Actions" : opt}
                  </option>
                ))}
              </select>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-xs text-gray-500">Resource:</span>
              <select
                value={resourceFilter}
                onChange={(e) => {
                  setResourceFilter(e.target.value);
                  setPage(1);
                }}
                className="bg-soc-surface border border-soc-border rounded px-2 py-1 text-xs text-gray-200"
              >
                {RESOURCE_OPTIONS.map((opt) => (
                  <option key={opt} value={opt}>
                    {opt === "all" ? "All Resources" : opt}
                  </option>
                ))}
              </select>
            </div>
            <button
              onClick={load}
              className="ml-auto p-2 text-gray-400 hover:text-gray-200 transition-colors"
              title="Refresh"
            >
              <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} />
            </button>
          </div>
        </div>

        {/* Table */}
        <div className="card overflow-hidden">
          <div className="flex items-center justify-between px-5 py-3 border-b border-soc-border">
            <span className="text-xs text-gray-400">
              {total} entr{total !== 1 ? "ies" : "y"}
            </span>
            <div className="flex items-center gap-2">
              <button
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                disabled={page <= 1}
                className="p-1 text-gray-400 hover:text-gray-200 disabled:opacity-30"
              >
                <ChevronLeft className="w-4 h-4" />
              </button>
              <span className="text-xs text-gray-400">
                {page} / {totalPages || 1}
              </span>
              <button
                onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                disabled={page >= totalPages}
                className="p-1 text-gray-400 hover:text-gray-200 disabled:opacity-30"
              >
                <ChevronRight className="w-4 h-4" />
              </button>
            </div>
          </div>

          {loading ? (
            <div className="flex items-center justify-center py-16">
              <div className="w-6 h-6 border-2 border-soc-accent border-t-transparent rounded-full animate-spin" />
            </div>
          ) : (
            <table className="w-full">
              <thead>
                <tr className="border-b border-soc-border text-left text-xs text-gray-500">
                  <th className="px-4 py-3 w-8"></th>
                  <th className="px-4 py-3">Timestamp</th>
                  <th className="px-4 py-3">Actor</th>
                  <th className="px-4 py-3">Action</th>
                  <th className="px-4 py-3">Resource</th>
                  <th className="px-4 py-3">Hash</th>
                </tr>
              </thead>
              <tbody>
                {entries.map((entry) => (
                  <>
                    <tr
                      key={entry.id}
                      onClick={() =>
                        setExpandedId(expandedId === entry.id ? null : entry.id)
                      }
                      className="border-b border-soc-border/50 hover:bg-soc-surface/50 cursor-pointer transition-colors"
                    >
                      <td className="px-4 py-3">
                        {expandedId === entry.id ? (
                          <ChevronUp className="w-3.5 h-3.5 text-gray-500" />
                        ) : (
                          <ChevronDown className="w-3.5 h-3.5 text-gray-500" />
                        )}
                      </td>
                      <td className="px-4 py-3 text-xs text-gray-400 whitespace-nowrap">
                        {new Date(entry.timestamp).toLocaleString()}
                      </td>
                      <td className="px-4 py-3">
                        <span className="text-xs px-1.5 py-0.5 bg-soc-surface rounded text-gray-400">
                          {entry.actor_type}
                        </span>
                        <span className="text-xs text-gray-500 ml-1 font-mono">
                          {entry.actor_id.slice(0, 8)}...
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <span className="text-xs font-medium text-soc-accent">
                          {entry.action}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-xs text-gray-300">
                        {entry.resource_type}:{entry.resource_id.slice(0, 8)}
                      </td>
                      <td className="px-4 py-3">
                        <span className="text-[10px] font-mono text-gray-600">
                          {entry.row_hash.slice(0, 12)}...
                        </span>
                      </td>
                    </tr>
                    {expandedId === entry.id && (
                      <tr key={`${entry.id}-details`} className="border-b border-soc-border/50">
                        <td colSpan={6} className="px-8 py-4 bg-soc-bg/50">
                          <div className="space-y-2">
                            <div className="text-xs text-gray-500">
                              <span className="font-medium text-gray-400">Resource ID:</span>{" "}
                              <span className="font-mono">{entry.resource_id}</span>
                            </div>
                            <div className="text-xs text-gray-500">
                              <span className="font-medium text-gray-400">Actor ID:</span>{" "}
                              <span className="font-mono">{entry.actor_id}</span>
                            </div>
                            <div className="text-xs text-gray-500">
                              <span className="font-medium text-gray-400">Hash:</span>{" "}
                              <span className="font-mono">{entry.row_hash}</span>
                            </div>
                            {entry.details && (
                              <div>
                                <span className="text-xs font-medium text-gray-400 block mb-1">
                                  Details:
                                </span>
                                <pre className="text-xs text-gray-300 bg-soc-surface rounded p-3 overflow-auto max-h-40 font-mono">
                                  {JSON.stringify(
                                    typeof entry.details === "string"
                                      ? JSON.parse(entry.details)
                                      : entry.details,
                                    null,
                                    2
                                  )}
                                </pre>
                              </div>
                            )}
                          </div>
                        </td>
                      </tr>
                    )}
                  </>
                ))}
              </tbody>
            </table>
          )}
          {!loading && entries.length === 0 && (
            <div className="text-center py-12 text-gray-500">
              No audit log entries found.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
