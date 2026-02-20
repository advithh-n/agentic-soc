"use client";

import { useCallback, useEffect, useState } from "react";
import { ChevronLeft, ChevronRight, Download, Filter, RefreshCw } from "lucide-react";
import { clsx } from "clsx";
import { Header } from "@/components/header";
import { AlertTable } from "@/components/alert-table";
import { getAlerts, getAlertExportUrl, getAccessToken, type Alert } from "@/lib/api";

const SEVERITIES = ["all", "critical", "high", "medium", "low"] as const;
const STATUSES = ["all", "open", "triaged", "investigating", "resolved", "false_positive"] as const;
const SOURCES = ["all", "stripe", "clerk", "aws", "wazuh", "langfuse", "ai_agent"] as const;

export default function AlertsPage() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [pageSize] = useState(20);
  const [severity, setSeverity] = useState("all");
  const [status, setStatus] = useState("all");
  const [source, setSource] = useState("all");
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const res = await getAlerts({
        severity: severity === "all" ? undefined : severity,
        status: status === "all" ? undefined : status,
        source: source === "all" ? undefined : source,
        page,
        page_size: pageSize,
      });
      setAlerts(res.alerts);
      setTotal(res.total);
    } catch (err) {
      console.error("Failed to load alerts:", err);
    } finally {
      setLoading(false);
    }
  }, [severity, status, source, page, pageSize]);

  useEffect(() => {
    load();
  }, [load]);

  const totalPages = Math.ceil(total / pageSize);

  return (
    <div>
      <Header title="Alerts" />

      <div className="p-6 space-y-4">
        {/* Filters */}
        <div className="card p-4">
          <div className="flex flex-wrap items-center gap-4">
            <div className="flex items-center gap-2 text-xs text-gray-400">
              <Filter className="w-3.5 h-3.5" />
              Filters:
            </div>

            <FilterGroup
              label="Severity"
              options={SEVERITIES}
              value={severity}
              onChange={(v) => { setSeverity(v); setPage(1); }}
            />
            <FilterGroup
              label="Status"
              options={STATUSES}
              value={status}
              onChange={(v) => { setStatus(v); setPage(1); }}
            />
            <FilterGroup
              label="Source"
              options={SOURCES}
              value={source}
              onChange={(v) => { setSource(v); setPage(1); }}
            />

            <div className="ml-auto flex items-center gap-1">
              <button
                onClick={() => {
                  const url = getAlertExportUrl({
                    severity: severity === "all" ? undefined : severity,
                    status: status === "all" ? undefined : status,
                    source: source === "all" ? undefined : source,
                  });
                  const token = getAccessToken();
                  // Open CSV download with auth header via fetch + blob
                  fetch(url, {
                    headers: token ? { Authorization: `Bearer ${token}` } : {},
                  })
                    .then((res) => res.blob())
                    .then((blob) => {
                      const a = document.createElement("a");
                      a.href = URL.createObjectURL(blob);
                      a.download = "alerts_export.csv";
                      a.click();
                      URL.revokeObjectURL(a.href);
                    });
                }}
                className="p-2 text-gray-400 hover:text-gray-200 transition-colors"
                title="Export CSV"
              >
                <Download className="w-4 h-4" />
              </button>
              <button
                onClick={load}
                className="p-2 text-gray-400 hover:text-gray-200 transition-colors"
                title="Refresh"
              >
                <RefreshCw className={clsx("w-4 h-4", loading && "animate-spin")} />
              </button>
            </div>
          </div>
        </div>

        {/* Results */}
        <div className="card">
          <div className="flex items-center justify-between px-5 py-3 border-b border-soc-border">
            <span className="text-xs text-gray-400">
              {total} alert{total !== 1 ? "s" : ""} found
            </span>
            <div className="flex items-center gap-2">
              <button
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                disabled={page <= 1}
                className="p-1 text-gray-400 hover:text-gray-200 disabled:opacity-30 transition-colors"
              >
                <ChevronLeft className="w-4 h-4" />
              </button>
              <span className="text-xs text-gray-400">
                {page} / {totalPages || 1}
              </span>
              <button
                onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                disabled={page >= totalPages}
                className="p-1 text-gray-400 hover:text-gray-200 disabled:opacity-30 transition-colors"
              >
                <ChevronRight className="w-4 h-4" />
              </button>
            </div>
          </div>
          <div className="p-5">
            {loading ? (
              <div className="flex items-center justify-center py-16">
                <div className="w-6 h-6 border-2 border-soc-accent border-t-transparent rounded-full animate-spin" />
              </div>
            ) : (
              <AlertTable alerts={alerts} />
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

function FilterGroup({
  label,
  options,
  value,
  onChange,
}: {
  label: string;
  options: readonly string[];
  value: string;
  onChange: (v: string) => void;
}) {
  return (
    <div className="flex items-center gap-1">
      <span className="text-[10px] text-gray-500 uppercase mr-1">{label}:</span>
      {options.map((opt) => (
        <button
          key={opt}
          onClick={() => onChange(opt)}
          className={clsx(
            "px-2 py-1 rounded text-xs transition-colors",
            value === opt
              ? "bg-soc-accent/20 text-soc-accent"
              : "text-gray-400 hover:bg-white/5 hover:text-gray-300"
          )}
        >
          {opt === "all" ? "All" : opt.replace("_", " ")}
        </button>
      ))}
    </div>
  );
}
