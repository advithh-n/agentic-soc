"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { formatDistanceToNow } from "date-fns";
import { Shield, ChevronRight, Filter } from "lucide-react";
import { Header } from "@/components/header";
import { StatsCard } from "@/components/stats-card";
import { SeverityBadge, StatusBadge } from "@/components/severity-badge";
import { getIncidents, type Incident } from "@/lib/api";

const STATUS_OPTIONS = ["all", "open", "investigating", "contained", "resolved", "closed"];

export default function IncidentsPage() {
  const router = useRouter();
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [statusFilter, setStatusFilter] = useState("all");

  useEffect(() => {
    (async () => {
      setLoading(true);
      try {
        const params = statusFilter !== "all" ? { status: statusFilter } : {};
        const data = await getIncidents(params);
        setIncidents(data.incidents);
        setTotal(data.total);
      } catch (err) {
        console.error("Failed to load incidents:", err);
      } finally {
        setLoading(false);
      }
    })();
  }, [statusFilter]);

  const openCount = incidents.filter((i) => i.status === "open").length;
  const investigatingCount = incidents.filter((i) => i.status === "investigating").length;
  const criticalCount = incidents.filter((i) => i.severity === "critical").length;

  return (
    <div>
      <Header title="Incidents" />
      <div className="p-6 space-y-6">
        {/* KPI Row */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <StatsCard label="Total Incidents" value={total} icon={<Shield className="w-5 h-5" />} accentColor="bg-blue-500" />
          <StatsCard label="Open" value={openCount} icon={<Shield className="w-5 h-5" />} accentColor="bg-yellow-500" />
          <StatsCard label="Investigating" value={investigatingCount} icon={<Shield className="w-5 h-5" />} accentColor="bg-blue-500" />
          <StatsCard label="Critical" value={criticalCount} icon={<Shield className="w-5 h-5" />} accentColor="bg-red-500" />
        </div>

        {/* Filter Bar */}
        <div className="flex items-center gap-2">
          <Filter className="h-4 w-4 text-gray-500" />
          <span className="text-xs text-gray-500">Status:</span>
          <div className="flex gap-1">
            {STATUS_OPTIONS.map((s) => (
              <button
                key={s}
                onClick={() => setStatusFilter(s)}
                className={`px-3 py-1 rounded text-xs font-medium transition-colors ${
                  statusFilter === s
                    ? "bg-soc-accent text-white"
                    : "bg-soc-surface text-gray-400 hover:text-white"
                }`}
              >
                {s}
              </button>
            ))}
          </div>
        </div>

        {/* Incident List */}
        <div className="card">
          <div className="flex items-center gap-2 px-5 py-4 border-b border-soc-border">
            <Shield className="w-4 h-4 text-gray-400" />
            <h3 className="text-sm font-semibold text-white">
              {statusFilter === "all" ? "All Incidents" : `${statusFilter} Incidents`}
            </h3>
            <span className="text-xs text-gray-500">({total})</span>
          </div>

          {loading ? (
            <div className="flex items-center justify-center py-16">
              <div className="w-6 h-6 border-2 border-soc-accent border-t-transparent rounded-full animate-spin" />
            </div>
          ) : incidents.length === 0 ? (
            <div className="text-center py-16 px-5">
              <Shield className="h-10 w-10 text-gray-600 mx-auto mb-3" />
              <p className="text-sm text-gray-500">
                {statusFilter !== "all"
                  ? `No ${statusFilter} incidents.`
                  : "No incidents yet. Incidents are auto-created when the investigation agent processes escalated alerts."}
              </p>
            </div>
          ) : (
            <div className="divide-y divide-soc-border/50">
              {incidents.map((inc) => (
                <div
                  key={inc.id}
                  onClick={() => router.push(`/incidents/${inc.id}`)}
                  className="px-5 py-4 hover:bg-soc-surface/50 cursor-pointer transition-colors flex items-center gap-4"
                >
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <SeverityBadge severity={inc.severity} />
                      <StatusBadge status={inc.status} />
                    </div>
                    <h4 className="text-sm font-medium text-white truncate">{inc.title}</h4>
                    {inc.root_cause && (
                      <p className="text-xs text-gray-400 mt-1 truncate max-w-2xl">
                        {inc.root_cause.split("\n")[0]}
                      </p>
                    )}
                  </div>
                  <div className="flex items-center gap-3 shrink-0">
                    <span className="text-xs text-gray-500 whitespace-nowrap">
                      {formatDistanceToNow(new Date(inc.created_at), { addSuffix: true })}
                    </span>
                    <ChevronRight className="h-4 w-4 text-gray-600" />
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
