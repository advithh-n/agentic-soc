"use client";

import { useEffect, useState } from "react";
import {
  AlertTriangle,
  Shield,
  Clock,
  TrendingUp,
  Zap,
  Eye,
  PlayCircle,
} from "lucide-react";
import { Header } from "@/components/header";
import { StatsCard } from "@/components/stats-card";
import { AlertTable } from "@/components/alert-table";
import { LiveFeed } from "@/components/live-feed";
import { getAlerts, getPendingActions, type Alert } from "@/lib/api";

export default function SOCOverview() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [stats, setStats] = useState({
    total: 0,
    open: 0,
    critical: 0,
    triaged: 0,
    pendingActions: 0,
  });
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function load() {
      try {
        const [allRes, openRes, critRes, pendingRes] = await Promise.all([
          getAlerts({ page_size: 10 }),
          getAlerts({ status: "open", page_size: 1 }),
          getAlerts({ severity: "critical", page_size: 1 }),
          getPendingActions().catch(() => []),
        ]);
        setAlerts(allRes.alerts);
        setStats({
          total: allRes.total,
          open: openRes.total,
          critical: critRes.total,
          triaged: allRes.total - openRes.total,
          pendingActions: Array.isArray(pendingRes) ? pendingRes.length : 0,
        });
      } catch (err) {
        console.error("Failed to load alerts:", err);
      } finally {
        setLoading(false);
      }
    }
    load();
    const interval = setInterval(load, 30000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div>
      <Header title="SOC Overview" />

      <div className="p-6 space-y-6">
        {/* KPI Cards */}
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-5 gap-4">
          <StatsCard
            label="Total Alerts"
            value={loading ? "-" : stats.total}
            icon={<AlertTriangle className="w-5 h-5" />}
            accentColor="bg-soc-accent"
          />
          <StatsCard
            label="Open"
            value={loading ? "-" : stats.open}
            icon={<Eye className="w-5 h-5" />}
            accentColor="bg-severity-high"
          />
          <StatsCard
            label="Critical"
            value={loading ? "-" : stats.critical}
            icon={<Zap className="w-5 h-5" />}
            accentColor="bg-severity-critical"
          />
          <StatsCard
            label="Triaged"
            value={loading ? "-" : stats.triaged}
            icon={<Shield className="w-5 h-5" />}
            accentColor="bg-green-500"
          />
          <StatsCard
            label="Pending Actions"
            value={loading ? "-" : stats.pendingActions}
            icon={<PlayCircle className="w-5 h-5" />}
            accentColor="bg-yellow-500"
          />
        </div>

        {/* Main content: Recent Alerts + Live Feed */}
        <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
          {/* Recent Alerts */}
          <div className="xl:col-span-2 card">
            <div className="flex items-center justify-between px-5 py-4 border-b border-soc-border">
              <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                <Clock className="w-4 h-4 text-gray-400" />
                Recent Alerts
              </h3>
              <a
                href="/alerts"
                className="text-xs text-soc-accent hover:text-blue-300 transition-colors"
              >
                View all
              </a>
            </div>
            <div className="p-5">
              {loading ? (
                <div className="flex items-center justify-center py-12">
                  <div className="w-6 h-6 border-2 border-soc-accent border-t-transparent rounded-full animate-spin" />
                </div>
              ) : (
                <AlertTable alerts={alerts} compact />
              )}
            </div>
          </div>

          {/* Live Feed */}
          <div className="xl:col-span-1">
            <LiveFeed />

            {/* Quick Stats */}
            <div className="card mt-4 p-5">
              <h3 className="text-sm font-semibold text-white flex items-center gap-2 mb-4">
                <TrendingUp className="w-4 h-4 text-gray-400" />
                Detection Modules
              </h3>
              <div className="space-y-3">
                <ModuleStatus name="Stripe Carding" status="active" rules={5} />
                <ModuleStatus name="Auth Anomaly" status="active" rules={4} />
                <ModuleStatus name="Infrastructure" status="active" rules={3} />
                <ModuleStatus name="AI Agent Monitor" status="active" rules={9} />
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

function ModuleStatus({
  name,
  status,
  rules,
}: {
  name: string;
  status: "active" | "planned";
  rules: number;
}) {
  return (
    <div className="flex items-center justify-between text-sm">
      <div className="flex items-center gap-2">
        <span
          className={`w-2 h-2 rounded-full ${
            status === "active" ? "bg-green-500" : "bg-gray-600"
          }`}
        />
        <span className="text-gray-300">{name}</span>
      </div>
      <span className="text-xs text-gray-500">
        {status === "active" ? `${rules} rules` : "Planned"}
      </span>
    </div>
  );
}
