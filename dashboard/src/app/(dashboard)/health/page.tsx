"use client";

import { useEffect, useState } from "react";
import {
  HeartPulse,
  Database,
  Server,
  Cpu,
  HardDrive,
  RefreshCw,
  CheckCircle,
  XCircle,
  AlertTriangle,
} from "lucide-react";
import { Header } from "@/components/header";
import { getSystemHealth, getAgentPerformance, type SystemHealth, type AgentPerformance } from "@/lib/api";

const SERVICE_ICONS: Record<string, typeof Server> = {
  agent_runtime: Cpu,
  module_engine: Server,
  mcp_servers: HardDrive,
  redis: Database,
  postgres: Database,
  neo4j: Database,
};

const SERVICE_LABELS: Record<string, string> = {
  agent_runtime: "Agent Runtime",
  module_engine: "Module Engine",
  mcp_servers: "MCP Servers",
  redis: "Redis Stack",
  postgres: "PostgreSQL",
  neo4j: "Neo4j Graph",
};

function StatusBadge({ status }: { status: string }) {
  if (status === "healthy" || status === "running") {
    return (
      <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium bg-green-500/15 text-green-400">
        <CheckCircle className="w-3 h-3" />
        {status}
      </span>
    );
  }
  if (status === "degraded") {
    return (
      <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium bg-yellow-500/15 text-yellow-400">
        <AlertTriangle className="w-3 h-3" />
        {status}
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium bg-red-500/15 text-red-400">
      <XCircle className="w-3 h-3" />
      {status}
    </span>
  );
}

export default function HealthPage() {
  const [health, setHealth] = useState<SystemHealth | null>(null);
  const [agent, setAgent] = useState<AgentPerformance | null>(null);
  const [loading, setLoading] = useState(true);
  const [lastRefresh, setLastRefresh] = useState<Date | null>(null);

  async function load() {
    try {
      const [h, a] = await Promise.all([
        getSystemHealth(),
        getAgentPerformance(),
      ]);
      setHealth(h);
      setAgent(a);
      setLastRefresh(new Date());
    } catch (err) {
      console.error("Failed to load health:", err);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    load();
    const interval = setInterval(load, 15000);
    return () => clearInterval(interval);
  }, []);

  if (loading) {
    return (
      <div className="p-6">
        <Header title="System Health" subtitle="Loading..." />
        <div className="mt-8 flex items-center justify-center">
          <div className="animate-spin rounded-full h-8 w-8 border-t-2 border-soc-accent" />
        </div>
      </div>
    );
  }

  const services = health?.services || {};
  const healthyCount = Object.values(services).filter((s) => s.status === "healthy").length;
  const totalCount = Object.keys(services).length;

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <Header title="System Health" subtitle="Real-time infrastructure monitoring" />
        <div className="flex items-center gap-3">
          {lastRefresh && (
            <span className="text-xs text-gray-500">
              Updated {lastRefresh.toLocaleTimeString()}
            </span>
          )}
          <button
            onClick={load}
            className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-soc-surface border border-soc-border text-sm text-gray-400 hover:text-white transition-colors"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            Refresh
          </button>
        </div>
      </div>

      {/* Overall Status */}
      <div className="card p-6">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            <div className={`w-16 h-16 rounded-2xl flex items-center justify-center ${
              health?.overall === "healthy" ? "bg-green-500/15" : "bg-yellow-500/15"
            }`}>
              <HeartPulse className={`w-8 h-8 ${
                health?.overall === "healthy" ? "text-green-400" : "text-yellow-400"
              }`} />
            </div>
            <div>
              <h2 className="text-xl font-bold text-white">
                System {health?.overall === "healthy" ? "Healthy" : "Degraded"}
              </h2>
              <p className="text-sm text-gray-400">
                {healthyCount}/{totalCount} services operational
              </p>
            </div>
          </div>
          <StatusBadge status={health?.overall || "unknown"} />
        </div>
      </div>

      {/* Service Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {Object.entries(services).map(([name, data]) => {
          const Icon = SERVICE_ICONS[name] || Server;
          const label = SERVICE_LABELS[name] || name;
          const { status, ...details } = data;

          return (
            <div key={name} className="card p-5">
              <div className="flex items-center justify-between mb-3">
                <div className="flex items-center gap-3">
                  <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${
                    status === "healthy" ? "bg-green-500/15" : "bg-red-500/15"
                  }`}>
                    <Icon className={`w-5 h-5 ${
                      status === "healthy" ? "text-green-400" : "text-red-400"
                    }`} />
                  </div>
                  <div>
                    <div className="text-sm font-medium text-white">{label}</div>
                    <div className="text-xs text-gray-500">{name}</div>
                  </div>
                </div>
                <StatusBadge status={String(status)} />
              </div>

              {/* Service-specific details */}
              {Object.entries(details).length > 0 && (
                <div className="border-t border-gray-800 pt-3 mt-1 space-y-1.5">
                  {Object.entries(details).map(([key, val]) => {
                    if (key === "error") {
                      return (
                        <div key={key} className="text-xs text-red-400 truncate" title={String(val)}>
                          {String(val)}
                        </div>
                      );
                    }
                    if (typeof val === "object" && val !== null) return null;
                    return (
                      <div key={key} className="flex items-center justify-between">
                        <span className="text-xs text-gray-500">{key.replace(/_/g, " ")}</span>
                        <span className="text-xs text-gray-300 font-mono">
                          {typeof val === "number" ? val.toLocaleString() : String(val)}
                        </span>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          );
        })}
      </div>

      {/* Agent Runtime Details */}
      {agent && (
        <div className="card p-6">
          <h3 className="text-sm font-medium text-gray-400 uppercase tracking-wider mb-4">Agent Runtime Details</h3>
          <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-4">
            <div className="text-center p-3 rounded-lg bg-gray-800/50">
              <div className="text-xl font-bold text-white">{agent.alerts_triaged}</div>
              <div className="text-[10px] text-gray-500 mt-1 uppercase">Triaged</div>
            </div>
            <div className="text-center p-3 rounded-lg bg-gray-800/50">
              <div className="text-xl font-bold text-white">{agent.investigations}</div>
              <div className="text-[10px] text-gray-500 mt-1 uppercase">Investigations</div>
            </div>
            <div className="text-center p-3 rounded-lg bg-gray-800/50">
              <div className="text-xl font-bold text-white">{agent.critic_reviews}</div>
              <div className="text-[10px] text-gray-500 mt-1 uppercase">Critic Reviews</div>
            </div>
            <div className="text-center p-3 rounded-lg bg-gray-800/50">
              <div className="text-xl font-bold text-green-400">{agent.actions_executed}</div>
              <div className="text-[10px] text-gray-500 mt-1 uppercase">Executed</div>
            </div>
            <div className="text-center p-3 rounded-lg bg-gray-800/50">
              <div className="text-xl font-bold text-yellow-400">{agent.actions_escalated}</div>
              <div className="text-[10px] text-gray-500 mt-1 uppercase">Escalated</div>
            </div>
            <div className="text-center p-3 rounded-lg bg-gray-800/50">
              <div className="text-xl font-bold text-cyan-400">{agent.playbooks_run}</div>
              <div className="text-[10px] text-gray-500 mt-1 uppercase">Playbooks</div>
            </div>
          </div>

          <div className="mt-4 flex items-center gap-4 text-xs text-gray-500">
            <span>Mode: <span className="text-gray-300">{agent.mode}</span></span>
            <span>Status: <span className={agent.status === "running" ? "text-green-400" : "text-red-400"}>{agent.status}</span></span>
          </div>
        </div>
      )}

      {/* Queue Depths */}
      {services.redis && (
        <div className="card p-6">
          <h3 className="text-sm font-medium text-gray-400 uppercase tracking-wider mb-4">Queue Depths</h3>
          <div className="grid grid-cols-2 gap-4">
            <div className="flex items-center justify-between p-4 rounded-lg bg-gray-800/30">
              <div>
                <div className="text-sm text-white">Triage Queue</div>
                <div className="text-xs text-gray-500">soc:alerts:triage</div>
              </div>
              <div className="text-2xl font-bold text-soc-accent">
                {(services.redis as Record<string, unknown>).triage_queue_depth ?? "?"}
              </div>
            </div>
            <div className="flex items-center justify-between p-4 rounded-lg bg-gray-800/30">
              <div>
                <div className="text-sm text-white">Playbook Queue</div>
                <div className="text-xs text-gray-500">soc:playbook:run</div>
              </div>
              <div className="text-2xl font-bold text-soc-accent">
                {(services.redis as Record<string, unknown>).playbook_queue_depth ?? "?"}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
