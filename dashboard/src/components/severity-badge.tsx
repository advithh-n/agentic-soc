import { clsx } from "clsx";

const SEVERITY_CLASSES: Record<string, string> = {
  critical: "severity-critical",
  high: "severity-high",
  medium: "severity-medium",
  low: "severity-low",
};

const STATUS_CLASSES: Record<string, string> = {
  open: "status-open",
  triaged: "status-triaged",
  investigating: "status-investigating",
  resolved: "status-resolved",
  false_positive: "bg-gray-500/20 text-gray-400 border border-gray-500/30",
};

export function SeverityBadge({ severity }: { severity: string }) {
  return (
    <span className={clsx("severity-badge", SEVERITY_CLASSES[severity] || "severity-low")}>
      {severity}
    </span>
  );
}

export function StatusBadge({ status }: { status: string }) {
  return (
    <span
      className={clsx(
        "status-badge",
        STATUS_CLASSES[status] || "status-open"
      )}
    >
      {status.replace("_", " ")}
    </span>
  );
}

export function SourceBadge({ source }: { source: string }) {
  const colors: Record<string, string> = {
    stripe: "bg-purple-500/20 text-purple-400 border-purple-500/30",
    clerk: "bg-blue-500/20 text-blue-400 border-blue-500/30",
    aws: "bg-orange-500/20 text-orange-400 border-orange-500/30",
    wazuh: "bg-cyan-500/20 text-cyan-400 border-cyan-500/30",
    langfuse: "bg-pink-500/20 text-pink-400 border-pink-500/30",
    ai_agent: "bg-emerald-500/20 text-emerald-400 border-emerald-500/30",
  };
  return (
    <span
      className={clsx(
        "inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border",
        colors[source] || "bg-gray-500/20 text-gray-400 border-gray-500/30"
      )}
    >
      {source}
    </span>
  );
}
