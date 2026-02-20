"use client";

import Link from "next/link";
import { formatDistanceToNow } from "date-fns";
import { SeverityBadge, StatusBadge, SourceBadge } from "./severity-badge";
import type { Alert } from "@/lib/api";

interface AlertTableProps {
  alerts: Alert[];
  compact?: boolean;
}

export function AlertTable({ alerts, compact }: AlertTableProps) {
  if (alerts.length === 0) {
    return (
      <div className="text-center py-12 text-gray-500">
        No alerts found
      </div>
    );
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-soc-border text-left text-xs text-gray-500 uppercase tracking-wider">
            <th className="pb-3 pr-4">Severity</th>
            <th className="pb-3 pr-4">Title</th>
            {!compact && <th className="pb-3 pr-4">Source</th>}
            <th className="pb-3 pr-4">Status</th>
            {!compact && <th className="pb-3 pr-4">MITRE</th>}
            <th className="pb-3 pr-4">Time</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-soc-border">
          {alerts.map((alert) => (
            <tr
              key={alert.id}
              className="hover:bg-white/[0.02] transition-colors"
            >
              <td className="py-3 pr-4">
                <SeverityBadge severity={alert.severity} />
              </td>
              <td className="py-3 pr-4">
                <Link
                  href={`/alerts/${alert.id}`}
                  className="text-gray-200 hover:text-soc-accent transition-colors font-medium"
                >
                  {alert.title}
                </Link>
                {compact && (
                  <div className="mt-0.5">
                    <SourceBadge source={alert.source} />
                  </div>
                )}
              </td>
              {!compact && (
                <td className="py-3 pr-4">
                  <SourceBadge source={alert.source} />
                </td>
              )}
              <td className="py-3 pr-4">
                <StatusBadge status={alert.status} />
              </td>
              {!compact && (
                <td className="py-3 pr-4">
                  <span className="text-xs font-mono text-gray-400">
                    {alert.mitre_technique || "-"}
                  </span>
                </td>
              )}
              <td className="py-3 pr-4 text-xs text-gray-400 whitespace-nowrap">
                {formatDistanceToNow(new Date(alert.created_at), {
                  addSuffix: true,
                })}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
