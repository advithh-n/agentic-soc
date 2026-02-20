import { clsx } from "clsx";
import type { ReactNode } from "react";

interface StatsCardProps {
  label: string;
  value: string | number;
  icon: ReactNode;
  trend?: { value: string; positive: boolean };
  accentColor?: string;
}

export function StatsCard({
  label,
  value,
  icon,
  trend,
  accentColor = "bg-soc-accent",
}: StatsCardProps) {
  return (
    <div className="card p-5">
      <div className="flex items-start justify-between">
        <div>
          <p className="text-xs text-gray-500 uppercase tracking-wider">{label}</p>
          <p className="text-2xl font-bold text-white mt-1">{value}</p>
          {trend && (
            <p
              className={clsx(
                "text-xs mt-1",
                trend.positive ? "text-green-400" : "text-red-400"
              )}
            >
              {trend.positive ? "+" : ""}{trend.value}
            </p>
          )}
        </div>
        <div
          className={clsx(
            "w-10 h-10 rounded-lg flex items-center justify-center",
            accentColor + "/15"
          )}
        >
          <div className={clsx("text-sm", accentColor.replace("bg-", "text-"))}>
            {icon}
          </div>
        </div>
      </div>
    </div>
  );
}
