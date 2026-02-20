"use client";

import { Bell, Radio } from "lucide-react";
import { useLiveAlerts } from "@/hooks/use-websocket";

export function Header({ title }: { title: string }) {
  const { messages } = useLiveAlerts(10);
  const recentCount = messages.filter((m) => m.type === "alert").length;

  return (
    <header className="h-16 border-b border-soc-border flex items-center justify-between px-6">
      <h1 className="text-lg font-semibold text-white">{title}</h1>
      <div className="flex items-center gap-4">
        {/* Live indicator */}
        <div className="flex items-center gap-2 text-xs text-gray-400">
          <span className="relative flex h-2 w-2">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75" />
            <span className="relative inline-flex rounded-full h-2 w-2 bg-green-500" />
          </span>
          <Radio className="w-3 h-3" />
          Live
        </div>

        {/* Alert bell */}
        <button className="relative p-2 text-gray-400 hover:text-gray-200 transition-colors">
          <Bell className="w-5 h-5" />
          {recentCount > 0 && (
            <span className="absolute -top-0.5 -right-0.5 w-4 h-4 bg-severity-critical rounded-full text-[10px] font-bold text-white flex items-center justify-center">
              {recentCount > 9 ? "9+" : recentCount}
            </span>
          )}
        </button>
      </div>
    </header>
  );
}
