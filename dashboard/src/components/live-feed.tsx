"use client";

import { formatDistanceToNow } from "date-fns";
import { Radio, AlertTriangle, Brain } from "lucide-react";
import { SeverityBadge } from "./severity-badge";
import { useLiveAlerts } from "@/hooks/use-websocket";
import type { WsMessage } from "@/lib/ws";

function FeedItem({ msg }: { msg: WsMessage }) {
  const data = msg.data as Record<string, string> | undefined;

  if (msg.type === "alert") {
    return (
      <div className="flex items-start gap-3 animate-slide-in">
        <div className="mt-0.5 w-6 h-6 rounded-full bg-severity-critical/20 flex items-center justify-center flex-shrink-0">
          <AlertTriangle className="w-3 h-3 text-severity-critical" />
        </div>
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <span className="text-sm text-gray-200 font-medium truncate">
              {data?.title || "New Alert"}
            </span>
            {data?.severity && <SeverityBadge severity={data.severity} />}
          </div>
          <p className="text-xs text-gray-500 mt-0.5">
            {data?.source || "unknown"} &middot;{" "}
            {data?.created_at
              ? formatDistanceToNow(new Date(data.created_at), { addSuffix: true })
              : "just now"}
          </p>
        </div>
      </div>
    );
  }

  if (msg.type === "triage") {
    return (
      <div className="flex items-start gap-3 animate-slide-in">
        <div className="mt-0.5 w-6 h-6 rounded-full bg-purple-500/20 flex items-center justify-center flex-shrink-0">
          <Brain className="w-3 h-3 text-purple-400" />
        </div>
        <div className="min-w-0 flex-1">
          <span className="text-sm text-gray-200">
            Triage complete: <span className="text-purple-400">{data?.classification || "classified"}</span>
          </span>
          <p className="text-xs text-gray-500 mt-0.5">
            Confidence: {data?.confidence || "N/A"}
          </p>
        </div>
      </div>
    );
  }

  return null;
}

export function LiveFeed() {
  const { messages, clear } = useLiveAlerts(20);

  return (
    <div className="card">
      <div className="flex items-center justify-between px-5 py-4 border-b border-soc-border">
        <div className="flex items-center gap-2">
          <Radio className="w-4 h-4 text-green-400" />
          <h3 className="text-sm font-semibold text-white">Live Feed</h3>
          <span className="relative flex h-2 w-2">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75" />
            <span className="relative inline-flex rounded-full h-2 w-2 bg-green-500" />
          </span>
        </div>
        {messages.length > 0 && (
          <button
            onClick={clear}
            className="text-xs text-gray-500 hover:text-gray-300 transition-colors"
          >
            Clear
          </button>
        )}
      </div>
      <div className="p-4 space-y-4 max-h-96 overflow-y-auto">
        {messages.length === 0 ? (
          <p className="text-sm text-gray-500 text-center py-8">
            Waiting for live events...
          </p>
        ) : (
          messages.map((msg, i) => <FeedItem key={i} msg={msg} />)
        )}
      </div>
    </div>
  );
}
