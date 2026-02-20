"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { useAuth } from "@/lib/auth";
import type { WsMessage } from "@/lib/ws";

export function useLiveAlerts(maxItems = 50) {
  const { subscribeAlerts } = useAuth();
  const [messages, setMessages] = useState<WsMessage[]>([]);
  const messagesRef = useRef(messages);
  messagesRef.current = messages;

  useEffect(() => {
    const unsub = subscribeAlerts((msg) => {
      setMessages((prev) => [msg, ...prev].slice(0, maxItems));
    });
    return unsub;
  }, [subscribeAlerts, maxItems]);

  const clear = useCallback(() => setMessages([]), []);

  return { messages, clear };
}
