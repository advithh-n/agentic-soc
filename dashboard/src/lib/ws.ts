const WS_URL = process.env.NEXT_PUBLIC_WS_URL || "ws://localhost:8050";

export type WsMessageType = "alert" | "triage" | "ping";

export interface WsMessage {
  type: WsMessageType;
  data?: Record<string, unknown>;
}

export type WsListener = (msg: WsMessage) => void;

export class AlertWebSocket {
  private ws: WebSocket | null = null;
  private listeners: Set<WsListener> = new Set();
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private token: string;
  private reconnectDelay = 2000;
  private maxReconnectDelay = 30000;

  constructor(token: string) {
    this.token = token;
  }

  connect() {
    if (this.ws?.readyState === WebSocket.OPEN) return;

    try {
      this.ws = new WebSocket(`${WS_URL}/ws/alerts?token=${this.token}`);

      this.ws.onopen = () => {
        this.reconnectDelay = 2000;
      };

      this.ws.onmessage = (event) => {
        try {
          const msg: WsMessage = JSON.parse(event.data);
          if (msg.type === "ping") return;
          this.listeners.forEach((fn) => fn(msg));
        } catch {
          // ignore malformed messages
        }
      };

      this.ws.onclose = (event) => {
        if (event.code !== 4001) {
          this.scheduleReconnect();
        }
      };

      this.ws.onerror = () => {
        this.ws?.close();
      };
    } catch {
      this.scheduleReconnect();
    }
  }

  private scheduleReconnect() {
    if (this.reconnectTimer) return;
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      this.reconnectDelay = Math.min(
        this.reconnectDelay * 1.5,
        this.maxReconnectDelay
      );
      this.connect();
    }, this.reconnectDelay);
  }

  subscribe(listener: WsListener) {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  }

  disconnect() {
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    this.ws?.close();
    this.ws = null;
    this.listeners.clear();
  }

  updateToken(token: string) {
    this.token = token;
    if (this.ws?.readyState === WebSocket.OPEN) {
      this.ws.close();
      this.connect();
    }
  }
}
