"use client";

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useRef,
  useState,
} from "react";
import type { ReactNode } from "react";
import {
  login as apiLogin,
  getMe,
  setTokens,
  clearTokens,
  getAccessToken,
  setOnAuthError,
  loadStoredRefreshToken,
} from "./api";
import { AlertWebSocket, type WsMessage, type WsListener } from "./ws";

interface User {
  user_id: string;
  tenant_id: string;
  role: string;
  email: string;
}

interface AuthContextValue {
  user: User | null;
  loading: boolean;
  login: (email: string, password: string, tenantSlug: string) => Promise<void>;
  logout: () => void;
  subscribeAlerts: (listener: WsListener) => () => void;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const wsRef = useRef<AlertWebSocket | null>(null);

  const logout = useCallback(() => {
    wsRef.current?.disconnect();
    wsRef.current = null;
    clearTokens();
    setUser(null);
  }, []);

  useEffect(() => {
    setOnAuthError(logout);

    const stored = loadStoredRefreshToken();
    if (!stored) {
      setLoading(false);
      return;
    }

    // Try to refresh session
    (async () => {
      try {
        const { apiFetch } = await import("./api");
        const data = await apiFetch<{
          access_token: string;
          refresh_token: string;
        }>("/api/v1/auth/refresh", {
          method: "POST",
          skipAuth: true,
          body: JSON.stringify({ refresh_token: stored }),
        });
        setTokens(data.access_token, data.refresh_token);
        const me = await getMe();
        setUser(me);

        wsRef.current = new AlertWebSocket(data.access_token);
        wsRef.current.connect();
      } catch {
        clearTokens();
      } finally {
        setLoading(false);
      }
    })();
  }, [logout]);

  const login = useCallback(
    async (email: string, password: string, tenantSlug: string) => {
      const data = await apiLogin(email, password, tenantSlug);
      const me = await getMe();
      setUser(me);

      wsRef.current?.disconnect();
      wsRef.current = new AlertWebSocket(data.access_token);
      wsRef.current.connect();
    },
    []
  );

  const subscribeAlerts = useCallback((listener: WsListener) => {
    if (!wsRef.current) return () => {};
    return wsRef.current.subscribe(listener);
  }, []);

  return (
    <AuthContext.Provider value={{ user, loading, login, logout, subscribeAlerts }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}
