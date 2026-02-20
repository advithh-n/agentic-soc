"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { Activity, AlertCircle, Lock } from "lucide-react";
import { useAuth } from "@/lib/auth";

export default function LoginPage() {
  const { login, user } = useAuth();
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [tenantSlug, setTenantSlug] = useState("");
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);

  // Redirect if already logged in
  useEffect(() => {
    if (user) {
      router.replace("/");
    }
  }, [user, router]);

  if (user) {
    return null;
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    setSubmitting(true);
    try {
      await login(email, password, tenantSlug);
      router.replace("/");
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Login failed. Check your credentials."
      );
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center p-4">
      <div className="w-full max-w-sm">
        {/* Logo */}
        <div className="flex flex-col items-center mb-8">
          <div className="w-14 h-14 rounded-2xl bg-soc-accent flex items-center justify-center mb-4">
            <Activity className="w-8 h-8 text-white" />
          </div>
          <h1 className="text-xl font-bold text-white">Agentic SOC</h1>
          <p className="text-sm text-gray-500 mt-1">Security Operations Center</p>
        </div>

        {/* Form */}
        <form onSubmit={handleSubmit} className="card p-6 space-y-4">
          {error && (
            <div className="flex items-center gap-2 p-3 rounded-lg bg-severity-critical/10 border border-severity-critical/20">
              <AlertCircle className="w-4 h-4 text-severity-critical flex-shrink-0" />
              <p className="text-sm text-severity-critical">{error}</p>
            </div>
          )}

          <div>
            <label className="block text-xs text-gray-400 mb-1.5">Organization</label>
            <input
              type="text"
              value={tenantSlug}
              onChange={(e) => setTenantSlug(e.target.value)}
              placeholder="e.g. heya"
              required
              className="w-full px-3 py-2.5 bg-soc-bg border border-soc-border rounded-lg text-sm text-white placeholder-gray-600 focus:outline-none focus:border-soc-accent transition-colors"
            />
          </div>

          <div>
            <label className="block text-xs text-gray-400 mb-1.5">Email</label>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="analyst@example.com"
              required
              className="w-full px-3 py-2.5 bg-soc-bg border border-soc-border rounded-lg text-sm text-white placeholder-gray-600 focus:outline-none focus:border-soc-accent transition-colors"
            />
          </div>

          <div>
            <label className="block text-xs text-gray-400 mb-1.5">Password</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Enter password"
              required
              className="w-full px-3 py-2.5 bg-soc-bg border border-soc-border rounded-lg text-sm text-white placeholder-gray-600 focus:outline-none focus:border-soc-accent transition-colors"
            />
          </div>

          <button
            type="submit"
            disabled={submitting}
            className="w-full flex items-center justify-center gap-2 py-2.5 bg-soc-accent hover:bg-blue-600 disabled:opacity-50 rounded-lg text-sm font-medium text-white transition-colors"
          >
            {submitting ? (
              <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
            ) : (
              <>
                <Lock className="w-4 h-4" />
                Sign In
              </>
            )}
          </button>
        </form>

        <p className="text-center text-xs text-gray-600 mt-6">
          Agentic SOC v5 &middot; Lean Enterprise
        </p>
      </div>
    </div>
  );
}
