"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { clsx } from "clsx";
import {
  LayoutDashboard,
  AlertTriangle,
  Shield,
  CheckCircle,
  Bot,
  Settings,
  LogOut,
  Activity,
  BarChart3,
  HeartPulse,
  FileText,
} from "lucide-react";
import { useAuth } from "@/lib/auth";

const NAV_ITEMS = [
  { href: "/", label: "SOC Overview", icon: LayoutDashboard },
  { href: "/alerts", label: "Alerts", icon: AlertTriangle },
  { href: "/incidents", label: "Incidents", icon: Shield },
  { href: "/approvals", label: "Approvals", icon: CheckCircle },
  { href: "/ai-agents", label: "AI Agents", icon: Bot },
  { href: "/analytics", label: "Analytics", icon: BarChart3 },
  { href: "/health", label: "System Health", icon: HeartPulse },
  { href: "/audit-log", label: "Audit Log", icon: FileText },
  { href: "/settings", label: "Settings", icon: Settings },
];

export function Sidebar() {
  const pathname = usePathname();
  const { user, logout } = useAuth();

  return (
    <aside className="fixed left-0 top-0 h-screen w-60 bg-soc-surface border-r border-soc-border flex flex-col z-50">
      {/* Logo */}
      <div className="h-16 flex items-center gap-2 px-5 border-b border-soc-border">
        <div className="w-8 h-8 rounded-lg bg-soc-accent flex items-center justify-center">
          <Activity className="w-5 h-5 text-white" />
        </div>
        <div>
          <div className="text-sm font-bold text-white tracking-wide">Agentic SOC</div>
          <div className="text-[10px] text-gray-500 uppercase tracking-widest">v5 Enterprise</div>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 py-4 px-3 space-y-1 overflow-y-auto">
        {NAV_ITEMS.map((item) => {
          const isActive =
            item.href === "/"
              ? pathname === "/"
              : pathname.startsWith(item.href);
          return (
            <Link
              key={item.href}
              href={item.href}
              className={clsx(
                "flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm transition-colors",
                isActive
                  ? "bg-soc-accent/15 text-soc-accent"
                  : "text-gray-400 hover:bg-white/5 hover:text-gray-200"
              )}
            >
              <item.icon className="w-4 h-4 flex-shrink-0" />
              {item.label}
            </Link>
          );
        })}
      </nav>

      {/* User section */}
      {user && (
        <div className="border-t border-soc-border p-4">
          <div className="flex items-center justify-between">
            <div className="min-w-0">
              <div className="text-sm text-gray-300 truncate">{user.email}</div>
              <div className="text-xs text-gray-500 uppercase">{user.role}</div>
            </div>
            <button
              onClick={logout}
              className="p-2 text-gray-500 hover:text-gray-300 transition-colors"
              title="Logout"
            >
              <LogOut className="w-4 h-4" />
            </button>
          </div>
        </div>
      )}
    </aside>
  );
}
