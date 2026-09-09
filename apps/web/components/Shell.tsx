"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useEffect } from "react";
import type { ReactNode } from "react";
import { useAuth } from "@/lib/auth";
import { useApi } from "@/lib/useApi";
import { api } from "@/lib/api";

const NAV = [
  { href: "/", label: "War Room", icon: "◎", group: "Operazioni" },
  { href: "/signals", label: "Segnalazioni", icon: "✉", group: "Operazioni" },
  { href: "/tickets", label: "Ticket", icon: "🎫", group: "Operazioni" },
  { href: "/topology", label: "Topologia", icon: "⧉", group: "Monitoraggio" },
  { href: "/inventory", label: "Asset", icon: "▦", group: "Monitoraggio" },
  { href: "/new-ui-inventory", label: "Inventario New UI", icon: "▤", group: "Monitoraggio" },
  { href: "/flows", label: "Attività & flow", icon: "↝", group: "Monitoraggio" },
  { href: "/risk", label: "Risk score Cisco", icon: "◔", group: "Sicurezza" },
  { href: "/events", label: "Eventi", icon: "❗", group: "Sicurezza" },
  { href: "/vulnerabilities", label: "Vulnerabilità", icon: "🐛", group: "Sicurezza" },
  { href: "/baseline", label: "Baseline", icon: "⇄", group: "Sicurezza" },
  { href: "/sensors", label: "Sensori & DPI", icon: "📡", group: "Piattaforma" },
  { href: "/vmware", label: "Ambiente VMware", icon: "🖧", group: "Piattaforma" },
  { href: "/sources", label: "Sorgenti & qualità", icon: "◈", group: "Piattaforma" },
  { href: "/evidence", label: "Evidenze & report", icon: "🗄", group: "Piattaforma" },
  { href: "/attacks", label: "Attacchi & Detection", icon: "⚔", group: "Moduli DTLab" },
  { href: "/twin", label: "Digital Twin", icon: "⚙", group: "Moduli DTLab" },
  { href: "/compliance", label: "Compliance", icon: "⛨", group: "Moduli DTLab" },
  { href: "/history", label: "Trend", icon: "📈", group: "Moduli DTLab" },
];

export function Shell({ children }: { children: ReactNode }) {
  const { token, role, ready, signOut } = useAuth();
  const router = useRouter();
  const pathname = usePathname();

  useEffect(() => {
    if (ready && !token) router.replace("/login");
  }, [ready, token, router]);

  if (!ready || !token) {
    return (
      <div className="flex h-screen items-center justify-center text-[var(--color-muted)]">
        Verifica sessione…
      </div>
    );
  }

  const groups = Array.from(new Set(NAV.map((n) => n.group)));

  return (
    <div className="flex h-screen overflow-hidden">
      <aside className="w-64 shrink-0 border-r border-[var(--color-border)] bg-[var(--color-surface)] flex flex-col">
        <div className="px-5 py-5 border-b border-[var(--color-border)]">
          <div className="flex items-center gap-2.5">
            <div className="h-9 w-9 rounded-xl bg-gradient-to-br from-indigo-500 to-violet-500 flex items-center justify-center text-white font-bold text-sm shadow-sm">
              DT
            </div>
            <div>
              <div className="text-sm font-semibold leading-tight text-[var(--color-ink)]">
                DTLab
              </div>
              <div className="text-[10px] uppercase tracking-widest text-[var(--color-faint)]">
                Control Center
              </div>
            </div>
          </div>
        </div>

        <nav className="flex-1 overflow-y-auto px-3 py-4 space-y-5">
          {groups.map((group) => (
            <div key={group}>
              <div className="px-2 mb-1.5 text-[10px] font-semibold uppercase tracking-widest text-[var(--color-faint)]">
                {group}
              </div>
              <div className="space-y-0.5">
                {NAV.filter((n) => n.group === group).map((item) => {
                  const active = pathname === item.href;
                  return (
                    <Link
                      key={item.href}
                      href={item.href}
                      className={`flex items-center gap-3 rounded-lg px-3 py-2 text-sm transition ${
                        active
                          ? "bg-[var(--color-brand-soft)] text-[var(--color-brand)] font-medium"
                          : "text-[var(--color-ink-2)] hover:bg-slate-50"
                      }`}
                    >
                      <span className="w-4 text-center text-[var(--color-faint)]">{item.icon}</span>
                      {item.label}
                    </Link>
                  );
                })}
              </div>
            </div>
          ))}
        </nav>

        <div className="px-4 py-3 border-t border-[var(--color-border)] text-xs text-[var(--color-muted)]">
          <div className="flex items-center justify-between">
            <span>
              Ruolo:{" "}
              <span className="text-[var(--color-brand)] font-medium font-mono">{role}</span>
            </span>
            <button
              onClick={signOut}
              className="text-[var(--color-faint)] hover:text-[var(--color-danger)] transition"
            >
              Esci
            </button>
          </div>
        </div>
      </aside>

      <div className="flex-1 flex flex-col overflow-hidden">
        <TopBar />
        <main className="flex-1 overflow-y-auto px-8 py-6">{children}</main>
      </div>
    </div>
  );
}

function TopBar() {
  const { data } = useApi(api.meta, []);
  const sandbox = data?.sync.publication_mode === "allow_demo";
  return (
    <header className="h-14 shrink-0 border-b border-[var(--color-border)] bg-[var(--color-surface)]/80 backdrop-blur flex items-center justify-between px-8">
      <div className="flex items-center gap-3 text-sm">
        <span className="h-2 w-2 rounded-full bg-emerald-500 live-dot" />
        <span className="text-[var(--color-ink)] font-medium">
          {data?.environment.name ?? "DTLab"}
        </span>
        {sandbox && (
          <span className="rounded-full border border-amber-200 bg-[var(--color-warn-soft)] px-2 py-0.5 text-[10px] font-medium uppercase tracking-wider text-[var(--color-warn)]">
            Sandbox
          </span>
        )}
      </div>
      <div className="flex items-center gap-3 text-xs text-[var(--color-muted)] font-mono">
        {data && (
          <>
            <span>schema {data.schema_version}</span>
            <span className="text-[var(--color-faint)]">·</span>
            <span>sync {data.sync.state}</span>
            <span className="text-[var(--color-faint)]">·</span>
            <span title={data.content_sha256}>#{data.content_sha256.slice(0, 8)}</span>
          </>
        )}
      </div>
    </header>
  );
}
