"use client";

import { useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import { api } from "@/lib/api";
import { useApi } from "@/lib/useApi";
import { useAuth } from "@/lib/auth";
import { Badge, Card, ErrorNote, PageHeader, Spinner, StatTile } from "@/components/ui";
import type { Signal } from "@/lib/types";

const TYPE_LABEL: Record<string, string> = {
  event: "Evento Cisco",
  finding: "Finding DTLab",
  baseline_difference: "Differenza baseline",
  vulnerability: "Vulnerabilità",
  new_ui_alert: "Alert New UI",
  new_ui_vulnerability: "Vuln New UI",
};
const SEV_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4, unknown: 5 };

function sevTone(s: string) {
  if (s === "critical" || s === "high") return "danger" as const;
  if (s === "medium") return "warn" as const;
  return "neutral" as const;
}

export default function SignalsPage() {
  const { role } = useAuth();
  const canWrite = role === "analyst" || role === "admin";
  const [tick, setTick] = useState(0);
  const summary = useApi(api.ticketingSummary, [tick]);
  const signals = useApi(api.signals, [tick]);

  const [search, setSearch] = useState("");
  const [onlyUnassigned, setOnlyUnassigned] = useState(true);
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const filtered = useMemo(() => {
    const items = signals.data?.items ?? [];
    const needle = search.trim().toLowerCase();
    return items
      .filter((s) => (onlyUnassigned ? s.ticket_state !== "open" : true))
      .filter((s) =>
        !needle
          ? true
          : `${s.title} ${s.description ?? ""} ${s.source_record_id ?? ""}`.toLowerCase().includes(needle),
      )
      .sort((a, b) => (SEV_ORDER[a.severity] ?? 5) - (SEV_ORDER[b.severity] ?? 5));
  }, [signals.data, search, onlyUnassigned]);

  const selected = filtered.find((s) => s.id === selectedId) ?? filtered[0] ?? null;

  if (signals.loading || summary.loading) return <Spinner />;
  if (signals.error) return <ErrorNote message={signals.error} />;

  const k = summary.data;

  return (
    <div>
      <PageHeader
        title="Segnalazioni"
        subtitle="Inbox deduplicata di eventi, finding, differenze baseline e vulnerabilità. Ogni ticket nasce solo da una decisione esplicita."
      />

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
        <StatTile label="Segnali" value={k?.signals ?? "—"} tone="brand" />
        <StatTile label="Da valutare" value={k?.unassigned ?? "—"} tone={(k?.unassigned ?? 0) > 0 ? "warn" : "ok"} />
        <StatTile label="Critici / alti" value={k?.critical_high ?? "—"} tone={(k?.critical_high ?? 0) > 0 ? "danger" : "ok"} />
        <StatTile label="Ticket attivi" value={k?.tickets_active ?? "—"} />
      </div>

      <div className="flex flex-wrap items-center gap-3 mb-4">
        <input
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Cerca titolo, descrizione, record…"
          className="flex-1 min-w-[240px] rounded-lg border border-[var(--color-border-strong)] bg-[var(--color-surface)] px-3 py-2 text-sm outline-none focus:border-[var(--color-brand)] focus:ring-2 focus:ring-indigo-100"
        />
        <label className="flex items-center gap-2 text-sm text-[var(--color-ink-2)]">
          <input type="checkbox" checked={onlyUnassigned} onChange={(e) => setOnlyUnassigned(e.target.checked)} />
          Solo da valutare
        </label>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-5 gap-6">
        <Card title={`Coda operativa · ${filtered.length}`} className="lg:col-span-3">
          <div className="divide-y divide-[var(--color-border)] -m-1">
            {filtered.map((s) => (
              <button
                key={s.id}
                onClick={() => setSelectedId(s.id)}
                className={`w-full text-left px-3 py-3 flex items-start gap-3 rounded-lg transition ${
                  selected?.id === s.id ? "bg-[var(--color-brand-soft)]" : "hover:bg-slate-50"
                }`}
              >
                <Badge tone={sevTone(s.severity)}>{s.severity}</Badge>
                <div className="min-w-0 flex-1">
                  <div className="text-sm font-medium text-[var(--color-ink)] truncate">{s.title}</div>
                  <div className="text-xs text-[var(--color-faint)]">
                    {TYPE_LABEL[s.signal_type] ?? s.signal_type} · {s.occurrence_count} osservazioni
                  </div>
                </div>
                {s.ticket_state === "open" ? (
                  <Badge tone="ok">ticket</Badge>
                ) : s.ticket_state === "resurfaced" ? (
                  <Badge tone="warn">riemerso</Badge>
                ) : (
                  <Badge tone="neutral">da valutare</Badge>
                )}
              </button>
            ))}
            {filtered.length === 0 && (
              <div className="text-sm text-[var(--color-muted)] px-3 py-6">Nessun segnale nei filtri.</div>
            )}
          </div>
        </Card>

        <div className="lg:col-span-2">
          {selected ? (
            <SignalDetail
              key={selected.id}
              signal={selected}
              canWrite={canWrite}
              onCreated={() => setTick((t) => t + 1)}
            />
          ) : (
            <Card title="Dettaglio">
              <div className="text-sm text-[var(--color-muted)]">Seleziona un segnale.</div>
            </Card>
          )}
        </div>
      </div>
    </div>
  );
}

function SignalDetail({
  signal,
  canWrite,
  onCreated,
}: {
  signal: Signal;
  canWrite: boolean;
  onCreated: () => void;
}) {
  const { token } = useAuth();
  const router = useRouter();
  const [priority, setPriority] = useState("");
  const [owner, setOwner] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const create = async () => {
    if (!token) return;
    setBusy(true);
    setError(null);
    try {
      const ticket = await api.createTicket(token, signal.id, {
        priority: priority || undefined,
        owner: owner || undefined,
      });
      onCreated();
      router.push(`/tickets?open=${encodeURIComponent(ticket.id)}`);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Errore");
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card title="Dettaglio segnale">
      <div className="space-y-3">
        <div>
          <div className="text-base font-semibold text-[var(--color-ink)]">{signal.title}</div>
          <p className="mt-1 text-sm text-[var(--color-muted)]">
            {signal.description || "Nessuna descrizione."}
          </p>
        </div>
        {signal.recommended_action && (
          <div className="rounded-lg border border-indigo-200 bg-[var(--color-brand-soft)] px-3 py-2 text-xs text-[var(--color-ink-2)]">
            Azione raccomandata: {signal.recommended_action}
          </div>
        )}
        <dl className="grid grid-cols-2 gap-2 text-xs">
          <div><dt className="text-[var(--color-faint)]">Osservazioni</dt><dd className="font-mono">{signal.occurrence_count}</dd></div>
          <div><dt className="text-[var(--color-faint)]">Ultima</dt><dd className="font-mono">{signal.last_observed_at?.replace("T", " ").replace("Z", "") ?? "—"}</dd></div>
          <div className="col-span-2"><dt className="text-[var(--color-faint)]">Fonte</dt><dd className="font-mono break-all">{signal.source_id ?? "—"}</dd></div>
        </dl>

        <div className="border-t border-[var(--color-border)] pt-3">
          {signal.ticket_id ? (
            <button
              onClick={() => router.push(`/tickets?open=${encodeURIComponent(signal.ticket_id!)}`)}
              className="w-full rounded-lg bg-[var(--color-brand)] px-3 py-2 text-sm font-semibold text-white hover:bg-[var(--color-brand-2)]"
            >
              Apri ticket collegato →
            </button>
          ) : !canWrite ? (
            <div className="text-xs text-[var(--color-faint)]">
              Serve il ruolo analyst per creare un ticket.
            </div>
          ) : (
            <div className="space-y-2">
              <div className="text-sm font-medium text-[var(--color-ink-2)]">Presa in carico</div>
              <div className="flex gap-2">
                <select
                  value={priority}
                  onChange={(e) => setPriority(e.target.value)}
                  className="rounded-lg border border-[var(--color-border-strong)] bg-[var(--color-surface)] px-2 py-2 text-sm"
                >
                  <option value="">Priorità auto</option>
                  <option value="p1">P1</option>
                  <option value="p2">P2</option>
                  <option value="p3">P3</option>
                  <option value="p4">P4</option>
                </select>
                <input
                  value={owner}
                  onChange={(e) => setOwner(e.target.value)}
                  placeholder="Owner (opzionale)"
                  className="flex-1 rounded-lg border border-[var(--color-border-strong)] bg-[var(--color-surface)] px-3 py-2 text-sm"
                />
              </div>
              <button
                disabled={busy}
                onClick={create}
                className="w-full rounded-lg bg-[var(--color-brand)] px-3 py-2 text-sm font-semibold text-white disabled:opacity-40 hover:bg-[var(--color-brand-2)]"
              >
                Crea ticket e checklist
              </button>
              <p className="text-xs text-[var(--color-faint)]">
                Aggiunge una checklist manual-first. Nessuna azione automatica su PLC/VM/rete.
              </p>
              {error && <div className="text-xs text-[var(--color-danger)]">{error}</div>}
            </div>
          )}
        </div>
      </div>
    </Card>
  );
}
