"use client";

import { useMemo, useState } from "react";
import { api } from "@/lib/api";
import { useApi } from "@/lib/useApi";
import { Badge, Card, ErrorNote, PageHeader, Spinner, StatTile } from "@/components/ui";

type Row = Record<string, unknown>;
const SEV_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4, unknown: 5 };
const SEV_LABEL: Record<string, string> = {
  critical: "Critici", high: "Alti", medium: "Medi", low: "Bassi", info: "Informativi", unknown: "N/D",
};
const TRIAGE = [
  "Verificare la provenienza e il timestamp dell'evento.",
  "Individuare asset o flow nello stesso intervallo temporale.",
  "Confrontare la comunicazione con la baseline.",
  "Documentare decisione ed evidenze senza alterare l'ambiente.",
];

function sevTone(s: string) {
  if (s === "critical" || s === "high") return "danger" as const;
  if (s === "medium") return "warn" as const;
  return "neutral" as const;
}

export default function EventsPage() {
  const events = useApi(api.events, []);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [checked, setChecked] = useState<Record<number, boolean>>({});

  const items = useMemo(
    () =>
      [...(events.data?.items ?? [])].sort(
        (a, b) => (SEV_ORDER[String(a.severity)] ?? 5) - (SEV_ORDER[String(b.severity)] ?? 5),
      ),
    [events.data],
  );

  const categories = useMemo(() => {
    const map = new Map<string, number>();
    for (const e of items) map.set(String(e.category), (map.get(String(e.category)) ?? 0) + 1);
    return [...map.entries()].sort((a, b) => b[1] - a[1]);
  }, [items]);

  const severities = useMemo(() => {
    const map = new Map<string, number>();
    for (const e of items) map.set(String(e.severity), (map.get(String(e.severity)) ?? 0) + 1);
    return map;
  }, [items]);

  if (events.loading) return <Spinner />;
  if (events.error) return <ErrorNote message={events.error} />;

  const selected = items.find((e) => e.id === selectedId) ?? items[0] ?? null;

  return (
    <div>
      <PageHeader
        title="Eventi e triage"
        subtitle="Eventi recenti aggregati dal widget Cisco cached, senza associazioni ad asset inventate dal portale."
      />

      <div className="grid grid-cols-3 md:grid-cols-6 gap-4 mb-6">
        {(["critical", "high", "medium", "low", "info", "unknown"] as const).map((s) => (
          <StatTile key={s} label={SEV_LABEL[s]} value={severities.get(s) ?? 0}
            tone={s === "critical" || s === "high" ? "danger" : s === "medium" ? "warn" : "default"} />
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <Card title="Categorie (Cisco cached)">
          <div className="space-y-2">
            {categories.map(([cat, n]) => (
              <div key={cat} className="flex justify-between text-sm">
                <span className="text-[var(--color-ink-2)]">{cat}</span>
                <span className="font-mono text-[var(--color-muted)]">{n}</span>
              </div>
            ))}
          </div>
        </Card>

        <Card title={`Eventi recenti · ${items.length}`} className="lg:col-span-2">
          <div className="divide-y divide-[var(--color-border)] -m-1">
            {items.map((e: Row) => (
              <button key={String(e.id)} onClick={() => setSelectedId(String(e.id))}
                className={`w-full text-left px-3 py-2.5 flex items-start gap-3 rounded-lg transition ${
                  selected?.id === e.id ? "bg-[var(--color-brand-soft)]" : "hover:bg-slate-50"
                }`}>
                <Badge tone={sevTone(String(e.severity))}>{String(e.severity)}</Badge>
                <div className="min-w-0">
                  <div className="text-sm font-medium text-[var(--color-ink)] truncate">{String(e.title)}</div>
                  <div className="text-xs text-[var(--color-faint)]">{String(e.category)}</div>
                </div>
              </button>
            ))}
          </div>
        </Card>
      </div>

      {selected && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mt-6">
          <Card title="Dettaglio evento">
            <div className="text-base font-semibold text-[var(--color-ink)]">{String(selected.title)}</div>
            <p className="mt-1 text-sm text-[var(--color-muted)]">{String(selected.description)}</p>
            <dl className="mt-3 grid grid-cols-2 gap-2 text-xs">
              <div><dt className="text-[var(--color-faint)]">Categoria</dt><dd>{String(selected.category)}</dd></div>
              <div><dt className="text-[var(--color-faint)]">Severità</dt><dd>{String(selected.severity)}</dd></div>
              <div className="col-span-2"><dt className="text-[var(--color-faint)]">Center</dt>
                <dd>{String(selected.center_label ?? selected.center_id ?? "N/D")}</dd></div>
            </dl>
          </Card>
          <Card title="Checklist triage">
            <div className="space-y-2">
              {TRIAGE.map((step, i) => (
                <label key={i} className="flex items-start gap-2 text-sm text-[var(--color-ink-2)]">
                  <input type="checkbox" checked={!!checked[i]}
                    onChange={(e) => setChecked((c) => ({ ...c, [i]: e.target.checked }))} className="mt-1" />
                  {step}
                </label>
              ))}
            </div>
          </Card>
        </div>
      )}
    </div>
  );
}
