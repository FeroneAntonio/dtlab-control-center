"use client";

import { api } from "@/lib/api";
import { useApi } from "@/lib/useApi";
import { Badge, Card, ErrorNote, PageHeader, Spinner, StatTile } from "@/components/ui";

type Row = Record<string, unknown>;

function counts(b: Row): Record<string, number> {
  const c = b.difference_counts;
  return (typeof c === "object" && c ? c : {}) as Record<string, number>;
}

export default function BaselinePage() {
  const baselines = useApi(api.baselines, []);
  const diffs = useApi(api.baselineDifferences, []);

  if (baselines.loading || diffs.loading) return <Spinner />;
  if (baselines.error) return <ErrorNote message={baselines.error} />;

  const bItems = baselines.data?.items ?? [];
  const dItems = diffs.data?.items ?? [];
  const newElements = bItems.reduce((acc, b) => {
    const c = counts(b);
    return acc + (Number(c.new_component ?? 0) || 0) + (Number(c.new_activity ?? 0) || 0);
  }, 0);

  return (
    <div>
      <PageHeader
        title="Baseline e differenze"
        subtitle="Baseline Cisco, comunicazioni nuove e variazioni rilevate rispetto al comportamento noto."
      />

      <div className="grid grid-cols-3 gap-4 mb-6">
        <StatTile label="Baseline" value={bItems.length} tone="brand" hint="Cisco Cyber Vision" />
        <StatTile label="Differenze" value={dItems.length} tone={dItems.length > 0 ? "warn" : "ok"} hint="endpoint differences" />
        <StatTile label="Nuovi elementi" value={newElements} hint="componenti + attività" />
      </div>

      <Card title="Baseline" className="mb-6">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-xs uppercase tracking-wider text-[var(--color-faint)] border-b border-[var(--color-border)]">
                <th className="py-2 pr-4 font-medium">Nome</th>
                <th className="py-2 pr-4 font-medium">Stato</th>
                <th className="py-2 pr-4 font-medium">Nuovi comp.</th>
                <th className="py-2 pr-4 font-medium">Comp. cambiati</th>
                <th className="py-2 pr-4 font-medium">Nuove attività</th>
                <th className="py-2 font-medium">Attività cambiate</th>
              </tr>
            </thead>
            <tbody>
              {bItems.map((b: Row) => {
                const c = counts(b);
                return (
                  <tr key={String(b.id)} className="border-b border-[var(--color-border)] last:border-0">
                    <td className="py-2.5 pr-4 font-medium text-[var(--color-ink)]">{String(b.name)}</td>
                    <td className="py-2.5 pr-4"><Badge tone="ok">{String(b.status)}</Badge></td>
                    <td className="py-2.5 pr-4 font-mono">{String(c.new_component ?? 0)}</td>
                    <td className="py-2.5 pr-4 font-mono">{String(c.changed_component ?? 0)}</td>
                    <td className="py-2.5 pr-4 font-mono">{String(c.new_activity ?? 0)}</td>
                    <td className="py-2.5 font-mono">{String(c.changed_activity ?? 0)}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </Card>

      <Card title={`Differenze · ${dItems.length}`}>
        {dItems.length === 0 ? (
          <div className="text-sm text-[var(--color-muted)]">Nessuna differenza restituita nell&apos;ultima lettura.</div>
        ) : (
          <div className="space-y-2">
            {dItems.map((d: Row) => (
              <div key={String(d.id)} className="rounded-lg border border-[var(--color-border)] p-3">
                <div className="flex items-center gap-2">
                  <Badge tone="warn">{String(d.difference_type)}</Badge>
                  <span className="text-sm font-medium text-[var(--color-ink)]">{String(d.description)}</span>
                </div>
                <div className="mt-1 text-xs text-[var(--color-faint)] font-mono">
                  {String(d.key ?? "")} = {String(d.value ?? "")} · {String(d.detected_at ?? "").replace("T", " ").slice(0, 19)}
                </div>
              </div>
            ))}
          </div>
        )}
      </Card>
    </div>
  );
}
