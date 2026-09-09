"use client";

import { api } from "@/lib/api";
import { useApi } from "@/lib/useApi";
import { Badge, Bar, Card, ErrorNote, PageHeader, Spinner, StatTile } from "@/components/ui";

type Row = Record<string, unknown>;

function str(v: unknown): string {
  if (Array.isArray(v)) return v.join(", ");
  return v == null ? "—" : String(v);
}
function statusTone(s: string) {
  if (s === "connected") return "ok" as const;
  if (s === "degraded" || s === "stale") return "warn" as const;
  if (s === "unavailable" || s === "not_configured") return "danger" as const;
  return "neutral" as const;
}

export default function SourcesPage() {
  const sources = useApi(api.sources, []);
  const quality = useApi(api.quality, []);

  if (sources.loading || quality.loading) return <Spinner />;
  if (sources.error) return <ErrorNote message={sources.error} />;

  const q = quality.data?.quality;
  const coverage = Object.entries(q?.coverage ?? {});
  const checks = (q?.checks ?? []) as Row[];

  return (
    <div>
      <PageHeader
        title="Sorgenti e qualità"
        subtitle="Provenienza, capability, copertura e limiti espliciti dell'ultima sincronizzazione."
      />

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
        <StatTile label="Qualità dati" value={q?.score != null ? `${q.score}%` : "—"} tone="brand" hint="metrica DTLab, separata dal rischio" />
        <StatTile label="Sorgenti" value={sources.data?.count ?? 0} />
        <StatTile label="Schema" value={str(quality.data?.sync?.["publication_mode"] ?? "—")} hint="modalità pubblicazione" />
        <StatTile label="Pointer" value={`#${(quality.data?.content_sha256 ?? "").slice(0, 8)}`} hint="snapshot corrente" />
      </div>

      <Card title="Sorgenti" className="mb-6">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-xs uppercase tracking-wider text-[var(--color-faint)] border-b border-[var(--color-border)]">
                <th className="py-2 pr-4 font-medium">Sorgente</th>
                <th className="py-2 pr-4 font-medium">Tipo</th>
                <th className="py-2 pr-4 font-medium">Stato</th>
                <th className="py-2 pr-4 font-medium">Versione</th>
                <th className="py-2 pr-4 font-medium">Ultimo successo</th>
                <th className="py-2 font-medium">Errore</th>
              </tr>
            </thead>
            <tbody>
              {(sources.data?.items ?? []).map((s: Row) => {
                const err = s.error as Row | null;
                return (
                  <tr key={str(s.id)} className="border-b border-[var(--color-border)] last:border-0">
                    <td className="py-2.5 pr-4 font-medium text-[var(--color-ink)]">{str(s.label)}</td>
                    <td className="py-2.5 pr-4 text-xs font-mono">{str(s.type)}</td>
                    <td className="py-2.5 pr-4"><Badge tone={statusTone(str(s.status))}>{str(s.status)}</Badge></td>
                    <td className="py-2.5 pr-4 text-xs">{str(s.version)}</td>
                    <td className="py-2.5 pr-4 text-xs text-[var(--color-faint)]">{str(s.last_success_at).replace("T", " ").slice(0, 19)}</td>
                    <td className="py-2.5 text-xs text-[var(--color-danger)]">{err ? str(err.code) : "—"}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </Card>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <Card title="Copertura per dominio">
          <div className="space-y-3">
            {coverage.map(([name, ratio]) => (
              <div key={name}>
                <div className="flex justify-between text-xs mb-1">
                  <span className="text-[var(--color-ink-2)]">{name}</span>
                  <span className="font-mono text-[var(--color-muted)]">{Math.round(Number(ratio) * 100)}%</span>
                </div>
                <Bar ratio={Number(ratio)} tone={Number(ratio) >= 0.8 ? "ok" : Number(ratio) >= 0.5 ? "warn" : "danger"} />
              </div>
            ))}
          </div>
        </Card>
        <Card title="Controlli qualità">
          <div className="space-y-2">
            {checks.map((c, i) => (
              <div key={i} className="flex items-start gap-2">
                <Badge tone={str(c.status) === "pass" ? "ok" : str(c.status) === "warn" ? "warn" : "danger"}>
                  {str(c.status)}
                </Badge>
                <div className="min-w-0">
                  <div className="text-sm text-[var(--color-ink)]">{str(c.label)}</div>
                  <div className="text-xs text-[var(--color-faint)]">{str(c.details)}</div>
                </div>
              </div>
            ))}
            {checks.length === 0 && <div className="text-sm text-[var(--color-muted)]">Nessun controllo.</div>}
          </div>
        </Card>
      </div>
    </div>
  );
}
