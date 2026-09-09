"use client";

import { api } from "@/lib/api";
import { useApi } from "@/lib/useApi";
import { Badge, Bar, Card, ErrorNote, PageHeader, Spinner, StatTile } from "@/components/ui";

type Row = Record<string, unknown>;
const BAND_LABEL: Record<string, string> = { low: "Basso", medium: "Medio", high: "Alto" };

function bandTone(b: string) {
  return b === "high" ? ("danger" as const) : b === "medium" ? ("warn" as const) : ("ok" as const);
}

export default function RiskPage() {
  const scores = useApi(api.riskScores, []);
  const dist = useApi(api.riskDistribution, []);
  const assets = useApi(api.assets, []);

  if (scores.loading || dist.loading || assets.loading) return <Spinner />;
  if (scores.error) return <ErrorNote message={scores.error} />;
  if (!scores.data || !dist.data) return null;

  const names = new Map(
    (assets.data?.items ?? []).map((a) => [String(a.id), String(a.name)]),
  );
  const ordered = [...scores.data.items].sort(
    (a, b) => Number(b.score ?? 0) - Number(a.score ?? 0),
  );
  const bands = dist.data.bands;

  return (
    <div>
      <PageHeader
        title="Risk score Cisco"
        subtitle="Punteggi per-device letti da Cisco Cyber Vision, senza formule DTLab sostitutive."
      />

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
        <StatTile label="Asset con score" value={dist.data.total} tone="brand" hint="Device Cisco Cyber Vision" />
        <StatTile label="Rischio alto" value={bands.high} tone={bands.high > 0 ? "danger" : "ok"} hint="70–100" />
        <StatTile label="Rischio medio" value={bands.medium} tone={bands.medium > 0 ? "warn" : "ok"} hint="40–69" />
        <StatTile label="Rischio basso" value={bands.low} tone="ok" hint="0–39" />
      </div>

      <Card
        title="Dettaglio per-device"
        action={<span className="text-xs text-[var(--color-faint)]">fonte: Cisco Cyber Vision</span>}
      >
        <div className="space-y-3">
          {ordered.map((s: Row) => {
            const band = String(s.band);
            return (
              <div key={String(s.id)} className="flex items-center gap-4">
                <div className="w-40 text-sm text-[var(--color-ink)] truncate">
                  {names.get(String(s.asset_id)) ?? String(s.asset_id)}
                </div>
                <div className="w-10 text-right font-mono text-sm">{Number(s.score)}</div>
                <div className="flex-1"><Bar ratio={Number(s.score) / 100} tone={bandTone(band)} /></div>
                <Badge tone={bandTone(band)}>{BAND_LABEL[band] ?? band}</Badge>
                <div className="w-24 text-right text-xs text-[var(--color-faint)]">
                  {Array.isArray(s.factors) ? `${s.factors.length} fattori` : "—"}
                </div>
              </div>
            );
          })}
          {ordered.length === 0 && (
            <div className="text-sm text-[var(--color-muted)]">Nessun risk score acquisito.</div>
          )}
        </div>
        <p className="mt-4 text-xs text-[var(--color-faint)]">
          Soglie Cisco: 0–39 basso, 40–69 medio, 70–100 alto. Il valore non è convertito né
          combinato con CVSS o CSRS.
        </p>
      </Card>
    </div>
  );
}
