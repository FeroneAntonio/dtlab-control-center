"use client";

import { api } from "@/lib/api";
import { useApi } from "@/lib/useApi";
import { Badge, Card, ErrorNote, PageHeader, Spinner, StatTile } from "@/components/ui";

type Row = Record<string, unknown>;
const OPERATIONAL = new Set(["active", "online", "operational", "running"]);

function str(v: unknown): string {
  if (Array.isArray(v)) return v.join(", ");
  return v == null ? "N/D" : String(v);
}

export default function SensorsPage() {
  const sensors = useApi(api.sensors, []);
  if (sensors.loading) return <Spinner />;
  if (sensors.error) return <ErrorNote message={sensors.error} />;

  const items = sensors.data?.items ?? [];
  const operational = items.filter((s) => OPERATIONAL.has(String(s.status).toLowerCase())).length;

  return (
    <div>
      <PageHeader
        title="Sensori e DPI"
        subtitle="Stato Cisco, capture mode e metriche tecniche dei sensori, senza health score sintetici."
      />

      <div className="grid grid-cols-2 md:grid-cols-3 gap-4 mb-6">
        <StatTile label="Sensori" value={items.length} tone="brand" hint="Cisco Cyber Vision" />
        <StatTile label="Operativi" value={`${operational}/${items.length}`} tone={operational === items.length ? "ok" : "warn"} />
        <StatTile label="Stats disponibili" value={items.some((s) => s.stats) ? "Sì" : "N/D"} hint="endpoint /sensors/{id}/stats" />
      </div>

      <Card title="Sensori">
        <div className="space-y-4">
          {items.map((s: Row) => {
            const stats = (s.stats && typeof s.stats === "object" ? s.stats : {}) as Row;
            return (
              <div key={str(s.id)} className="rounded-xl border border-[var(--color-border)] p-4">
                <div className="flex items-center justify-between mb-2">
                  <div>
                    <div className="font-medium text-[var(--color-ink)]">{str(s.name)}</div>
                    <div className="text-xs text-[var(--color-faint)]">
                      {str(s.sensor_type)} · capture {str(s.capture_mode)} · v{str(s.version)}
                    </div>
                  </div>
                  <Badge tone={OPERATIONAL.has(String(s.status).toLowerCase()) ? "ok" : "warn"}>{str(s.status)}</Badge>
                </div>
                <div className="grid grid-cols-3 md:grid-cols-6 gap-2 text-xs">
                  {[
                    ["CPU %", stats.cpu_percent],
                    ["RAM %", stats.memory_percent],
                    ["Disco %", stats.disk_percent],
                    ["pps", stats.packet_rate_pps],
                    ["Pacchetti", stats.packet_count],
                    ["Drop", stats.drop_count],
                  ].map(([label, val]) => (
                    <div key={String(label)} className="rounded-lg bg-[var(--color-surface-2)] border border-[var(--color-border)] px-2 py-1.5">
                      <div className="text-[var(--color-faint)]">{String(label)}</div>
                      <div className="font-mono text-[var(--color-ink)]">{val == null ? "N/D" : String(val)}</div>
                    </div>
                  ))}
                </div>
              </div>
            );
          })}
          {items.length === 0 && <div className="text-sm text-[var(--color-muted)]">Nessun sensore.</div>}
        </div>
        <p className="mt-3 text-xs text-[var(--color-faint)]">
          I campi N/D non diventano zero: indicano che Cisco non li ha restituiti.
        </p>
      </Card>
    </div>
  );
}
