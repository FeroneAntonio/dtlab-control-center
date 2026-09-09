"use client";

import Link from "next/link";
import { api } from "@/lib/api";
import { useApi } from "@/lib/useApi";
import { Badge, Bar, Card, ErrorNote, PageHeader, Spinner, StatTile } from "@/components/ui";

const FRAMEWORK_LABEL: Record<string, string> = {
  iec_62443: "IEC 62443",
  nis2: "NIS2",
  mitre_attack_ics: "ATT&CK ICS",
  purdue: "Purdue",
};

function pct(v: number | null | undefined) {
  return v == null ? "—" : `${Math.round(v * 100)}%`;
}

export default function WarRoom() {
  const { data, error, loading } = useApi(api.overview, []);

  if (loading) return <Spinner />;
  if (error) return <ErrorNote message={error} />;
  if (!data) return null;

  const k = data.kpis;
  const cov = k.detection_coverage ?? 0;
  const covTone = cov >= 0.8 ? "ok" : cov >= 0.5 ? "warn" : "danger";

  return (
    <div>
      <PageHeader
        title="War Room"
        subtitle="Quadro operativo unico: rischio, attacchi, rilevamento e conformità del laboratorio OT."
      />

      <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-6 gap-4 mb-6">
        <StatTile label="Asset OT" value={k.assets} tone="brand" />
        <StatTile label="Attacchi" value={k.attack_runs} />
        <StatTile
          label="Rilevati"
          value={`${k.detections}/${k.attack_runs}`}
          tone={covTone}
          hint={`copertura ${pct(k.detection_coverage)}`}
        />
        <StatTile
          label="Latenza media"
          value={k.mean_detection_latency_seconds == null ? "—" : `${k.mean_detection_latency_seconds}s`}
          hint="attacco → detection"
        />
        <StatTile
          label="Vulnerabilità"
          value={k.open_vulnerabilities}
          tone={k.open_vulnerabilities > 0 ? "warn" : "ok"}
        />
        <StatTile label="Qualità dati" value={k.quality_score ?? "—"} tone="brand" hint="score DTLab" />
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        <Card
          title="Timeline attacchi → detection"
          className="xl:col-span-2"
          action={
            <Link href="/attacks" className="text-xs font-medium text-[var(--color-brand)] hover:underline">
              Dettaglio →
            </Link>
          }
        >
          <div className="space-y-2.5">
            {data.attack_timeline.map((entry) => {
              const detected = entry.detected === true;
              const gap = entry.detected === false;
              return (
                <div
                  key={entry.run_id}
                  className="flex items-center gap-4 rounded-xl border border-[var(--color-border)] bg-[var(--color-surface-2)] px-4 py-3"
                >
                  <div className={`h-2.5 w-2.5 rounded-full ${detected ? "bg-emerald-500" : "bg-red-500"}`} />
                  <div className="flex-1 min-w-0">
                    <div className="text-sm font-medium text-[var(--color-ink)] truncate">
                      {entry.scenario_name}
                    </div>
                    <div className="text-xs text-[var(--color-faint)] font-mono">
                      {entry.started_at?.replace("T", " ").replace("Z", "")}
                    </div>
                  </div>
                  {detected ? (
                    <Badge tone="ok">rilevato · {entry.detection_latency_seconds}s</Badge>
                  ) : gap ? (
                    <Badge tone="danger">non rilevato</Badge>
                  ) : (
                    <Badge tone="neutral">n/d</Badge>
                  )}
                </div>
              );
            })}
          </div>
        </Card>

        <div className="space-y-6">
          <Card title="Stato processo (Digital Twin)">
            {data.digital_twin ? (
              <div className="flex items-center gap-4">
                <BeltIndicator state={data.digital_twin.belt_state} />
                <div>
                  <div className="text-lg font-semibold text-[var(--color-ink)]">
                    {data.digital_twin.belt_state === "fault"
                      ? "Guasto"
                      : data.digital_twin.belt_state === "running"
                        ? "In marcia"
                        : "Fermo"}
                  </div>
                  {data.digital_twin.anomaly && (
                    <div className="mt-1">
                      <Badge tone="danger">anomalia: {data.digital_twin.anomaly}</Badge>
                    </div>
                  )}
                  <div className="mt-1 text-xs text-[var(--color-faint)]">
                    Nastro trasportatore BeerFactory
                  </div>
                </div>
              </div>
            ) : (
              <div className="text-sm text-[var(--color-muted)]">Nessun dato di processo.</div>
            )}
          </Card>

          <Card title="Copertura compliance">
            <div className="space-y-3">
              {Object.entries(data.compliance_coverage).map(([framework, ratio]) => (
                <div key={framework}>
                  <div className="flex justify-between text-xs mb-1.5">
                    <span className="text-[var(--color-ink-2)]">
                      {FRAMEWORK_LABEL[framework] ?? framework}
                    </span>
                    <span className="font-mono text-[var(--color-muted)]">{pct(ratio)}</span>
                  </div>
                  <Bar
                    ratio={ratio ?? 0}
                    tone={(ratio ?? 0) >= 0.8 ? "ok" : (ratio ?? 0) >= 0.5 ? "warn" : "danger"}
                  />
                </div>
              ))}
            </div>
          </Card>
        </div>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6 mt-6">
        <Card
          title="Asset a maggior rischio"
          action={<span className="text-xs text-[var(--color-faint)]">fonte: Cisco Cyber Vision</span>}
        >
          <div className="space-y-2.5">
            {data.top_risk_assets.map((r) => (
              <div key={r.id} className="flex items-center gap-3">
                <div className="w-10 text-right font-mono text-sm text-[var(--color-ink)]">{r.score}</div>
                <Bar ratio={r.score / 100} tone={r.band === "high" ? "danger" : r.band === "medium" ? "warn" : "ok"} />
                <Badge tone={r.band === "high" ? "danger" : r.band === "medium" ? "warn" : "ok"}>
                  {r.band}
                </Badge>
              </div>
            ))}
            {data.top_risk_assets.length === 0 && (
              <div className="text-sm text-[var(--color-muted)]">Nessun risk score.</div>
            )}
          </div>
        </Card>

        <Card title="Eventi recenti">
          <div className="space-y-2">
            {data.recent_events.map((e) => (
              <div
                key={e.id}
                className="flex items-start gap-3 rounded-xl border border-[var(--color-border)] px-3 py-2.5"
              >
                <Badge tone={severityTone(e.severity)}>{e.severity}</Badge>
                <div className="min-w-0">
                  <div className="text-sm text-[var(--color-ink)] truncate">{e.title}</div>
                  <div className="text-xs text-[var(--color-faint)]">{e.category}</div>
                </div>
              </div>
            ))}
          </div>
        </Card>
      </div>
    </div>
  );
}

function severityTone(sev: string) {
  if (sev === "critical" || sev === "high") return "danger" as const;
  if (sev === "medium") return "warn" as const;
  return "neutral" as const;
}

function BeltIndicator({ state }: { state: string }) {
  const color = state === "running" ? "#059669" : state === "fault" ? "#dc2626" : "#94a3b8";
  const bg = state === "running" ? "#ecfdf5" : state === "fault" ? "#fef2f2" : "#f1f5f9";
  return (
    <div
      className="h-14 w-14 rounded-2xl border flex items-center justify-center text-2xl"
      style={{ borderColor: color, color, background: bg }}
    >
      <span>{state === "fault" ? "⚠" : "⚙"}</span>
    </div>
  );
}
