"use client";

import { api } from "@/lib/api";
import { useApi } from "@/lib/useApi";
import { Badge, Card, ErrorNote, PageHeader, Spinner, StatTile } from "@/components/ui";
import type { AttackRun, AttackScenario } from "@/lib/types";

function Tech({ id }: { id: string }) {
  return (
    <span className="rounded-md border border-violet-200 bg-violet-50 px-1.5 py-0.5 text-[11px] font-mono text-violet-700">
      {id}
    </span>
  );
}

export default function AttacksPage() {
  const runs = useApi(api.attackRuns, []);
  const scenarios = useApi(api.scenarios, []);
  const summary = useApi(api.detectionSummary, []);

  if (runs.loading || scenarios.loading || summary.loading) return <Spinner />;
  if (runs.error) return <ErrorNote message={runs.error} />;
  if (!runs.data || !scenarios.data || !summary.data) return null;

  const scenarioById = new Map(scenarios.data.items.map((s) => [s.id, s]));
  const s = summary.data;

  return (
    <div>
      <PageHeader
        title="Attacchi & Detection"
        subtitle="Scenari offensivi (sandbox) correlati al rilevamento di Cisco Cyber Vision, con latenza e gap."
      />

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
        <StatTile
          label="Copertura detection"
          value={s.coverage == null ? "—" : `${Math.round(s.coverage * 100)}%`}
          tone={(s.coverage ?? 0) >= 0.8 ? "ok" : "warn"}
          hint={`${s.detected}/${s.attack_runs} rilevati`}
        />
        <StatTile label="Latenza minima" value={s.latency_seconds.min == null ? "—" : `${s.latency_seconds.min}s`} tone="ok" />
        <StatTile label="Latenza media" value={s.latency_seconds.mean == null ? "—" : `${s.latency_seconds.mean}s`} />
        <StatTile label="Gap di detection" value={s.undetected} tone={s.undetected > 0 ? "danger" : "ok"} />
      </div>

      {s.detection_gaps.length > 0 && (
        <div className="mb-6 rounded-2xl border border-red-200 bg-[var(--color-danger-soft)] px-4 py-3.5">
          <div className="text-sm font-semibold text-[var(--color-danger)] mb-1.5">
            ⚠ Gap di rilevamento
          </div>
          <div className="flex flex-wrap gap-2">
            {s.detection_gaps.map((g) => (
              <Badge key={g.attack_run_id} tone="danger">
                {g.scenario_name} · {g.mitre_technique_id}
              </Badge>
            ))}
          </div>
        </div>
      )}

      <Card title="Run di attacco" className="mb-6">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-xs uppercase tracking-wider text-[var(--color-faint)] border-b border-[var(--color-border)]">
                <th className="py-2 pr-4 font-medium">Scenario</th>
                <th className="py-2 pr-4 font-medium">Tecniche ATT&CK</th>
                <th className="py-2 pr-4 font-medium">Esito</th>
                <th className="py-2 pr-4 font-medium">Detection</th>
                <th className="py-2 font-medium">Latenza</th>
              </tr>
            </thead>
            <tbody>
              {runs.data.items.map((run: AttackRun) => {
                const scenario = scenarioById.get(run.scenario_id);
                return (
                  <tr key={run.id} className="border-b border-[var(--color-border)] last:border-0">
                    <td className="py-3 pr-4">
                      <div className="font-medium text-[var(--color-ink)]">
                        {scenario?.name ?? run.scenario_id}
                      </div>
                      <div className="text-xs text-[var(--color-faint)]">{scenario?.category}</div>
                    </td>
                    <td className="py-3 pr-4">
                      <div className="flex flex-wrap gap-1">
                        {(scenario?.mitre_techniques ?? []).map((t) => (
                          <Tech key={t.technique_id} id={t.technique_id} />
                        ))}
                      </div>
                    </td>
                    <td className="py-3 pr-4">
                      <Badge tone={run.outcome === "success" ? "warn" : "neutral"}>{run.outcome}</Badge>
                    </td>
                    <td className="py-3 pr-4">
                      {run.detected === true ? (
                        <Badge tone="ok">rilevato · {run.detection?.detection_source}</Badge>
                      ) : (
                        <Badge tone="danger">non rilevato</Badge>
                      )}
                    </td>
                    <td className="py-3 font-mono text-[var(--color-ink)]">
                      {run.detection?.detection_latency_seconds != null
                        ? `${run.detection.detection_latency_seconds}s`
                        : "—"}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </Card>

      <Card title="Catalogo scenari (MITRE ATT&CK for ICS)">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {scenarios.data.items.map((sc: AttackScenario) => (
            <div key={sc.id} className="rounded-xl border border-[var(--color-border)] bg-[var(--color-surface-2)] p-4">
              <div className="flex items-center justify-between mb-1.5">
                <div className="font-medium text-[var(--color-ink)]">{sc.name}</div>
                <Badge tone={sc.severity === "high" ? "danger" : sc.severity === "medium" ? "warn" : "neutral"}>
                  {sc.severity}
                </Badge>
              </div>
              <p className="text-xs text-[var(--color-muted)] mb-2.5">{sc.description}</p>
              <div className="flex flex-wrap gap-1 mb-2.5">
                {sc.mitre_techniques.map((t) => (
                  <Tech key={t.technique_id} id={`${t.technique_id} ${t.technique_name}`} />
                ))}
              </div>
              <div className="flex items-center gap-2 text-xs text-[var(--color-faint)]">
                <Badge tone="brand">{sc.execution_mode}</Badge>
                <span>RoE: {sc.roe_reference ?? "non richiesta (simulato)"}</span>
              </div>
            </div>
          ))}
        </div>
      </Card>
    </div>
  );
}
