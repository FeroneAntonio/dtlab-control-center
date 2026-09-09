"use client";

import { api } from "@/lib/api";
import { useApi } from "@/lib/useApi";
import { Badge, Bar, Card, ErrorNote, PageHeader, Spinner } from "@/components/ui";

const FRAMEWORK_LABEL: Record<string, string> = {
  iec_62443: "IEC 62443",
  nis2: "NIS2",
  mitre_attack_ics: "MITRE ATT&CK for ICS",
  purdue: "Modello di Purdue",
};

interface Zone {
  id: string;
  name: string;
  purdue_level: string;
  iec62443_zone: string | null;
  target_security_level: string;
  asset_ids: string[];
  description: string;
}

export default function CompliancePage() {
  const coverage = useApi(api.complianceCoverage, []);
  const purdue = useApi(api.purdue, []);

  if (coverage.loading || purdue.loading) return <Spinner />;
  if (coverage.error) return <ErrorNote message={coverage.error} />;
  if (!coverage.data || !purdue.data) return null;

  return (
    <div>
      <PageHeader
        title="Compliance & Architettura"
        subtitle="Copertura IEC 62443 / NIS2 / MITRE ATT&CK ICS e modello di Purdue con zone e conduit."
      />

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-8">
        {coverage.data.frameworks.map((f) => (
          <Card key={f.framework} title={FRAMEWORK_LABEL[f.framework] ?? f.framework}>
            <div className="flex items-end justify-between mb-3">
              <div className="text-3xl font-mono font-semibold">
                {f.covered_ratio == null ? "—" : `${Math.round(f.covered_ratio * 100)}%`}
              </div>
              <div className="text-xs text-[var(--color-muted)]">{f.total} controlli</div>
            </div>
            <Bar
              ratio={f.covered_ratio ?? 0}
              tone={(f.covered_ratio ?? 0) >= 0.8 ? "ok" : (f.covered_ratio ?? 0) >= 0.5 ? "warn" : "danger"}
            />
            <div className="mt-3 flex flex-wrap gap-2">
              {Object.entries(f.counts)
                .filter(([, n]) => n > 0)
                .map(([status, n]) => (
                  <Badge key={status} tone={statusTone(status)}>
                    {statusLabel(status)}: {n}
                  </Badge>
                ))}
            </div>
          </Card>
        ))}
      </div>

      <h2 className="text-lg font-semibold tracking-tight mb-3 text-[var(--color-ink)]">
        Modello di Purdue · zone IEC 62443
      </h2>
      <div className="space-y-3">
        {purdue.data.levels.map((lvl) => (
          <div key={lvl.level} className="flex gap-4">
            <div className="w-24 shrink-0 flex items-center justify-center rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] font-mono text-sm text-[var(--color-ink-2)] shadow-[var(--shadow-card)]">
              {lvl.level === "unknown" ? "Test" : `Livello ${lvl.level}`}
            </div>
            <div className="flex-1 grid grid-cols-1 md:grid-cols-2 gap-3">
              {(lvl.zones as unknown as Zone[]).map((zone) => (
                <div
                  key={zone.id}
                  className="rounded-xl border border-[var(--color-border)] bg-[var(--color-surface)] p-3.5 shadow-[var(--shadow-card)]"
                >
                  <div className="flex items-center justify-between">
                    <div className="font-medium text-sm text-[var(--color-ink)]">{zone.name}</div>
                    <Badge tone="brand">{zone.target_security_level}</Badge>
                  </div>
                  <div className="text-xs text-[var(--color-muted)] mt-1">{zone.description}</div>
                  <div className="text-xs text-[var(--color-faint)] mt-1">
                    {zone.asset_ids.length} asset · {zone.iec62443_zone ?? "—"}
                  </div>
                </div>
              ))}
              {lvl.zones.length === 0 && (
                <div className="text-sm text-[var(--color-faint)]">—</div>
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

function statusTone(status: string) {
  return status === "covered"
    ? ("ok" as const)
    : status === "partial" || status === "planned"
      ? ("warn" as const)
      : status === "not_covered"
        ? ("danger" as const)
        : ("neutral" as const);
}

function statusLabel(status: string) {
  return (
    {
      covered: "coperti",
      partial: "parziali",
      not_covered: "scoperti",
      not_applicable: "n/a",
      planned: "pianificati",
    }[status] ?? status
  );
}
