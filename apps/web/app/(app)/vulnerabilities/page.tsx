"use client";

import { useMemo, useState } from "react";
import { api } from "@/lib/api";
import { useApi } from "@/lib/useApi";
import { Badge, Card, ErrorNote, PageHeader, Spinner, StatTile } from "@/components/ui";

type Row = Record<string, unknown>;

export default function VulnerabilitiesPage() {
  const catalog = useApi(api.vulnerabilityCatalog, []);
  const assoc = useApi(api.vulnerabilities, []);
  const assets = useApi(api.assets, []);

  const [query, setQuery] = useState("");
  const [minCvss, setMinCvss] = useState(0);

  const names = new Map(
    (assets.data?.items ?? []).map((a) => [String(a.id), String(a.name)]),
  );

  const filteredCatalog = useMemo(() => {
    const items = catalog.data?.items ?? [];
    const needle = query.trim().toLowerCase();
    return items
      .filter((c) => (minCvss > 0 ? Number(c.cvss_score ?? 0) >= minCvss : true))
      .filter((c) =>
        !needle ? true : `${c.external_id} ${c.title} ${c.vendor_id}`.toLowerCase().includes(needle),
      )
      .sort((a, b) => Number(b.cvss_score ?? 0) - Number(a.cvss_score ?? 0));
  }, [catalog.data, query, minCvss]);

  if (catalog.loading || assoc.loading) return <Spinner />;
  if (catalog.error) return <ErrorNote message={catalog.error} />;

  const maxCvss = Math.max(0, ...(catalog.data?.items ?? []).map((c) => Number(c.cvss_score ?? 0)));

  return (
    <div>
      <PageHeader
        title="Vulnerabilità"
        subtitle="Catalogo CVE Cisco ricercabile e associazioni device–vulnerabilità esplicite, con CVSS sempre separato dal Cisco Security Risk Score."
      />

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
        <StatTile label="Catalogo Cisco" value={catalog.data?.count ?? "—"} tone="brand" hint="CVE indicizzate" />
        <StatTile label="CVSS massimo" value={maxCvss || "—"} tone="warn" hint="valore tecnico Cisco" />
        <StatTile label="Associate agli asset" value={assoc.data?.count ?? 0} hint="relazioni esplicite" />
        <StatTile label="Capability" value={catalog.data?.capability_available ? "OK" : "N/D"}
          tone={catalog.data?.capability_available ? "ok" : "default"} />
      </div>

      <Card title="Catalogo globale Cisco" className="mb-6">
        <div className="flex flex-wrap items-center gap-3 mb-4">
          <input value={query} onChange={(e) => setQuery(e.target.value)}
            placeholder="Cerca CVE, titolo o vendor…"
            className="flex-1 min-w-[220px] rounded-lg border border-[var(--color-border-strong)] bg-[var(--color-surface)] px-3 py-2 text-sm outline-none focus:border-[var(--color-brand)] focus:ring-2 focus:ring-indigo-100" />
          <label className="flex items-center gap-2 text-sm text-[var(--color-ink-2)]">
            CVSS ≥ {minCvss.toFixed(1)}
            <input type="range" min={0} max={10} step={0.5} value={minCvss}
              onChange={(e) => setMinCvss(Number(e.target.value))} />
          </label>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-xs uppercase tracking-wider text-[var(--color-faint)] border-b border-[var(--color-border)]">
                <th className="py-2 pr-4 font-medium">CVE / ID</th>
                <th className="py-2 pr-4 font-medium">Titolo</th>
                <th className="py-2 pr-4 font-medium">CVSS</th>
                <th className="py-2 pr-4 font-medium">Vendor</th>
                <th className="py-2 font-medium">Pubblicata</th>
              </tr>
            </thead>
            <tbody>
              {filteredCatalog.map((c: Row) => (
                <tr key={String(c.external_id)} className="border-b border-[var(--color-border)] last:border-0">
                  <td className="py-2.5 pr-4 font-mono text-xs">{String(c.external_id)}</td>
                  <td className="py-2.5 pr-4">{String(c.title)}</td>
                  <td className="py-2.5 pr-4">
                    <Badge tone={Number(c.cvss_score) >= 9 ? "danger" : Number(c.cvss_score) >= 7 ? "warn" : "neutral"}>
                      {String(c.cvss_score)}
                    </Badge>
                  </td>
                  <td className="py-2.5 pr-4 text-xs">{String(c.vendor_id)}</td>
                  <td className="py-2.5 text-xs text-[var(--color-faint)]">
                    {String(c.published_at ?? "").slice(0, 10)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <div className="mt-2 text-xs text-[var(--color-faint)]">
            {filteredCatalog.length} record su {catalog.data?.count ?? 0}. Essere nel catalogo non
            significa che una CVE sia presente su un asset DTLab.
          </div>
        </div>
      </Card>

      <Card title="Associazioni device–vulnerabilità">
        {(assoc.data?.items ?? []).length === 0 ? (
          <div className="text-sm text-[var(--color-muted)]">
            Nessuna associazione esplicita per-device nell&apos;ultima acquisizione.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-xs uppercase tracking-wider text-[var(--color-faint)] border-b border-[var(--color-border)]">
                  <th className="py-2 pr-4 font-medium">Asset</th>
                  <th className="py-2 pr-4 font-medium">CVE</th>
                  <th className="py-2 pr-4 font-medium">Titolo</th>
                  <th className="py-2 pr-4 font-medium">Severità</th>
                  <th className="py-2 font-medium">CVSS</th>
                </tr>
              </thead>
              <tbody>
                {(assoc.data?.items ?? []).map((v: Row) => (
                  <tr key={String(v.id)} className="border-b border-[var(--color-border)] last:border-0">
                    <td className="py-2.5 pr-4">{names.get(String(v.asset_id)) ?? String(v.asset_id)}</td>
                    <td className="py-2.5 pr-4 font-mono text-xs">{String(v.external_id ?? "—")}</td>
                    <td className="py-2.5 pr-4">{String(v.title)}</td>
                    <td className="py-2.5 pr-4"><Badge tone="warn">{String(v.severity)}</Badge></td>
                    <td className="py-2.5 font-mono">{String(v.cvss_score ?? "—")}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <p className="mt-3 text-xs text-[var(--color-faint)]">
          Il CVSS valuta la severità tecnica della vulnerabilità: non è il risk score del device
          né il CSRS.
        </p>
      </Card>
    </div>
  );
}
