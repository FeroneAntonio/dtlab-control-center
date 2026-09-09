"use client";

import { useState } from "react";
import { api } from "@/lib/api";
import { useApi } from "@/lib/useApi";
import { Badge, Card, ErrorNote, PageHeader, Spinner, StatTile } from "@/components/ui";

type Row = Record<string, unknown>;
function str(v: unknown): string {
  if (Array.isArray(v)) return v.join(", ");
  return v == null ? "—" : String(v);
}

const TABS = ["Profili asset", "Reti e gerarchia"] as const;
type Tab = (typeof TABS)[number];

export default function NewUiInventoryPage() {
  const inv = useApi(api.newUiInventory, []);
  const [tab, setTab] = useState<Tab>("Profili asset");

  if (inv.loading) return <Spinner />;
  if (inv.error) return <ErrorNote message={inv.error} />;
  if (!inv.data) return null;

  const { profiles, networks } = inv.data;

  return (
    <div>
      <PageHeader
        title="Inventario New UI"
        subtitle="Profili asset, reti OT, gerarchia, alert e vulnerabilità dalla API New UI, separati dai Device Classic."
      />

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
        <StatTile label="Profili asset" value={profiles.length} tone="brand" hint="non sommati ai Classic" />
        <StatTile label="Alert New UI" value={inv.data.active_alerts} tone={inv.data.active_alerts > 0 ? "warn" : "ok"} />
        <StatTile label="Vulnerabilità New UI" value={inv.data.vulnerabilities} hint="CSRS e CVSS separati" />
        <StatTile label="Reti OT" value={networks.length} hint="livelli gerarchia" />
      </div>

      <div className="mb-4 rounded-xl border border-indigo-200 bg-[var(--color-brand-soft)] px-4 py-3 text-sm text-[var(--color-ink-2)]">
        I profili New UI hanno identificativi diversi dai Device Classic. Sono presentati come
        inventario sorgente e non alterano topologia, flow o risk score Classic.
      </div>

      <div className="flex gap-1 border-b border-[var(--color-border)] mb-4">
        {TABS.map((tb) => (
          <button key={tb} onClick={() => setTab(tb)}
            className={`px-3 py-2 text-sm border-b-2 -mb-px transition ${
              tab === tb
                ? "border-[var(--color-brand)] text-[var(--color-brand)] font-medium"
                : "border-transparent text-[var(--color-muted)] hover:text-[var(--color-ink)]"
            }`}>
            {tb}
          </button>
        ))}
      </div>

      {tab === "Profili asset" ? (
        <Card title={`Profili · ${profiles.length}`}>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-xs uppercase tracking-wider text-[var(--color-faint)] border-b border-[var(--color-border)]">
                  <th className="py-2 pr-4 font-medium">Profilo</th>
                  <th className="py-2 pr-4 font-medium">Tipo</th>
                  <th className="py-2 pr-4 font-medium">Vendor</th>
                  <th className="py-2 pr-4 font-medium">Interface</th>
                  <th className="py-2 pr-4 font-medium">Gruppo funzionale</th>
                  <th className="py-2 pr-4 font-medium">Alert</th>
                  <th className="py-2 font-medium">Sensori</th>
                </tr>
              </thead>
              <tbody>
                {(profiles as Row[]).map((p) => (
                  <tr key={str(p.profile_id)} className="border-b border-[var(--color-border)] last:border-0">
                    <td className="py-2.5 pr-4 font-medium text-[var(--color-ink)]">{str(p.name)}</td>
                    <td className="py-2.5 pr-4"><Badge tone="neutral">{str(p.type)}</Badge></td>
                    <td className="py-2.5 pr-4 text-xs">{str(p.vendor)}</td>
                    <td className="py-2.5 pr-4 font-mono text-xs">{str(p.interface)}</td>
                    <td className="py-2.5 pr-4 text-xs">{str(p.functional_group)}</td>
                    <td className="py-2.5 pr-4 font-mono">{str(p.active_alerts)}</td>
                    <td className="py-2.5 text-xs">{str(p.sensors)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      ) : (
        <Card title={`Reti e gerarchia · ${networks.length}`}>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-xs uppercase tracking-wider text-[var(--color-faint)] border-b border-[var(--color-border)]">
                  <th className="py-2 pr-4 font-medium">Rete</th>
                  <th className="py-2 pr-4 font-medium">CIDR</th>
                  <th className="py-2 pr-4 font-medium">Livello</th>
                  <th className="py-2 font-medium">Componenti</th>
                </tr>
              </thead>
              <tbody>
                {(networks as Row[]).map((n) => (
                  <tr key={str(n.network_id)} className="border-b border-[var(--color-border)] last:border-0">
                    <td className="py-2.5 pr-4 font-medium text-[var(--color-ink)]">{str(n.name)}</td>
                    <td className="py-2.5 pr-4 font-mono text-xs">{str(n.cidr)}</td>
                    <td className="py-2.5 pr-4"><Badge tone="brand">{str(n.level)}</Badge></td>
                    <td className="py-2.5 font-mono">{str(n.components)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}
    </div>
  );
}
