"use client";

import { api } from "@/lib/api";
import { useApi } from "@/lib/useApi";
import { Badge, Card, ErrorNote, PageHeader, Spinner, StatTile } from "@/components/ui";

type Row = Record<string, unknown>;

function str(v: unknown): string {
  return v == null ? "—" : String(v);
}
function ctx(vm: Row): Row {
  return (vm.operational_context && typeof vm.operational_context === "object"
    ? vm.operational_context
    : {}) as Row;
}

export default function VmwarePage() {
  const vms = useApi(api.vms, []);
  if (vms.loading) return <Spinner />;
  if (vms.error) return <ErrorNote message={vms.error} />;

  const items = vms.data?.items ?? [];
  const on = items.filter((v) => v.power_state === "powered_on").length;
  const vcpu = items.reduce((a, v) => a + Number(v.cpu_count ?? 0), 0);
  const ramGb = Math.round(items.reduce((a, v) => a + Number(v.memory_mb ?? 0), 0) / 1024);

  return (
    <div>
      <PageHeader
        title="Ambiente VMware"
        subtitle="Inventario ESXi read-only: VM, risorse, NIC e ruolo operativo."
      />

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
        <StatTile label="VM" value={`${on}/${items.length}`} tone="brand" hint="powered on" />
        <StatTile label="vCPU" value={vcpu} hint="configurate" />
        <StatTile label="RAM" value={`${ramGb} GB`} hint="configurata" />
        <StatTile label="Target ufficiale" value={items.filter((v) => ctx(v).official_target).length} hint="conferma operatore" />
      </div>

      <Card title="Macchine virtuali">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-xs uppercase tracking-wider text-[var(--color-faint)] border-b border-[var(--color-border)]">
                <th className="py-2 pr-4 font-medium">VM</th>
                <th className="py-2 pr-4 font-medium">Ruolo</th>
                <th className="py-2 pr-4 font-medium">Lifecycle</th>
                <th className="py-2 pr-4 font-medium">Target</th>
                <th className="py-2 pr-4 font-medium">Guest OS</th>
                <th className="py-2 pr-4 font-medium">IP</th>
                <th className="py-2 font-medium">Power</th>
              </tr>
            </thead>
            <tbody>
              {items.map((v: Row) => {
                const c = ctx(v);
                return (
                  <tr key={str(v.id)} className="border-b border-[var(--color-border)] last:border-0">
                    <td className="py-2.5 pr-4 font-medium text-[var(--color-ink)]">{str(v.name).replace("[Relatech] ", "")}</td>
                    <td className="py-2.5 pr-4 text-xs">{str(c.purpose)}</td>
                    <td className="py-2.5 pr-4 text-xs">{str(c.lifecycle_role)}</td>
                    <td className="py-2.5 pr-4">{c.official_target ? <Badge tone="brand">ufficiale</Badge> : <span className="text-xs text-[var(--color-faint)]">—</span>}</td>
                    <td className="py-2.5 pr-4 text-xs">{str(v.guest_os)}</td>
                    <td className="py-2.5 pr-4 font-mono text-xs">{str(v.primary_ip)}</td>
                    <td className="py-2.5"><Badge tone={v.power_state === "powered_on" ? "ok" : "neutral"}>{str(v.power_state)}</Badge></td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
}
