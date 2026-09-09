"use client";

import { api } from "@/lib/api";
import { useApi } from "@/lib/useApi";
import { Badge, Card, ErrorNote, PageHeader, Spinner } from "@/components/ui";

type Row = Record<string, unknown>;

function str(v: unknown): string {
  if (Array.isArray(v)) return v.join(", ");
  return v == null ? "—" : String(v);
}

export default function InventoryPage() {
  const assets = useApi(api.assets, []);
  const vms = useApi(api.vms, []);

  if (assets.loading || vms.loading) return <Spinner />;
  if (assets.error) return <ErrorNote message={assets.error} />;
  if (!assets.data || !vms.data) return null;

  return (
    <div>
      <PageHeader
        title="Inventario"
        subtitle="Asset OT osservati da Cyber Vision e macchine virtuali VMware ESXi."
      />

      <Card title={`Asset OT · ${assets.data.count}`} className="mb-6">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-xs uppercase tracking-wider text-[var(--color-faint)] border-b border-[var(--color-border)]">
                <th className="py-2 pr-4">Nome</th>
                <th className="py-2 pr-4">Tipo</th>
                <th className="py-2 pr-4">IP</th>
                <th className="py-2 pr-4">Protocolli</th>
                <th className="py-2 pr-4">Ruolo</th>
                <th className="py-2">Stato</th>
              </tr>
            </thead>
            <tbody>
              {(assets.data.items as Row[]).map((a) => (
                <tr key={str(a.id)} className="border-b border-[var(--color-border)]/50">
                  <td className="py-2.5 pr-4 font-medium">{str(a.name)}</td>
                  <td className="py-2.5 pr-4">{str(a.device_type)}</td>
                  <td className="py-2.5 pr-4 font-mono text-xs">{str(a.ip_addresses)}</td>
                  <td className="py-2.5 pr-4 text-xs">{str(a.protocols)}</td>
                  <td className="py-2.5 pr-4">
                    <Badge tone={a.operational_role === "target" ? "accent" : "neutral"}>
                      {str(a.operational_role)}
                    </Badge>
                  </td>
                  <td className="py-2.5">
                    <Badge tone={a.status === "online" ? "ok" : a.status === "stale" ? "warn" : "neutral"}>
                      {str(a.status)}
                    </Badge>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>

      <Card title={`Macchine virtuali · ${vms.data.count}`}>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-xs uppercase tracking-wider text-[var(--color-faint)] border-b border-[var(--color-border)]">
                <th className="py-2 pr-4">Nome</th>
                <th className="py-2 pr-4">Guest OS</th>
                <th className="py-2 pr-4">IP</th>
                <th className="py-2">Alimentazione</th>
              </tr>
            </thead>
            <tbody>
              {(vms.data.items as Row[]).map((v) => (
                <tr key={str(v.id)} className="border-b border-[var(--color-border)]/50">
                  <td className="py-2.5 pr-4 font-medium">{str(v.name)}</td>
                  <td className="py-2.5 pr-4 text-xs">{str(v.guest_os)}</td>
                  <td className="py-2.5 pr-4 font-mono text-xs">{str(v.primary_ip)}</td>
                  <td className="py-2.5">
                    <Badge tone={v.power_state === "powered_on" ? "ok" : "neutral"}>
                      {str(v.power_state)}
                    </Badge>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
}
