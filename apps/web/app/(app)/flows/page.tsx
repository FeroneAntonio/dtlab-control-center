"use client";

import { api } from "@/lib/api";
import { useApi } from "@/lib/useApi";
import { Badge, Card, ErrorNote, PageHeader, Spinner, StatTile } from "@/components/ui";

type Row = Record<string, unknown>;
const DIR_LABEL: Record<string, string> = {
  left_to_right: "→", right_to_left: "←", undetermined: "↔", unknown: "?",
};

function str(v: unknown): string {
  return v == null ? "—" : String(v);
}
function num(v: unknown): string {
  return v == null ? "—" : Number(v).toLocaleString("it-IT");
}

export default function FlowsPage() {
  const flows = useApi(api.flows, []);
  const activities = useApi(api.activities, []);

  if (flows.loading || activities.loading) return <Spinner />;
  if (flows.error) return <ErrorNote message={flows.error} />;

  const fItems = flows.data?.items ?? [];
  const aItems = activities.data?.items ?? [];
  const totalPackets = fItems.reduce((a, f) => a + Number(f.packet_count ?? 0), 0);

  return (
    <div>
      <PageHeader
        title="Attività e flow"
        subtitle="Attività aggregate e singoli flow Cisco, con componenti, contatori e timestamp."
      />

      <div className="grid grid-cols-2 md:grid-cols-3 gap-4 mb-6">
        <StatTile label="Flow" value={fItems.length} tone="brand" />
        <StatTile label="Attività" value={aItems.length} />
        <StatTile label="Pacchetti" value={num(totalPackets)} hint="somma flow" />
      </div>

      <Card title="Flow osservati" className="mb-6">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-xs uppercase tracking-wider text-[var(--color-faint)] border-b border-[var(--color-border)]">
                <th className="py-2 pr-4 font-medium">Sorgente</th>
                <th className="py-2 pr-4 font-medium">Dir</th>
                <th className="py-2 pr-4 font-medium">Destinazione</th>
                <th className="py-2 pr-4 font-medium">Protocollo</th>
                <th className="py-2 pr-4 font-medium">Porta</th>
                <th className="py-2 font-medium">Pacchetti</th>
              </tr>
            </thead>
            <tbody>
              {fItems.map((f: Row) => (
                <tr key={str(f.id)} className="border-b border-[var(--color-border)] last:border-0">
                  <td className="py-2.5 pr-4">{str(f.left_label)} <span className="text-[var(--color-faint)] font-mono text-xs">{str(f.left_ip)}</span></td>
                  <td className="py-2.5 pr-4 text-center font-mono">{DIR_LABEL[str(f.direction)] ?? "?"}</td>
                  <td className="py-2.5 pr-4">{str(f.right_label)} <span className="text-[var(--color-faint)] font-mono text-xs">{str(f.right_ip)}</span></td>
                  <td className="py-2.5 pr-4"><Badge tone={str(f.protocol) === "Modbus" ? "brand" : "neutral"}>{str(f.protocol)}</Badge></td>
                  <td className="py-2.5 pr-4 font-mono text-xs">{str(f.right_port)}</td>
                  <td className="py-2.5 font-mono">{num(f.packet_count)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>

      <Card title="Attività">
        <div className="space-y-2">
          {aItems.map((a: Row) => (
            <div key={str(a.id)} className="flex items-center justify-between rounded-lg border border-[var(--color-border)] px-3 py-2.5">
              <div>
                <div className="text-sm font-medium text-[var(--color-ink)]">{str(a.type)}</div>
                <div className="text-xs text-[var(--color-faint)]">{str(a.protocol)} · {num(a.flow_count)} flow · {num(a.event_count)} eventi</div>
              </div>
              <div className="text-xs font-mono text-[var(--color-muted)]">{num(a.packet_count)} pkt</div>
            </div>
          ))}
          {aItems.length === 0 && <div className="text-sm text-[var(--color-muted)]">Nessuna attività.</div>}
        </div>
      </Card>
    </div>
  );
}
