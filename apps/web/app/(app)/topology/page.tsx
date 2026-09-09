"use client";

import { useMemo } from "react";
import { api } from "@/lib/api";
import { useApi } from "@/lib/useApi";
import { Card, ErrorNote, PageHeader, Spinner } from "@/components/ui";

const W = 900;
const BAND_H = 130;
const PAD_TOP = 12;

function levelRank(level: string): number {
  if (level === "unknown") return 99;
  return Number(level);
}
function roleColor(role: string): { fill: string; stroke: string } {
  if (role === "target") return { fill: "#eef2ff", stroke: "#4f46e5" };
  if (role === "security_test") return { fill: "#fef2f2", stroke: "#dc2626" };
  if (role === "legacy") return { fill: "#f1f5f9", stroke: "#94a3b8" };
  return { fill: "#ecfdf5", stroke: "#059669" };
}

export default function TopologyPage() {
  const topo = useApi(api.topology, []);
  const topologyData = topo.data;

  const layout = useMemo(() => {
    if (!topologyData) return null;
    const zones = [...topologyData.zones].sort((a, b) => levelRank(b.purdue_level) - levelRank(a.purdue_level));
    const bandOf = new Map(zones.map((z, i) => [z.id, i]));
    const nodesByZone = new Map<string, typeof topologyData.nodes>();
    for (const z of zones) nodesByZone.set(z.id, []);
    const unzoned: typeof topologyData.nodes = [];
    for (const n of topologyData.nodes) {
      if (n.zone_id && nodesByZone.has(n.zone_id)) nodesByZone.get(n.zone_id)!.push(n);
      else unzoned.push(n);
    }
    const pos = new Map<string, { x: number; y: number }>();
    const place = (list: typeof topologyData.nodes, band: number) => {
      const y = PAD_TOP + band * BAND_H + BAND_H / 2 + 18;
      list.forEach((n, i) => {
        const step = W / (list.length + 1);
        pos.set(n.id, { x: step * (i + 1), y });
      });
    };
    zones.forEach((z, i) => place(nodesByZone.get(z.id)!, i));
    const extraBand = zones.length;
    if (unzoned.length) place(unzoned, extraBand);
    const bands = zones.length + (unzoned.length ? 1 : 0);
    return { zones, bandOf, pos, unzoned, height: PAD_TOP + bands * BAND_H + 20 };
  }, [topologyData]);

  if (topo.loading) return <Spinner />;
  if (topo.error) return <ErrorNote message={topo.error} />;
  if (!topo.data || !layout) return null;

  const nodeById = new Map(topo.data.nodes.map((n) => [n.id, n]));

  return (
    <div>
      <PageHeader
        title="Topologia OT"
        subtitle="Modello di Purdue: zone come bande, asset come nodi, flow Cisco come collegamenti."
      />
      <Card title="Vista integrata · Purdue / IEC 62443">
        <div className="overflow-x-auto">
          <svg viewBox={`0 0 ${W} ${layout.height}`} className="w-full" style={{ minWidth: 640 }}>
            {/* zone bands */}
            {layout.zones.map((z, i) => (
              <g key={z.id}>
                <rect x={0} y={PAD_TOP + i * BAND_H} width={W} height={BAND_H - 8}
                  rx={12} fill={i % 2 ? "#f8fafc" : "#f1f5f9"} stroke="#e6e8ec" />
                <text x={14} y={PAD_TOP + i * BAND_H + 22} fontSize={12} fontWeight={600} fill="#334155">
                  {z.purdue_level === "unknown" ? "Test" : `Livello ${z.purdue_level}`} · {z.name}
                </text>
                <text x={14} y={PAD_TOP + i * BAND_H + 40} fontSize={11} fill="#94a3b8">
                  {z.target_security_level}
                </text>
              </g>
            ))}
            {layout.unzoned.length > 0 && (
              <rect x={0} y={PAD_TOP + layout.zones.length * BAND_H} width={W} height={BAND_H - 8}
                rx={12} fill="#f8fafc" stroke="#e6e8ec" />
            )}

            {/* edges */}
            {topo.data.edges.map((e) => {
              const a = layout.pos.get(e.source);
              const b = layout.pos.get(e.target);
              if (!a || !b) return null;
              const midY = (a.y + b.y) / 2;
              return (
                <g key={e.id}>
                  <path d={`M ${a.x} ${a.y} C ${a.x} ${midY}, ${b.x} ${midY}, ${b.x} ${b.y}`}
                    fill="none" stroke="#c7d2fe" strokeWidth={2} />
                  <text x={(a.x + b.x) / 2} y={midY - 4} fontSize={10} fill="#818cf8" textAnchor="middle">
                    {e.protocol}
                  </text>
                </g>
              );
            })}

            {/* nodes */}
            {topo.data.nodes.map((n) => {
              const p = layout.pos.get(n.id);
              if (!p) return null;
              const c = roleColor(n.role);
              return (
                <g key={n.id}>
                  <circle cx={p.x} cy={p.y} r={22} fill={c.fill} stroke={c.stroke} strokeWidth={2} />
                  <text x={p.x} y={p.y + 4} fontSize={11} textAnchor="middle" fill={c.stroke} fontWeight={600}>
                    {n.device_type?.slice(0, 3).toUpperCase()}
                  </text>
                  <text x={p.x} y={p.y + 40} fontSize={11} textAnchor="middle" fill="#334155">
                    {n.name?.split(" ")[0]}
                  </text>
                  <text x={p.x} y={p.y + 54} fontSize={9} textAnchor="middle" fill="#94a3b8" fontFamily="monospace">
                    {n.ip}
                  </text>
                </g>
              );
            })}
          </svg>
        </div>
        <div className="mt-3 flex flex-wrap gap-4 text-xs text-[var(--color-muted)]">
          <span><span className="inline-block w-2.5 h-2.5 rounded-full align-middle mr-1" style={{ background: "#4f46e5" }} /> target</span>
          <span><span className="inline-block w-2.5 h-2.5 rounded-full align-middle mr-1" style={{ background: "#dc2626" }} /> test offensivo</span>
          <span><span className="inline-block w-2.5 h-2.5 rounded-full align-middle mr-1" style={{ background: "#94a3b8" }} /> legacy</span>
          <span><span className="inline-block w-2.5 h-2.5 rounded-full align-middle mr-1" style={{ background: "#059669" }} /> operativo</span>
        </div>
      </Card>

      <div className="mt-4 text-xs text-[var(--color-faint)]">
        {nodeById.size} asset · {topo.data.edges.length} flow · {topo.data.zones.length} zone.
      </div>
    </div>
  );
}
