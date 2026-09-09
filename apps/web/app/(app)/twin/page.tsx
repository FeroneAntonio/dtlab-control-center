"use client";

import { useState } from "react";
import {
  CartesianGrid,
  Line,
  LineChart,
  ReferenceArea,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { api } from "@/lib/api";
import { useApi } from "@/lib/useApi";
import { Badge, Card, ErrorNote, PageHeader, Spinner } from "@/components/ui";

const DEFAULT_REGISTER = "conveyor_speed_rpm";

export default function TwinPage() {
  const registers = useApi(api.telemetryRegisters, []);
  const [selected, setSelected] = useState(DEFAULT_REGISTER);
  const series = useApi((t) => api.telemetrySeries(t, selected), [selected]);

  if (registers.loading) return <Spinner />;
  if (registers.error) return <ErrorNote message={registers.error} />;

  const points = (series.data?.points ?? []).map((p) => ({
    idx: p.sample_index,
    value: typeof p.value === "boolean" ? (p.value ? 1 : 0) : p.value,
    in_bounds: p.in_bounds,
    anomaly: p.anomaly,
    belt: p.belt_state,
  }));

  const anomalyWindow = points.filter((p) => p.anomaly);
  const beltStates = points.map((p) => p.belt);

  return (
    <div>
      <PageHeader
        title="Digital Twin · BeerFactory"
        subtitle="Registri e coil Modbus del nastro trasportatore nel tempo, con bande attese e manomissioni."
      />

      <Card title="Nastro trasportatore" className="mb-6">
        <div className="flex items-center gap-6">
          <ConveyorAnimation states={beltStates} />
          <div className="text-sm text-[var(--color-muted)]">
            Ogni segmento è un campione Modbus.{" "}
            <span className="text-emerald-600 font-medium">verde</span> = in marcia,{" "}
            <span className="text-red-600 font-medium">rosso</span> = guasto durante l&apos;attacco.
          </div>
        </div>
      </Card>

      <Card
        title="Serie registro"
        action={
          <div className="flex flex-wrap gap-1">
            {registers.data?.items.map((name) => (
              <button
                key={name}
                onClick={() => setSelected(name)}
                className={`rounded-md px-2 py-1 text-xs font-mono transition ${
                  selected === name
                    ? "bg-[var(--color-brand-soft)] text-[var(--color-brand)] border border-indigo-200"
                    : "text-[var(--color-muted)] hover:bg-slate-50 border border-transparent"
                }`}
              >
                {name}
              </button>
            ))}
          </div>
        }
      >
        {series.loading ? (
          <Spinner />
        ) : series.error ? (
          <ErrorNote message={series.error} />
        ) : (
          <div>
            <div className="flex items-center gap-3 mb-3 text-sm">
              <span className="text-[var(--color-muted)]">{selected}</span>
              {series.data?.unit && <Badge tone="neutral">{series.data.unit}</Badge>}
              {anomalyWindow.length > 0 && (
                <Badge tone="danger">{anomalyWindow.length} campioni fuori norma</Badge>
              )}
            </div>
            <div style={{ width: "100%", height: 320 }}>
              <ResponsiveContainer>
                <LineChart data={points} margin={{ top: 10, right: 20, bottom: 0, left: -10 }}>
                  <CartesianGrid stroke="#eef0f3" strokeDasharray="3 3" />
                  <XAxis dataKey="idx" stroke="#94a3b8" fontSize={11} />
                  <YAxis stroke="#94a3b8" fontSize={11} />
                  <Tooltip
                    contentStyle={{
                      background: "#ffffff",
                      border: "1px solid #e6e8ec",
                      borderRadius: 10,
                      boxShadow: "0 8px 24px rgba(16,24,40,0.08)",
                      fontSize: 12,
                    }}
                  />
                  {anomalyWindow.length > 0 && (
                    <ReferenceArea
                      x1={anomalyWindow[0].idx}
                      x2={anomalyWindow[anomalyWindow.length - 1].idx}
                      fill="#dc2626"
                      fillOpacity={0.08}
                    />
                  )}
                  <Line
                    type="monotone"
                    dataKey="value"
                    stroke="#4f46e5"
                    strokeWidth={2}
                    dot={{ r: 2 }}
                    isAnimationActive={false}
                  />
                </LineChart>
              </ResponsiveContainer>
            </div>
          </div>
        )}
      </Card>
    </div>
  );
}

function ConveyorAnimation({ states }: { states: string[] }) {
  return (
    <div className="flex gap-1 items-center overflow-x-auto py-2">
      {states.map((state, i) => (
        <div
          key={i}
          title={`campione ${i} · ${state}`}
          className="h-8 w-3 rounded-sm shrink-0"
          style={{
            background:
              state === "running" ? "#059669" : state === "fault" ? "#dc2626" : "#cbd5e1",
            opacity: state === "fault" ? 1 : 0.85,
          }}
        />
      ))}
    </div>
  );
}
