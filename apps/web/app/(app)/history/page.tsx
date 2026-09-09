"use client";

import { useState } from "react";
import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { api } from "@/lib/api";
import { useApi } from "@/lib/useApi";
import { Card, ErrorNote, PageHeader, Spinner } from "@/components/ui";

const METRIC_LABEL: Record<string, string> = {
  detections: "Rilevamenti",
  undetected_attacks: "Attacchi non rilevati",
  mean_detection_latency_seconds: "Latenza media (s)",
  attack_detection_coverage: "Copertura detection",
  open_tickets: "Ticket aperti",
  high_risk_assets: "Asset ad alto rischio",
  quality_score: "Qualità dati",
};

export default function HistoryPage() {
  const metrics = useApi(api.historyMetrics, []);
  const [metric, setMetric] = useState("detections");
  const series = useApi((t) => api.historySeries(t, metric), [metric]);

  if (metrics.loading) return <Spinner />;
  if (metrics.error) return <ErrorNote message={metrics.error} />;

  const data = (series.data?.points ?? []).map((p) => ({
    date: p.generated_at.slice(0, 10),
    value: p.value,
  }));

  return (
    <div>
      <PageHeader title="Trend" subtitle="Andamento storico delle metriche del laboratorio (retention giornaliera)." />

      <div className="flex flex-wrap gap-2 mb-4">
        {metrics.data?.items.map((m) => (
          <button
            key={m}
            onClick={() => setMetric(m)}
            className={`rounded-lg px-3 py-1.5 text-xs font-medium transition ${
              metric === m
                ? "bg-[var(--color-brand-soft)] text-[var(--color-brand)] border border-indigo-200"
                : "text-[var(--color-muted)] hover:bg-slate-50 border border-[var(--color-border)]"
            }`}
          >
            {METRIC_LABEL[m] ?? m}
          </button>
        ))}
      </div>

      <Card title={METRIC_LABEL[metric] ?? metric}>
        {series.loading ? (
          <Spinner />
        ) : series.error ? (
          <ErrorNote message={series.error} />
        ) : (
          <div style={{ width: "100%", height: 340 }}>
            <ResponsiveContainer>
              <AreaChart data={data} margin={{ top: 10, right: 20, bottom: 0, left: -10 }}>
                <defs>
                  <linearGradient id="grad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#4f46e5" stopOpacity={0.25} />
                    <stop offset="100%" stopColor="#4f46e5" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid stroke="#eef0f3" strokeDasharray="3 3" />
                <XAxis dataKey="date" stroke="#94a3b8" fontSize={11} />
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
                <Area
                  type="monotone"
                  dataKey="value"
                  stroke="#4f46e5"
                  strokeWidth={2}
                  fill="url(#grad)"
                  isAnimationActive={false}
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        )}
      </Card>
    </div>
  );
}
