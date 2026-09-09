// Typed client for the DTLab API. The bearer token is held client-side and
// passed on every call; the base URL comes from NEXT_PUBLIC_API_BASE.

import type {
  AttackRun,
  AttackScenario,
  Collection,
  ComplianceCoverage,
  DetectionSummary,
  HistorySeries,
  Meta,
  Overview,
  Signal,
  TelemetrySeries,
  Ticket,
  TicketDocument,
  TicketingPolicy,
  TicketingSummary,
} from "./types";

export const API_BASE =
  process.env.NEXT_PUBLIC_API_BASE ?? "http://127.0.0.1:8531";

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

async function request<T>(path: string, token: string): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { Authorization: `Bearer ${token}` },
    cache: "no-store",
  });
  if (!res.ok) throw await toError(res);
  return res.json() as Promise<T>;
}

async function post<T>(path: string, token: string, body: unknown): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(body ?? {}),
  });
  if (!res.ok) throw await toError(res);
  return res.json() as Promise<T>;
}

export async function downloadFile(url: string, token: string, filename: string): Promise<void> {
  const res = await fetch(url, { headers: { Authorization: `Bearer ${token}` } });
  if (!res.ok) throw await toError(res);
  const blob = await res.blob();
  const objectUrl = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = objectUrl;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(objectUrl);
}

async function toError(res: Response): Promise<ApiError> {
  let detail = res.statusText;
  try {
    const body = await res.json();
    detail = body.detail ?? detail;
  } catch {
    /* ignore */
  }
  return new ApiError(res.status, detail);
}

export const api = {
  meta: (t: string) => request<Meta>("/api/meta", t),
  me: (t: string) => request<{ subject: string; role: string }>("/api/me", t),
  overview: (t: string) => request<Overview>("/api/overview", t),
  scenarios: (t: string) => request<Collection<AttackScenario>>("/api/attack-scenarios", t),
  attackRuns: (t: string) => request<Collection<AttackRun>>("/api/attack-runs", t),
  detectionSummary: (t: string) => request<DetectionSummary>("/api/detection/summary", t),
  telemetrySeries: (t: string, register: string) =>
    request<TelemetrySeries>(`/api/telemetry/series?register=${encodeURIComponent(register)}`, t),
  telemetryRegisters: (t: string) =>
    request<Collection<string>>("/api/telemetry/registers", t),
  complianceCoverage: (t: string) => request<ComplianceCoverage>("/api/compliance/coverage", t),
  purdue: (t: string) => request<{ levels: { level: string; zones: unknown[] }[] }>("/api/purdue", t),
  assets: (t: string) => request<Collection<Record<string, unknown>>>("/api/assets", t),
  vms: (t: string) => request<Collection<Record<string, unknown>>>("/api/virtual-machines", t),
  historyMetrics: (t: string) => request<Collection<string>>("/api/history/metrics", t),
  historySeries: (t: string, metric: string) =>
    request<HistorySeries>(`/api/history/series/${encodeURIComponent(metric)}`, t),

  // operations: signals + tickets
  signals: (t: string) => request<Collection<Signal>>("/api/signals", t),
  tickets: (t: string) => request<Collection<Ticket>>("/api/tickets", t),
  ticket: (t: string, id: string) =>
    request<TicketDocument>(`/api/tickets/${encodeURIComponent(id)}`, t),
  ticketingSummary: (t: string) => request<TicketingSummary>("/api/ticketing/summary", t),
  ticketingPolicy: (t: string) => request<TicketingPolicy>("/api/ticketing/policy", t),
  createTicket: (t: string, signalId: string, body: { priority?: string; owner?: string }) =>
    post<Ticket>(`/api/signals/${encodeURIComponent(signalId)}/ticket`, t, body),
  transitionTicket: (t: string, id: string, body: { target: string; note?: string }) =>
    post<Ticket>(`/api/tickets/${encodeURIComponent(id)}/transition`, t, body),
  updateGovernance: (t: string, id: string, body: { owner?: string; priority?: string }) =>
    post<Ticket>(`/api/tickets/${encodeURIComponent(id)}/governance`, t, body),
  addComment: (t: string, id: string, body: string) =>
    post<unknown>(`/api/tickets/${encodeURIComponent(id)}/comments`, t, { body }),
  updateTaskStatus: (t: string, taskId: string, status: string) =>
    post<unknown>(`/api/tasks/${encodeURIComponent(taskId)}/status`, t, { status }),
  ticketExportUrl: (id: string) => `${API_BASE}/api/tickets/${encodeURIComponent(id)}/export`,

  // security
  riskScores: (t: string) => request<Collection<Record<string, unknown>>>("/api/risk-scores", t),
  riskDistribution: (t: string) =>
    request<{ total: number; bands: Record<string, number>; methodology: string }>(
      "/api/risk/distribution", t),
  events: (t: string) => request<Collection<Record<string, unknown>>>("/api/events", t),
  vulnerabilities: (t: string) =>
    request<Collection<Record<string, unknown>>>("/api/vulnerabilities", t),
  vulnerabilityCatalog: (t: string) =>
    request<{ count: number; items: Record<string, unknown>[]; capability_available: boolean }>(
      "/api/vulnerability-catalog", t),
  baselines: (t: string) => request<Collection<Record<string, unknown>>>("/api/baselines", t),
  baselineDifferences: (t: string) =>
    request<Collection<Record<string, unknown>>>("/api/baseline-differences", t),

  // platform + monitoring
  sources: (t: string) => request<Collection<Record<string, unknown>>>("/api/sources", t),
  sensors: (t: string) => request<Collection<Record<string, unknown>>>("/api/sensors", t),
  networks: (t: string) => request<Collection<Record<string, unknown>>>("/api/networks", t),
  flows: (t: string) => request<Collection<Record<string, unknown>>>("/api/flows", t),
  activities: (t: string) => request<Collection<Record<string, unknown>>>("/api/activities", t),
  quality: (t: string) =>
    request<{
      quality: { score?: number; methodology?: string; checks?: Record<string, unknown>[]; coverage?: Record<string, number> };
      sync: Record<string, unknown>;
      snapshot_id: string;
      content_sha256: string;
    }>("/api/quality", t),
  topology: (t: string) =>
    request<{
      zones: { id: string; name: string; purdue_level: string; target_security_level: string }[];
      nodes: { id: string; name: string; device_type: string; role: string; ip: string | null; zone_id: string | null }[];
      edges: { id: string; source: string; target: string; protocol: string; direction: string }[];
    }>("/api/topology", t),

  // evidence & export
  manifest: (t: string) =>
    request<{
      manifest_version: string;
      contract_version: string;
      snapshot_id: string;
      generated_at: string;
      sha256: string;
      byte_length: number;
      record_counts: Record<string, number>;
    }>("/api/export/manifest", t),
  exportSnapshotUrl: () => `${API_BASE}/api/export/snapshot`,
  exportAssetUrl: (id: string) => `${API_BASE}/api/export/asset/${encodeURIComponent(id)}`,

  newUiInventory: (t: string) =>
    request<{
      profiles: Record<string, unknown>[];
      networks: Record<string, unknown>[];
      active_alerts: number;
      vulnerabilities: number;
      available: boolean;
    }>("/api/new-ui-inventory", t),
};
