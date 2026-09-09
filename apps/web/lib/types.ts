// Types for the DTLab API responses the web app consumes.

export interface Meta {
  snapshot_id: string;
  schema_version: string;
  generated_at: string;
  source: string;
  content_sha256: string;
  loaded_at: string;
  sync: Sync;
  environment: { id: string; name: string; kind: string; status: string };
  counts: Record<string, number>;
}

export interface Sync {
  state: string;
  publication_mode: string;
  started_at: string;
  completed_at: string;
  max_age_seconds: number;
  collector_version: string;
  vpn_required: boolean;
  last_known_good_snapshot_id: string | null;
}

export interface Overview {
  meta: Meta;
  sync: Sync;
  kpis: {
    assets: number;
    high_risk_assets: number;
    open_findings: number;
    open_vulnerabilities: number;
    attack_runs: number;
    detections: number;
    detection_coverage: number | null;
    mean_detection_latency_seconds: number | null;
    quality_score: number | null;
  };
  compliance_coverage: Record<string, number | null>;
  digital_twin: { captured_at: string; belt_state: string; anomaly: string | null } | null;
  top_risk_assets: RiskScore[];
  recent_events: EventRecord[];
  attack_timeline: TimelineEntry[];
}

export interface TimelineEntry {
  run_id: string;
  scenario_name: string | null;
  started_at: string | null;
  outcome: string;
  detected: boolean | null;
  detection_latency_seconds: number | null;
}

export interface RiskScore {
  id: string;
  asset_id: string;
  score: number;
  band: string;
  methodology: string;
}

export interface EventRecord {
  id: string;
  occurred_at: string;
  severity: string;
  category: string;
  title: string;
  description: string;
  asset_ids: string[];
}

export interface DetectionSummary {
  attack_runs: number;
  correlations: number;
  detected: number;
  undetected: number;
  coverage: number | null;
  latency_seconds: {
    min: number | null;
    max: number | null;
    mean: number | null;
    median: number | null;
  };
  detection_gaps: {
    attack_run_id: string;
    scenario_id: string | null;
    scenario_name: string | null;
    mitre_technique_id: string | null;
  }[];
}

export interface MitreTechnique {
  technique_id: string;
  technique_name: string;
  tactic: string;
}

export interface AttackScenario {
  id: string;
  name: string;
  description: string;
  category: string;
  severity: string;
  execution_mode: string;
  target_asset_role: string;
  mitre_techniques: MitreTechnique[];
  expected_signals: string[];
  roe_reference: string | null;
}

export interface AttackRun {
  id: string;
  scenario_id: string;
  status: string;
  execution_mode: string;
  started_at: string | null;
  completed_at: string | null;
  source_asset_id: string | null;
  target_asset_ids: string[];
  outcome: string;
  steps: { step_id: string; technique_id?: string; description: string; outcome: string }[];
  detected: boolean | null;
  detection: {
    detected: boolean;
    detection_source: string;
    detection_latency_seconds: number | null;
    detected_at: string | null;
    event_id: string | null;
    mitre_technique_id: string | null;
  } | null;
}

export interface TelemetrySeriesPoint {
  sample_index: number;
  captured_at: string;
  value: number | boolean | null;
  in_bounds: boolean | null;
  belt_state: string;
  anomaly: string | null;
}

export interface TelemetrySeries {
  register: string;
  unit: string | null;
  count: number;
  points: TelemetrySeriesPoint[];
}

export interface ComplianceCoverage {
  frameworks: {
    framework: string;
    total: number;
    counts: Record<string, number>;
    covered_ratio: number | null;
  }[];
}

export interface HistorySeries {
  metric: string;
  count: number;
  points: { snapshot_id: string; generated_at: string; value: number | null }[];
}

export interface Collection<T> {
  count: number;
  items: T[];
}

// --- operations: signals + tickets ---------------------------------------
export interface Signal {
  id: string;
  signal_type: string;
  severity: string;
  title: string;
  description: string | null;
  source_id: string | null;
  source_record_id: string | null;
  occurrence_count: number;
  last_observed_at: string | null;
  updated_at: string | null;
  asset_ids: string[];
  recommended_action?: string | null;
  ticket_id: string | null;
  ticket_state: "unassigned" | "open" | "resurfaced";
}

export interface Sla {
  state: "on_time" | "due_soon" | "overdue" | "stopped";
  due_at: string | null;
  remaining_seconds: number;
}

export interface Ticket {
  id: string;
  signal_id: string;
  title: string;
  description: string | null;
  status: string;
  priority: string;
  owner: string | null;
  created_by: string;
  created_at: string | null;
  updated_at: string | null;
  sla: Sla;
}

export interface TicketTask {
  id: string;
  position: number;
  title: string;
  description: string | null;
  status: string;
  owner: string | null;
  due_at: string | null;
}

export interface TicketComment {
  author: string;
  body: string;
  created_at: string;
}

export interface AuditEntry {
  sequence: number;
  occurred_at: string;
  actor: string;
  action: string;
  details: Record<string, unknown>;
}

export interface TicketDocument {
  ticket: Ticket;
  signal: Signal;
  tasks: TicketTask[];
  comments: TicketComment[];
  audit: AuditEntry[];
  occurrences?: unknown[];
}

export interface TicketingSummary {
  signals: number;
  unassigned: number;
  critical_high: number;
  tickets_active: number;
  tickets_p1_p2: number;
  tickets_unowned: number;
  sla_overdue: number;
  sla_due_soon: number;
  tickets_closed: number;
}

export interface TicketingPolicy {
  priorities: string[];
  statuses: string[];
  task_statuses: string[];
  sla_hours: Record<string, number>;
}
