"use client";

import { useEffect, useState } from "react";
import { api, downloadFile } from "@/lib/api";
import { useApi } from "@/lib/useApi";
import { useAuth } from "@/lib/auth";
import { Badge, Card, ErrorNote, PageHeader, Spinner, StatTile } from "@/components/ui";
import type { Ticket } from "@/lib/types";

const STATUS_LABEL: Record<string, string> = {
  new: "Nuovo", acknowledged: "Preso in carico", investigating: "In analisi",
  remediating: "In remediation", waiting_ot: "In attesa OT", resolved: "Risolto",
  closed: "Chiuso", false_positive: "Falso positivo", accepted_risk: "Rischio accettato",
  suppressed: "Soppresso",
};
const SLA_LABEL: Record<string, string> = {
  on_time: "In tempo", due_soon: "In scadenza", overdue: "Scaduto", stopped: "Fermato",
};
const TASK_LABEL: Record<string, string> = {
  pending: "Da fare", completed: "Completata", skipped: "Non applicabile",
};
const NOTE_REQUIRED = new Set(["resolved", "false_positive", "accepted_risk", "suppressed"]);

function slaTone(s: string) {
  return s === "overdue" ? ("danger" as const) : s === "due_soon" ? ("warn" as const) : ("ok" as const);
}
function prioTone(p: string) {
  return p === "p1" ? ("danger" as const) : p === "p2" ? ("warn" as const) : ("neutral" as const);
}

export default function TicketsPage() {
  const [tick, setTick] = useState(0);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const summary = useApi(api.ticketingSummary, [tick]);
  const tickets = useApi(api.tickets, [tick]);

  useEffect(() => {
    const open = new URLSearchParams(window.location.search).get("open");
    if (!open) return;
    const handle = window.setTimeout(() => setSelectedId(open), 0);
    return () => window.clearTimeout(handle);
  }, []);

  if (tickets.loading || summary.loading) return <Spinner />;
  if (tickets.error) return <ErrorNote message={tickets.error} />;

  const k = summary.data;
  const items = tickets.data?.items ?? [];

  return (
    <div>
      <PageHeader
        title="Ticket & remediation"
        subtitle="Registro persistente con SLA, checklist manual-first, decisioni e audit append-only."
      />

      <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-6 gap-4 mb-6">
        <StatTile label="Attivi" value={k?.tickets_active ?? "—"} tone="brand" />
        <StatTile label="P1 / P2 · DTLab" value={k?.tickets_p1_p2 ?? "—"} tone={(k?.tickets_p1_p2 ?? 0) > 0 ? "warn" : "ok"} />
        <StatTile label="Non assegnati" value={k?.tickets_unowned ?? "—"} />
        <StatTile label="SLA scaduti" value={k?.sla_overdue ?? "—"} tone={(k?.sla_overdue ?? 0) > 0 ? "danger" : "ok"} />
        <StatTile label="In scadenza" value={k?.sla_due_soon ?? "—"} tone={(k?.sla_due_soon ?? 0) > 0 ? "warn" : "ok"} />
        <StatTile label="Chiusi" value={k?.tickets_closed ?? "—"} />
      </div>

      {items.length === 0 ? (
        <Card title="Registro ticket">
          <div className="text-sm text-[var(--color-muted)]">
            Nessun ticket. Apri <b>Segnalazioni</b> e prendi in carico un segnale.
          </div>
        </Card>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-5 gap-6">
          <Card title={`Registro · ${items.length}`} className="lg:col-span-2">
            <div className="divide-y divide-[var(--color-border)] -m-1">
              {items.map((t) => (
                <button
                  key={t.id}
                  onClick={() => setSelectedId(t.id)}
                  className={`w-full text-left px-3 py-3 rounded-lg transition ${
                    selectedId === t.id ? "bg-[var(--color-brand-soft)]" : "hover:bg-slate-50"
                  }`}
                >
                  <div className="flex items-center gap-2 mb-1">
                    <Badge tone={prioTone(t.priority)}>{t.priority.toUpperCase()}</Badge>
                    <Badge tone={slaTone(t.sla.state)}>{SLA_LABEL[t.sla.state]}</Badge>
                  </div>
                  <div className="text-sm font-medium text-[var(--color-ink)] truncate">{t.title}</div>
                  <div className="text-xs text-[var(--color-faint)]">
                    {STATUS_LABEL[t.status] ?? t.status} · {t.owner ?? "non assegnato"}
                  </div>
                </button>
              ))}
            </div>
          </Card>

          <div className="lg:col-span-3">
            {selectedId ? (
              <Workspace key={selectedId} ticketId={selectedId} onChange={() => setTick((x) => x + 1)} />
            ) : (
              <Card title="Workspace"><div className="text-sm text-[var(--color-muted)]">Seleziona un ticket.</div></Card>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

const TABS = ["Governance", "Checklist", "Commenti", "Audit"] as const;
type Tab = (typeof TABS)[number];

function Workspace({ ticketId, onChange }: { ticketId: string; onChange: () => void }) {
  const { token, role } = useAuth();
  const canWrite = role === "analyst" || role === "admin";
  const [local, setLocal] = useState(0);
  const doc = useApi((t) => api.ticket(t, ticketId), [ticketId, local]);
  const [tab, setTab] = useState<Tab>("Governance");

  const refresh = () => {
    setLocal((x) => x + 1);
    onChange();
  };

  if (doc.loading) return <Card title="Workspace"><Spinner /></Card>;
  if (doc.error) return <ErrorNote message={doc.error} />;
  if (!doc.data) return null;
  const { ticket, tasks, comments, audit } = doc.data;

  return (
    <Card
      title={ticket.title}
      action={
        <button
          onClick={() => token && downloadFile(api.ticketExportUrl(ticketId), token, `${ticketId}.json`)}
          className="text-xs text-[var(--color-brand)] hover:underline"
        >
          Export JSON
        </button>
      }
    >
      <div className="flex items-center gap-2 flex-wrap mb-3 text-xs">
        <Badge tone={prioTone(ticket.priority)}>{ticket.priority.toUpperCase()}</Badge>
        <Badge tone="neutral">{STATUS_LABEL[ticket.status] ?? ticket.status}</Badge>
        <Badge tone={slaTone(ticket.sla.state)}>{SLA_LABEL[ticket.sla.state]}</Badge>
        <span className="text-[var(--color-faint)]">owner: {ticket.owner ?? "—"}</span>
      </div>

      <div className="flex gap-1 border-b border-[var(--color-border)] mb-4">
        {TABS.map((tb) => (
          <button
            key={tb}
            onClick={() => setTab(tb)}
            className={`px-3 py-2 text-sm border-b-2 -mb-px transition ${
              tab === tb
                ? "border-[var(--color-brand)] text-[var(--color-brand)] font-medium"
                : "border-transparent text-[var(--color-muted)] hover:text-[var(--color-ink)]"
            }`}
          >
            {tb}
          </button>
        ))}
      </div>

      {tab === "Governance" && (
        <Governance token={token!} ticket={ticket} canWrite={canWrite} onDone={refresh} />
      )}
      {tab === "Checklist" && (
        <div className="space-y-2">
          {tasks.length === 0 && <div className="text-sm text-[var(--color-muted)]">Nessuna attività.</div>}
          {tasks.map((task) => (
            <div key={task.id} className="rounded-lg border border-[var(--color-border)] p-3">
              <div className="flex items-center justify-between gap-2">
                <div className="text-sm font-medium text-[var(--color-ink)]">
                  {task.position}. {task.title}
                </div>
                {canWrite ? (
                  <select
                    value={task.status}
                    onChange={async (e) => {
                      if (!token) return;
                      await api.updateTaskStatus(token, task.id, e.target.value);
                      refresh();
                    }}
                    className="rounded-md border border-[var(--color-border-strong)] bg-[var(--color-surface)] px-2 py-1 text-xs"
                  >
                    {Object.entries(TASK_LABEL).map(([v, l]) => (
                      <option key={v} value={v}>{l}</option>
                    ))}
                  </select>
                ) : (
                  <Badge tone={task.status === "completed" ? "ok" : "neutral"}>{TASK_LABEL[task.status]}</Badge>
                )}
              </div>
              {task.description && <p className="mt-1 text-xs text-[var(--color-muted)]">{task.description}</p>}
            </div>
          ))}
        </div>
      )}
      {tab === "Commenti" && <Comments token={token!} ticketId={ticketId} comments={comments} canWrite={canWrite} onDone={refresh} />}
      {tab === "Audit" && (
        <div className="space-y-2">
          {audit.map((a) => (
            <div key={a.sequence} className="flex gap-3 text-xs">
              <span className="text-[var(--color-faint)] font-mono w-8">{a.sequence}</span>
              <span className="text-[var(--color-faint)] font-mono whitespace-nowrap">
                {a.occurred_at.replace("T", " ").slice(0, 19)}
              </span>
              <span className="text-[var(--color-ink-2)]"><b>{a.actor}</b> · {a.action}</span>
            </div>
          ))}
        </div>
      )}
    </Card>
  );
}

function Governance({
  token, ticket, canWrite, onDone,
}: {
  token: string;
  ticket: Ticket;
  canWrite: boolean;
  onDone: () => void;
}) {
  const policy = useApi(api.ticketingPolicy, []);
  const [target, setTarget] = useState("");
  const [note, setNote] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  if (!canWrite) return <div className="text-sm text-[var(--color-faint)]">Serve il ruolo analyst per governare il ticket.</div>;

  const targets = (policy.data?.statuses ?? []).filter((s) => s !== ticket.status);

  const transition = async () => {
    if (!target) return;
    if (NOTE_REQUIRED.has(target) && !note.trim()) {
      setError("Nota decisionale obbligatoria per questo stato.");
      return;
    }
    setBusy(true); setError(null);
    try {
      await api.transitionTicket(token, ticket.id, { target, note: note || undefined });
      setNote(""); setTarget("");
      onDone();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Errore");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-4">
      <div className="text-sm font-medium text-[var(--color-ink-2)]">Cambia stato</div>
      <div className="flex gap-2">
        <select value={target} onChange={(e) => setTarget(e.target.value)}
          className="rounded-lg border border-[var(--color-border-strong)] bg-[var(--color-surface)] px-2 py-2 text-sm">
          <option value="">Nuovo stato…</option>
          {targets.map((s) => <option key={s} value={s}>{STATUS_LABEL[s] ?? s}</option>)}
        </select>
        <button disabled={busy || !target} onClick={transition}
          className="rounded-lg bg-[var(--color-brand)] px-4 py-2 text-sm font-semibold text-white disabled:opacity-40 hover:bg-[var(--color-brand-2)]">
          Registra
        </button>
      </div>
      <textarea value={note} onChange={(e) => setNote(e.target.value)} rows={2}
        placeholder="Nota decisionale (obbligatoria per risoluzione/falso positivo/rischio accettato/soppressione)"
        className="w-full rounded-lg border border-[var(--color-border-strong)] bg-[var(--color-surface)] px-3 py-2 text-sm" />
      {error && <div className="text-xs text-[var(--color-danger)]">{error}</div>}
      <p className="text-xs text-[var(--color-faint)]">
        Le transizioni sono registrate nell&apos;audit append-only. Nessuna azione automatica su PLC/VM/rete.
      </p>
    </div>
  );
}

function Comments({
  token, ticketId, comments, canWrite, onDone,
}: {
  token: string;
  ticketId: string;
  comments: { author: string; body: string; created_at: string }[];
  canWrite: boolean;
  onDone: () => void;
}) {
  const [body, setBody] = useState("");
  const [busy, setBusy] = useState(false);

  const send = async () => {
    if (!body.trim()) return;
    setBusy(true);
    try {
      await api.addComment(token, ticketId, body);
      setBody("");
      onDone();
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-3">
      {comments.length === 0 && <div className="text-sm text-[var(--color-muted)]">Nessun commento.</div>}
      {comments.map((c, i) => (
        <div key={i} className="rounded-lg border border-[var(--color-border)] p-3">
          <div className="text-xs text-[var(--color-faint)] mb-1">
            <b className="text-[var(--color-ink-2)]">{c.author}</b> · {c.created_at.replace("T", " ").slice(0, 19)}
          </div>
          <div className="text-sm text-[var(--color-ink)]">{c.body}</div>
        </div>
      ))}
      {canWrite && (
        <div className="flex gap-2">
          <input value={body} onChange={(e) => setBody(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && send()}
            placeholder="Nuovo commento…"
            className="flex-1 rounded-lg border border-[var(--color-border-strong)] bg-[var(--color-surface)] px-3 py-2 text-sm" />
          <button disabled={busy || !body.trim()} onClick={send}
            className="rounded-lg bg-[var(--color-brand)] px-4 py-2 text-sm font-semibold text-white disabled:opacity-40 hover:bg-[var(--color-brand-2)]">
            Invia
          </button>
        </div>
      )}
    </div>
  );
}
