"""Ticketing service: reuses the existing v2 data-plane engine over the API.

The operational workflow (deduplicated signals, persistent tickets, SLA, tasks,
comments, audit) is NOT re-implemented — it is the same ``dtlab.services``
engine that powers the Streamlit v2. The API only projects the current v3
snapshot down to its v2 shape (the offensive/twin/compliance/history domains are
irrelevant to ticketing), ingests it idempotently into a SQLite store, and
exposes the store operations.
"""

from __future__ import annotations

import tempfile
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from dtlab import contract as v2
from dtlab.services.playbooks import tasks_for_signal
from dtlab.services.signal_ingest import SnapshotIngestResult, ingest_snapshot
from dtlab.services.ticket_store import (
    SLA_POLICY_HOURS,
    TASK_STATUSES,
    TICKET_PRIORITIES,
    TICKET_STATUSES,
    TicketStore,
    derive_ticket_sla,
)

_V3_ONLY = {
    "attack_scenarios",
    "attack_runs",
    "detection_correlations",
    "process_telemetry",
    "security_zones",
    "compliance_mappings",
    "history",
}
_TERMINAL = frozenset({"closed", "false_positive", "accepted_risk", "suppressed"})
_DECISION = _TERMINAL | {"resolved"}
_PRIORITY_FOR_SEVERITY = {
    "critical": "p1",
    "high": "p2",
    "medium": "p3",
    "low": "p4",
    "info": "p4",
}


def v2_projection(snapshot: dict[str, Any]) -> dict[str, Any]:
    """Return a schema-v2 view of a v3 snapshot (drops v3-only domains)."""

    projection = {k: v for k, v in snapshot.items() if k not in _V3_ONLY}
    projection["schema_version"] = "2.0.0"
    return projection


def priority_for_severity(severity: object) -> str:
    return _PRIORITY_FOR_SEVERITY.get(str(severity or "").casefold(), "p3")


def playbook_tasks(signal_type: str) -> list[dict[str, str]]:
    return [
        {"title": task.title, "description": task.description}
        for task in tasks_for_signal(signal_type)
    ]


class TicketService:
    """Thread-safe wrapper around a TicketStore fed by the current snapshot."""

    def __init__(self, db_path: str | Path | None = None) -> None:
        if db_path is None:
            db_path = Path(tempfile.gettempdir()) / "dtlab-api-tickets" / "tickets.sqlite3"
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self.store = TicketStore(str(self.db_path))
        self._last_ingest: SnapshotIngestResult | None = None

    # -- ingest -----------------------------------------------------------
    def ingest(self, snapshot: dict[str, Any]) -> SnapshotIngestResult:
        projection = v2_projection(snapshot)
        sha = v2.snapshot_sha256(projection)
        with self._lock:
            result = ingest_snapshot(self.store, projection, expected_sha256=sha)
            self._last_ingest = result
            return result

    # -- reads ------------------------------------------------------------
    def signals(self) -> list[dict[str, Any]]:
        with self._lock:
            signals = self.store.list_signals(limit=1000)
            tickets = self.store.list_tickets(limit=1000)
        by_signal = {str(t["signal_id"]): t for t in tickets}
        enriched: list[dict[str, Any]] = []
        for signal in signals:
            ticket = by_signal.get(str(signal["id"]))
            state = (
                "resurfaced"
                if ticket and self._needs_review(signal, ticket)
                else "open"
                if ticket
                else "unassigned"
            )
            enriched.append({**signal, "ticket_id": ticket["id"] if ticket else None,
                             "ticket_state": state})
        return enriched

    def signal(self, signal_id: str) -> dict[str, Any] | None:
        with self._lock:
            try:
                return self.store.get_signal(signal_id)
            except Exception:
                return None

    def tickets(self, *, now: datetime | None = None) -> list[dict[str, Any]]:
        now = now or datetime.now(UTC)
        with self._lock:
            tickets = self.store.list_tickets(limit=1000)
        return [{**t, "sla": derive_ticket_sla(t, now=now)} for t in tickets]

    def ticket_document(self, ticket_id: str) -> dict[str, Any] | None:
        with self._lock:
            try:
                document = self.store.export_ticket(ticket_id)
            except Exception:
                return None
        document["ticket"]["sla"] = derive_ticket_sla(document["ticket"])
        return document

    def ticket_json(self, ticket_id: str) -> str | None:
        with self._lock:
            try:
                return self.store.export_ticket_json(ticket_id)
            except Exception:
                return None

    def kpis(self, *, now: datetime | None = None) -> dict[str, Any]:
        now = now or datetime.now(UTC)
        with self._lock:
            signals = self.store.list_signals(limit=1000)
            tickets = self.store.list_tickets(limit=1000)
        by_signal = {str(t["signal_id"]): t for t in tickets}
        active = [t for t in tickets if t["status"] not in _TERMINAL]
        sla = {t["id"]: derive_ticket_sla(t, now=now) for t in tickets}
        unassigned = sum(
            self._needs_review(s, by_signal.get(str(s["id"]))) for s in signals
        )
        return {
            "signals": len(signals),
            "unassigned": unassigned,
            "critical_high": sum(
                s.get("severity") in {"critical", "high"}
                and self._needs_review(s, by_signal.get(str(s["id"])))
                for s in signals
            ),
            "tickets_active": len(active),
            "tickets_p1_p2": sum(t["priority"] in {"p1", "p2"} for t in active),
            "tickets_unowned": sum(not t.get("owner") for t in active),
            "sla_overdue": sum(v["state"] == "overdue" for v in sla.values()),
            "sla_due_soon": sum(v["state"] == "due_soon" for v in sla.values()),
            "tickets_closed": len(tickets) - len(active),
        }

    # -- writes -----------------------------------------------------------
    def create_ticket(
        self, signal_id: str, *, actor: str, priority: str | None, owner: str | None
    ) -> dict[str, Any]:
        with self._lock:
            signal = self.store.get_signal(signal_id)
            ticket, _added = self.store.create_ticket_with_tasks(
                signal_id,
                actor=actor,
                tasks=playbook_tasks(str(signal["signal_type"])),
                priority=priority or priority_for_severity(signal.get("severity")),
                owner=owner or None,
            )
            return ticket

    def transition(self, ticket_id: str, target: str, *, actor: str, note: str | None):
        with self._lock:
            return self.store.transition_ticket(ticket_id, target, actor=actor, note=note)

    def governance(self, ticket_id: str, *, owner: str | None, priority: str | None, actor: str):
        with self._lock:
            return self.store.update_ticket_governance(
                ticket_id, owner=owner, priority=priority, actor=actor
            )

    def add_comment(self, ticket_id: str, *, author: str, body: str):
        with self._lock:
            return self.store.add_comment(ticket_id, author=author, body=body)

    def add_task(self, ticket_id: str, *, actor: str, title: str, description: str | None,
                 owner: str | None, due_at: str | None):
        with self._lock:
            return self.store.add_task(ticket_id, actor=actor, title=title,
                                       description=description, owner=owner, due_at=due_at)

    def update_task(self, task_id: str, status: str, *, actor: str):
        with self._lock:
            return self.store.update_task_status(task_id, status, actor=actor)

    # -- helpers ----------------------------------------------------------
    @staticmethod
    def _needs_review(signal: dict[str, Any] | None, ticket: dict[str, Any] | None) -> bool:
        if signal is None:
            return False
        if ticket is None:
            return True
        if ticket.get("status") not in _DECISION:
            return False
        if signal.get("signal_type") not in {
            "finding", "vulnerability", "new_ui_alert", "new_ui_vulnerability"
        }:
            return False
        decision_at = ticket.get("closed_at") or ticket.get("resolved_at")
        changed_at = signal.get("updated_at")
        if not decision_at or not changed_at:
            return False
        return str(changed_at) > str(decision_at)


# Metadata exposed to clients so the UI can render enums/policies.
POLICY = {
    "priorities": sorted(TICKET_PRIORITIES),
    "statuses": sorted(TICKET_STATUSES),
    "task_statuses": sorted(TASK_STATUSES),
    "sla_hours": dict(SLA_POLICY_HOURS),
}
