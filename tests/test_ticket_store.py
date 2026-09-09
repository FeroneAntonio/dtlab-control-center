from __future__ import annotations

import hashlib
import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta, timezone

import pytest

from dtlab.services.ticket_store import (
    SLA_POLICY_HOURS,
    InvalidTransitionError,
    SignalInput,
    TicketStore,
    TicketValidationError,
    derive_ticket_sla,
)


def _fixed_clock() -> datetime:
    return datetime(2026, 8, 3, 12, 0, tzinfo=UTC)


def _signal() -> SignalInput:
    identity = b"dtlab-test-signal"
    return SignalInput(
        fingerprint=hashlib.sha256(identity).hexdigest(),
        signal_type="event",
        snapshot_sha256="a" * 64,
        evidence={
            "source_id": "src:cisco-cyber-vision:dtlab-01",
            "source_record_id": "dashboard-event:event-1",
            "truth": "real",
            "observed_at": "2026-08-03T10:00:02Z",
            "fetched_at": "2026-08-03T10:00:02Z",
            "completeness": 1,
            "notes": [],
        },
        severity="high",
        title="Nuova attività OT",
        description="Cyber Vision ha restituito una nuova attività.",
        occurred_at="2026-08-03T10:00:02Z",
        observed_at="2026-08-03T10:00:02Z",
        asset_ids=(),
        recommended_action=None,
        payload={"id": "event:1", "status": "active"},
    )


def _store_with_signal(tmp_path) -> tuple[TicketStore, str]:
    store = TicketStore(tmp_path / "ticketing.sqlite3", clock=_fixed_clock)
    store.ingest_signals([_signal()])
    signal_id = store.list_signals()[0]["id"]
    return store, signal_id


def test_ticket_is_created_only_explicitly_and_creation_is_idempotent(tmp_path) -> None:
    store, signal_id = _store_with_signal(tmp_path)

    assert store.list_tickets() == []
    assert len(store.list_signals(without_ticket=True)) == 1

    created = store.create_ticket_from_signal(
        signal_id,
        actor="analyst@example.test",
        priority="P2",
        owner="ot-team",
    )
    repeated = store.create_ticket_from_signal(
        signal_id,
        actor="another-analyst@example.test",
        priority="p4",
    )

    assert created == repeated
    assert created["status"] == "new"
    assert created["priority"] == "p2"
    assert created["owner"] == "ot-team"
    assert len(store.list_tickets()) == 1
    assert store.list_signals(without_ticket=True) == []


@pytest.mark.parametrize(
    ("priority", "expected_due_at"),
    [
        ("p1", "2026-08-03T16:00:00Z"),
        ("p2", "2026-08-03T20:00:00Z"),
        ("p3", "2026-08-04T12:00:00Z"),
        ("p4", "2026-08-06T12:00:00Z"),
    ],
)
def test_sla_deadline_is_persisted_from_explicit_priority_policy(
    tmp_path,
    priority: str,
    expected_due_at: str,
) -> None:
    store, signal_id = _store_with_signal(tmp_path)

    ticket = store.create_ticket_from_signal(signal_id, actor="triage", priority=priority)
    created_audit = store.export_ticket(ticket["id"])["audit"][0]

    assert SLA_POLICY_HOURS == {"p1": 4, "p2": 8, "p3": 24, "p4": 72}
    assert ticket["sla_due_at"] == expected_due_at
    assert created_audit["details"]["sla_due_at"] == expected_due_at
    assert created_audit["details"]["sla_policy_hours"] == SLA_POLICY_HOURS[priority]


def test_sla_states_use_one_utc_clock_and_the_final_quarter_as_due_soon(tmp_path) -> None:
    store, signal_id = _store_with_signal(tmp_path)
    ticket = store.create_ticket_from_signal(signal_id, actor="triage", priority="p2")

    assert derive_ticket_sla(
        ticket, now=datetime(2026, 8, 3, 17, 59, 59, tzinfo=UTC)
    )["state"] == "on_time"
    due_soon = derive_ticket_sla(ticket, now=datetime(2026, 8, 3, 18, 0, tzinfo=UTC))
    assert due_soon["state"] == "due_soon"
    assert due_soon["remaining_seconds"] == 2 * 60 * 60
    # 22:00 at UTC+02 is the exact 20:00Z deadline.
    overdue = derive_ticket_sla(
        ticket,
        now=datetime(2026, 8, 3, 22, 0, tzinfo=timezone(timedelta(hours=2))),
    )
    assert overdue["state"] == "overdue"
    assert overdue["remaining_seconds"] == 0


def test_priority_change_recalculates_from_creation_and_audits_both_deadlines(tmp_path) -> None:
    current = [datetime(2026, 8, 3, 12, 0, tzinfo=UTC)]
    store = TicketStore(tmp_path / "tickets.sqlite3", clock=lambda: current[0])
    store.ingest_signals([_signal()])
    signal_id = store.list_signals()[0]["id"]
    ticket = store.create_ticket_from_signal(signal_id, actor="triage", priority="p3")
    original_due_at = ticket["sla_due_at"]
    current[0] += timedelta(hours=2)

    updated = store.set_ticket_priority(ticket["id"], "p1", actor="supervisor")
    priority_audit = store.export_ticket(ticket["id"])["audit"][-1]

    assert original_due_at == "2026-08-04T12:00:00Z"
    assert updated["sla_due_at"] == "2026-08-03T16:00:00Z"
    assert priority_audit["action"] == "ticket.priority_changed"
    assert priority_audit["details"] == {
        "from": "p3",
        "to": "p1",
        "from_sla_due_at": original_due_at,
        "to_sla_due_at": "2026-08-03T16:00:00Z",
        "sla_anchor": "ticket.created_at",
        "sla_policy_hours": 4,
    }


def test_terminal_closure_stops_sla_at_the_persisted_close_time(tmp_path) -> None:
    store, signal_id = _store_with_signal(tmp_path)
    ticket = store.create_ticket_from_signal(signal_id, actor="analyst", priority="p3")
    for status in ("acknowledged", "investigating", "resolved", "closed"):
        ticket = store.transition_ticket(
            ticket["id"],
            status,
            actor="analyst",
            note="Decisione verificata" if status == "resolved" else None,
        )

    sla = derive_ticket_sla(ticket, now=datetime(2026, 8, 10, tzinfo=UTC))

    assert sla["state"] == "stopped"
    assert sla["stopped_at"] == "2026-08-03T12:00:00Z"
    assert sla["stop_reason"] == "closed"
    assert sla["remaining_seconds"] == 24 * 60 * 60


def test_existing_database_sla_migration_is_idempotent(tmp_path) -> None:
    database = tmp_path / "legacy.sqlite3"
    store = TicketStore(database, clock=_fixed_clock)
    store.ingest_signals([_signal()])
    signal_id = store.list_signals()[0]["id"]
    ticket = store.create_ticket_from_signal(signal_id, actor="triage", priority="p2")
    with sqlite3.connect(database) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute("ALTER TABLE tickets DROP COLUMN sla_due_at")
        legacy_row = connection.execute(
            "SELECT * FROM tickets WHERE id = ?", (ticket["id"],)
        ).fetchone()

    assert legacy_row is not None
    assert TicketStore._ticket_from_row(legacy_row)["sla_due_at"] == (
        "2026-08-03T20:00:00Z"
    )

    migrated = TicketStore(database, clock=_fixed_clock)
    migrated_tickets = migrated.list_tickets()
    first_due_at = migrated_tickets[0]["sla_due_at"]
    reopened = TicketStore(database, clock=_fixed_clock)

    assert migrated_tickets[0]["id"] == ticket["id"]
    assert first_due_at == "2026-08-03T20:00:00Z"
    assert reopened.get_ticket(ticket["id"])["sla_due_at"] == first_due_at


def test_ticket_and_initial_checklist_are_one_idempotent_transaction(tmp_path) -> None:
    store, signal_id = _store_with_signal(tmp_path)
    definitions = (
        {"title": "Confermare la sorgente", "description": "Verifica manuale."},
        {"title": "Concordare con OT", "description": "Nessuna azione automatica."},
    )

    ticket, added = store.create_ticket_with_tasks(
        signal_id,
        actor="triage",
        priority="p2",
        owner="team-ot",
        tasks=definitions,
    )
    repeated, repeated_added = store.create_ticket_with_tasks(
        signal_id,
        actor="altro-operatore",
        tasks=definitions,
    )
    exported = store.export_ticket(ticket["id"])

    assert repeated == ticket
    assert added == 2
    assert repeated_added == 0
    assert [task["title"] for task in exported["tasks"]] == [
        "Confermare la sorgente",
        "Concordare con OT",
    ]


def test_ticket_creation_rolls_back_if_initial_checklist_fails(tmp_path) -> None:
    store, signal_id = _store_with_signal(tmp_path)
    with sqlite3.connect(store.database_path) as connection:
        connection.execute(
            """
            CREATE TRIGGER reject_test_task
            BEFORE INSERT ON ticket_tasks
            WHEN NEW.title = 'Rifiuta inserimento'
            BEGIN
                SELECT RAISE(ABORT, 'test task rejected');
            END
            """
        )

    with pytest.raises(sqlite3.IntegrityError, match="test task rejected"):
        store.create_ticket_with_tasks(
            signal_id,
            actor="triage",
            tasks=(
                {"title": "Prima attività"},
                {"title": "Rifiuta inserimento"},
            ),
        )

    assert store.list_tickets() == []
    with sqlite3.connect(store.database_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM ticket_tasks").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0] == 0


def test_lifecycle_rejects_invalid_transitions_and_supports_reopen(tmp_path) -> None:
    store, signal_id = _store_with_signal(tmp_path)
    ticket = store.create_ticket_from_signal(signal_id, actor="analyst")

    with pytest.raises(InvalidTransitionError, match="new -> closed"):
        store.transition_ticket(ticket["id"], "closed", actor="analyst")

    for status in (
        "acknowledged",
        "investigating",
        "remediating",
        "waiting_ot",
        "resolved",
        "closed",
    ):
        ticket = store.transition_ticket(
            ticket["id"],
            status,
            actor="analyst",
            note=f"Passaggio a {status}",
        )

    assert ticket["closed_at"] == "2026-08-03T12:00:00Z"
    reopened = store.transition_ticket(ticket["id"], "investigating", actor="analyst")
    assert reopened["resolved_at"] is None
    assert reopened["closed_at"] is None


@pytest.mark.parametrize("status", ["false_positive", "accepted_risk", "suppressed"])
def test_alternative_terminal_states_are_supported(tmp_path, status: str) -> None:
    store, signal_id = _store_with_signal(tmp_path)
    ticket = store.create_ticket_from_signal(signal_id, actor="analyst")

    terminal = store.transition_ticket(
        ticket["id"],
        status,
        actor="analyst",
        note="Decisione verificata e approvata.",
    )

    assert terminal["status"] == status
    assert terminal["resolved_at"] == "2026-08-03T12:00:00Z"


def test_decision_status_requires_a_note_in_the_backend(tmp_path) -> None:
    store, signal_id = _store_with_signal(tmp_path)
    ticket = store.create_ticket_from_signal(signal_id, actor="analyst")
    store.transition_ticket(ticket["id"], "investigating", actor="analyst")

    with pytest.raises(TicketValidationError, match="nota decisionale"):
        store.transition_ticket(ticket["id"], "resolved", actor="analyst")


def test_governance_update_commits_owner_and_priority_together(tmp_path) -> None:
    store, signal_id = _store_with_signal(tmp_path)
    ticket = store.create_ticket_from_signal(signal_id, actor="triage")

    updated = store.update_ticket_governance(
        ticket["id"],
        owner="team-ot",
        priority="p1",
        actor="triage",
    )
    exported = store.export_ticket(ticket["id"])

    assert updated["owner"] == "team-ot"
    assert updated["priority"] == "p1"
    assert [event["action"] for event in exported["audit"]][-2:] == [
        "ticket.assigned",
        "ticket.priority_changed",
    ]


def test_playbook_task_initialization_is_atomic_and_concurrency_safe(tmp_path) -> None:
    store, signal_id = _store_with_signal(tmp_path)
    database = store.database_path
    ticket = store.create_ticket_from_signal(signal_id, actor="triage")
    tasks = (
        {"title": "Confermare la sorgente", "description": "Verifica manuale."},
        {"title": "Concordare con OT", "description": "Nessuna azione automatica."},
    )
    stores = (store, TicketStore(database, clock=_fixed_clock))

    def initialize(candidate: TicketStore) -> int:
        return candidate.ensure_tasks(
            ticket["id"],
            actor="triage",
            tasks=tasks,
            owner="team-ot",
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        added = list(executor.map(initialize, stores))

    assert sum(added) == 2
    assert len(store.export_ticket(ticket["id"])["tasks"]) == 2


def test_owner_priority_comments_tasks_and_export_are_audited(tmp_path) -> None:
    store, signal_id = _store_with_signal(tmp_path)
    ticket = store.create_ticket_from_signal(signal_id, actor="triage")
    ticket = store.assign_ticket(ticket["id"], "analyst-1", actor="triage")
    ticket = store.set_ticket_priority(ticket["id"], "p1", actor="analyst-1")
    comment = store.add_comment(
        ticket["id"],
        author="analyst-1",
        body="Verificata la provenienza del record Cisco.",
    )
    task = store.add_task(
        ticket["id"],
        actor="analyst-1",
        title="Confermare lo stato del processo",
        description="Contattare il referente OT prima di intervenire.",
        owner="ot-owner",
        due_at="2026-08-03T14:00:00Z",
    )
    completed = store.update_task_status(task["id"], "completed", actor="ot-owner")
    store.transition_ticket(ticket["id"], "acknowledged", actor="analyst-1")

    first_export = store.export_ticket_json(ticket["id"])
    second_export = store.export_ticket_json(ticket["id"])
    exported = json.loads(first_export)

    assert first_export == second_export
    assert first_export.endswith("\n")
    assert exported["schema_version"] == "dtlab-ticket-v1"
    assert exported["ticket"]["owner"] == "analyst-1"
    assert exported["ticket"]["priority"] == "p1"
    assert exported["signal"]["snapshot_sha256"] == "a" * 64
    assert exported["comments"] == [comment]
    assert completed["status"] == "completed"
    assert exported["tasks"][0]["completed_at"] == "2026-08-03T12:00:00Z"
    actions = [event["action"] for event in exported["audit"]]
    assert actions == [
        "ticket.created",
        "ticket.assigned",
        "ticket.priority_changed",
        "ticket.comment_added",
        "ticket.task_added",
        "ticket.task_status_changed",
        "ticket.status_changed",
    ]


def test_audit_table_is_append_only_at_database_level(tmp_path) -> None:
    store, signal_id = _store_with_signal(tmp_path)
    ticket = store.create_ticket_from_signal(signal_id, actor="analyst")

    with sqlite3.connect(store.database_path) as connection:
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute(
                "UPDATE audit_events SET actor = 'tampered' WHERE ticket_id = ?",
                (ticket["id"],),
            )
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute(
                "DELETE FROM audit_events WHERE ticket_id = ?",
                (ticket["id"],),
            )


def test_store_rejects_non_persistent_memory_database() -> None:
    with pytest.raises(TicketValidationError, match="persistente"):
        TicketStore(":memory:")
