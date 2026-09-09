from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from types import SimpleNamespace

from streamlit.testing.v1 import AppTest

from dtlab.contract import snapshot_sha256
from dtlab.services.ticket_store import SignalInput, TicketStore
from dtlab.ui.views import operations
from dtlab.ui.views.operations import (
    _current_evidence_record_id,
    _ensure_playbook_tasks,
    _filter_signals,
    _filter_tickets,
    _format_duration,
    _priority_for_severity,
    _requires_transition_note,
    _signal_sort_key,
    _sla_remaining_label,
    _source_owned_signal_evidence_json,
    _ticket_register_rows,
    default_ticket_store_path,
    get_ticket_store,
    signal_is_actionable,
    signal_needs_review,
    sync_ticket_store,
)
from tests.factories import valid_snapshot


def _signal_input(*, signal_type: str = "event") -> SignalInput:
    return SignalInput(
        fingerprint=hashlib.sha256(f"operation-{signal_type}".encode()).hexdigest(),
        signal_type=signal_type,
        snapshot_sha256="a" * 64,
        evidence={
            "source_id": "src:cisco-cyber-vision:test",
            "source_record_id": "event:source:1",
            "truth": "real",
        },
        severity="high",
        title="Comando Modbus inatteso",
        description="Evento OT restituito dalla sorgente.",
        occurred_at="2026-08-03T10:00:00Z",
        observed_at="2026-08-03T10:00:00Z",
        asset_ids=("asset:plc:1",),
        recommended_action=None,
        payload={"id": "event:test:1", "title": "Comando Modbus inatteso"},
    )


def _render_ticket_tasks_for_test(database_path: str, ticket_id: str) -> None:
    from dtlab.services.ticket_store import TicketStore
    from dtlab.ui.views.operations import _render_ticket_tasks

    store = TicketStore(database_path)
    _render_ticket_tasks(store, store.export_ticket(ticket_id), "analista collaudo")


def test_ticket_store_path_is_configurable_and_shared(tmp_path, monkeypatch) -> None:
    configured = tmp_path / "operational" / "tickets.sqlite3"
    monkeypatch.setenv("DTLAB_TICKET_STORE", str(configured))

    first = get_ticket_store()
    second = get_ticket_store(configured)

    assert default_ticket_store_path() == configured.resolve()
    assert first is second
    assert first.database_path == configured.resolve()


def test_public_sync_helper_ingests_only_the_verified_canonical_snapshot(
    tmp_path, monkeypatch
) -> None:
    configured = tmp_path / "sync" / "tickets.sqlite3"
    monkeypatch.setenv("DTLAB_TICKET_STORE", str(configured))
    snapshot = valid_snapshot()
    digest = snapshot_sha256(snapshot)
    context = SimpleNamespace(
        canonical_snapshot=snapshot,
        manifest={"sha256": digest},
    )

    store, result = sync_ticket_store(context)

    assert store.database_path == configured.resolve()
    assert result.snapshot_sha256 == digest
    assert result.signals_seen == 0
    assert store.list_signals() == []


def test_signal_and_ticket_filters_search_operational_fields(tmp_path) -> None:
    store = TicketStore(tmp_path / "tickets.sqlite3")
    store.ingest_signals([_signal_input()])
    signal = store.list_signals()[0]
    ticket = store.create_ticket_from_signal(
        signal["id"], actor="analista", priority="p2", owner="team-ot"
    )

    assert _filter_signals([signal], search="PLC:1") == [signal]
    assert (
        _filter_signals(
            [signal],
            without_ticket=True,
            ticket_signal_ids=frozenset({signal["id"]}),
        )
        == []
    )
    assert _filter_tickets(
        [ticket],
        search="team-ot",
        statuses=["new"],
        priorities=["p2"],
        signals_by_id={signal["id"]: signal},
    ) == [ticket]
    assert _filter_tickets([ticket], owners=["altro-team"]) == []


def test_ticket_filter_and_labels_expose_derived_sla_state(tmp_path) -> None:
    store = TicketStore(
        tmp_path / "tickets.sqlite3",
        clock=lambda: datetime(2026, 8, 3, 12, 0, tzinfo=UTC),
    )
    store.ingest_signals([_signal_input()])
    signal = store.list_signals()[0]
    ticket = store.create_ticket_from_signal(
        signal["id"], actor="analista", priority="p1"
    )
    evaluated_at = datetime(2026, 8, 3, 15, 30, tzinfo=UTC)

    assert _filter_tickets(
        [ticket], sla_states=["due_soon"], now=evaluated_at
    ) == [ticket]
    assert _filter_tickets(
        [ticket], sla_states=["overdue"], now=evaluated_at
    ) == []
    assert _format_duration(90 * 60) == "1 h 30 min"
    assert _sla_remaining_label(
        {"state": "due_soon", "remaining_seconds": 30 * 60}
    ) == "Restano 30 min"
    assert _sla_remaining_label(
        {"state": "overdue", "remaining_seconds": -(2 * 60 * 60)}
    ) == "Scaduto da 2 h"


def test_ticket_register_row_accepts_pre_migration_session_record_without_due_at() -> None:
    legacy_ticket = {
        "id": "ticket:legacy",
        "signal_id": "signal:legacy",
        "title": "Ticket creato prima dello SLA",
        "status": "investigating",
        "priority": "p2",
        "owner": None,
        "created_at": "2026-08-03T12:00:00Z",
        "updated_at": "2026-08-03T12:30:00Z",
        "resolved_at": None,
        "closed_at": None,
    }
    evaluated_at = datetime(2026, 8, 3, 18, 30, tzinfo=UTC)
    sla = operations.derive_ticket_sla(legacy_ticket, now=evaluated_at)

    rows = _ticket_register_rows(
        [legacy_ticket],
        sla_by_ticket_id={"ticket:legacy": sla},
        signals_by_id={"signal:legacy": {"signal_type": "event"}},
        resurfaced_ids=set(),
    )

    assert rows == [
        {
            "Priorità": "P2",
            "Stato": "In analisi",
            "Titolo": "Ticket creato prima dello SLA",
            "Owner": "Non assegnato",
            "SLA": "In scadenza",
            "Tempo SLA": "Restano 1 h 30 min",
            "Deadline SLA": "03/08/2026 · 22:00:00",
            "Aggiornato": "03/08/2026 · 14:30:00",
            "Riemerso": "No",
            "Tipo segnale": "Evento Cisco",
        }
    ]


def test_historical_findings_remain_searchable_but_leave_the_default_inbox() -> None:
    historical = {
        "id": "signal:historical",
        "signal_type": "finding",
        "severity": "info",
        "title": "PLC legacy mantenuta intenzionalmente",
        "description": "Eccezione confermata.",
        "payload": {
            "status": "accepted",
            "exclude_from_operational_kpis": True,
        },
        "asset_ids": [],
    }

    assert not signal_is_actionable(historical)
    assert _filter_signals([historical], include_historical=False) == []
    assert _filter_signals([historical], include_historical=True) == [historical]


def test_new_ui_alert_status_controls_default_inbox_without_hiding_unknowns() -> None:
    active = {"signal_type": "new_ui_alert", "payload": {"status": "Active"}}
    cleared = {"signal_type": "new_ui_alert", "payload": {"status": "Cleared"}}
    muted = {"signal_type": "new_ui_alert", "payload": {"status": "Muted"}}
    unknown = {"signal_type": "new_ui_alert", "payload": {"status": None}}

    assert signal_is_actionable(active)
    assert not signal_is_actionable(cleared)
    assert not signal_is_actionable(muted)
    assert signal_is_actionable(unknown)
    assert _filter_signals([active, cleared, muted], include_historical=False) == [active]


def test_new_ui_evidence_json_is_source_owned_and_has_no_inferred_collection() -> None:
    signal = {
        "id": "signal:new-ui-alert",
        "signal_type": "new_ui_alert",
        "snapshot_sha256": "a" * 64,
        "source_id": "src:cisco-cyber-vision-new-ui:dtlab-01",
        "source_record_id": "new-ui-alert:profile-1:instance-1",
        "asset_ids": ["profile-1"],
        "occurred_at": "2026-08-03T09:58:00Z",
        "last_observed_at": "2026-08-03T10:00:00Z",
        "evidence": {"truth": "real"},
        "payload": {
            "asset_id": "profile-1",
            "status": "Active",
            "alert": {"instance_id": "instance-1"},
        },
    }

    exported = json.loads(_source_owned_signal_evidence_json(signal))

    assert exported["payload"] == signal["payload"]
    assert exported["correlation_policy"] == "source_owned_only_no_classic_inference"


def test_host_modbus_evidence_json_never_claims_cisco_attribution() -> None:
    signal = {
        "id": "signal:host-modbus:test",
        "signal_type": "host_modbus_write",
        "snapshot_sha256": "b" * 64,
        "source_id": "src:dtlab-host-ot:plc-desktop",
        "source_record_id": "host-modbus:boot-1:episode-7",
        "asset_ids": ["asset:plc:1"],
        "occurred_at": "2026-09-01T10:40:00Z",
        "last_observed_at": "2026-09-01T10:40:02Z",
        "evidence": {"truth": "endpoint_server_processed"},
        "payload": {
            "source_ip": "172.16.10.10",
            "destination_ip": "172.16.10.10",
            "function_code": 6,
        },
    }

    exported = json.loads(_source_owned_signal_evidence_json(signal))

    assert exported["correlation_policy"] == "host_sensor_only_no_cisco_attribution"
    assert exported["source_id"] == "src:dtlab-host-ot:plc-desktop"
    assert exported["signal_type"] == "host_modbus_write"
    assert "related_flows" not in exported
    assert "classic_assets" not in exported


def test_signal_sort_is_severity_first_then_most_recent() -> None:
    signals = [
        {"severity": "high", "last_observed_at": "2026-08-03T09:00:00Z"},
        {"severity": "medium", "last_observed_at": "2026-08-03T12:00:00Z"},
        {"severity": "high", "last_observed_at": "2026-08-03T11:00:00Z"},
    ]

    signals.sort(key=_signal_sort_key)

    assert [signal["last_observed_at"] for signal in signals] == [
        "2026-08-03T11:00:00Z",
        "2026-08-03T09:00:00Z",
        "2026-08-03T12:00:00Z",
    ]


def test_terminal_ticket_resurfaces_only_for_semantic_condition_change() -> None:
    signal = {
        "signal_type": "vulnerability",
        "updated_at": "2026-08-03T12:00:00Z",
    }
    terminal = {
        "status": "closed",
        "resolved_at": "2026-08-03T10:00:00Z",
        "closed_at": "2026-08-03T11:00:00Z",
    }

    assert signal_needs_review(signal, None)
    assert signal_needs_review(signal, terminal)
    terminal["closed_at"] = "2026-08-03T13:00:00Z"
    assert not signal_needs_review(signal, terminal)
    assert not signal_needs_review(signal, {"status": "investigating"})


def test_cached_point_event_never_resurfaces_after_terminal_decision() -> None:
    event = {
        "signal_type": "event",
        "updated_at": "2026-08-03T14:00:00Z",
        "last_observed_at": "2026-08-03T14:00:00Z",
    }
    terminal = {
        "status": "closed",
        "resolved_at": "2026-08-03T10:00:00Z",
        "closed_at": "2026-08-03T11:00:00Z",
    }

    assert not signal_needs_review(event, terminal)


def test_playbook_is_manual_first_and_added_only_once(tmp_path) -> None:
    store = TicketStore(tmp_path / "tickets.sqlite3")
    store.ingest_signals([_signal_input(signal_type="vulnerability")])
    signal = store.list_signals()[0]
    ticket = store.create_ticket_from_signal(signal["id"], actor="analista")

    first_added = _ensure_playbook_tasks(
        store,
        ticket_id=ticket["id"],
        signal_type="vulnerability",
        actor="analista",
        owner="team-ot",
    )
    second_added = _ensure_playbook_tasks(
        store,
        ticket_id=ticket["id"],
        signal_type="vulnerability",
        actor="analista",
        owner="team-ot",
    )
    tasks = store.export_ticket(ticket["id"])["tasks"]

    assert first_added == 4
    assert second_added == 0
    assert len(tasks) == 4
    assert all(task["status"] == "pending" for task in tasks)
    assert any("finestra di change" in (task["description"] or "") for task in tasks)


def test_checklist_status_can_change_inside_the_streamlit_form(tmp_path) -> None:
    database_path = tmp_path / "tickets.sqlite3"
    store = TicketStore(database_path)
    store.ingest_signals([_signal_input()])
    signal = store.list_signals()[0]
    ticket = store.create_ticket_from_signal(signal["id"], actor="analista")
    _ensure_playbook_tasks(
        store,
        ticket_id=ticket["id"],
        signal_type=signal["signal_type"],
        actor="analista",
        owner=None,
    )

    app = AppTest.from_function(
        _render_ticket_tasks_for_test,
        args=(str(database_path), ticket["id"]),
        default_timeout=20,
    ).run(timeout=20)

    first_update = next(
        button for button in app.button if button.label == "Aggiorna attività"
    )
    assert not first_update.disabled
    app.selectbox[0].set_value("completed")
    first_update.click().run(timeout=20)

    refreshed = TicketStore(database_path).export_ticket(ticket["id"])
    assert refreshed["tasks"][0]["status"] == "completed"


def test_evidence_download_requires_exact_current_record_identity() -> None:
    snapshot = {
        "events": [{"id": "event:test:1"}],
        "findings": [{"id": "finding:test:1"}],
    }
    event_signal = {
        "signal_type": "event",
        "payload": {"id": "event:test:1"},
    }

    assert _current_evidence_record_id(snapshot, event_signal) == "event:test:1"
    event_signal["payload"]["id"] = "event:old:1"
    assert _current_evidence_record_id(snapshot, event_signal) is None
    assert (
        _current_evidence_record_id(
            snapshot,
            {"signal_type": "vulnerability", "payload": {"id": "cve:1"}},
        )
        is None
    )


def test_ui_lifecycle_matches_store_and_requires_decision_notes() -> None:
    assert set(operations._ALLOWED_TRANSITIONS) == set(operations.TICKET_STATUSES)
    assert all(
        set(targets) <= set(operations.TICKET_STATUSES)
        for targets in operations._ALLOWED_TRANSITIONS.values()
    )
    assert _priority_for_severity("critical") == "p1"
    assert _priority_for_severity("high") == "p2"
    assert _priority_for_severity("unknown") == "p3"
    assert _requires_transition_note("resolved")
    assert _requires_transition_note("accepted_risk")
    assert not _requires_transition_note("investigating")
