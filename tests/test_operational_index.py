from __future__ import annotations

from datetime import UTC, datetime

from dtlab.ui.operational_index import asset_workflow_records, build_operational_index

NOW = datetime(2026, 8, 3, 20, 0, tzinfo=UTC)


def _signal(
    signal_id: str,
    *,
    severity: str = "medium",
    asset_ids: list[str] | None = None,
) -> dict:
    return {
        "id": signal_id,
        "signal_type": "event",
        "severity": severity,
        "title": f"Signal {signal_id}",
        "description": "Evidenza sorgente",
        "recommended_action": "Verificare manualmente.",
        "asset_ids": asset_ids or [],
        "payload": {},
        "occurrence_count": 1,
        "last_observed_at": "2026-08-03T19:00:00Z",
        "updated_at": "2026-08-03T19:00:00Z",
    }


def _ticket(
    ticket_id: str,
    signal_id: str,
    *,
    priority: str,
    created_at: str,
    owner: str | None = "SOC DTLab",
) -> dict:
    return {
        "id": ticket_id,
        "signal_id": signal_id,
        "title": f"Ticket {ticket_id}",
        "description": "Analisi manuale",
        "status": "investigating",
        "priority": priority,
        "owner": owner,
        "created_by": "analista",
        "created_at": created_at,
        "updated_at": created_at,
        "sla_due_at": None,
        "resolved_at": None,
        "closed_at": None,
    }


def test_operational_index_is_ticket_first_and_sla_aware() -> None:
    signals = [
        _signal("signal:overdue", severity="medium"),
        _signal("signal:due-soon", severity="low"),
        _signal("signal:critical", severity="critical"),
    ]
    tickets = [
        _ticket(
            "ticket:overdue",
            "signal:overdue",
            priority="p1",
            created_at="2026-08-03T12:00:00Z",
        ),
        _ticket(
            "ticket:due-soon",
            "signal:due-soon",
            priority="p2",
            created_at="2026-08-03T13:00:00Z",
        ),
    ]

    result = build_operational_index(signals, tickets, now=NOW)

    assert [item["signal_id"] for item in result["queue"]] == [
        "signal:overdue",
        "signal:due-soon",
        "signal:critical",
    ]
    assert result["queue"][0]["sla_state"] == "overdue"
    assert result["queue"][1]["sla_state"] == "due_soon"
    assert result["summary"] == {
        "unassigned": 1,
        "without_ticket": 1,
        "resurfaced": 0,
        "active": 2,
        "high_priority": 2,
        "unowned": 0,
        "sla_overdue": 1,
        "sla_due_soon": 1,
        "queue_total": 3,
        "truncated": 0,
    }


def test_asset_workflow_records_never_infers_by_title_or_description() -> None:
    explicit = _signal("signal:explicit", asset_ids=["asset:1"])
    misleading = _signal("signal:name-only")
    misleading["title"] = "Problema su asset:1"
    tickets = [
        _ticket(
            "ticket:explicit",
            "signal:explicit",
            priority="p3",
            created_at="2026-08-03T18:00:00Z",
        ),
        _ticket(
            "ticket:name-only",
            "signal:name-only",
            priority="p3",
            created_at="2026-08-03T18:00:00Z",
        ),
    ]
    index = build_operational_index([explicit, misleading], tickets, now=NOW)

    signals, linked_tickets = asset_workflow_records(index, asset_id="asset:1")

    assert [signal["id"] for signal in signals] == ["signal:explicit"]
    assert [ticket["id"] for ticket in linked_tickets] == ["ticket:explicit"]


def test_active_ticket_survives_when_the_source_condition_becomes_non_actionable() -> None:
    resolved = _signal("signal:resolved", asset_ids=["asset:1"])
    resolved["signal_type"] = "finding"
    resolved["payload"] = {"status": "resolved", "exclude_from_operational_kpis": False}
    active_ticket = _ticket(
        "ticket:still-open",
        "signal:resolved",
        priority="p2",
        created_at="2026-08-03T18:00:00Z",
    )

    index = build_operational_index([resolved], [active_ticket], now=NOW)
    signals, tickets = asset_workflow_records(index, asset_id="asset:1")

    assert [item["signal_id"] for item in index["queue"]] == ["signal:resolved"]
    assert index["summary"]["unassigned"] == 0
    assert [signal["id"] for signal in signals] == ["signal:resolved"]
    assert [ticket["id"] for ticket in tickets] == ["ticket:still-open"]


def test_asset_workflow_preserves_closed_history_without_putting_it_back_in_queue() -> None:
    resolved = _signal("signal:closed", asset_ids=["asset:1"])
    resolved["signal_type"] = "finding"
    resolved["payload"] = {"status": "resolved", "exclude_from_operational_kpis": False}
    closed_ticket = _ticket(
        "ticket:closed",
        "signal:closed",
        priority="p3",
        created_at="2026-08-03T12:00:00Z",
    )
    closed_ticket.update(
        {
            "status": "closed",
            "updated_at": "2026-08-03T16:00:00Z",
            "closed_at": "2026-08-03T16:00:00Z",
        }
    )

    index = build_operational_index([resolved], [closed_ticket], now=NOW)
    signals, tickets = asset_workflow_records(index, asset_id="asset:1")

    assert index["queue"] == []
    assert [signal["id"] for signal in signals] == ["signal:closed"]
    assert [ticket["id"] for ticket in tickets] == ["ticket:closed"]


def test_operational_index_rejects_a_naive_sla_clock() -> None:
    try:
        build_operational_index([], [], now=datetime(2026, 8, 3, 20, 0))
    except ValueError as exc:
        assert "fuso orario" in str(exc)
    else:
        raise AssertionError("Un clock naive deve essere rifiutato")
