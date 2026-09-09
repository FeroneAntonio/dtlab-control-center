from datetime import UTC, datetime

import pytest

from dtlab.services.operational_settings import (
    BusinessHoursPolicy,
    OperationalSettingsStore,
    add_business_hours,
    is_business_open,
)
from dtlab.services.ticket_store import SignalInput, TicketStore


def test_business_hours_skip_nights_and_weekends() -> None:
    policy = BusinessHoursPolicy()
    # Friday 17:00 Europe/Rome + 4 working hours -> Monday 12:00 Europe/Rome.
    anchor = datetime(2026, 9, 4, 15, 0, tzinfo=UTC)
    due = add_business_hours(anchor, 4, policy)

    assert due == datetime(2026, 9, 7, 10, 0, tzinfo=UTC)
    assert is_business_open(datetime(2026, 9, 7, 8, 30, tzinfo=UTC), policy)
    assert not is_business_open(datetime(2026, 9, 6, 8, 30, tzinfo=UTC), policy)


def test_settings_and_operator_registry_are_persistent(tmp_path) -> None:
    database = tmp_path / "tickets.sqlite3"
    store = OperationalSettingsStore(database)
    policy = BusinessHoursPolicy(start="08:30", end="17:30", weekdays=(0, 1, 2, 3, 4))
    store.set_business_hours(policy, actor="responsabile")
    store.set_syslog(
        {
            "enabled": True,
            "host": "siem.example.test",
            "port": 6514,
            "protocol": "TCP+TLS",
        },
        actor="responsabile",
    )
    store.save_operator("Mario Rossi", "Operatore OT")

    reopened = OperationalSettingsStore(database)
    assert reopened.get_business_hours() == policy
    assert reopened.get_syslog()["host"] == "siem.example.test"
    assert any(item["display_name"] == "Mario Rossi" for item in reopened.list_operators())


def test_syslog_cannot_be_enabled_without_receiver(tmp_path) -> None:
    store = OperationalSettingsStore(tmp_path / "tickets.sqlite3")
    with pytest.raises(ValueError, match="receiver"):
        store.set_syslog({"enabled": True, "host": ""}, actor="admin")


def test_ticket_store_uses_persisted_business_calendar_when_enabled(tmp_path) -> None:
    database = tmp_path / "tickets.sqlite3"
    OperationalSettingsStore(database).set_business_hours(
        BusinessHoursPolicy(), actor="admin"
    )
    def clock() -> datetime:
        return datetime(2026, 9, 4, 15, 0, tzinfo=UTC)

    store = TicketStore(database, clock=clock, use_operational_settings=True)
    signal = SignalInput(
        fingerprint="a" * 64,
        signal_type="event",
        snapshot_sha256="b" * 64,
        evidence={},
        severity="critical",
        title="Test",
        description="Test",
        occurred_at="2026-09-04T15:00:00Z",
        observed_at="2026-09-04T15:00:00Z",
        asset_ids=(),
        recommended_action=None,
        payload={"test": True},
    )
    store.ingest_signals([signal])
    ticket = store.create_ticket_from_signal(
        store.list_signals()[0]["id"], actor="Operatore DTLab", priority="p1"
    )

    assert ticket["sla_due_at"] == "2026-09-07T10:00:00Z"

    # These operations run inside write transactions and must reuse the policy
    # loaded before SQLite is locked by the ticket update.
    assert store.recalculate_open_sla_deadlines(actor="admin") == 0
    updated = store.set_ticket_priority(ticket["id"], "p2", actor="admin")
    assert updated["sla_due_at"] == "2026-09-07T14:00:00Z"
