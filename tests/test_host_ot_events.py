from __future__ import annotations

import hashlib
import json

import pytest

from dtlab.services.host_ot_events import (
    HOST_OT_SOURCE_ID,
    HostOtEventValidationError,
    canonical_host_ot_event_bytes,
    host_ot_event_sha256,
    ingest_host_ot_event,
    signal_from_host_ot_event,
    validate_host_ot_event,
)
from dtlab.services.ticket_policy import apply_host_ot_ticket_policy
from dtlab.services.ticket_store import SignalInput, TicketStore, TicketValidationError


def _values_sha(values: list[int]) -> str:
    content = json.dumps(values, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(content).hexdigest()


def _write(address: int, value: int, *, count: int = 1) -> dict:
    values = [value]
    return {
        "function_code": 6,
        "address": address,
        "quantity": 1,
        "values": values,
        "values_sha256": _values_sha(values),
        "values_truncated": False,
        "count": count,
    }


def host_event(
    *,
    writes: list[dict] | None = None,
    episode_id: str = "host-modbus:boot-1:episode-1",
    revision: int = 1,
    processed: bool = True,
    source_ip: str = "172.16.10.10",
    source_classification: str = "plc_self",
) -> dict:
    writes = writes or [_write(3, 0)]
    request_count = sum(item["count"] for item in writes)
    shutdown = {
        (item["address"] + offset, value)
        for item in writes
        if not item["values_truncated"]
        for offset, value in enumerate(item["values"])
    }.issuperset({(3, 0), (4, 0), (16, 0)})
    state = "processed" if processed else "unknown"
    truth = "endpoint_server_processed" if processed else "endpoint_request_observed"
    return {
        "schema_version": "dtlab-host-ot-event-v1",
        "event_type": "modbus_write",
        "event_id": episode_id,
        "episode_id": episode_id,
        "revision": revision,
        "episode_sequence": 1,
        "boot_id": "boot-1",
        "first_observed_at": "2026-09-01T10:30:00Z",
        "last_observed_at": f"2026-09-01T10:30:0{revision}Z",
        "timestamp_basis": "endpoint_utc",
        "sensor": {
            "id": "plc-endpoint-sensor",
            "version": "1.0.0",
            "capture_kind": "server_hook" if processed else "packet_capture",
        },
        "source": {
            "ip": source_ip,
            "port": 41000,
            "classification": source_classification,
        },
        "destination": {
            "asset_id": "asset:cybervision:dtlab-01:42",
            "ip": "172.16.10.10",
            "port": 502,
            "unit_id": 1,
        },
        "modbus": {
            "operation": "write",
            "function_codes": [6],
            "writes": writes,
            "request_count": request_count,
            "dropped_operation_buckets": 0,
        },
        "outcome": {
            "states": {
                "processed": request_count if processed else 0,
                "rejected": 0,
                "unknown": 0 if processed else request_count,
            },
            "last_state": state,
        },
        "detection": {
            "rule_id": "plc-self-modbus-write",
            "classification": (
                "process_shutdown_sequence" if shutdown else "modbus_write"
            ),
            "severity": "critical" if shutdown else "high",
            "priority": "p1" if shutdown else "p2",
            "policy_decision": "alert",
            "reason": "Scrittura Modbus verso il servizio PLC locale.",
        },
        "evidence": {
            "truth": truth,
            "source_id": HOST_OT_SOURCE_ID,
            "source_record_id": episode_id,
            "notes": ["Evento autenticato dal receiver prima della validazione contenuto."],
        },
        "process": {
            "pid": 123,
            "executable": "python_2",
            "script": "attack_shutdown.py",
        },
    }


def heartbeat_event() -> dict:
    episode_id = "host-heartbeat:boot-1:1"
    return {
        "schema_version": "dtlab-host-ot-event-v1",
        "event_type": "heartbeat",
        "event_id": episode_id,
        "episode_id": episode_id,
        "revision": 1,
        "episode_sequence": 0,
        "boot_id": "boot-1",
        "first_observed_at": "2026-09-01T10:30:00Z",
        "last_observed_at": "2026-09-01T10:30:00Z",
        "timestamp_basis": "endpoint_utc",
        "sensor": {
            "id": "plc-endpoint-sensor",
            "version": "1.0.0",
            "capture_kind": "server_hook",
        },
        "source": {
            "ip": "172.16.10.10",
            "port": None,
            "classification": "plc_self",
        },
        "destination": None,
        "modbus": None,
        "outcome": None,
        "detection": None,
        "evidence": {
            "truth": "endpoint_heartbeat",
            "source_id": HOST_OT_SOURCE_ID,
            "source_record_id": episode_id,
            "notes": ["Heartbeat autenticato."],
        },
        "process": None,
    }


def test_valid_event_has_deterministic_document_sha_and_fixed_non_cisco_source() -> None:
    event = host_event()

    assert validate_host_ot_event(event) is event
    digest, signal = signal_from_host_ot_event(event)

    assert digest == host_ot_event_sha256(event)
    assert hashlib.sha256(canonical_host_ot_event_bytes(event)).hexdigest() == digest
    assert signal is not None
    assert signal.evidence["source_id"] == HOST_OT_SOURCE_ID
    assert "cisco" not in signal.evidence["source_id"]
    assert signal.evidence["source_record_id"] == event["episode_id"]
    assert signal.signal_type == "host_modbus_write"
    assert signal.severity == "high"
    assert signal.asset_ids == ("asset:cybervision:dtlab-01:42",)
    assert any("non restituita da Cisco" in note for note in signal.evidence["notes"])


@pytest.mark.parametrize(
    ("source_ip", "classification", "expected_label", "unexpected_label"),
    [
        ("172.16.10.10", "plc_self", "PLC→PLC", "Kali/test"),
        ("172.16.10.30", "security_test", "Kali/test di sicurezza→PLC", "PLC→PLC"),
        ("172.16.10.20", "authorized_hmi", "HMI autorizzata→PLC", "PLC→PLC"),
        ("172.16.10.99", "unknown", "sorgente sconosciuta→PLC", "PLC→PLC"),
    ],
)
def test_signal_names_the_actual_source_path(
    source_ip: str,
    classification: str,
    expected_label: str,
    unexpected_label: str,
) -> None:
    event = host_event(
        source_ip=source_ip,
        source_classification=classification,
    )

    _, signal = signal_from_host_ot_event(event)

    assert signal is not None
    assert expected_label in signal.title
    assert expected_label in signal.description
    assert unexpected_label not in signal.title
    assert source_ip in signal.description


def test_equal_source_and_destination_ip_is_reported_as_plc_self_path() -> None:
    event = host_event(source_classification="unknown")

    _, signal = signal_from_host_ot_event(event)

    assert signal is not None
    assert "PLC→PLC" in signal.title


def test_standalone_ingest_is_idempotent_and_creates_one_p2_ticket(tmp_path) -> None:
    store = TicketStore(tmp_path / "tickets.sqlite3")
    event = host_event()

    first = ingest_host_ot_event(store, event)
    second = ingest_host_ot_event(store, event, document_sha256=first.document_sha256)

    assert first.signals_created == 1
    assert first.occurrences_created == 1
    assert first.ticket_created is True
    assert first.tasks_added == 4
    assert second.signals_created == 0
    assert second.occurrences_created == 0
    assert second.ticket_created is False
    assert second.tasks_added == 0
    assert first.signal_id == second.signal_id
    assert first.ticket_id == second.ticket_id
    ticket = store.get_ticket(str(first.ticket_id))
    assert ticket["priority"] == "p2"
    assert len(store.export_ticket(str(first.ticket_id))["tasks"]) == 4


def test_same_episode_shutdown_revision_updates_signal_and_escalates_ticket(tmp_path) -> None:
    store = TicketStore(tmp_path / "tickets.sqlite3")
    initial = ingest_host_ot_event(store, host_event())
    shutdown = host_event(
        writes=[_write(3, 0), _write(4, 0), _write(16, 0)],
        revision=2,
    )

    updated = ingest_host_ot_event(store, shutdown)

    assert updated.signal_id == initial.signal_id
    assert updated.ticket_id == initial.ticket_id
    assert updated.signals_created == 0
    assert updated.occurrences_created == 1
    assert updated.ticket_escalated is True
    signal = store.get_signal(str(updated.signal_id))
    ticket = store.get_ticket(str(updated.ticket_id))
    assert signal["severity"] == "critical"
    assert signal["occurrence_count"] == 2
    assert signal["payload"]["event"]["detection"]["classification"] == (
        "process_shutdown_sequence"
    )
    assert ticket["priority"] == "p1"
    assert any(
        item["action"] == "ticket.priority_changed"
        for item in store.export_ticket(str(updated.ticket_id))["audit"]
    )


def test_stale_or_conflicting_episode_revision_is_rejected(tmp_path) -> None:
    store = TicketStore(tmp_path / "tickets.sqlite3")
    current = host_event(
        writes=[_write(3, 0), _write(4, 0), _write(16, 0)],
        revision=2,
    )
    ingest_host_ot_event(store, current)

    with pytest.raises(HostOtEventValidationError, match="precedente"):
        ingest_host_ot_event(store, host_event(revision=1))

    conflict = host_event(
        writes=[_write(3, 1)],
        revision=2,
    )
    with pytest.raises(HostOtEventValidationError, match="documento diverso"):
        ingest_host_ot_event(store, conflict)


def test_new_episode_creates_a_new_signal_and_ticket(tmp_path) -> None:
    store = TicketStore(tmp_path / "tickets.sqlite3")
    first = ingest_host_ot_event(store, host_event())
    second = ingest_host_ot_event(
        store,
        host_event(episode_id="host-modbus:boot-1:episode-2"),
    )

    assert first.signal_id != second.signal_id
    assert first.ticket_id != second.ticket_id
    assert len(store.list_signals(signal_type="host_modbus_write")) == 2
    assert len(store.list_tickets()) == 2


def test_heartbeat_is_validated_and_hashed_without_signal_or_ticket(tmp_path) -> None:
    store = TicketStore(tmp_path / "tickets.sqlite3")

    result = ingest_host_ot_event(store, heartbeat_event())

    assert result.event_type == "heartbeat"
    assert result.signal_id is None
    assert result.ticket_id is None
    assert result.signals_seen == 0
    assert store.list_signals() == []
    assert store.list_tickets() == []


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (
            lambda item: item["evidence"].update(
                {"source_id": "src:cisco-cyber-vision:dtlab-01"}
            ),
            "source_id",
        ),
        (
            lambda item: item.update({"episode_id": "different-episode"}),
            "episode_id",
        ),
        (
            lambda item: item["detection"].update({"priority": "p1"}),
            "detection.priority",
        ),
        (
            lambda item: item["modbus"].update({"request_count": 99}),
            "request_count",
        ),
        (
            lambda item: item.update({"unexpected": True}),
            "unexpected",
        ),
    ],
)
def test_invalid_or_spoofed_events_fail_closed(mutation, message: str) -> None:
    event = host_event()
    mutation(event)

    with pytest.raises(HostOtEventValidationError, match=message):
        validate_host_ot_event(event)


def test_document_sha_mismatch_is_rejected() -> None:
    with pytest.raises(HostOtEventValidationError, match="non corrisponde"):
        signal_from_host_ot_event(host_event(), document_sha256="0" * 64)


def test_ticket_policy_rejects_non_host_signal(tmp_path) -> None:
    store = TicketStore(tmp_path / "tickets.sqlite3")
    fingerprint = hashlib.sha256(b"ordinary-event").hexdigest()
    store.ingest_signals(
        [
            SignalInput(
                fingerprint=fingerprint,
                signal_type="event",
                snapshot_sha256="a" * 64,
                evidence={
                    "source_id": "src:cisco-cyber-vision:dtlab-01",
                    "source_record_id": "event-1",
                },
                severity="high",
                title="Evento Cisco",
                description="Evento ordinario",
                occurred_at="2026-09-01T10:30:00Z",
                observed_at="2026-09-01T10:30:00Z",
                asset_ids=(),
                recommended_action=None,
                payload={},
            )
        ]
    )

    with pytest.raises(TicketValidationError, match="solo segnali endpoint"):
        apply_host_ot_ticket_policy(store, f"signal:{fingerprint}")
