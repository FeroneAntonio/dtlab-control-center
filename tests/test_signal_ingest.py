from __future__ import annotations

import sqlite3
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from datetime import UTC, datetime

import pytest

from dtlab.contract import snapshot_sha256
from dtlab.services.signal_ingest import ingest_snapshot, signals_from_snapshot
from dtlab.services.ticket_store import TicketStore
from tests.factories import FETCHED_AT, add_cisco_asset, evidence, source, valid_snapshot


def _snapshot_with_supported_signals() -> dict:
    snapshot = valid_snapshot()
    asset_id = add_cisco_asset(snapshot)
    cv_id = "src:cisco-cyber-vision:dtlab-01"
    vm_id = snapshot["virtual_machines"][0]["id"]
    baseline_id = "baseline:cybervision:dtlab-01:normal"
    snapshot["events"].append(
        {
            "id": "event:cybervision:dtlab-01:event-1",
            "evidence": evidence(cv_id, "real", "dashboard-event:event-1"),
            "occurred_at": FETCHED_AT,
            "severity": "high",
            "category": "Anomaly Detection",
            "title": "Baseline changed",
            "description": "Cisco ha rilevato una variazione della baseline.",
            "center_id": "center-1",
            "center_label": "DTLab Center",
            "status": None,
            # The ingest layer must not infer an asset from title or timing.
            "asset_ids": [],
            "acknowledged": None,
        }
    )
    snapshot["findings"].append(
        {
            "id": "finding:vmware:guest-telemetry",
            "evidence": evidence(
                "src:vmware-esxi:dtlab-01",
                "observed",
                "finding:guest-telemetry",
            ),
            "code": "guest_telemetry_unavailable",
            "severity": "medium",
            "title": "Telemetria guest non disponibile",
            "description": "VMware Tools non espone la telemetria guest.",
            "status": "open",
            "entity_ids": [vm_id],
            "first_detected_at": FETCHED_AT,
            "last_detected_at": FETCHED_AT,
            "recommended_action": "Verificare VMware Tools in finestra autorizzata.",
            "exclude_from_operational_kpis": True,
        }
    )
    snapshot["baselines"].append(
        {
            "id": baseline_id,
            "evidence": evidence(cv_id, "real", "baseline:normal"),
            "name": "Traffico normale",
            "description": "Baseline approvata",
            "status": "active",
            "created_at": FETCHED_AT,
            "creation_period_start": "2026-08-02T10:00:02Z",
            "creation_period_end": FETCHED_AT,
            "last_scan_at": FETCHED_AT,
            "next_scan_at": None,
            "difference_counts": {
                "new_component": 0,
                "changed_component": 0,
                "new_activity": 1,
                "changed_activity": 0,
            },
        }
    )
    snapshot["baseline_differences"].append(
        {
            "id": "baseline-difference:cybervision:normal:1",
            "evidence": evidence(cv_id, "real", "baseline:normal:difference:1"),
            "baseline_id": baseline_id,
            "difference_type": "new_activity",
            "target_id": "activity:1",
            "key": "protocol",
            "value": "Modbus",
            "asset_ids": [asset_id],
            "flow_id": None,
            "detected_at": FETCHED_AT,
            "description": "Nuova attività Modbus osservata.",
        }
    )
    snapshot["vulnerabilities"].append(
        {
            "id": "vulnerability:cybervision:dtlab-01:42:cve-2026-0001",
            "evidence": evidence(
                cv_id,
                "real",
                "device:42:vulnerability:cve-2026-0001",
            ),
            "asset_id": asset_id,
            "external_id": "CVE-2026-0001",
            "title": "Vulnerabilità firmware PLC",
            "severity": "critical",
            "cvss_score": 9.8,
            "status": "open",
            "published_at": "2026-08-01T10:00:00Z",
            "details": {
                "summary": "Vulnerabilità associata al firmware osservato.",
                "solution": "Applicare la mitigazione approvata dal referente OT.",
                "matching_at": FETCHED_AT,
            },
        }
    )
    return snapshot


def _fixed_clock() -> datetime:
    return datetime(2026, 8, 3, 12, 0, tzinfo=UTC)


def _snapshot_with_new_ui_signals() -> dict:
    snapshot = valid_snapshot()
    source_id = "src:cisco-cyber-vision-new-ui:dtlab-01"
    new_ui_source = source(
        source_id,
        "Cisco Cyber Vision · New UI",
        "cisco_cyber_vision_new_ui",
        "connected",
        "real",
    )
    new_ui_source["details"] = {
        "center_id": "center-1",
        "alert_assets": [
            {
                "asset_id": "new-ui-profile-1",
                "asset_name": "PLC profile",
                "query_status": "Active",
                "alerts": [
                    {
                        "alert_id": "alert-1",
                        "instance_id": "instance-1",
                        "alert_type": "Communication",
                        "category": "Security",
                        "last_occurrence": "2026-08-03T09:58:00Z",
                        "severity": "high",
                        "trigger": "New peer",
                        "status": "Active",
                    }
                ],
            },
            # Independent status queries can overlap briefly.  This duplicate
            # must not hide the same live instance as historical.
            {
                "asset_id": "new-ui-profile-1",
                "asset_name": "PLC profile",
                "query_status": "Cleared",
                "alerts": [
                    {
                        "alert_id": "alert-1",
                        "instance_id": "instance-1",
                        "alert_type": "Communication",
                        "category": "Security",
                        "last_occurrence": "2026-08-03T09:58:00Z",
                        "severity": "high",
                        "trigger": "New peer",
                        "status": "Cleared",
                    },
                    {
                        "alert_id": "alert-2",
                        "instance_id": "instance-2",
                        "alert_type": "Authentication",
                        "category": "Security",
                        "last_occurrence": "2026-08-03T09:40:00Z",
                        "severity": "medium",
                        "trigger": "Login failed",
                        "status": "Cleared",
                    },
                ],
            },
            {
                "asset_id": "new-ui-profile-1",
                "asset_name": "PLC profile",
                "query_status": "Muted",
                "alerts": [
                    {
                        "alert_id": "alert-3",
                        "instance_id": "instance-3",
                        "alert_type": "Policy",
                        "category": "Operations",
                        "last_occurrence": "2026-08-03T09:30:00Z",
                        "severity": "low",
                        "trigger": "Maintenance profile",
                        "status": "Muted",
                    }
                ],
            },
        ],
        "vulnerability_assets": [
            {
                "asset_id": "new-ui-profile-1",
                "asset_name": "PLC profile",
                "vulnerabilities": [
                    {
                        "cve_id": "CVE-2026-0001",
                        "name": "Example vulnerability",
                        "source": "public",
                        "csrs_score": "72",
                        "cvss_score": "8.1",
                    },
                    {
                        "cve_id": "CVE-2026-0001",
                        "name": "Example vulnerability",
                        "source": "public",
                        "csrs_score": "72",
                        "cvss_score": "8.1",
                    },
                ],
            }
        ],
    }
    snapshot["sources"].append(new_ui_source)
    return snapshot


def test_new_ui_source_details_become_separate_deduplicated_signals() -> None:
    snapshot = _snapshot_with_new_ui_signals()

    _digest, signals = signals_from_snapshot(snapshot)

    alerts = [signal for signal in signals if signal.signal_type == "new_ui_alert"]
    vulnerabilities = [
        signal for signal in signals if signal.signal_type == "new_ui_vulnerability"
    ]
    assert len(alerts) == 3
    assert len(vulnerabilities) == 1
    active = next(
        signal
        for signal in alerts
        if signal.payload["alert"]["instance_id"] == "instance-1"
    )
    assert active.payload["status"] == "Active"
    assert active.asset_ids == ("new-ui-profile-1",)
    assert active.evidence["source_id"] == "src:cisco-cyber-vision-new-ui:dtlab-01"
    assert active.evidence["source_record_id"].endswith(":instance-1")
    assert any("nessuna associazione" in note.lower() for note in active.evidence["notes"])
    vulnerability = vulnerabilities[0]
    assert vulnerability.severity == "high"
    assert vulnerability.payload["vulnerability"]["csrs_score"] == "72"
    assert vulnerability.payload["vulnerability"]["cvss_score"] == "8.1"
    assert vulnerability.asset_ids == ("new-ui-profile-1",)


def test_new_ui_fingerprints_survive_polling_and_status_or_score_updates() -> None:
    first_snapshot = _snapshot_with_new_ui_signals()
    second_snapshot = deepcopy(first_snapshot)
    second_snapshot["snapshot_id"] = "snapshot:test:new-ui-update"
    source_details = second_snapshot["sources"][-1]["details"]
    source_details["alert_assets"][0]["alerts"][0]["status"] = "Cleared"
    source_details["alert_assets"][0]["query_status"] = "Cleared"
    source_details["alert_assets"] = [source_details["alert_assets"][0]]
    source_details["vulnerability_assets"][0]["vulnerabilities"] = [
        source_details["vulnerability_assets"][0]["vulnerabilities"][0]
    ]
    source_details["vulnerability_assets"][0]["vulnerabilities"][0]["cvss_score"] = "9.1"
    second_snapshot["sources"][-1]["evidence"]["fetched_at"] = "2026-08-03T10:01:02Z"
    second_snapshot["sources"][-1]["evidence"]["observed_at"] = "2026-08-03T10:01:02Z"

    _first_digest, first = signals_from_snapshot(first_snapshot)
    _second_digest, second = signals_from_snapshot(second_snapshot)
    first_alert = next(
        signal
        for signal in first
        if signal.signal_type == "new_ui_alert"
        and signal.payload["alert"]["instance_id"] == "instance-1"
    )
    second_alert = next(signal for signal in second if signal.signal_type == "new_ui_alert")
    first_vulnerability = next(
        signal for signal in first if signal.signal_type == "new_ui_vulnerability"
    )
    second_vulnerability = next(
        signal for signal in second if signal.signal_type == "new_ui_vulnerability"
    )

    assert first_alert.fingerprint == second_alert.fingerprint
    assert second_alert.payload["status"] == "Cleared"
    assert first_vulnerability.fingerprint == second_vulnerability.fingerprint
    assert second_vulnerability.severity == "critical"


def test_new_ui_signals_are_persisted_once_in_ticket_store(tmp_path) -> None:
    store = TicketStore(tmp_path / "tickets.sqlite3", clock=_fixed_clock)
    snapshot = _snapshot_with_new_ui_signals()

    first = ingest_snapshot(store, snapshot)
    second = ingest_snapshot(store, snapshot)

    assert first.signals_seen == 4
    assert first.signals_created == 4
    assert first.occurrences_created == 4
    assert second.signals_created == 0
    assert second.occurrences_created == 0
    assert {signal["signal_type"] for signal in store.list_signals()} == {
        "new_ui_alert",
        "new_ui_vulnerability",
    }


def test_ingest_is_idempotent_and_preserves_only_explicit_asset_links(tmp_path) -> None:
    store = TicketStore(tmp_path / "tickets.sqlite3", clock=_fixed_clock)
    snapshot = _snapshot_with_supported_signals()

    first = ingest_snapshot(store, snapshot)
    second = ingest_snapshot(store, snapshot)

    assert first.signals_seen == 4
    assert first.signals_created == 4
    assert first.occurrences_created == 4
    assert second.signals_created == 0
    assert second.occurrences_created == 0

    event = store.list_signals(signal_type="event")[0]
    finding = store.list_signals(signal_type="finding")[0]
    vulnerability = store.list_signals(signal_type="vulnerability")[0]
    assert event["asset_ids"] == []
    assert finding["asset_ids"] == []
    assert finding["recommended_action"].startswith("Verificare VMware Tools")
    assert vulnerability["asset_ids"] == ["asset:cybervision:dtlab-01:42"]
    assert vulnerability["recommended_action"].startswith("Applicare la mitigazione")
    assert all(signal["occurrence_count"] == 1 for signal in store.list_signals())


def test_same_signals_in_a_new_snapshot_increment_occurrences_without_new_signals(
    tmp_path,
) -> None:
    store = TicketStore(tmp_path / "tickets.sqlite3", clock=_fixed_clock)
    first_snapshot = _snapshot_with_supported_signals()
    second_snapshot = deepcopy(first_snapshot)
    second_snapshot["snapshot_id"] = "snapshot:test:0002"

    ingest_snapshot(store, first_snapshot)
    result = ingest_snapshot(store, second_snapshot)

    assert result.signals_created == 0
    assert result.occurrences_created == 4
    assert all(signal["occurrence_count"] == 2 for signal in store.list_signals())
    assert all(
        signal["snapshot_sha256"] == snapshot_sha256(second_snapshot)
        for signal in store.list_signals()
    )
    with sqlite3.connect(store.database_path) as connection:
        # Observation counters advance, while identical full payloads are stored once.
        assert connection.execute("SELECT COUNT(*) FROM signal_occurrences").fetchone()[0] == 4
        assert connection.execute("SELECT COUNT(*) FROM snapshot_ingests").fetchone()[0] == 2


def test_poll_timestamp_noise_does_not_create_a_new_payload_version(tmp_path) -> None:
    store = TicketStore(tmp_path / "tickets.sqlite3", clock=_fixed_clock)
    first_snapshot = _snapshot_with_supported_signals()
    second_snapshot = deepcopy(first_snapshot)
    second_snapshot["snapshot_id"] = "snapshot:test:poll-noise"
    second_snapshot["generated_at"] = "2026-08-03T10:01:02Z"
    for collection in ("events", "findings", "baseline_differences", "vulnerabilities"):
        for record in second_snapshot[collection]:
            record["evidence"]["fetched_at"] = "2026-08-03T10:01:02Z"
            record["evidence"]["observed_at"] = "2026-08-03T10:01:02Z"

    ingest_snapshot(store, first_snapshot)
    result = ingest_snapshot(store, second_snapshot)

    assert result.occurrences_created == 4
    assert all(signal["occurrence_count"] == 2 for signal in store.list_signals())
    with sqlite3.connect(store.database_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM signal_occurrences").fetchone()[0] == 4


def test_semantic_change_creates_one_new_payload_version(tmp_path) -> None:
    store = TicketStore(tmp_path / "tickets.sqlite3", clock=_fixed_clock)
    first_snapshot = _snapshot_with_supported_signals()
    second_snapshot = deepcopy(first_snapshot)
    second_snapshot["snapshot_id"] = "snapshot:test:semantic-change"
    second_snapshot["events"][0]["status"] = "acknowledged"

    ingest_snapshot(store, first_snapshot)
    ingest_snapshot(store, second_snapshot)

    with sqlite3.connect(store.database_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM signal_occurrences").fetchone()[0] == 5


def test_snapshot_marker_and_signal_updates_commit_atomically(tmp_path) -> None:
    store = TicketStore(tmp_path / "tickets.sqlite3", clock=_fixed_clock)
    snapshot = _snapshot_with_supported_signals()
    with sqlite3.connect(store.database_path) as connection:
        connection.execute(
            """
            CREATE TRIGGER reject_snapshot_marker
            BEFORE INSERT ON snapshot_ingests
            BEGIN
                SELECT RAISE(ABORT, 'marker rejected');
            END
            """
        )

    with pytest.raises(sqlite3.IntegrityError, match="marker rejected"):
        ingest_snapshot(store, snapshot)

    assert store.list_signals() == []
    assert not store.snapshot_ingested(snapshot_sha256(snapshot))


def test_positional_event_fallback_is_stable_when_list_position_changes() -> None:
    snapshot = _snapshot_with_supported_signals()
    event = snapshot["events"][0]
    event["id"] = "event:cybervision:dtlab-01:0"
    event["evidence"]["source_record_id"] = "dashboard-event:0"
    first_digest, first_signals = signals_from_snapshot(snapshot)

    reordered = deepcopy(snapshot)
    reordered["snapshot_id"] = "snapshot:test:reordered"
    reordered["events"][0]["id"] = "event:cybervision:dtlab-01:7"
    reordered["events"][0]["evidence"]["source_record_id"] = "dashboard-event:7"
    second_digest, second_signals = signals_from_snapshot(reordered)

    assert first_digest != second_digest
    first_event = next(signal for signal in first_signals if signal.signal_type == "event")
    second_event = next(signal for signal in second_signals if signal.signal_type == "event")
    assert first_event.fingerprint == second_event.fingerprint


def test_expected_snapshot_hash_is_enforced() -> None:
    snapshot = _snapshot_with_supported_signals()

    with pytest.raises(ValueError, match="SHA snapshot non corrispondente"):
        signals_from_snapshot(snapshot, expected_sha256="0" * 64)


def test_concurrent_ingest_is_thread_safe_and_deduplicated(tmp_path) -> None:
    store = TicketStore(tmp_path / "tickets.sqlite3", clock=_fixed_clock)
    snapshot = _snapshot_with_supported_signals()

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(lambda _: ingest_snapshot(store, snapshot), range(12)))

    assert sum(result.signals_created for result in results) == 4
    assert sum(result.occurrences_created for result in results) == 4
    assert len(store.list_signals()) == 4
    assert all(signal["occurrence_count"] == 1 for signal in store.list_signals())
