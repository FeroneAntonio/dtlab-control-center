from __future__ import annotations

import hashlib
import io
import json
import zipfile
from copy import deepcopy
from datetime import datetime

import pytest
from jsonschema import Draft202012Validator

from dtlab.contract import snapshot_sha256
from dtlab.services.siem_exports import (
    SIEM_EVENT_SCHEMA_VERSION,
    SIEM_MANIFEST_SCHEMA_VERSION,
    build_siem_cef,
    build_siem_event_schema_json,
    build_siem_events,
    build_siem_export_bundle,
    build_siem_ndjson,
)
from tests.factories import FETCHED_AT, add_cisco_asset, evidence, source, valid_snapshot


def _supported_snapshot() -> dict:
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
            "category": "Security|OT=Control\\Path",
            "title": "Comando | Modbus=write\\coil",
            "description": "Prima riga\nSeconda=riga|test\\ok",
            "center_id": "center-1",
            "center_label": "DTLab Center",
            "status": None,
            "asset_ids": [asset_id],
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
            "description": "Finding associato esplicitamente a una VM, non a un asset.",
            "status": "open",
            "entity_ids": [vm_id],
            "first_detected_at": FETCHED_AT,
            "last_detected_at": FETCHED_AT,
            "recommended_action": "Verificare VMware Tools.",
            "exclude_from_operational_kpis": False,
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
                "solution": "Applicare la mitigazione approvata.",
                "matching_at": FETCHED_AT,
            },
        }
    )

    new_ui_id = "src:cisco-cyber-vision-new-ui:dtlab-01"
    new_ui = source(
        new_ui_id,
        "Cisco Cyber Vision · New UI",
        "cisco_cyber_vision_new_ui",
        "connected",
        "real",
    )
    new_ui["details"] = {
        "center_id": "center-1",
        "alert_assets": [
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
                    }
                ],
            },
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
        ],
        "vulnerability_assets": [
            {
                "asset_id": "new-ui-profile-1",
                "asset_name": "PLC profile",
                "vulnerabilities": [
                    {
                        "cve_id": "CVE-2026-0002",
                        "name": "New UI vulnerability",
                        "source": "public",
                        "csrs_score": "72",
                        "cvss_score": "8.1",
                    },
                    {
                        "cve_id": "CVE-2026-0002",
                        "name": "New UI vulnerability",
                        "source": "public",
                        "csrs_score": "72",
                        "cvss_score": "8.1",
                    },
                ],
            }
        ],
    }
    snapshot["sources"].append(new_ui)
    return snapshot


def _zip_files(bundle: bytes) -> dict[str, bytes]:
    with zipfile.ZipFile(io.BytesIO(bundle)) as archive:
        return {name: archive.read(name) for name in archive.namelist()}


def test_normalized_events_cover_every_supported_source_without_inference() -> None:
    snapshot = _supported_snapshot()
    events = build_siem_events(snapshot)
    datasets = {event["dataset"] for event in events}

    assert datasets == {
        "dtlab.event",
        "dtlab.finding",
        "dtlab.baseline_difference",
        "dtlab.device_vulnerability",
        "dtlab.new_ui.alert",
        "dtlab.new_ui.vulnerability",
    }
    assert len(events) == 6
    assert len({event["event_id"] for event in events}) == 6
    assert all(event["schema_version"] == SIEM_EVENT_SCHEMA_VERSION for event in events)
    assert all(event["timestamp"].endswith("Z") for event in events)
    assert all(event["snapshot_sha256"] == snapshot_sha256(snapshot) for event in events)

    finding = next(event for event in events if event["dataset"] == "dtlab.finding")
    assert finding["asset_ids"] == []
    classic_event = next(event for event in events if event["dataset"] == "dtlab.event")
    assert classic_event["asset_ids"] == ["asset:cybervision:dtlab-01:42"]
    new_ui_events = [
        event for event in events if event["dataset"].startswith("dtlab.new_ui.")
    ]
    assert all(event["asset_ids"] == ["new-ui-profile-1"] for event in new_ui_events)


def test_event_identity_is_stable_across_snapshots_while_snapshot_identity_changes() -> None:
    first = _supported_snapshot()
    second = deepcopy(first)
    second["snapshot_id"] = "snapshot:test:0002"

    first_events = build_siem_events(first)
    second_events = build_siem_events(second)

    assert [event["event_id"] for event in first_events] == [
        event["event_id"] for event in second_events
    ]
    assert {event["snapshot_sha256"] for event in first_events} == {
        snapshot_sha256(first)
    }
    assert {event["snapshot_sha256"] for event in second_events} == {
        snapshot_sha256(second)
    }


def test_ndjson_is_deterministic_utf8_and_has_one_json_event_per_line() -> None:
    snapshot = _supported_snapshot()

    first = build_siem_ndjson(snapshot)
    second = build_siem_ndjson(snapshot)
    records = [json.loads(line) for line in first.decode("utf-8").splitlines()]

    assert first == second
    assert first.endswith(b"\n")
    assert records == list(build_siem_events(snapshot))
    assert len(records) == 6


def test_event_schema_is_valid_and_accepts_every_normalized_record() -> None:
    schema = json.loads(build_siem_event_schema_json())
    validator = Draft202012Validator(schema)

    assert schema["$schema"].endswith("2020-12/schema")
    for record in build_siem_events(_supported_snapshot()):
        assert list(validator.iter_errors(record)) == []


def test_cef_is_deterministic_utf8_and_escapes_reserved_characters() -> None:
    snapshot = _supported_snapshot()

    first = build_siem_cef(snapshot)
    second = build_siem_cef(snapshot)
    text = first.decode("utf-8")

    assert first == second
    assert len(text.splitlines()) == 6
    assert "Comando \\| Modbus\\=write\\\\coil" in text
    assert "Prima riga\\nSeconda\\=riga\\|test\\\\ok" in text
    assert "Security\\|OT\\=Control\\\\Path" in text
    assert all(line.startswith("CEF:0|DTLab|Control Center|2.0|") for line in text.splitlines())
    parsed_timestamp = datetime.fromisoformat(FETCHED_AT.replace("Z", "+00:00"))
    expected_epoch_ms = int(parsed_timestamp.timestamp() * 1000)
    assert f"rt={expected_epoch_ms}" in text


def test_bundle_is_deterministic_and_manifest_hashes_every_payload() -> None:
    snapshot = _supported_snapshot()

    first = build_siem_export_bundle(snapshot)
    second = build_siem_export_bundle(snapshot)
    files = _zip_files(first)
    manifest = json.loads(files["manifest.json"])

    assert first == second
    assert set(files) == {
        "README.txt",
        "event-schema.json",
        "events.cef",
        "events.ndjson",
        "manifest.json",
    }
    assert manifest["schema_version"] == SIEM_MANIFEST_SCHEMA_VERSION
    assert manifest["event_schema_version"] == SIEM_EVENT_SCHEMA_VERSION
    assert manifest["export_mode"] == "technical"
    assert manifest["snapshot_sha256"] == snapshot_sha256(snapshot)
    assert manifest["record_count"] == 6
    assert manifest["correlation_policy"] == "explicit_source_references_only_no_inference"
    for name, metadata in manifest["files"].items():
        assert metadata["bytes"] == len(files[name])
        assert metadata["sha256"] == hashlib.sha256(files[name]).hexdigest()
    assert b"technical export" in files["README.txt"]


def test_export_rejects_unsupported_mode_and_invalid_snapshot() -> None:
    snapshot = _supported_snapshot()

    with pytest.raises(ValueError, match="technical"):
        build_siem_export_bundle(snapshot, mode="public")

    invalid = deepcopy(snapshot)
    invalid["events"][0]["asset_ids"] = ["asset:missing"]
    with pytest.raises(ValueError, match="riferimento sconosciuto"):
        build_siem_ndjson(invalid)

    secret_bearing = deepcopy(snapshot)
    secret_bearing["sources"][-1]["details"]["api_token"] = "must-not-export"
    bundle_files = _zip_files(build_siem_export_bundle(secret_bearing))
    assert all(b"must-not-export" not in content for content in bundle_files.values())
