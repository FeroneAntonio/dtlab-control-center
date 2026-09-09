from __future__ import annotations

import csv
import hashlib
import io
import json
import zipfile
from datetime import UTC, datetime

import pytest

from dtlab.contract import snapshot_sha256
from dtlab.services.exports import (
    build_asset_profile_json,
    build_canonical_snapshot_json,
    build_cve_dossier_json,
    build_export_bundle,
    build_signal_evidence_bundle,
    build_snapshot_schema_json,
    build_ticket_register_csv,
)
from tests.factories import FETCHED_AT, add_cisco_asset, evidence, valid_snapshot


def _files(bundle: bytes) -> dict[str, bytes]:
    with zipfile.ZipFile(io.BytesIO(bundle)) as archive:
        return {name: archive.read(name) for name in archive.namelist()}


def _add_second_asset(snapshot: dict) -> str:
    source_id = "src:cisco-cyber-vision:dtlab-01"
    asset_id = "asset:cybervision:dtlab-01:43"
    snapshot["assets"].append(
        {
            "id": asset_id,
            "evidence": evidence(source_id, "real", "device:43"),
            "name": "HMI BeerFactory",
            "category": "Industrial automation",
            "device_type": "HMI",
            "vendor": None,
            "ip_addresses": ["172.16.10.20"],
            "mac_addresses": [],
            "network_ids": [],
            "zone": None,
            "protocols": ["Modbus"],
            "status": "online",
            "last_seen_at": FETCHED_AT,
            "operational_role": "support",
        }
    )
    return asset_id


def _add_flow(snapshot: dict, flow_id: str, left_id: str, right_id: str) -> None:
    source_id = "src:cisco-cyber-vision:dtlab-01"
    snapshot["flows"].append(
        {
            "id": flow_id,
            "evidence": evidence(source_id, "real", flow_id),
            "left_asset_id": left_id,
            "right_asset_id": right_id,
            "left_component_id": None,
            "right_component_id": None,
            "left_label": "Left",
            "right_label": "Right",
            "left_ip": "172.16.10.10",
            "right_ip": "172.16.10.20",
            "protocol": "Modbus",
            "direction": "left_to_right",
            "direction_raw": "leftRight",
            "left_port": 502,
            "right_port": 502,
            "first_seen_at": FETCHED_AT,
            "last_seen_at": FETCHED_AT,
            "packet_count": 4,
            "byte_count": 256,
        }
    )


def _add_event(snapshot: dict, event_id: str, asset_ids: list[str]) -> None:
    source_id = "src:cisco-cyber-vision:dtlab-01"
    snapshot["events"].append(
        {
            "id": event_id,
            "evidence": evidence(source_id, "real", event_id),
            "occurred_at": FETCHED_AT,
            "severity": "high",
            "category": "Security",
            "title": "Comando Modbus anomalo",
            "description": "Evento restituito da Cisco.",
            "center_id": None,
            "center_label": None,
            "status": "open",
            "asset_ids": asset_ids,
            "acknowledged": False,
        }
    )


def test_bundle_is_deterministic_and_every_file_has_a_manifest_hash() -> None:
    snapshot = valid_snapshot()

    first = build_export_bundle(snapshot, mode="technical")
    second = build_export_bundle(snapshot, mode="technical")
    files = _files(first)
    manifest = json.loads(files["manifest.json"])

    assert first == second
    for name, metadata in manifest["files"].items():
        assert hashlib.sha256(files[name]).hexdigest() == metadata["sha256"]
        assert len(files[name]) == metadata["bytes"]


def test_public_bundle_redacts_addresses_but_technical_bundle_preserves_them() -> None:
    snapshot = valid_snapshot()

    technical = _files(build_export_bundle(snapshot, mode="technical"))
    public = _files(
        build_export_bundle(
            snapshot,
            mode="public",
            salt=b"0123456789abcdef",
        )
    )

    assert b"172.16.10.10" in technical["snapshot.json"]
    assert b"172.16.10.10" not in public["snapshot.json"]
    assert b"ip-" in public["snapshot.json"]


def test_csv_formula_injection_is_neutralized_in_bundle() -> None:
    snapshot = valid_snapshot()
    asset_id = add_cisco_asset(snapshot)
    asset = next(item for item in snapshot["assets"] if item["id"] == asset_id)
    asset["name"] = "=HYPERLINK(\"https://invalid\")"

    files = _files(build_export_bundle(snapshot, mode="technical"))
    rows = list(
        csv.DictReader(
            io.StringIO(files["tables/assets.csv"].decode("utf-8-sig"))
        )
    )

    assert rows[0]["name"].startswith("'=")


def test_asset_evidence_bundle_remains_contract_valid() -> None:
    snapshot = valid_snapshot()
    asset_id = add_cisco_asset(snapshot, score=68)

    bundle = build_export_bundle(
        snapshot,
        mode="technical",
        asset_id=asset_id,
    )
    files = _files(bundle)
    exported = json.loads(files["snapshot.json"])

    assert [asset["id"] for asset in exported["assets"]] == [asset_id]
    assert [score["asset_id"] for score in exported["risk_scores"]] == [asset_id]


def test_asset_bundle_drops_findings_that_reference_a_removed_asset() -> None:
    snapshot = valid_snapshot()
    selected_id = add_cisco_asset(snapshot, score=68)
    other_id = _add_second_asset(snapshot)
    source_id = "src:cisco-cyber-vision:dtlab-01"
    snapshot["findings"].append(
        {
            "id": "finding:other-asset",
            "evidence": evidence(source_id, "real", "finding:other-asset"),
            "code": "other_asset_only",
            "severity": "medium",
            "title": "Finding HMI",
            "description": "Riguarda soltanto l'altro asset.",
            "status": "open",
            "entity_ids": [other_id],
            "first_detected_at": FETCHED_AT,
            "last_detected_at": FETCHED_AT,
            "recommended_action": "Verificare HMI.",
            "exclude_from_operational_kpis": False,
        }
    )

    files = _files(
        build_export_bundle(snapshot, mode="technical", asset_id=selected_id)
    )
    exported = json.loads(files["snapshot.json"])

    assert [asset["id"] for asset in exported["assets"]] == [selected_id]
    assert exported["findings"] == []


def test_asset_bundle_keeps_assets_explicitly_referenced_by_a_baseline_difference() -> None:
    snapshot = valid_snapshot()
    selected_id = add_cisco_asset(snapshot, score=68)
    other_id = _add_second_asset(snapshot)
    source_id = "src:cisco-cyber-vision:dtlab-01"
    snapshot["baselines"].append(
        {
            "id": "baseline:test",
            "evidence": evidence(source_id, "real", "baseline:test"),
            "name": "Baseline test",
            "description": "Baseline approvata",
            "status": "active",
            "created_at": FETCHED_AT,
            "creation_period_start": FETCHED_AT,
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
            "id": "baseline-difference:test",
            "evidence": evidence(source_id, "real", "baseline-difference:test"),
            "baseline_id": "baseline:test",
            "difference_type": "new_activity",
            "target_id": "activity:test",
            "key": "protocol",
            "value": "Modbus",
            "asset_ids": [selected_id, other_id],
            "flow_id": None,
            "detected_at": FETCHED_AT,
            "description": "Comunicazione esplicita tra PLC e HMI.",
        }
    )

    files = _files(
        build_export_bundle(snapshot, mode="technical", asset_id=selected_id)
    )
    exported = json.loads(files["snapshot.json"])

    assert {asset["id"] for asset in exported["assets"]} == {selected_id, other_id}
    assert [item["id"] for item in exported["baseline_differences"]] == [
        "baseline-difference:test"
    ]


def test_direct_snapshot_and_release_schema_are_deterministic() -> None:
    snapshot = valid_snapshot()

    first = build_canonical_snapshot_json(snapshot)
    second = build_canonical_snapshot_json(snapshot)
    schema = json.loads(build_snapshot_schema_json())

    assert first == second
    assert json.loads(first) == snapshot
    assert hashlib.sha256(first).hexdigest() == snapshot_sha256(snapshot)
    assert schema["properties"]["schema_version"]["const"] == snapshot["schema_version"]


def test_ticket_register_csv_is_deterministic_sla_aware_and_formula_safe() -> None:
    ticket = {
        "id": "ticket:1",
        "signal_id": "signal:1",
        "title": "=HYPERLINK(\"https://invalid\")",
        "status": "investigating",
        "priority": "p2",
        "owner": "team-ot",
        "created_by": "triage",
        "created_at": "2026-08-03T12:00:00Z",
        "updated_at": "2026-08-03T12:30:00Z",
        "resolved_at": None,
        "closed_at": None,
    }
    signals = {
        "signal:1": {
            "signal_type": "event",
            "source_record_id": "event:source:1",
            "asset_ids": ["asset:plc:1"],
        }
    }
    evaluated_at = datetime(2026, 8, 3, 18, 30, tzinfo=UTC)

    first = build_ticket_register_csv(
        [ticket], signals_by_id=signals, evaluated_at=evaluated_at
    )
    second = build_ticket_register_csv(
        [ticket], signals_by_id=signals, evaluated_at=evaluated_at
    )
    row = next(csv.DictReader(io.StringIO(first.decode("utf-8-sig"))))

    assert first == second
    assert row["sla_state"] == "due_soon"
    assert row["sla_remaining_seconds"] == "5400"
    assert row["sla_evaluated_at"] == "2026-08-03T18:30:00Z"
    assert row["title"].startswith("'=")
    assert json.loads(row["asset_ids"]) == ["asset:plc:1"]


def test_technical_bundle_carries_schema_sources_and_source_snapshot_identity() -> None:
    snapshot = valid_snapshot()

    files = _files(build_export_bundle(snapshot, mode="technical"))
    manifest = json.loads(files["manifest.json"])

    assert "schema/dtlab-snapshot-v2.schema.json" in files
    assert "tables/sources.csv" in files
    assert manifest["manifest_version"] == "1.1"
    assert manifest["bundle_type"] == "dtlab_snapshot_export"
    assert manifest["snapshot_sha256"] == snapshot_sha256(snapshot)
    assert manifest["contract_version"] == snapshot["schema_version"]
    assert manifest["exporter_version"] == snapshot["sync"]["collector_version"]
    sources = csv.DictReader(
        io.StringIO(files["tables/sources.csv"].decode("utf-8-sig"))
    )
    assert len(list(sources)) == 3


def test_asset_profile_contains_only_explicitly_related_records() -> None:
    snapshot = valid_snapshot()
    selected_id = add_cisco_asset(snapshot, score=68)
    other_id = _add_second_asset(snapshot)
    _add_flow(snapshot, "flow:selected", selected_id, other_id)
    _add_flow(snapshot, "flow:other", other_id, other_id)
    _add_event(snapshot, "event:selected", [selected_id])
    _add_event(snapshot, "event:other", [other_id])

    profile = json.loads(
        build_asset_profile_json(snapshot, asset_id=selected_id, mode="technical")
    )

    assert profile["asset"]["id"] == selected_id
    assert [score["asset_id"] for score in profile["risk_scores"]] == [selected_id]
    assert [flow["id"] for flow in profile["flows"]] == ["flow:selected"]
    assert [event["id"] for event in profile["events"]] == ["event:selected"]
    assert profile["snapshot_sha256"] == snapshot_sha256(snapshot)


def test_cve_dossier_separates_catalog_from_explicit_device_associations() -> None:
    snapshot = valid_snapshot()
    asset_id = add_cisco_asset(snapshot, score=68)
    source = snapshot["sources"][2]
    source["capabilities"]["vulnerabilities"] = {
        "status": "available",
        "records": 2,
        "error_code": None,
    }
    source["capabilities"]["device_vulnerabilities"] = {
        "status": "available",
        "records": 2,
        "error_code": None,
    }
    selected = {
        "source_record_id": "cisco-cve:1",
        "external_id": "CVE-2026-0001",
        "title": "Vulnerabilità test",
        "cvss_score": 9.8,
        "cvss_version": 3.1,
        "published_at": "2026-08-01T10:00:00Z",
        "vendor_id": "VENDOR-1",
    }
    source["details"] = {
        "vulnerability_catalog": [
            selected,
            {
                **selected,
                "source_record_id": "cisco-cve:2",
                "external_id": "CVE-2026-9999",
            },
        ]
    }
    snapshot["vulnerabilities"].extend(
        [
            {
                "id": "vulnerability:matching",
                "evidence": evidence(
                    source["id"], "real", "device:42:vulnerability:cve-2026-0001"
                ),
                "asset_id": asset_id,
                "external_id": "CVE-2026-0001",
                "title": "Associazione Cisco",
                "severity": "critical",
                "cvss_score": 9.8,
                "status": "open",
                "published_at": "2026-08-01T10:00:00Z",
                "details": {"solution": "Mitigazione approvata."},
            },
            {
                "id": "vulnerability:other",
                "evidence": evidence(source["id"], "real", "device:42:vulnerability:other"),
                "asset_id": asset_id,
                "external_id": "CVE-2026-9999",
                "title": "Altra associazione",
                "severity": "low",
                "cvss_score": 3.1,
                "status": "open",
                "published_at": "2026-08-01T10:00:00Z",
                "details": {},
            },
        ]
    )

    first = build_cve_dossier_json(snapshot, catalog_record=selected)
    second = build_cve_dossier_json(snapshot, catalog_record=selected)
    dossier = json.loads(first)

    assert first == second
    assert dossier["catalog_record"]["external_id"] == "CVE-2026-0001"
    assert dossier["association_statement"].startswith("Associazioni")
    assert [
        item["vulnerability"]["id"] for item in dossier["device_associations"]
    ] == ["vulnerability:matching"]
    assert dossier["device_associations"][0]["asset"]["id"] == asset_id
    assert dossier["device_associations"][0]["cisco_device_risk_score"]["score"] == 68
    assert dossier["snapshot_sha256"] == snapshot_sha256(snapshot)
    assert dossier["snapshot_generated_at"] == FETCHED_AT
    assert dossier["snapshot_sync"] == {
        "state": "partial",
        "completed_at": FETCHED_AT,
    }
    assert dossier["catalog_source"]["last_success_at"] == FETCHED_AT
    assert dossier["catalog_source"]["catalog_capability"]["status"] == "available"
    assert (
        dossier["catalog_source"]["device_associations_capability"]["status"]
        == "available"
    )


def test_cve_dossier_states_that_catalog_presence_is_not_device_presence() -> None:
    snapshot = valid_snapshot()
    selected = {
        "source_record_id": "cisco-cve:1",
        "external_id": "CVE-2026-0001",
        "title": "Catalog only",
    }
    source = snapshot["sources"][2]
    source["details"] = {"vulnerability_catalog": [selected]}
    source["capabilities"]["device_vulnerabilities"] = {
        "status": "available",
        "records": 0,
        "error_code": None,
    }

    dossier = json.loads(build_cve_dossier_json(snapshot, catalog_record=selected))

    assert dossier["device_associations"] == []
    assert dossier["association_statement"] == (
        "Presente nel catalogo globale Cisco; nessuna associazione "
        "device–vulnerabilità restituita."
    )


def test_cve_dossier_does_not_report_zero_when_device_associations_failed() -> None:
    snapshot = valid_snapshot()
    selected = {
        "source_record_id": "cisco-cve:1",
        "external_id": "CVE-2026-0001",
        "title": "Catalog only",
    }
    source = snapshot["sources"][2]
    source["details"] = {"vulnerability_catalog": [selected]}
    source["capabilities"].update(
        {
            "vulnerabilities": {
                "status": "available",
                "records": 1,
                "error_code": None,
            },
            "device_vulnerabilities": {
                "status": "error",
                "records": 0,
                "error_code": "http_500",
            },
        }
    )

    dossier = json.loads(build_cve_dossier_json(snapshot, catalog_record=selected))

    assert dossier["device_associations"] == []
    assert "non verificabili" in dossier["association_statement"]
    assert "nessuna associazione" not in dossier["association_statement"]
    assert dossier["catalog_source"]["catalog_capability"]["status"] == "available"
    assert (
        dossier["catalog_source"]["device_associations_capability"]["status"]
        == "error"
    )


def test_cve_dossier_rejects_a_record_not_present_in_the_verified_catalog() -> None:
    snapshot = valid_snapshot()
    snapshot["sources"][2]["details"] = {
        "vulnerability_catalog": [
            {
                "source_record_id": "cisco-cve:known",
                "external_id": "CVE-2026-0001",
                "title": "Known",
            }
        ]
    }

    with pytest.raises(ValueError, match="catalogo Cisco"):
        build_cve_dossier_json(
            snapshot,
            catalog_record={
                "source_record_id": "cisco-cve:foreign",
                "external_id": "CVE-2026-9999",
                "title": "Caller supplied",
            },
        )


def test_cve_dossier_prefers_the_exact_source_record_over_a_duplicate_external_id() -> None:
    snapshot = valid_snapshot()
    first = {
        "source_record_id": "cisco-cve:first",
        "external_id": "CVE-2026-0001",
        "title": "First record",
    }
    second = {
        "source_record_id": "cisco-cve:second",
        "external_id": "CVE-2026-0001",
        "title": "Second record",
    }
    snapshot["sources"][2]["details"] = {
        "vulnerability_catalog": [first, second]
    }

    dossier = json.loads(build_cve_dossier_json(snapshot, catalog_record=second))

    assert dossier["catalog_record"]["source_record_id"] == "cisco-cve:second"
    assert dossier["catalog_record"]["title"] == "Second record"


def test_public_cve_dossier_resolves_before_redacting_a_sensitive_source_record_id() -> None:
    snapshot = valid_snapshot()
    selected = {
        "source_record_id": "record:172.16.10.77",
        "external_id": "CVE-2026-0001",
        "title": "Catalog record",
    }
    snapshot["sources"][2]["details"] = {"vulnerability_catalog": [selected]}

    public_bytes = build_cve_dossier_json(
        snapshot,
        catalog_record=selected,
        mode="public",
        salt=b"stable-public-test-salt",
    )
    dossier = json.loads(public_bytes)

    assert dossier["catalog_record"]["external_id"] == "CVE-2026-0001"
    assert "172.16.10.77" not in public_bytes.decode("utf-8")


def test_event_evidence_uses_only_direct_asset_ids_and_verifiable_file_hashes() -> None:
    snapshot = valid_snapshot()
    selected_id = add_cisco_asset(snapshot)
    other_id = _add_second_asset(snapshot)
    _add_flow(snapshot, "flow:selected", selected_id, other_id)
    _add_flow(snapshot, "flow:other", other_id, other_id)
    _add_event(snapshot, "event:selected", [selected_id])

    first = build_signal_evidence_bundle(
        snapshot,
        signal_type="event",
        signal_id="event:selected",
    )
    second = build_signal_evidence_bundle(
        snapshot,
        signal_type="event",
        signal_id="event:selected",
    )
    files = _files(first)
    manifest = json.loads(files["manifest.json"])
    assets = json.loads(files["assets.json"])
    flows = list(
        csv.DictReader(
            io.StringIO(files["related-flows.csv"].decode("utf-8-sig"))
        )
    )

    assert first == second
    assert [asset["id"] for asset in assets] == [selected_id]
    assert [flow["id"] for flow in flows] == ["flow:selected"]
    assert manifest["correlated_asset_ids"] == [selected_id]
    assert manifest["snapshot_sha256"] == snapshot_sha256(snapshot)
    for name, metadata in manifest["files"].items():
        assert hashlib.sha256(files[name]).hexdigest() == metadata["sha256"]
        assert len(files[name]) == metadata["bytes"]


def test_finding_does_not_infer_assets_or_flows_from_a_vm_reference() -> None:
    snapshot = valid_snapshot()
    selected_id = add_cisco_asset(snapshot)
    other_id = _add_second_asset(snapshot)
    vm_id = snapshot["virtual_machines"][0]["id"]
    source_id = "src:vmware-esxi:dtlab-01"
    snapshot["identity_links"].append(
        {
            "id": "identity:test:plc",
            "evidence": evidence(source_id, "observed", "identity:test:plc"),
            "virtual_machine_id": vm_id,
            "asset_id": selected_id,
            "method": "ip_match",
            "confidence": 1.0,
            "status": "confirmed",
        }
    )
    _add_flow(snapshot, "flow:selected", selected_id, other_id)
    snapshot["findings"].append(
        {
            "id": "finding:test:vm-only",
            "evidence": evidence(source_id, "observed", "finding:test:vm-only"),
            "code": "vm_only",
            "severity": "info",
            "title": "Finding VMware",
            "description": "Riferimento diretto esclusivamente alla VM.",
            "status": "open",
            "entity_ids": [vm_id],
            "first_detected_at": FETCHED_AT,
            "last_detected_at": FETCHED_AT,
            "recommended_action": "Verificare manualmente.",
            "exclude_from_operational_kpis": False,
        }
    )

    files = _files(
        build_signal_evidence_bundle(
            snapshot,
            signal_type="finding",
            signal_id="finding:test:vm-only",
        )
    )

    assert json.loads(files["assets.json"]) == []
    assert files["related-flows.csv"] == b""
    assert json.loads(files["manifest.json"])["correlated_asset_ids"] == []


def test_signal_bundle_rejects_unknown_type_or_id() -> None:
    snapshot = valid_snapshot()

    with pytest.raises(ValueError, match="signal_type"):
        build_signal_evidence_bundle(snapshot, signal_type="alert", signal_id="missing")
    with pytest.raises(ValueError, match="Event non trovato"):
        build_signal_evidence_bundle(snapshot, signal_type="event", signal_id="missing")
