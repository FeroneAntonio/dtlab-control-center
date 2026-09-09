"""Deterministic, redacted technical and evidence export bundles."""

from __future__ import annotations

import csv
import hashlib
import io
import json
import zipfile
from collections.abc import Mapping, Sequence
from copy import deepcopy
from datetime import datetime
from typing import Any

from dtlab import __version__
from dtlab.contract import canonical_bytes, load_schema, snapshot_sha256
from dtlab.services.redaction import redacted_snapshot, safe_csv_cell
from dtlab.services.ticket_store import derive_ticket_sla

EXPORT_MANIFEST_VERSION = "1.1"

_COLLECTIONS = (
    "virtual_machines",
    "networks",
    "assets",
    "identity_links",
    "risk_scores",
    "activities",
    "flows",
    "events",
    "vulnerabilities",
    "baselines",
    "baseline_differences",
    "sensors",
    "reports",
    "findings",
)

_SIGNAL_COLLECTIONS = {
    "event": "events",
    "finding": "findings",
}


def _timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _within(value: str | None, start: datetime | None, end: datetime | None) -> bool:
    if start is None and end is None:
        return True
    parsed = _timestamp(value)
    if parsed is None:
        return False
    return (start is None or parsed >= start) and (end is None or parsed <= end)


def _filtered_snapshot(
    snapshot: Mapping[str, Any],
    *,
    asset_id: str | None,
    start: datetime | None,
    end: datetime | None,
) -> dict[str, Any]:
    result = deepcopy(snapshot)
    if not asset_id and start is None and end is None:
        return result
    related_flow_ids = {
        flow["id"]
        for flow in result["flows"]
        if (
            not asset_id
            or asset_id in {flow["left_asset_id"], flow["right_asset_id"]}
        )
        and _within(flow["last_seen_at"], start, end)
    }
    filtered_flows = [
        flow for flow in result["flows"] if flow["id"] in related_flow_ids
    ]
    filtered_activities = [
        item
        for item in result["activities"]
        if (not asset_id or asset_id in item["asset_ids"])
        and _within(item["last_seen_at"], start, end)
    ]
    filtered_events = [
        item
        for item in result["events"]
        if (not asset_id or asset_id in item["asset_ids"])
        and _within(item["occurred_at"], start, end)
    ]
    filtered_differences = [
        item
        for item in result["baseline_differences"]
        if (
            item["flow_id"] in related_flow_ids
            or (
                item["flow_id"] is None
                and (not asset_id or asset_id in item["asset_ids"])
            )
        )
    ]
    if asset_id:
        original_asset_ids = {asset["id"] for asset in result["assets"]}
        related_asset_ids = {asset_id}
        for flow in filtered_flows:
            related_asset_ids.update(
                value
                for value in (
                    flow["left_asset_id"],
                    flow["right_asset_id"],
                )
                if value
            )
        for item in [*filtered_activities, *filtered_events]:
            related_asset_ids.update(item["asset_ids"])
        for item in filtered_differences:
            related_asset_ids.update(item["asset_ids"])
        result["assets"] = [
            asset for asset in result["assets"] if asset["id"] in related_asset_ids
        ]
        result["risk_scores"] = [
            score for score in result["risk_scores"] if score["asset_id"] == asset_id
        ]
        result["vulnerabilities"] = [
            item for item in result["vulnerabilities"] if item["asset_id"] == asset_id
        ]
        result["identity_links"] = [
            link
            for link in result["identity_links"]
            if link["asset_id"] in related_asset_ids
        ]
        related_vm_ids = {
            link["virtual_machine_id"] for link in result["identity_links"]
        }
        related_network_ids = {
            network_id
            for asset in result["assets"]
            for network_id in asset.get("network_ids", [])
        }
        related_entity_ids = (
            related_asset_ids
            | related_vm_ids
            | related_network_ids
            | related_flow_ids
            | {link["id"] for link in result["identity_links"]}
        )
        removed_asset_ids = original_asset_ids - related_asset_ids
        result["findings"] = [
            finding
            for finding in result["findings"]
            if (
                set(finding.get("entity_ids", []))
                and not set(finding.get("entity_ids", [])).intersection(removed_asset_ids)
                and set(finding.get("entity_ids", [])).intersection(related_entity_ids)
            )
        ]
    result["activities"] = filtered_activities
    result["events"] = filtered_events
    result["flows"] = filtered_flows
    result["baseline_differences"] = filtered_differences
    if asset_id:
        known_entity_ids = {result["environment"]["id"]}
        for collection in ("sources", *(_COLLECTIONS[:-1])):
            known_entity_ids.update(
                record["id"]
                for record in result.get(collection, [])
                if isinstance(record, Mapping) and isinstance(record.get("id"), str)
            )
        result["findings"] = [
            finding
            for finding in result["findings"]
            if set(finding.get("entity_ids", [])).issubset(known_entity_ids)
        ]
    return result


def _csv_bytes(records: list[dict[str, Any]]) -> bytes:
    if not records:
        return b""
    columns = sorted({key for record in records for key in record})
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=columns, extrasaction="ignore")
    writer.writeheader()
    for record in sorted(records, key=lambda item: str(item.get("id", ""))):
        row: dict[str, Any] = {}
        for key in columns:
            value = record.get(key)
            if isinstance(value, (Mapping, list)):
                value = json.dumps(value, ensure_ascii=False, sort_keys=True)
            row[key] = safe_csv_cell(value)
        writer.writerow(row)
    return output.getvalue().encode("utf-8-sig")


def _json_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    ).encode("utf-8")


def build_ticket_register_csv(
    tickets: Sequence[Mapping[str, Any]],
    *,
    signals_by_id: Mapping[str, Mapping[str, Any]],
    evaluated_at: datetime,
) -> bytes:
    """Export the filtered operational register with one consistent SLA clock."""

    records: list[dict[str, Any]] = []
    for ticket in tickets:
        signal = signals_by_id.get(str(ticket.get("signal_id")), {})
        sla = derive_ticket_sla(ticket, now=evaluated_at)
        records.append(
            {
                "id": ticket.get("id"),
                "priority": ticket.get("priority"),
                "status": ticket.get("status"),
                "sla_state": sla["state"],
                "sla_due_at": sla["due_at"],
                "sla_remaining_seconds": sla["remaining_seconds"],
                "sla_evaluated_at": sla["evaluated_at"],
                "sla_policy_hours": sla["policy_hours"],
                "sla_stopped_at": sla["stopped_at"],
                "sla_stop_reason": sla["stop_reason"],
                "owner": ticket.get("owner"),
                "title": ticket.get("title"),
                "created_by": ticket.get("created_by"),
                "created_at": ticket.get("created_at"),
                "updated_at": ticket.get("updated_at"),
                "signal_id": ticket.get("signal_id"),
                "signal_type": signal.get("signal_type"),
                "source_record_id": signal.get("source_record_id"),
                "asset_ids": signal.get("asset_ids", []),
            }
        )
    return _csv_bytes(records)


def _zip_info(name: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = 0o640 << 16
    return info


def _archive_bytes(files: Mapping[str, bytes]) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, mode="w") as archive:
        for name, content in sorted(files.items()):
            archive.writestr(_zip_info(name), content)
    return output.getvalue()


def _file_manifest(files: Mapping[str, bytes]) -> dict[str, dict[str, int | str]]:
    return {
        name: {
            "sha256": hashlib.sha256(content).hexdigest(),
            "bytes": len(content),
        }
        for name, content in sorted(files.items())
    }


def build_canonical_snapshot_json(snapshot: Mapping[str, Any]) -> bytes:
    """Return the exact validated bytes used by the content-addressed snapshot store."""

    return canonical_bytes(snapshot)


def build_snapshot_schema_json() -> bytes:
    """Return the canonical schema bundled with the running release."""

    return _json_bytes(load_schema())


def _record_index(records: list[dict[str, Any]], record_id: str, *, label: str) -> int:
    for index, record in enumerate(records):
        if record.get("id") == record_id:
            return index
    raise ValueError(f"{label} non trovato: {record_id}")


def build_asset_profile_json(
    snapshot: Mapping[str, Any],
    *,
    asset_id: str,
    mode: str = "technical",
    salt: bytes | None = None,
) -> bytes:
    """Build a deterministic profile using only explicit canonical asset references."""

    original_assets = list(snapshot.get("assets", []))
    asset_index = _record_index(original_assets, asset_id, label="Asset")
    if mode == "technical":
        exported = snapshot
    else:
        exported = redacted_snapshot(snapshot, mode=mode, salt=salt)
    asset = exported["assets"][asset_index]
    exported_asset_id = asset["id"]
    flows = [
        flow
        for flow in exported["flows"]
        if exported_asset_id in {flow["left_asset_id"], flow["right_asset_id"]}
    ]
    related_flow_ids = {flow["id"] for flow in flows}
    identity_links = [
        link
        for link in exported["identity_links"]
        if link["asset_id"] == exported_asset_id
    ]
    linked_vm_ids = {link["virtual_machine_id"] for link in identity_links}
    profile = {
        "profile_version": "1.0",
        "snapshot_id": exported["snapshot_id"],
        "snapshot_sha256": snapshot_sha256(snapshot),
        "snapshot_generated_at": exported.get("generated_at"),
        "snapshot_sync": {
            "state": exported.get("sync", {}).get("state"),
            "completed_at": exported.get("sync", {}).get("completed_at"),
        },
        "contract_version": exported["schema_version"],
        "exporter_version": __version__,
        "mode": mode,
        "asset": asset,
        "identity_links": identity_links,
        "virtual_machines": [
            vm for vm in exported["virtual_machines"] if vm["id"] in linked_vm_ids
        ],
        "risk_scores": [
            score
            for score in exported["risk_scores"]
            if score["asset_id"] == exported_asset_id
        ],
        "vulnerabilities": [
            vulnerability
            for vulnerability in exported["vulnerabilities"]
            if vulnerability["asset_id"] == exported_asset_id
        ],
        "activities": [
            activity
            for activity in exported["activities"]
            if exported_asset_id in activity["asset_ids"]
        ],
        "events": [
            event
            for event in exported["events"]
            if exported_asset_id in event["asset_ids"]
        ],
        "flows": flows,
        "baseline_differences": [
            difference
            for difference in exported["baseline_differences"]
            if exported_asset_id in difference["asset_ids"]
            or difference["flow_id"] in related_flow_ids
        ],
    }
    return _json_bytes(profile)


def build_cve_dossier_json(
    snapshot: Mapping[str, Any],
    *,
    catalog_record: Mapping[str, Any],
    mode: str = "technical",
    salt: bytes | None = None,
) -> bytes:
    """Build one deterministic CVE dossier using exact source-owned identifiers.

    A global catalog entry is not evidence that a device is vulnerable.  Device
    associations are included only when their ``external_id`` exactly matches the
    selected catalog record; Cisco risk scores remain separate records.
    """

    requested_external_id = str(catalog_record.get("external_id") or "").strip()
    source_record_id = str(catalog_record.get("source_record_id") or "").strip()
    if not requested_external_id and not source_record_id:
        raise ValueError("Il record catalogo deve avere external_id o source_record_id")

    original_source = next(
        (
            source
            for source in snapshot.get("sources", [])
            if source.get("type") == "cisco_cyber_vision"
        ),
        {},
    )
    original_details = original_source.get("details")
    original_catalog = (
        original_details.get("vulnerability_catalog", [])
        if isinstance(original_details, Mapping)
        else []
    )
    if source_record_id:
        match_indices = [
            index
            for index, item in enumerate(original_catalog)
            if isinstance(item, Mapping)
            and str(item.get("source_record_id") or "") == source_record_id
        ]
    else:
        match_indices = [
            index
            for index, item in enumerate(original_catalog)
            if isinstance(item, Mapping)
            and str(item.get("external_id") or "").casefold()
            == requested_external_id.casefold()
        ]
    if len(match_indices) != 1:
        raise ValueError(
            "Il record CVE selezionato non è risolvibile in modo univoco nel catalogo Cisco."
        )
    catalog_index = match_indices[0]

    if mode == "technical":
        exported = snapshot
    else:
        exported = redacted_snapshot(snapshot, mode=mode, salt=salt)
    classic_source = next(
        (
            source
            for source in exported.get("sources", [])
            if source.get("type") == "cisco_cyber_vision"
        ),
        {},
    )
    details = classic_source.get("details")
    catalog = details.get("vulnerability_catalog", []) if isinstance(details, Mapping) else []
    if catalog_index >= len(catalog) or not isinstance(catalog[catalog_index], Mapping):
        raise ValueError(
            "Il catalogo CVE redatto non conserva l'identità strutturale del record."
        )
    exported_catalog_record = dict(catalog[catalog_index])
    external_id = str(exported_catalog_record.get("external_id") or "").strip()
    associations = [
        vulnerability
        for vulnerability in exported.get("vulnerabilities", [])
        if external_id
        and str(vulnerability.get("external_id") or "").casefold()
        == external_id.casefold()
    ]
    assets = {asset["id"]: asset for asset in exported.get("assets", [])}
    scores = {
        score["asset_id"]: score for score in exported.get("risk_scores", [])
    }
    capabilities = classic_source.get("capabilities", {})
    catalog_capability = capabilities.get("vulnerabilities", {})
    device_associations_capability = capabilities.get("device_vulnerabilities", {})
    device_associations_available = device_associations_capability.get("status") in {
        "available",
        "partial",
        "truncated",
    }
    if not device_associations_available:
        association_statement = (
            "Lo snapshot contiene associazioni device–vulnerabilità esplicite, ma la "
            "capability Cisco non è disponibile: la completezza non è verificabile."
            if associations
            else "Associazioni device–vulnerabilità non verificabili: la capability "
            "Cisco non è disponibile in questo snapshot."
        )
    elif associations:
        association_statement = (
            "Associazioni device–vulnerabilità restituite esplicitamente da Cisco."
        )
    else:
        association_statement = (
            "Presente nel catalogo globale Cisco; nessuna associazione "
            "device–vulnerabilità restituita."
        )
    dossier = {
        "dossier_version": "1.0",
        "snapshot_id": exported["snapshot_id"],
        "snapshot_sha256": snapshot_sha256(snapshot),
        "snapshot_generated_at": exported.get("generated_at"),
        "snapshot_sync": {
            "state": exported.get("sync", {}).get("state"),
            "completed_at": exported.get("sync", {}).get("completed_at"),
        },
        "contract_version": exported["schema_version"],
        "exporter_version": __version__,
        "mode": mode,
        "catalog_source": {
            "source_id": classic_source.get("id"),
            "source_label": classic_source.get("label"),
            "source_version": classic_source.get("version"),
            "last_success_at": classic_source.get("last_success_at"),
            # Keep the original key for backwards-compatible consumers.
            "capability": catalog_capability,
            "catalog_capability": catalog_capability,
            "device_associations_capability": device_associations_capability,
        },
        "catalog_record": exported_catalog_record,
        "association_statement": association_statement,
        "device_associations": [
            {
                "vulnerability": association,
                "asset": assets.get(association.get("asset_id")),
                "cisco_device_risk_score": scores.get(association.get("asset_id")),
            }
            for association in associations
        ],
    }
    return _json_bytes(dossier)


def _explicit_signal_asset_ids(
    exported: Mapping[str, Any],
    *,
    collection: str,
    record: Mapping[str, Any],
) -> set[str]:
    known_asset_ids = {asset["id"] for asset in exported["assets"]}
    if collection == "events":
        references = record.get("asset_ids", [])
    else:
        references = record.get("entity_ids", [])
    return {
        reference
        for reference in references
        if isinstance(reference, str) and reference in known_asset_ids
    }


def build_signal_evidence_bundle(
    snapshot: Mapping[str, Any],
    *,
    signal_type: str,
    signal_id: str,
    mode: str = "technical",
    salt: bytes | None = None,
) -> bytes:
    """Build evidence for one event or finding without inferred correlations.

    Assets must be directly referenced by the selected record. Flows are included only
    when at least one endpoint has one of those proven asset IDs.
    """

    collection = _SIGNAL_COLLECTIONS.get(signal_type)
    if collection is None:
        raise ValueError("signal_type deve essere 'event' o 'finding'")
    original_records = list(snapshot.get(collection, []))
    record_index = _record_index(original_records, signal_id, label=signal_type.capitalize())
    exported = redacted_snapshot(snapshot, mode=mode, salt=salt)
    record = exported[collection][record_index]
    asset_ids = _explicit_signal_asset_ids(
        exported,
        collection=collection,
        record=record,
    )
    assets = [asset for asset in exported["assets"] if asset["id"] in asset_ids]
    flows = [
        flow
        for flow in exported["flows"]
        if asset_ids.intersection({flow["left_asset_id"], flow["right_asset_id"]})
    ]
    files: dict[str, bytes] = {
        "record.json": _json_bytes(record),
        "assets.json": _json_bytes(assets),
        "related-flows.csv": _csv_bytes(flows),
        "README.txt": (
            "DTLab OT Security evidence bundle\n"
            f"Tipo segnale: {signal_type}\n"
            f"Record: {record['id']}\n"
            f"Snapshot: {exported['snapshot_id']}\n"
            f"Modalità: {mode}\n"
            "Asset inclusi soltanto se referenziati direttamente dal record.\n"
            "Flow inclusi soltanto tramite endpoint asset esplicitamente correlati.\n"
        ).encode(),
    }
    manifest = {
        "manifest_version": EXPORT_MANIFEST_VERSION,
        "bundle_type": "dtlab_signal_evidence",
        "signal_type": signal_type,
        "signal_id": record["id"],
        "snapshot_id": exported["snapshot_id"],
        "snapshot_sha256": snapshot_sha256(snapshot),
        "contract_version": exported["schema_version"],
        "exporter_version": __version__,
        "mode": mode,
        "correlated_asset_ids": sorted(asset_ids),
        "files": _file_manifest(files),
    }
    files["manifest.json"] = _json_bytes(manifest)
    return _archive_bytes(files)


def build_export_bundle(
    snapshot: Mapping[str, Any],
    *,
    mode: str,
    salt: bytes | None = None,
    asset_id: str | None = None,
    start: datetime | None = None,
    end: datetime | None = None,
) -> bytes:
    scoped = _filtered_snapshot(snapshot, asset_id=asset_id, start=start, end=end)
    exported = redacted_snapshot(scoped, mode=mode, salt=salt)
    files: dict[str, bytes] = {
        "snapshot.json": _json_bytes(exported),
        "README.txt": (
            "DTLab OT Security evidence bundle\n"
            f"Snapshot: {exported['snapshot_id']}\n"
            f"Modalità: {mode}\n"
            "Risk score: esclusivamente Cisco Cyber Vision per-device.\n"
            "Qualità dati DTLab: metrica separata, non è un risk score.\n"
        ).encode(),
    }
    for collection in _COLLECTIONS:
        files[f"tables/{collection}.csv"] = _csv_bytes(exported.get(collection, []))
    if mode == "technical":
        files["schema/dtlab-snapshot-v2.schema.json"] = build_snapshot_schema_json()
        files["tables/sources.csv"] = _csv_bytes(exported["sources"])

    manifest = {
        "manifest_version": EXPORT_MANIFEST_VERSION,
        "bundle_type": "dtlab_snapshot_export",
        "snapshot_id": exported["snapshot_id"],
        "snapshot_sha256": snapshot_sha256(snapshot),
        "schema_version": exported["schema_version"],
        "contract_version": exported["schema_version"],
        "exporter_version": __version__,
        "mode": mode,
        "asset_id": asset_id,
        "window": {
            "from": start.isoformat() if start else None,
            "to": end.isoformat() if end else None,
        },
        "files": _file_manifest(files),
    }
    files["manifest.json"] = _json_bytes(manifest)
    return _archive_bytes(files)
