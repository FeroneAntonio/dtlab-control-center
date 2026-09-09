"""Deterministic, source-owned SIEM exports for canonical DTLab snapshots.

The exporter is deliberately independent from the mutable ticket store.  It emits
only records and relationships explicitly present in one validated v2 snapshot.
The current contract supports the technical mode only; consumers that need public
redaction must not treat this export as safe for unrestricted distribution.
"""

from __future__ import annotations

import hashlib
import io
import json
import zipfile
from collections import Counter
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

from dtlab.contract import snapshot_sha256, validate_snapshot

SIEM_EVENT_SCHEMA_VERSION = "dtlab-siem-event-v1"
SIEM_MANIFEST_SCHEMA_VERSION = "dtlab-siem-manifest-v1"
SIEM_BUNDLE_VERSION = "1.0"

_SIEM_DATASETS = (
    "dtlab.baseline_difference",
    "dtlab.device_vulnerability",
    "dtlab.event",
    "dtlab.finding",
    "dtlab.new_ui.alert",
    "dtlab.new_ui.vulnerability",
)

_SEVERITIES = frozenset({"critical", "high", "medium", "low", "info", "unknown"})
_CEF_SEVERITY = {
    "critical": 10,
    "high": 8,
    "medium": 5,
    "low": 3,
    "info": 1,
    "unknown": 0,
}


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _text(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _normalized_severity(value: object) -> str:
    severity = (_text(value) or "unknown").casefold()
    return severity if severity in _SEVERITIES else "unknown"


def _cvss_severity(value: object) -> str:
    try:
        score = float(str(value).strip())
    except (TypeError, ValueError):
        return "unknown"
    if not 0 <= score <= 10:
        return "unknown"
    if score >= 9:
        return "critical"
    if score >= 7:
        return "high"
    if score >= 4:
        return "medium"
    if score > 0:
        return "low"
    return "info"


def _utc_timestamp(value: object, *, fallback: str) -> str:
    candidate = _text(value) or fallback
    parsed = datetime.fromisoformat(candidate.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("I timestamp SIEM devono includere il fuso orario")
    return parsed.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _evidence(record: Mapping[str, Any]) -> dict[str, Any]:
    raw = record.get("evidence")
    return dict(raw) if isinstance(raw, Mapping) else {}


def _stable_event_id(identity: Mapping[str, Any]) -> str:
    digest = hashlib.sha256(_canonical_json(identity).encode("utf-8")).hexdigest()
    return f"dtlab:siem:{digest}"


def _event_identity(record: Mapping[str, Any], evidence: Mapping[str, Any]) -> dict[str, Any]:
    source_record_id = _text(evidence.get("source_record_id"))
    positional = bool(
        source_record_id
        and source_record_id.startswith("dashboard-event:")
        and source_record_id.removeprefix("dashboard-event:").isdigit()
    )
    if source_record_id and not positional:
        return {
            "dataset": "dtlab.event",
            "source_id": evidence.get("source_id"),
            "source_record_id": source_record_id,
        }
    return {
        "dataset": "dtlab.event",
        "source_id": evidence.get("source_id"),
        "occurred_at": record.get("occurred_at"),
        "center_id": record.get("center_id"),
        "category": record.get("category"),
        "title": record.get("title"),
        "severity": record.get("severity"),
        "asset_ids": sorted(str(value) for value in record.get("asset_ids", [])),
    }


def _base_event(
    *,
    identity: Mapping[str, Any],
    dataset: str,
    event_type: str,
    severity: str,
    title: str,
    description: str,
    asset_ids: list[str],
    source_id: str | None,
    source_record_id: str | None,
    timestamp: object,
    timestamp_basis: str,
    snapshot: Mapping[str, Any],
    digest: str,
    truth: object,
) -> dict[str, Any]:
    return {
        "schema_version": SIEM_EVENT_SCHEMA_VERSION,
        "event_id": _stable_event_id(identity),
        "timestamp": _utc_timestamp(timestamp, fallback=str(snapshot["generated_at"])),
        "timestamp_basis": timestamp_basis,
        "dataset": dataset,
        "type": event_type,
        "severity": severity,
        "title": title,
        "description": description,
        "asset_ids": sorted(dict.fromkeys(asset_ids)),
        "source_id": source_id,
        "source_record_id": source_record_id,
        "truth": _text(truth) or "unavailable",
        "snapshot_id": str(snapshot["snapshot_id"]),
        "snapshot_sha256": digest,
    }


def _classic_events(snapshot: Mapping[str, Any], digest: str) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    known_asset_ids = frozenset(str(asset["id"]) for asset in snapshot["assets"])

    for record in snapshot["events"]:
        evidence = _evidence(record)
        result.append(
            _base_event(
                identity=_event_identity(record, evidence),
                dataset="dtlab.event",
                event_type=_text(record.get("category")) or "event",
                severity=_normalized_severity(record.get("severity")),
                title=_text(record.get("title")) or "Evento Cisco",
                description=_text(record.get("description")) or "Evento Cisco",
                asset_ids=[str(value) for value in record.get("asset_ids", [])],
                source_id=_text(evidence.get("source_id")),
                source_record_id=_text(evidence.get("source_record_id")),
                timestamp=record.get("occurred_at"),
                timestamp_basis="occurred_at",
                snapshot=snapshot,
                digest=digest,
                truth=evidence.get("truth"),
            )
        )

    for record in snapshot["findings"]:
        evidence = _evidence(record)
        entity_ids = sorted(str(value) for value in record.get("entity_ids", []))
        result.append(
            _base_event(
                identity={
                    "dataset": "dtlab.finding",
                    "source_id": evidence.get("source_id"),
                    "code": record.get("code"),
                    "entity_ids": entity_ids,
                },
                dataset="dtlab.finding",
                event_type=_text(record.get("code")) or "finding",
                severity=_normalized_severity(record.get("severity")),
                title=_text(record.get("title")) or "Finding DTLab",
                description=_text(record.get("description")) or "Finding DTLab",
                asset_ids=[value for value in entity_ids if value in known_asset_ids],
                source_id=_text(evidence.get("source_id")),
                source_record_id=_text(evidence.get("source_record_id")),
                timestamp=record.get("last_detected_at") or record.get("first_detected_at"),
                timestamp_basis="last_detected_at",
                snapshot=snapshot,
                digest=digest,
                truth=evidence.get("truth"),
            )
        )

    for record in snapshot["baseline_differences"]:
        evidence = _evidence(record)
        identity = {
            "dataset": "dtlab.baseline_difference",
            "source_id": evidence.get("source_id"),
            "baseline_id": record.get("baseline_id"),
            "difference_type": record.get("difference_type"),
            "target_id": record.get("target_id"),
            "key": record.get("key"),
            "value": record.get("value"),
            "asset_ids": sorted(str(value) for value in record.get("asset_ids", [])),
            "flow_id": record.get("flow_id"),
            "detected_at": record.get("detected_at"),
        }
        difference_type = _text(record.get("difference_type")) or "baseline_difference"
        result.append(
            _base_event(
                identity=identity,
                dataset="dtlab.baseline_difference",
                event_type=difference_type,
                severity="unknown",
                title=f"Differenza baseline: {difference_type}",
                description=_text(record.get("description")) or difference_type,
                asset_ids=[str(value) for value in record.get("asset_ids", [])],
                source_id=_text(evidence.get("source_id")),
                source_record_id=_text(evidence.get("source_record_id")),
                timestamp=record.get("detected_at"),
                timestamp_basis="detected_at",
                snapshot=snapshot,
                digest=digest,
                truth=evidence.get("truth"),
            )
        )

    for record in snapshot["vulnerabilities"]:
        evidence = _evidence(record)
        details = record.get("details")
        details = details if isinstance(details, Mapping) else {}
        external_id = _text(record.get("external_id"))
        source_record_id = _text(evidence.get("source_record_id"))
        result.append(
            _base_event(
                identity={
                    "dataset": "dtlab.device_vulnerability",
                    "source_id": evidence.get("source_id"),
                    "asset_id": record.get("asset_id"),
                    "vulnerability_id": external_id or source_record_id or record.get("id"),
                },
                dataset="dtlab.device_vulnerability",
                event_type=external_id or "device_vulnerability",
                severity=_normalized_severity(record.get("severity")),
                title=_text(record.get("title")) or external_id or "Vulnerabilità",
                description=(
                    _text(details.get("full_description"))
                    or _text(details.get("summary"))
                    or _text(record.get("title"))
                    or "Vulnerabilità"
                ),
                asset_ids=[str(record["asset_id"])],
                source_id=_text(evidence.get("source_id")),
                source_record_id=source_record_id,
                timestamp=details.get("matching_at") or record.get("published_at"),
                timestamp_basis=(
                    "matching_at" if details.get("matching_at") else "published_at"
                ),
                snapshot=snapshot,
                digest=digest,
                truth=evidence.get("truth"),
            )
        )
    return result


def _new_ui_alert_key(source_id: str, asset_id: str, alert: Mapping[str, Any]) -> str:
    native_id = _text(alert.get("instance_id")) or _text(alert.get("alert_id"))
    identity: dict[str, Any] = {
        "dataset": "dtlab.new_ui.alert",
        "source_id": source_id,
        "asset_id": asset_id,
    }
    if native_id:
        identity["native_id"] = native_id
    else:
        identity["source_fields"] = {
            "alert_type": alert.get("alert_type"),
            "category": alert.get("category"),
            "trigger": alert.get("trigger"),
        }
    return _canonical_json(identity)


def _new_ui_records(snapshot: Mapping[str, Any], digest: str) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for source in snapshot["sources"]:
        if source.get("type") != "cisco_cyber_vision_new_ui":
            continue
        source_id = str(source["id"])
        source_evidence = _evidence(source)
        details = source.get("details")
        if not isinstance(details, Mapping):
            continue

        alerts: dict[str, tuple[int, str, Mapping[str, Any]]] = {}
        alert_assets = details.get("alert_assets")
        for asset in alert_assets if isinstance(alert_assets, list) else []:
            if not isinstance(asset, Mapping):
                continue
            asset_id = _text(asset.get("asset_id"))
            if not asset_id:
                continue
            records = asset.get("alerts")
            for alert in records if isinstance(records, list) else []:
                if not isinstance(alert, Mapping):
                    continue
                key = _new_ui_alert_key(source_id, asset_id, alert)
                status = (_text(alert.get("status")) or _text(asset.get("query_status")) or "")
                rank = {"active": 3, "muted": 2, "cleared": 1}.get(status.casefold(), 2)
                current = alerts.get(key)
                if current is None or rank > current[0]:
                    alerts[key] = (rank, asset_id, alert)

        for key in sorted(alerts):
            _rank, asset_id, alert = alerts[key]
            identity = json.loads(key)
            native_id = (
                _text(alert.get("instance_id"))
                or _text(alert.get("alert_id"))
                or _stable_event_id(identity).removeprefix("dtlab:siem:")
            )
            alert_type = _text(alert.get("alert_type")) or "new_ui_alert"
            trigger = _text(alert.get("trigger"))
            description_parts = [
                value
                for value in (_text(alert.get("category")), alert_type, trigger)
                if value
            ]
            result.append(
                _base_event(
                    identity=identity,
                    dataset="dtlab.new_ui.alert",
                    event_type=alert_type,
                    severity=_normalized_severity(alert.get("severity")),
                    title=trigger or alert_type,
                    description=" · ".join(dict.fromkeys(description_parts)),
                    asset_ids=[asset_id],
                    source_id=source_id,
                    source_record_id=f"new-ui-alert:{asset_id}:{native_id}",
                    timestamp=alert.get("last_occurrence"),
                    timestamp_basis=(
                        "last_occurrence"
                        if alert.get("last_occurrence")
                        else "snapshot_generated_at"
                    ),
                    snapshot=snapshot,
                    digest=digest,
                    truth=source_evidence.get("truth"),
                )
            )

        vulnerabilities: dict[str, tuple[str, Mapping[str, Any]]] = {}
        vulnerability_assets = details.get("vulnerability_assets")
        for asset in vulnerability_assets if isinstance(vulnerability_assets, list) else []:
            if not isinstance(asset, Mapping):
                continue
            asset_id = _text(asset.get("asset_id"))
            if not asset_id:
                continue
            records = asset.get("vulnerabilities")
            for vulnerability in records if isinstance(records, list) else []:
                if not isinstance(vulnerability, Mapping):
                    continue
                identity = {
                    "dataset": "dtlab.new_ui.vulnerability",
                    "source_id": source_id,
                    "asset_id": asset_id,
                    "vulnerability_id": _text(vulnerability.get("cve_id"))
                    or {
                        "name": _text(vulnerability.get("name")),
                        "source": _text(vulnerability.get("source")),
                    },
                }
                vulnerabilities.setdefault(_canonical_json(identity), (asset_id, vulnerability))

        for key in sorted(vulnerabilities):
            asset_id, vulnerability = vulnerabilities[key]
            identity = json.loads(key)
            cve_id = _text(vulnerability.get("cve_id"))
            title = _text(vulnerability.get("name")) or cve_id or "Vulnerabilità New UI"
            description_parts = [
                value
                for value in (
                    cve_id,
                    (
                        f"Fonte {vulnerability['source']}"
                        if _text(vulnerability.get("source"))
                        else None
                    ),
                    (
                        f"CVSS {vulnerability['cvss_score']}"
                        if _text(vulnerability.get("cvss_score"))
                        else None
                    ),
                    (
                        f"CSRS {vulnerability['csrs_score']}"
                        if _text(vulnerability.get("csrs_score"))
                        else None
                    ),
                )
                if value
            ]
            native_id = cve_id or _stable_event_id(identity).removeprefix("dtlab:siem:")
            result.append(
                _base_event(
                    identity=identity,
                    dataset="dtlab.new_ui.vulnerability",
                    event_type=cve_id or "new_ui_vulnerability",
                    severity=_cvss_severity(vulnerability.get("cvss_score")),
                    title=title,
                    description=" · ".join(description_parts) or title,
                    asset_ids=[asset_id],
                    source_id=source_id,
                    source_record_id=f"new-ui-vulnerability:{asset_id}:{native_id}",
                    timestamp=snapshot["generated_at"],
                    timestamp_basis="snapshot_generated_at",
                    snapshot=snapshot,
                    digest=digest,
                    truth=source_evidence.get("truth"),
                )
            )
    return result


def build_siem_events(snapshot: Mapping[str, Any]) -> tuple[dict[str, Any], ...]:
    """Return normalized SIEM events sorted by stable ``event_id``.

    The input must be one canonical DTLab v2 snapshot.  No ticket data and no
    name/IP/time-based correlation is added.  ``asset_ids`` contains only explicit
    source references; New UI profile identifiers remain in their own namespace.
    """

    validate_snapshot(snapshot)
    digest = snapshot_sha256(snapshot)
    records = [*_classic_events(snapshot, digest), *_new_ui_records(snapshot, digest)]
    records.sort(key=lambda item: (str(item["event_id"]), str(item["dataset"])))
    return tuple(records)


def _ndjson_bytes(events: tuple[dict[str, Any], ...]) -> bytes:
    if not events:
        return b""
    return ("\n".join(_canonical_json(event) for event in events) + "\n").encode("utf-8")


def build_siem_ndjson(snapshot: Mapping[str, Any]) -> bytes:
    """Return deterministic UTF-8 NDJSON with one normalized event per line."""

    return _ndjson_bytes(build_siem_events(snapshot))


def build_siem_event_schema_json() -> bytes:
    """Return the JSON Schema for one line of the NDJSON event stream."""

    schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://modbus.sitoclone.it/schemas/dtlab-siem-event-v1.schema.json",
        "title": "DTLab normalized SIEM event",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "schema_version",
            "event_id",
            "timestamp",
            "timestamp_basis",
            "dataset",
            "type",
            "severity",
            "title",
            "description",
            "asset_ids",
            "source_id",
            "source_record_id",
            "truth",
            "snapshot_id",
            "snapshot_sha256",
        ],
        "properties": {
            "schema_version": {"const": SIEM_EVENT_SCHEMA_VERSION},
            "event_id": {"type": "string", "pattern": "^dtlab:siem:[0-9a-f]{64}$"},
            "timestamp": {"type": "string", "format": "date-time"},
            "timestamp_basis": {"type": "string", "minLength": 1},
            "dataset": {"type": "string", "enum": list(_SIEM_DATASETS)},
            "type": {"type": "string", "minLength": 1},
            "severity": {"type": "string", "enum": sorted(_SEVERITIES)},
            "title": {"type": "string", "minLength": 1},
            "description": {"type": "string", "minLength": 1},
            "asset_ids": {
                "type": "array",
                "items": {"type": "string", "minLength": 1},
                "uniqueItems": True,
            },
            "source_id": {"type": ["string", "null"]},
            "source_record_id": {"type": ["string", "null"]},
            "truth": {"type": "string", "minLength": 1},
            "snapshot_id": {"type": "string", "minLength": 1},
            "snapshot_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
        },
    }
    return (json.dumps(schema, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode(
        "utf-8"
    )


def _cef_escape(value: object) -> str:
    text = "" if value is None else str(value)
    return (
        text.replace("\\", "\\\\")
        .replace("\r", "\\r")
        .replace("\n", "\\n")
        .replace("|", "\\|")
        .replace("=", "\\=")
    )


def _cef_timestamp(value: str) -> str:
    """Return CEF ``rt`` as UTC epoch milliseconds for broad parser support."""

    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("Il timestamp CEF deve includere il fuso orario")
    return str(int(parsed.astimezone(UTC).timestamp() * 1000))


def _cef_bytes(events: tuple[dict[str, Any], ...]) -> bytes:
    lines: list[str] = []
    for event in events:
        asset_ids = _canonical_json(event["asset_ids"])
        extension = (
            ("rt", _cef_timestamp(str(event["timestamp"]))),
            ("externalId", event["event_id"]),
            ("cs1Label", "dataset"),
            ("cs1", event["dataset"]),
            ("cs2Label", "asset_ids"),
            ("cs2", asset_ids),
            ("cs3Label", "source_id"),
            ("cs3", event["source_id"] or ""),
            ("cs4Label", "source_record_id"),
            ("cs4", event["source_record_id"] or ""),
            ("cs5Label", "snapshot_id"),
            ("cs5", event["snapshot_id"]),
            ("cs6Label", "snapshot_sha256"),
            ("cs6", event["snapshot_sha256"]),
            ("msg", event["description"]),
        )
        signature = f"{event['dataset']}:{event['type']}"
        line = (
            "CEF:0|DTLab|Control Center|2.0|"
            f"{_cef_escape(signature)}|{_cef_escape(event['title'])}|"
            f"{_CEF_SEVERITY[str(event['severity'])]}|"
            + " ".join(f"{key}={_cef_escape(value)}" for key, value in extension)
        )
        lines.append(line)
    return (("\n".join(lines) + "\n") if lines else "").encode("utf-8")


def build_siem_cef(snapshot: Mapping[str, Any]) -> bytes:
    """Return deterministic UTF-8 CEF lines for the normalized SIEM events."""

    return _cef_bytes(build_siem_events(snapshot))


def _zip_info(name: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = 0o640 << 16
    return info


def _readme(snapshot: Mapping[str, Any], digest: str, count: int) -> bytes:
    return (
        "DTLab SIEM export bundle\n"
        f"Bundle version: {SIEM_BUNDLE_VERSION}\n"
        f"Event schema: {SIEM_EVENT_SCHEMA_VERSION}\n"
        f"Snapshot: {snapshot['snapshot_id']}\n"
        f"Snapshot SHA-256: {digest}\n"
        f"Records: {count}\n\n"
        "This is a technical export and may contain real asset identifiers.\n"
        "It contains source-owned snapshot records only; no ticket-store data and no\n"
        "correlations inferred from names, addresses, or temporal proximity.\n"
        "New UI profile IDs are not rewritten as Classic device IDs.\n"
        "event-schema.json validates each events.ndjson line; CEF rt uses UTC epoch ms.\n"
        "Verify every file against manifest.json before ingestion.\n"
    ).encode()


def build_siem_export_bundle(
    snapshot: Mapping[str, Any],
    *,
    mode: str = "technical",
) -> bytes:
    """Return a deterministic ZIP containing NDJSON, CEF, README and manifest.

    Only ``mode="technical"`` is supported.  The manifest hashes every payload
    file and identifies the exact canonical snapshot from which it was built.
    """

    if mode != "technical":
        raise ValueError("SIEM export supportato solo in modalità technical")
    events = build_siem_events(snapshot)
    digest = snapshot_sha256(snapshot)
    ndjson = _ndjson_bytes(events)
    cef = _cef_bytes(events)
    readme = _readme(snapshot, digest, len(events))
    event_schema = build_siem_event_schema_json()
    files = {
        "events.cef": cef,
        "events.ndjson": ndjson,
        "event-schema.json": event_schema,
        "README.txt": readme,
    }
    datasets = Counter(str(event["dataset"]) for event in events)
    manifest = {
        "schema_version": SIEM_MANIFEST_SCHEMA_VERSION,
        "bundle_version": SIEM_BUNDLE_VERSION,
        "event_schema_version": SIEM_EVENT_SCHEMA_VERSION,
        "export_mode": mode,
        "snapshot_id": snapshot["snapshot_id"],
        "snapshot_sha256": digest,
        "snapshot_generated_at": snapshot["generated_at"],
        "record_count": len(events),
        "datasets": dict(sorted(datasets.items())),
        "correlation_policy": "explicit_source_references_only_no_inference",
        "files": {
            name: {
                "bytes": len(content),
                "sha256": hashlib.sha256(content).hexdigest(),
            }
            for name, content in sorted(files.items())
        },
    }
    files["manifest.json"] = (
        json.dumps(manifest, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    ).encode("utf-8")
    output = io.BytesIO()
    with zipfile.ZipFile(output, mode="w") as archive:
        for name, content in sorted(files.items()):
            archive.writestr(_zip_info(name), content)
    return output.getvalue()
