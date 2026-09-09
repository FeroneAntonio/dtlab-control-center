"""Idempotent conversion of immutable DTLab snapshots into operational signals."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from dtlab.contract import snapshot_sha256, validate_snapshot
from dtlab.services.ticket_store import IngestStats, SignalInput, TicketStore


@dataclass(frozen=True, slots=True)
class SnapshotIngestResult:
    """Outcome of one verified snapshot ingest."""

    snapshot_sha256: str
    signals_seen: int
    signals_created: int
    occurrences_created: int


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _fingerprint(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _text(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _evidence(record: Mapping[str, Any]) -> dict[str, Any]:
    value = record.get("evidence")
    return dict(value) if isinstance(value, Mapping) else {}


def _observed_at(
    record: Mapping[str, Any],
    *,
    snapshot_generated_at: str,
    fallback: str | None,
) -> str:
    evidence = _evidence(record)
    return str(
        evidence.get("observed_at")
        or fallback
        or evidence.get("fetched_at")
        or snapshot_generated_at
    )


def _severity(value: object) -> str:
    return (_text(value) or "unknown").lower()


def _source_identity(evidence: Mapping[str, Any]) -> dict[str, str | None]:
    return {
        "source_id": _text(evidence.get("source_id")),
        "source_record_id": _text(evidence.get("source_record_id")),
    }


def _event_signal(
    record: Mapping[str, Any],
    *,
    digest: str,
    generated_at: str,
) -> SignalInput:
    evidence = _evidence(record)
    source = _source_identity(evidence)
    source_record_id = source["source_record_id"]
    positional_fallback = bool(
        source_record_id
        and source_record_id.startswith("dashboard-event:")
        and source_record_id.removeprefix("dashboard-event:").isdigit()
    )
    if source_record_id and not positional_fallback:
        identity: dict[str, Any] = {"signal_type": "event", **source}
    else:
        # A list position is not stable across snapshots.  The semantic fallback uses
        # only source-owned fields and never adds an inferred asset relationship.
        identity = {
            "signal_type": "event",
            "source_id": source["source_id"],
            "occurred_at": record.get("occurred_at"),
            "center_id": record.get("center_id"),
            "category": record.get("category"),
            "title": record.get("title"),
            "severity": record.get("severity"),
            "asset_ids": sorted(str(value) for value in record.get("asset_ids", [])),
        }
    occurred_at = _text(record.get("occurred_at"))
    title = _text(record.get("title")) or "Evento Cyber Vision"
    description = _text(record.get("description")) or title
    return SignalInput(
        fingerprint=_fingerprint(identity),
        signal_type="event",
        snapshot_sha256=digest,
        evidence=evidence,
        severity=_severity(record.get("severity")),
        title=title,
        description=description,
        occurred_at=occurred_at,
        observed_at=_observed_at(
            record,
            snapshot_generated_at=generated_at,
            fallback=occurred_at,
        ),
        asset_ids=tuple(sorted(str(value) for value in record.get("asset_ids", []))),
        recommended_action=None,
        payload=dict(record),
    )


def _finding_signal(
    record: Mapping[str, Any],
    *,
    digest: str,
    generated_at: str,
    known_asset_ids: frozenset[str],
) -> SignalInput:
    evidence = _evidence(record)
    entity_ids = tuple(sorted(str(value) for value in record.get("entity_ids", [])))
    identity = {
        "signal_type": "finding",
        "source_id": evidence.get("source_id"),
        "code": record.get("code"),
        "entity_ids": entity_ids,
    }
    occurred_at = _text(record.get("last_detected_at")) or _text(
        record.get("first_detected_at")
    )
    title = _text(record.get("title")) or (_text(record.get("code")) or "Finding DTLab")
    description = _text(record.get("description")) or title
    # Findings may reference VMs, networks, or the environment.  Only identifiers
    # already present in snapshot.assets are exported as asset correlations.
    asset_ids = tuple(value for value in entity_ids if value in known_asset_ids)
    return SignalInput(
        fingerprint=_fingerprint(identity),
        signal_type="finding",
        snapshot_sha256=digest,
        evidence=evidence,
        severity=_severity(record.get("severity")),
        title=title,
        description=description,
        occurred_at=occurred_at,
        observed_at=_observed_at(
            record,
            snapshot_generated_at=generated_at,
            fallback=occurred_at,
        ),
        asset_ids=asset_ids,
        recommended_action=_text(record.get("recommended_action")),
        payload=dict(record),
    )


def _baseline_difference_signal(
    record: Mapping[str, Any],
    *,
    digest: str,
    generated_at: str,
) -> SignalInput:
    evidence = _evidence(record)
    identity = {
        "signal_type": "baseline_difference",
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
    occurred_at = _text(record.get("detected_at"))
    difference_type = _text(record.get("difference_type")) or "unknown"
    description = _text(record.get("description")) or difference_type
    return SignalInput(
        fingerprint=_fingerprint(identity),
        signal_type="baseline_difference",
        snapshot_sha256=digest,
        evidence=evidence,
        severity="unknown",
        title=f"Differenza baseline: {difference_type}",
        description=description,
        occurred_at=occurred_at,
        observed_at=_observed_at(
            record,
            snapshot_generated_at=generated_at,
            fallback=occurred_at,
        ),
        asset_ids=tuple(sorted(str(value) for value in record.get("asset_ids", []))),
        recommended_action=None,
        payload=dict(record),
    )


def _vulnerability_signal(
    record: Mapping[str, Any],
    *,
    digest: str,
    generated_at: str,
) -> SignalInput:
    evidence = _evidence(record)
    external_id = _text(record.get("external_id"))
    source_record_id = _text(evidence.get("source_record_id"))
    identity = {
        "signal_type": "vulnerability",
        "source_id": evidence.get("source_id"),
        "asset_id": record.get("asset_id"),
        "vulnerability_id": external_id or source_record_id or record.get("id"),
    }
    details = record.get("details") if isinstance(record.get("details"), Mapping) else {}
    occurred_at = _text(details.get("matching_at")) or _text(record.get("published_at"))
    title = _text(record.get("title")) or external_id or "Vulnerabilità"
    description = (
        _text(details.get("full_description"))
        or _text(details.get("summary"))
        or title
    )
    asset_id = _text(record.get("asset_id"))
    return SignalInput(
        fingerprint=_fingerprint(identity),
        signal_type="vulnerability",
        snapshot_sha256=digest,
        evidence=evidence,
        severity=_severity(record.get("severity")),
        title=title,
        description=description,
        occurred_at=occurred_at,
        observed_at=_observed_at(
            record,
            snapshot_generated_at=generated_at,
            fallback=occurred_at,
        ),
        asset_ids=(asset_id,) if asset_id else (),
        recommended_action=_text(details.get("solution")),
        payload=dict(record),
    )


def _new_ui_signal_evidence(
    source: Mapping[str, Any],
    *,
    source_record_id: str,
) -> dict[str, Any]:
    """Create record-level evidence without claiming a Classic asset correlation."""

    raw_evidence = source.get("evidence")
    evidence = dict(raw_evidence) if isinstance(raw_evidence, Mapping) else {}
    evidence["source_id"] = str(source["id"])
    evidence["source_record_id"] = source_record_id
    notes = [str(note) for note in evidence.get("notes", []) if _text(note)]
    scope_note = (
        "L'ID asset appartiene al profilo Cisco New UI; nessuna associazione con "
        "un Device Classic è stata inferita."
    )
    if scope_note not in notes:
        notes.append(scope_note)
    evidence["notes"] = notes
    return evidence


def _new_ui_alert_identity(
    source_id: str,
    asset_id: str,
    alert: Mapping[str, Any],
) -> dict[str, Any]:
    """Prefer native instance IDs, with a stable source-field-only fallback."""

    instance_id = _text(alert.get("instance_id"))
    alert_id = _text(alert.get("alert_id"))
    identity: dict[str, Any] = {
        "signal_type": "new_ui_alert",
        "source_id": source_id,
        "asset_id": asset_id,
    }
    if instance_id:
        identity["instance_id"] = instance_id
    elif alert_id:
        identity["alert_id"] = alert_id
    else:
        identity["source_fields"] = {
            "alert_type": alert.get("alert_type"),
            "category": alert.get("category"),
            "trigger": alert.get("trigger"),
        }
    return identity


def _new_ui_alert_signal(
    source: Mapping[str, Any],
    asset: Mapping[str, Any],
    alert: Mapping[str, Any],
    *,
    digest: str,
    generated_at: str,
) -> SignalInput | None:
    source_id = str(source["id"])
    asset_id = _text(asset.get("asset_id"))
    if not asset_id:
        return None
    identity = _new_ui_alert_identity(source_id, asset_id, alert)
    fingerprint = _fingerprint(identity)
    instance_id = _text(alert.get("instance_id"))
    alert_id = _text(alert.get("alert_id"))
    native_id = instance_id or alert_id or fingerprint
    evidence = _new_ui_signal_evidence(
        source,
        source_record_id=f"new-ui-alert:{asset_id}:{native_id}",
    )
    occurred_at = _text(alert.get("last_occurrence"))
    status = _text(alert.get("status")) or _text(asset.get("query_status"))
    alert_type = _text(alert.get("alert_type"))
    category = _text(alert.get("category"))
    trigger = _text(alert.get("trigger"))
    title = trigger or alert_type or alert_id or "Alert Cisco New UI"
    description_parts = [part for part in (category, alert_type, trigger) if part]
    description = " · ".join(dict.fromkeys(description_parts)) or title
    payload = {
        "source_scope": "cisco_cyber_vision_new_ui",
        "center_id": source.get("details", {}).get("center_id"),
        "asset_id": asset_id,
        "asset_name": _text(asset.get("asset_name")),
        "status": status,
        "alert": dict(alert),
        "evidence": evidence,
    }
    return SignalInput(
        fingerprint=fingerprint,
        signal_type="new_ui_alert",
        snapshot_sha256=digest,
        evidence=evidence,
        severity=_severity(alert.get("severity")),
        title=title,
        description=description,
        occurred_at=occurred_at,
        observed_at=_observed_at(
            payload,
            snapshot_generated_at=generated_at,
            fallback=occurred_at,
        ),
        # This is the explicit New UI profile ID.  It is deliberately not
        # rewritten to a canonical Classic asset ID.
        asset_ids=(asset_id,),
        recommended_action=None,
        payload=payload,
    )


def _cvss_severity(value: object) -> str:
    """Return the standard CVSS qualitative band, or unknown for invalid scores."""

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


def _new_ui_vulnerability_signal(
    source: Mapping[str, Any],
    asset: Mapping[str, Any],
    vulnerability: Mapping[str, Any],
    *,
    digest: str,
    generated_at: str,
) -> SignalInput | None:
    source_id = str(source["id"])
    asset_id = _text(asset.get("asset_id"))
    if not asset_id:
        return None
    cve_id = _text(vulnerability.get("cve_id"))
    name = _text(vulnerability.get("name"))
    vulnerability_source = _text(vulnerability.get("source"))
    source_key: Any = cve_id or {
        "name": name,
        "source": vulnerability_source,
    }
    identity = {
        "signal_type": "new_ui_vulnerability",
        "source_id": source_id,
        "asset_id": asset_id,
        "vulnerability_id": source_key,
    }
    fingerprint = _fingerprint(identity)
    native_id = cve_id or fingerprint
    evidence = _new_ui_signal_evidence(
        source,
        source_record_id=f"new-ui-vulnerability:{asset_id}:{native_id}",
    )
    title = name or cve_id or "Vulnerabilità Cisco New UI"
    description_parts = [
        cve_id,
        f"Fonte {vulnerability_source}" if vulnerability_source else None,
        (
            f"CVSS {vulnerability.get('cvss_score')}"
            if _text(vulnerability.get("cvss_score"))
            else None
        ),
        (
            f"CSRS {vulnerability.get('csrs_score')}"
            if _text(vulnerability.get("csrs_score"))
            else None
        ),
    ]
    description = " · ".join(part for part in description_parts if part) or title
    payload = {
        "source_scope": "cisco_cyber_vision_new_ui",
        "center_id": source.get("details", {}).get("center_id"),
        "asset_id": asset_id,
        "asset_name": _text(asset.get("asset_name")),
        "vulnerability": dict(vulnerability),
        "evidence": evidence,
    }
    return SignalInput(
        fingerprint=fingerprint,
        signal_type="new_ui_vulnerability",
        snapshot_sha256=digest,
        evidence=evidence,
        severity=_cvss_severity(vulnerability.get("cvss_score")),
        title=title,
        description=description,
        occurred_at=None,
        observed_at=_observed_at(
            payload,
            snapshot_generated_at=generated_at,
            fallback=None,
        ),
        asset_ids=(asset_id,),
        recommended_action=None,
        payload=payload,
    )


def _alert_status_rank(signal: SignalInput) -> int:
    payload_status = _text(signal.payload.get("status"))
    return {
        "active": 3,
        "muted": 2,
        "cleared": 1,
    }.get((payload_status or "").casefold(), 2)


def _new_ui_signals(
    source: Mapping[str, Any],
    *,
    digest: str,
    generated_at: str,
) -> tuple[SignalInput, ...]:
    """Flatten source-owned New UI detail records and deduplicate API overlaps."""

    details = source.get("details")
    if not isinstance(details, Mapping):
        return ()
    alerts: dict[str, SignalInput] = {}
    alert_assets = details.get("alert_assets")
    for asset in alert_assets if isinstance(alert_assets, list) else []:
        if not isinstance(asset, Mapping):
            continue
        records = asset.get("alerts")
        for alert in records if isinstance(records, list) else []:
            if not isinstance(alert, Mapping):
                continue
            signal = _new_ui_alert_signal(
                source,
                asset,
                alert,
                digest=digest,
                generated_at=generated_at,
            )
            if signal is None:
                continue
            existing = alerts.get(signal.fingerprint)
            # Three independent status queries can briefly overlap.  Prefer Active
            # deterministically so a live alert cannot be hidden as historical.
            if existing is None or _alert_status_rank(signal) > _alert_status_rank(existing):
                alerts[signal.fingerprint] = signal

    vulnerabilities: dict[str, SignalInput] = {}
    vulnerability_assets = details.get("vulnerability_assets")
    for asset in vulnerability_assets if isinstance(vulnerability_assets, list) else []:
        if not isinstance(asset, Mapping):
            continue
        records = asset.get("vulnerabilities")
        for vulnerability in records if isinstance(records, list) else []:
            if not isinstance(vulnerability, Mapping):
                continue
            signal = _new_ui_vulnerability_signal(
                source,
                asset,
                vulnerability,
                digest=digest,
                generated_at=generated_at,
            )
            if signal is not None:
                vulnerabilities.setdefault(signal.fingerprint, signal)
    return (*alerts.values(), *vulnerabilities.values())


def signals_from_snapshot(
    snapshot: Mapping[str, Any],
    *,
    expected_sha256: str | None = None,
) -> tuple[str, tuple[SignalInput, ...]]:
    """Validate a snapshot and prepare source-owned signals without correlation guesses."""

    validate_snapshot(snapshot)
    digest = snapshot_sha256(snapshot)
    if expected_sha256 is not None and expected_sha256.lower() != digest:
        raise ValueError(
            f"SHA snapshot non corrispondente: atteso {expected_sha256.lower()}, calcolato {digest}"
        )
    generated_at = str(snapshot["generated_at"])
    known_asset_ids = frozenset(str(asset["id"]) for asset in snapshot["assets"])
    signals: list[SignalInput] = []
    signals.extend(
        _event_signal(record, digest=digest, generated_at=generated_at)
        for record in snapshot["events"]
    )
    signals.extend(
        _finding_signal(
            record,
            digest=digest,
            generated_at=generated_at,
            known_asset_ids=known_asset_ids,
        )
        for record in snapshot["findings"]
    )
    signals.extend(
        _baseline_difference_signal(record, digest=digest, generated_at=generated_at)
        for record in snapshot["baseline_differences"]
    )
    signals.extend(
        _vulnerability_signal(record, digest=digest, generated_at=generated_at)
        for record in snapshot["vulnerabilities"]
    )
    for source in snapshot["sources"]:
        if source.get("type") != "cisco_cyber_vision_new_ui":
            continue
        signals.extend(
            _new_ui_signals(
                source,
                digest=digest,
                generated_at=generated_at,
            )
        )
    return digest, tuple(signals)


def ingest_snapshot(
    store: TicketStore,
    snapshot: Mapping[str, Any],
    *,
    expected_sha256: str | None = None,
) -> SnapshotIngestResult:
    """Validate and atomically ingest all supported signal collections."""

    digest, signals = signals_from_snapshot(snapshot, expected_sha256=expected_sha256)
    stats: IngestStats = store.ingest_snapshot_signals(
        signals,
        snapshot_sha256=digest,
        snapshot_id=str(snapshot["snapshot_id"]),
        generated_at=str(snapshot["generated_at"]),
    )
    return SnapshotIngestResult(
        snapshot_sha256=digest,
        signals_seen=stats.signals_seen,
        signals_created=stats.signals_created,
        occurrences_created=stats.occurrences_created,
    )
