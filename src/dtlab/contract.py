"""Validation and freshness rules for the canonical DTLab snapshot."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable, Mapping
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

SCHEMA_VERSION = "2.0.0"
MAX_SNAPSHOT_BYTES = 25 * 1024 * 1024

TRUTH_LABELS_IT = {
    "real": "Reale",
    "observed": "Osservata",
    "expected": "Attesa",
    "demo": "Demo",
    "unavailable": "Non disponibile",
    "stale": "Obsoleta",
}

ENTITY_COLLECTIONS = (
    "sources",
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

_FORBIDDEN_KEY = re.compile(
    r"(?:password|passwd|authorization|credential|api[_-]?key|x[_-]?token[_-]?id|"
    r"access[_-]?token|refresh[_-]?token|client[_-]?secret|private[_-]?key)",
    re.IGNORECASE,
)
_URL_WITH_USERINFO = re.compile(r"https?://[^\s/:@]+:[^\s/@]+@", re.IGNORECASE)
_SECRET_QUERY = re.compile(
    r"[?&](?:token|api[_-]?key|password|secret|authorization)=[^&#\s]+",
    re.IGNORECASE,
)


class ContractValidationError(ValueError):
    """A snapshot failed structural, referential, or security validation."""

    def __init__(self, errors: Iterable[str]):
        self.errors = tuple(dict.fromkeys(errors))
        message = "Snapshot DTLab non valido:\n- " + "\n- ".join(self.errors)
        super().__init__(message)


def schema_path() -> Path:
    """Return the canonical JSON Schema path in a source or deployed checkout."""

    return Path(__file__).resolve().parents[2] / "schemas" / "dtlab-snapshot-v2.schema.json"


def load_schema() -> dict[str, Any]:
    return json.loads(schema_path().read_text(encoding="utf-8"))


def _format_jsonschema_error(error: Any) -> str:
    path = ".".join(str(part) for part in error.absolute_path) or "$"
    return f"{path}: {error.message}"


def _parse_datetime(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp senza fuso orario")
    return parsed.astimezone(UTC)


def _records(snapshot: Mapping[str, Any]) -> Iterable[tuple[str, Mapping[str, Any]]]:
    environment = snapshot.get("environment")
    if isinstance(environment, Mapping):
        yield "environment", environment
    for collection in ENTITY_COLLECTIONS:
        for record in snapshot.get(collection, []):
            if isinstance(record, Mapping):
                yield collection, record


def _evidences(value: Any, path: str = "$") -> Iterable[tuple[str, Mapping[str, Any]]]:
    if isinstance(value, Mapping):
        for key, nested in value.items():
            nested_path = f"{path}.{key}"
            if key == "evidence" and isinstance(nested, Mapping):
                yield nested_path, nested
            yield from _evidences(nested, nested_path)
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            yield from _evidences(nested, f"{path}[{index}]")


def find_secret_leaks(value: Any, path: str = "$") -> list[str]:
    """Return paths that look like credential material.

    Infrastructure addresses are not credentials and are intentionally not rejected here.
    Export-specific IP/MAC redaction is handled separately.
    """

    leaks: list[str] = []
    if isinstance(value, Mapping):
        for key, nested in value.items():
            nested_path = f"{path}.{key}"
            if _FORBIDDEN_KEY.search(str(key)):
                leaks.append(f"{nested_path}: nome campo sensibile")
            leaks.extend(find_secret_leaks(nested, nested_path))
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            leaks.extend(find_secret_leaks(nested, f"{path}[{index}]"))
    elif isinstance(value, str):
        if _URL_WITH_USERINFO.search(value):
            leaks.append(f"{path}: URL con credenziali incorporate")
        if _SECRET_QUERY.search(value):
            leaks.append(f"{path}: parametro segreto in URL")
    return leaks


def _unique_ids(snapshot: Mapping[str, Any]) -> tuple[dict[str, set[str]], list[str]]:
    ids: dict[str, set[str]] = {}
    errors: list[str] = []
    for collection in ENTITY_COLLECTIONS:
        seen: set[str] = set()
        for index, record in enumerate(snapshot.get(collection, [])):
            record_id = record.get("id") if isinstance(record, Mapping) else None
            if not isinstance(record_id, str):
                continue
            if record_id in seen:
                errors.append(f"{collection}[{index}].id: ID duplicato '{record_id}'")
            seen.add(record_id)
        ids[collection] = seen
    return ids, errors


def _missing_reference(
    errors: list[str],
    path: str,
    reference: Any,
    known_ids: set[str],
    *,
    nullable: bool = False,
) -> None:
    if reference is None and nullable:
        return
    if isinstance(reference, str) and reference not in known_ids:
        errors.append(f"{path}: riferimento sconosciuto '{reference}'")


def _cross_reference_errors(
    snapshot: Mapping[str, Any], ids: Mapping[str, set[str]]
) -> list[str]:
    errors: list[str] = []
    source_ids = ids["sources"]
    network_ids = ids["networks"]
    vm_ids = ids["virtual_machines"]
    asset_ids = ids["assets"]
    flow_ids = ids["flows"]
    baseline_ids = ids["baselines"]

    for path, evidence in _evidences(snapshot):
        _missing_reference(errors, f"{path}.source_id", evidence.get("source_id"), source_ids)

    for vm_index, vm in enumerate(snapshot.get("virtual_machines", [])):
        for nic_index, interface in enumerate(vm.get("interfaces", [])):
            _missing_reference(
                errors,
                f"virtual_machines[{vm_index}].interfaces[{nic_index}].network_id",
                interface.get("network_id"),
                network_ids,
                nullable=True,
            )

    for asset_index, asset in enumerate(snapshot.get("assets", [])):
        for network_index, network_id in enumerate(asset.get("network_ids", [])):
            _missing_reference(
                errors,
                f"assets[{asset_index}].network_ids[{network_index}]",
                network_id,
                network_ids,
            )

    for index, link in enumerate(snapshot.get("identity_links", [])):
        _missing_reference(
            errors,
            f"identity_links[{index}].virtual_machine_id",
            link.get("virtual_machine_id"),
            vm_ids,
        )
        _missing_reference(
            errors, f"identity_links[{index}].asset_id", link.get("asset_id"), asset_ids
        )

    for index, score in enumerate(snapshot.get("risk_scores", [])):
        _missing_reference(
            errors, f"risk_scores[{index}].asset_id", score.get("asset_id"), asset_ids
        )

    for index, activity in enumerate(snapshot.get("activities", [])):
        for asset_index, asset_id in enumerate(activity.get("asset_ids", [])):
            _missing_reference(
                errors,
                f"activities[{index}].asset_ids[{asset_index}]",
                asset_id,
                asset_ids,
            )

    for index, flow in enumerate(snapshot.get("flows", [])):
        for field in ("left_asset_id", "right_asset_id"):
            _missing_reference(
                errors,
                f"flows[{index}].{field}",
                flow.get(field),
                asset_ids,
                nullable=True,
            )

    for index, event in enumerate(snapshot.get("events", [])):
        for asset_index, asset_id in enumerate(event.get("asset_ids", [])):
            _missing_reference(
                errors, f"events[{index}].asset_ids[{asset_index}]", asset_id, asset_ids
            )

    for index, vulnerability in enumerate(snapshot.get("vulnerabilities", [])):
        _missing_reference(
            errors,
            f"vulnerabilities[{index}].asset_id",
            vulnerability.get("asset_id"),
            asset_ids,
        )

    for index, difference in enumerate(snapshot.get("baseline_differences", [])):
        _missing_reference(
            errors,
            f"baseline_differences[{index}].baseline_id",
            difference.get("baseline_id"),
            baseline_ids,
        )
        _missing_reference(
            errors,
            f"baseline_differences[{index}].flow_id",
            difference.get("flow_id"),
            flow_ids,
            nullable=True,
        )
        for asset_index, asset_id in enumerate(difference.get("asset_ids", [])):
            _missing_reference(
                errors,
                f"baseline_differences[{index}].asset_ids[{asset_index}]",
                asset_id,
                asset_ids,
            )
    return errors


def _semantic_errors(
    snapshot: Mapping[str, Any], ids: Mapping[str, set[str]]
) -> list[str]:
    errors: list[str] = []
    sources_by_id = {
        source["id"]: source
        for source in snapshot.get("sources", [])
        if isinstance(source, Mapping) and isinstance(source.get("id"), str)
    }

    for index, score in enumerate(snapshot.get("risk_scores", [])):
        value = score.get("score")
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            expected_band = "low" if value < 40 else "medium" if value < 70 else "high"
            if score.get("band") != expected_band:
                errors.append(
                    f"risk_scores[{index}].band: per score {value} deve essere '{expected_band}'"
                )
        evidence = score.get("evidence", {})
        source = sources_by_id.get(evidence.get("source_id"), {})
        if source.get("type") != "cisco_cyber_vision":
            errors.append(
                f"risk_scores[{index}]: il risk score Cisco può provenire solo da "
                "una sorgente cisco_cyber_vision"
            )
        if evidence.get("truth") not in {"real", "stale"}:
            errors.append(
                f"risk_scores[{index}].evidence.truth: deve essere 'real' o 'stale'"
            )

    official_targets = [
        vm
        for vm in snapshot.get("virtual_machines", [])
        if vm.get("operational_context", {}).get("official_target") is True
    ]
    if len(official_targets) > 1:
        errors.append("virtual_machines: esiste più di un target operativo ufficiale")

    if snapshot.get("sync", {}).get("publication_mode") == "real_only":
        for path, evidence in _evidences(snapshot):
            if evidence.get("truth") == "demo":
                errors.append(f"{path}.truth: dati demo vietati in modalità real_only")

    try:
        started = _parse_datetime(snapshot["sync"]["started_at"])
        completed = _parse_datetime(snapshot["sync"]["completed_at"])
        generated = _parse_datetime(snapshot["generated_at"])
        if completed < started:
            errors.append("sync.completed_at: precedente a sync.started_at")
        if generated < completed:
            errors.append("generated_at: precedente al completamento della sincronizzazione")
    except (KeyError, TypeError, ValueError):
        pass

    all_entity_ids = {snapshot.get("environment", {}).get("id")}
    for collection_ids in ids.values():
        all_entity_ids.update(collection_ids)
    for index, finding in enumerate(snapshot.get("findings", [])):
        for entity_index, entity_id in enumerate(finding.get("entity_ids", [])):
            if entity_id not in all_entity_ids:
                errors.append(
                    f"findings[{index}].entity_ids[{entity_index}]: "
                    f"riferimento sconosciuto '{entity_id}'"
                )
    return errors


def validate_snapshot(snapshot: Mapping[str, Any]) -> Mapping[str, Any]:
    """Validate a snapshot and return it unchanged, or raise one aggregated error."""

    if not isinstance(snapshot, Mapping):
        raise ContractValidationError(["$: lo snapshot deve essere un oggetto JSON"])

    validator = Draft202012Validator(load_schema(), format_checker=FormatChecker())
    errors = [
        _format_jsonschema_error(error)
        for error in sorted(validator.iter_errors(snapshot), key=lambda item: list(item.path))
    ]
    if not errors:
        ids, id_errors = _unique_ids(snapshot)
        errors.extend(id_errors)
        errors.extend(_cross_reference_errors(snapshot, ids))
        errors.extend(_semantic_errors(snapshot, ids))
    errors.extend(find_secret_leaks(snapshot))

    if errors:
        raise ContractValidationError(errors)
    return snapshot


def load_snapshot(path: str | Path, *, max_bytes: int = MAX_SNAPSHOT_BYTES) -> dict[str, Any]:
    """Read and validate a snapshot with a strict file-size limit."""

    snapshot_path = Path(path)
    size = snapshot_path.stat().st_size
    if size > max_bytes:
        raise ContractValidationError(
            [f"$: file troppo grande ({size} byte; massimo {max_bytes})"]
        )
    try:
        payload = json.loads(snapshot_path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ContractValidationError([f"$: JSON non valido ({exc})"]) from exc
    validate_snapshot(payload)
    return payload


def canonical_bytes(snapshot: Mapping[str, Any]) -> bytes:
    """Return deterministic UTF-8 JSON bytes after validation."""

    validate_snapshot(snapshot)
    return (
        json.dumps(snapshot, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def snapshot_sha256(snapshot: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_bytes(snapshot)).hexdigest()


def snapshot_age_seconds(
    snapshot: Mapping[str, Any], *, now: datetime | None = None
) -> int:
    completed = _parse_datetime(snapshot["sync"]["completed_at"])
    reference = (now or datetime.now(UTC)).astimezone(UTC)
    return max(0, int((reference - completed).total_seconds()))


def effective_sync_state(
    snapshot: Mapping[str, Any], *, now: datetime | None = None
) -> str:
    """Derive runtime freshness without mutating the last-known-good snapshot."""

    state = str(snapshot["sync"]["state"])
    if state in {"offline", "failed", "stale"}:
        return state
    if snapshot_age_seconds(snapshot, now=now) > int(snapshot["sync"]["max_age_seconds"]):
        return "stale"
    return state


def with_stale_truth(snapshot: Mapping[str, Any], *, now: datetime | None = None) -> dict[str, Any]:
    """Return a display copy whose previously factual evidence is visibly stale."""

    result = deepcopy(snapshot)
    if effective_sync_state(result, now=now) != "stale":
        return result
    result["sync"]["state"] = "stale"
    for _, evidence in _evidences(result):
        if evidence.get("truth") in {"real", "observed"}:
            evidence["truth"] = "stale"
    return result


def truth_label_it(value: str) -> str:
    return TRUTH_LABELS_IT.get(value, "Sconosciuta")
