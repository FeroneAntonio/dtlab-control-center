"""Validation rules for the additive DTLab v3 snapshot.

The v3 snapshot is a strict superset of v2: it reuses every v2 entity definition
(via JSON Schema ``$ref``) and adds the offensive, digital-twin, compliance and
history domains. This module never mutates or re-implements the v2 contract; it
imports the v2 helpers and layers v3-specific structural, referential and
semantic checks on top. A valid v2 snapshot keeps validating against the v2
contract unchanged.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from functools import lru_cache
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

from dtlab import contract as v2
from dtlab.contract import ContractValidationError, find_secret_leaks

SCHEMA_VERSION = "3.0.0"

# Collections introduced by v3. Ordered for deterministic error output.
V3_ENTITY_COLLECTIONS = (
    "attack_scenarios",
    "attack_runs",
    "detection_correlations",
    "process_telemetry",
    "security_zones",
    "compliance_mappings",
)

_TECHNIQUE_RE = re.compile(r"^T[0-9]{4}(\.[0-9]{3})?$")


def v3_schema_path() -> Path:
    """Return the canonical v3 JSON Schema path in a source or deployed checkout."""

    return Path(__file__).resolve().parents[2] / "schemas" / "dtlab-snapshot-v3.schema.json"


def load_v3_schema() -> dict[str, Any]:
    return json.loads(v3_schema_path().read_text(encoding="utf-8"))


@lru_cache(maxsize=1)
def _validator() -> Draft202012Validator:
    """Build a v3 validator with a registry that resolves the v2 ``$ref`` base."""

    v2_schema = v2.load_schema()
    v3_schema = load_v3_schema()
    registry: Registry = Registry().with_resources(
        [
            (v2_schema["$id"], Resource.from_contents(v2_schema)),
            (v3_schema["$id"], Resource.from_contents(v3_schema)),
        ]
    )
    return Draft202012Validator(
        v3_schema, registry=registry, format_checker=FormatChecker()
    )


def _v3_unique_ids(snapshot: Mapping[str, Any]) -> tuple[dict[str, set[str]], list[str]]:
    ids: dict[str, set[str]] = {}
    errors: list[str] = []
    for collection in V3_ENTITY_COLLECTIONS:
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


def _all_known_ids(
    snapshot: Mapping[str, Any],
    v2_ids: Mapping[str, set[str]],
    v3_ids: Mapping[str, set[str]],
) -> set[str]:
    known: set[str] = {snapshot.get("environment", {}).get("id")}
    for collection_ids in v2_ids.values():
        known.update(collection_ids)
    for collection_ids in v3_ids.values():
        known.update(collection_ids)
    known.discard(None)
    return known


def _v3_cross_reference_errors(
    snapshot: Mapping[str, Any],
    v2_ids: Mapping[str, set[str]],
    v3_ids: Mapping[str, set[str]],
) -> list[str]:
    errors: list[str] = []
    missing = v2._missing_reference
    asset_ids = v2_ids["assets"]
    event_ids = v2_ids["events"]
    scenario_ids = v3_ids["attack_scenarios"]
    run_ids = v3_ids["attack_runs"]
    zone_ids = v3_ids["security_zones"]
    known_ids = _all_known_ids(snapshot, v2_ids, v3_ids)

    for index, run in enumerate(snapshot.get("attack_runs", [])):
        missing(errors, f"attack_runs[{index}].scenario_id", run.get("scenario_id"), scenario_ids)
        missing(
            errors,
            f"attack_runs[{index}].source_asset_id",
            run.get("source_asset_id"),
            asset_ids,
            nullable=True,
        )
        for asset_index, asset_id in enumerate(run.get("target_asset_ids", [])):
            missing(
                errors,
                f"attack_runs[{index}].target_asset_ids[{asset_index}]",
                asset_id,
                asset_ids,
            )

    for index, correlation in enumerate(snapshot.get("detection_correlations", [])):
        missing(
            errors,
            f"detection_correlations[{index}].attack_run_id",
            correlation.get("attack_run_id"),
            run_ids,
        )
        missing(
            errors,
            f"detection_correlations[{index}].event_id",
            correlation.get("event_id"),
            event_ids,
            nullable=True,
        )

    for index, sample in enumerate(snapshot.get("process_telemetry", [])):
        missing(
            errors,
            f"process_telemetry[{index}].asset_id",
            sample.get("asset_id"),
            asset_ids,
            nullable=True,
        )
        missing(
            errors,
            f"process_telemetry[{index}].attack_run_id",
            sample.get("attack_run_id"),
            run_ids,
            nullable=True,
        )

    for index, zone in enumerate(snapshot.get("security_zones", [])):
        for asset_index, asset_id in enumerate(zone.get("asset_ids", [])):
            missing(
                errors,
                f"security_zones[{index}].asset_ids[{asset_index}]",
                asset_id,
                asset_ids,
            )
        for conduit_index, conduit in enumerate(zone.get("conduits", [])):
            missing(
                errors,
                f"security_zones[{index}].conduits[{conduit_index}].to_zone_id",
                conduit.get("to_zone_id"),
                zone_ids,
            )

    for index, mapping in enumerate(snapshot.get("compliance_mappings", [])):
        for asset_index, asset_id in enumerate(mapping.get("asset_ids", [])):
            missing(
                errors,
                f"compliance_mappings[{index}].asset_ids[{asset_index}]",
                asset_id,
                asset_ids,
            )
        for zone_index, zone_id in enumerate(mapping.get("zone_ids", [])):
            missing(
                errors,
                f"compliance_mappings[{index}].zone_ids[{zone_index}]",
                zone_id,
                zone_ids,
            )
        for ref_index, reference in enumerate(mapping.get("evidence_refs", [])):
            if isinstance(reference, str) and reference not in known_ids:
                errors.append(
                    f"compliance_mappings[{index}].evidence_refs[{ref_index}]: "
                    f"riferimento sconosciuto '{reference}'"
                )
    return errors


def _v3_semantic_errors(
    snapshot: Mapping[str, Any],
    v2_ids: Mapping[str, set[str]],
    v3_ids: Mapping[str, set[str]],
) -> list[str]:
    errors: list[str] = []

    for index, scenario in enumerate(snapshot.get("attack_scenarios", [])):
        if scenario.get("execution_mode") == "real" and not scenario.get("roe_reference"):
            errors.append(
                f"attack_scenarios[{index}].roe_reference: obbligatorio quando "
                "execution_mode è 'real'"
            )

    for index, run in enumerate(snapshot.get("attack_runs", [])):
        if run.get("execution_mode") == "real" and not run.get("roe_reference"):
            errors.append(
                f"attack_runs[{index}].roe_reference: obbligatorio quando "
                "execution_mode è 'real'"
            )
        started = run.get("started_at")
        completed = run.get("completed_at")
        status = run.get("status")
        if status in {"completed", "failed"} and not started:
            errors.append(
                f"attack_runs[{index}].started_at: obbligatorio per status '{status}'"
            )
        if completed and not started:
            errors.append(
                f"attack_runs[{index}]: completed_at presente ma started_at nullo"
            )
        if started and completed:
            try:
                if v2._parse_datetime(completed) < v2._parse_datetime(started):
                    errors.append(
                        f"attack_runs[{index}].completed_at: precedente a started_at"
                    )
            except (TypeError, ValueError):
                pass

    for index, correlation in enumerate(snapshot.get("detection_correlations", [])):
        detected = correlation.get("detected")
        detected_at = correlation.get("detected_at")
        latency = correlation.get("detection_latency_seconds")
        source = correlation.get("detection_source")
        event_id = correlation.get("event_id")
        attack_at = correlation.get("attack_at")
        prefix = f"detection_correlations[{index}]"
        if detected is True:
            if detected_at is None:
                errors.append(f"{prefix}.detected_at: obbligatorio quando detected è true")
            if latency is None:
                errors.append(
                    f"{prefix}.detection_latency_seconds: obbligatorio quando detected è true"
                )
            if source == "none":
                errors.append(
                    f"{prefix}.detection_source: non può essere 'none' quando detected è true"
                )
            if source in {"cisco_cyber_vision", "cisco_cyber_vision_new_ui"} and not event_id:
                errors.append(
                    f"{prefix}.event_id: obbligatorio per una detection Cisco rilevata"
                )
            if attack_at and detected_at:
                try:
                    attack_time = v2._parse_datetime(attack_at)
                    detect_time = v2._parse_datetime(detected_at)
                    if detect_time < attack_time:
                        errors.append(f"{prefix}.detected_at: precedente ad attack_at")
                    elif latency is not None:
                        computed = int((detect_time - attack_time).total_seconds())
                        if abs(computed - int(latency)) > 1:
                            errors.append(
                                f"{prefix}.detection_latency_seconds: {latency} incoerente "
                                f"con l'intervallo osservato ({computed}s)"
                            )
                except (TypeError, ValueError):
                    pass
        elif detected is False:
            if detected_at is not None:
                errors.append(f"{prefix}.detected_at: deve essere nullo quando detected è false")
            if latency is not None:
                errors.append(
                    f"{prefix}.detection_latency_seconds: deve essere nullo quando detected è false"
                )
            if source != "none":
                errors.append(
                    f"{prefix}.detection_source: deve essere 'none' quando detected è false"
                )

    for index, sample in enumerate(snapshot.get("process_telemetry", [])):
        for reg_index, register in enumerate(sample.get("registers", [])):
            minimum = register.get("expected_min")
            maximum = register.get("expected_max")
            value = register.get("value")
            in_bounds = register.get("in_bounds")
            numeric = isinstance(value, (int, float)) and not isinstance(value, bool)
            if numeric and in_bounds is not None and minimum is not None and maximum is not None:
                expected = minimum <= value <= maximum
                if bool(in_bounds) != expected:
                    errors.append(
                        f"process_telemetry[{index}].registers[{reg_index}].in_bounds: "
                        f"{in_bounds} incoerente con value {value} e range "
                        f"[{minimum}, {maximum}]"
                    )

    for index, mapping in enumerate(snapshot.get("compliance_mappings", [])):
        if mapping.get("framework") == "mitre_attack_ics" and not _TECHNIQUE_RE.match(
            str(mapping.get("reference_id", ""))
        ):
            errors.append(
                f"compliance_mappings[{index}].reference_id: per framework "
                "mitre_attack_ics deve essere una tecnica ATT&CK (T####)"
            )
    return errors


def validate_snapshot_v3(snapshot: Mapping[str, Any]) -> Mapping[str, Any]:
    """Validate a v3 snapshot and return it unchanged, or raise one aggregated error."""

    if not isinstance(snapshot, Mapping):
        raise ContractValidationError(["$: lo snapshot deve essere un oggetto JSON"])

    validator = _validator()
    errors = [
        v2._format_jsonschema_error(error)
        for error in sorted(validator.iter_errors(snapshot), key=lambda item: list(item.path))
    ]
    if not errors:
        v2_ids, v2_id_errors = v2._unique_ids(snapshot)
        errors.extend(v2_id_errors)
        errors.extend(v2._cross_reference_errors(snapshot, v2_ids))
        errors.extend(v2._semantic_errors(snapshot, v2_ids))
        v3_ids, v3_id_errors = _v3_unique_ids(snapshot)
        errors.extend(v3_id_errors)
        errors.extend(_v3_cross_reference_errors(snapshot, v2_ids, v3_ids))
        errors.extend(_v3_semantic_errors(snapshot, v2_ids, v3_ids))
    errors.extend(find_secret_leaks(snapshot))

    if errors:
        raise ContractValidationError(errors)
    return snapshot


def load_snapshot_v3(
    path: str | Path, *, max_bytes: int = v2.MAX_SNAPSHOT_BYTES
) -> dict[str, Any]:
    """Read and validate a v3 snapshot with a strict file-size limit."""

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
    validate_snapshot_v3(payload)
    return payload


def canonical_bytes_v3(snapshot: Mapping[str, Any]) -> bytes:
    """Return deterministic UTF-8 JSON bytes after v3 validation."""

    validate_snapshot_v3(snapshot)
    return (
        json.dumps(snapshot, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def snapshot_sha256_v3(snapshot: Mapping[str, Any]) -> str:
    import hashlib

    return hashlib.sha256(canonical_bytes_v3(snapshot)).hexdigest()
