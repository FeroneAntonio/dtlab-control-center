"""Approve a local staging snapshot without network access or remote mutations."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from dtlab.contract import effective_sync_state, snapshot_age_seconds  # noqa: E402
from dtlab.services.snapshot_store import (  # noqa: E402
    AtomicSnapshotStore,
    SnapshotStoreError,
    StoredSnapshot,
)

DEFAULT_MIN_QUALITY = 80
STRICT_FRESHNESS_POLICY = "strict"
ROLLBACK_STALE_FRESHNESS_POLICY = "rollback_verified_stale_allowed"
REQUIRED_SOURCE_TYPES = (
    "vmware_esxi",
    "cisco_cyber_vision",
    "cisco_cyber_vision_new_ui",
)
_SOURCE_KEYS = {
    "vmware_esxi": "esxi",
    "cisco_cyber_vision": "classic",
    "cisco_cyber_vision_new_ui": "new_ui",
}
_REQUIRED_CAPABILITIES = {
    "vmware_esxi": frozenset(
        {
            "vm_inventory",
        }
    ),
    "cisco_cyber_vision": frozenset(
        {
            "activities",
            "baseline_differences",
            "baselines",
            "components",
            "device_risk_scores",
            "device_vulnerabilities",
            "devices",
            "event_categories",
            "event_severities",
            "flows",
            "protocol_distribution",
            "reports_metadata",
            "risk_distribution",
            "sensor_details",
            "sensor_stats",
            "sensors",
            "version",
            "vulnerabilities",
        }
    ),
    "cisco_cyber_vision_new_ui": frozenset(
        {
            "alerts",
            "assets",
            "networks",
            "org_hierarchy",
            "vulnerability_assets",
        }
    ),
}


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _read_current(store_root: Path) -> StoredSnapshot:
    """Load ``current`` through AtomicSnapshotStore without creating or chmodding paths."""

    if not store_root.is_dir():
        raise SnapshotStoreError("Store snapshot non disponibile")

    return AtomicSnapshotStore(store_root, create_layout=False).load("current")


def _contains_demo_truth(value: Any) -> bool:
    if isinstance(value, Mapping):
        if value.get("truth") == "demo":
            return True
        return any(_contains_demo_truth(nested) for nested in value.values())
    if isinstance(value, list):
        return any(_contains_demo_truth(nested) for nested in value)
    return False


def _capability_problem(
    source_type: str,
    name: str,
    capability: Mapping[str, Any],
    *,
    allow_sensor_stats_server_error: bool,
) -> tuple[str | None, str | None, str | None]:
    """Return a fixed failure, warning, or approved-exception code."""

    status = capability.get("status")
    error_code = capability.get("error_code")
    if status == "available" and error_code is None:
        return None, None, None

    if (
        source_type == "vmware_esxi"
        and name == "host_network_scope"
        and status == "endpoint_unavailable"
        and error_code == "permission_scope"
    ):
        return None, "esxi_host_network_scope_permission_scope", None

    if (
        source_type == "cisco_cyber_vision"
        and name == "sensor_stats"
        and status == "error"
        and error_code == "server_error"
    ):
        if allow_sensor_stats_server_error:
            return None, None, "classic_sensor_stats_server_error"
        return "classic_sensor_stats_server_error_not_approved", None, None

    return f"{_SOURCE_KEYS[source_type]}_capability_error", None, None


def evaluate_snapshot(
    stored: StoredSnapshot,
    *,
    min_quality: int = DEFAULT_MIN_QUALITY,
    allow_sensor_stats_server_error: bool = False,
    allow_stale_for_rollback: bool = False,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Evaluate a verified current snapshot and return an address-free result."""

    snapshot = stored.snapshot
    failures: set[str] = set()
    warnings: set[str] = set()
    approved_exceptions: set[str] = set()

    if snapshot["sync"]["publication_mode"] != "real_only":
        failures.add("publication_mode_not_real_only")
    if any(source.get("type") == "demo" for source in snapshot["sources"]):
        failures.add("demo_source_present")
    if _contains_demo_truth(snapshot):
        failures.add("demo_evidence_present")

    quality_score = int(snapshot["quality"]["score"])
    if quality_score < min_quality:
        failures.add("quality_below_threshold")

    sources_by_type: dict[str, list[Mapping[str, Any]]] = {
        source_type: [] for source_type in REQUIRED_SOURCE_TYPES
    }
    for source in snapshot["sources"]:
        source_type = source.get("type")
        if source_type in sources_by_type:
            sources_by_type[source_type].append(source)

    source_results: dict[str, str] = {}
    sensor_exception_observed = False
    for source_type in REQUIRED_SOURCE_TYPES:
        output_key = _SOURCE_KEYS[source_type]
        matching = sources_by_type[source_type]
        if not matching:
            failures.add(f"{output_key}_source_missing")
            source_results[output_key] = "missing"
            continue
        if len(matching) != 1:
            failures.add(f"{output_key}_source_ambiguous")
            source_results[output_key] = "fail"
            continue

        source = matching[0]
        source_failures_before = len(failures)
        source_warnings_before = len(warnings)
        capabilities = source.get("capabilities")
        if not isinstance(capabilities, Mapping):
            failures.add(f"{output_key}_capability_error")
            capabilities = {}

        missing_capabilities = _REQUIRED_CAPABILITIES[source_type] - set(capabilities)
        if missing_capabilities:
            failures.add(f"{output_key}_capability_missing")

        for name, capability in capabilities.items():
            if not isinstance(name, str) or not isinstance(capability, Mapping):
                failures.add(f"{output_key}_capability_error")
                continue
            failure, warning, approved = _capability_problem(
                source_type,
                name,
                capability,
                allow_sensor_stats_server_error=allow_sensor_stats_server_error,
            )
            if failure:
                failures.add(failure)
            if warning:
                warnings.add(warning)
            if approved:
                approved_exceptions.add(approved)
                sensor_exception_observed = True

        source_error = source.get("error")
        source_status = source.get("status")
        allowed_classic_degradation = (
            source_type == "cisco_cyber_vision"
            and sensor_exception_observed
            and source_status == "degraded"
            and isinstance(source_error, Mapping)
            and source_error.get("code") == "partial_capabilities"
        )
        if source_status != "connected" and not allowed_classic_degradation:
            failures.add(f"{output_key}_source_unhealthy")
        if source_error is not None and not allowed_classic_degradation:
            failures.add(f"{output_key}_source_error")

        if len(failures) > source_failures_before:
            source_results[output_key] = "fail"
        elif len(warnings) > source_warnings_before or allowed_classic_degradation:
            source_results[output_key] = "warning"
        else:
            source_results[output_key] = "pass"

    sync_state = snapshot["sync"]["state"]
    evaluated_at = now or _utc_now()
    runtime_state = effective_sync_state(snapshot, now=evaluated_at)
    age_seconds = snapshot_age_seconds(snapshot, now=evaluated_at)
    rollback_stale_candidate = False
    if runtime_state == "stale":
        if allow_stale_for_rollback and sync_state in {"fresh", "partial"}:
            rollback_stale_candidate = True
        else:
            failures.add("snapshot_stale_by_age")

    if sync_state == "partial":
        if not (allow_sensor_stats_server_error and sensor_exception_observed):
            failures.add("snapshot_partial_not_approved")
        else:
            warnings.add("snapshot_partial_for_approved_classic_exception")
    elif sync_state != "fresh":
        failures.add("snapshot_not_fresh")

    freshness_policy = STRICT_FRESHNESS_POLICY
    if rollback_stale_candidate and not failures:
        freshness_policy = ROLLBACK_STALE_FRESHNESS_POLICY
        warnings.add(ROLLBACK_STALE_FRESHNESS_POLICY)

    result = {
        "approved": not failures,
        "approved_exceptions": sorted(approved_exceptions),
        "failures": sorted(failures),
        "freshness_policy": freshness_policy,
        "gate_version": "1.1",
        "manifest_sha256": stored.manifest["sha256"],
        "manifest_verified": True,
        "minimum_quality": min_quality,
        "pointer": "current",
        "quality_score": quality_score,
        "runtime_sync_state": runtime_state,
        "snapshot_age_seconds": age_seconds,
        "source_results": source_results,
        "sync_state": sync_state,
        "warnings": sorted(warnings),
    }
    return result


def verify_store(
    store_root: Path,
    *,
    min_quality: int = DEFAULT_MIN_QUALITY,
    allow_sensor_stats_server_error: bool = False,
    allow_stale_for_rollback: bool = False,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Read and evaluate the current pointer, returning a safe failure on store errors."""

    try:
        stored = _read_current(store_root)
    except (OSError, SnapshotStoreError):
        return {
            "approved": False,
            "approved_exceptions": [],
            "failures": ["snapshot_store_invalid"],
            "freshness_policy": STRICT_FRESHNESS_POLICY,
            "gate_version": "1.1",
            "manifest_verified": False,
            "minimum_quality": min_quality,
            "pointer": "current",
            "warnings": [],
        }
    return evaluate_snapshot(
        stored,
        min_quality=min_quality,
        allow_sensor_stats_server_error=allow_sensor_stats_server_error,
        allow_stale_for_rollback=allow_stale_for_rollback,
        now=now,
    )


def _quality_threshold(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("la soglia deve essere un intero") from exc
    if not 0 <= parsed <= 100:
        raise argparse.ArgumentTypeError("la soglia deve essere compresa tra 0 e 100")
    return parsed


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Verifica locale read-only dello snapshot current destinato allo staging."
    )
    parser.add_argument("--store", type=Path, required=True)
    parser.add_argument(
        "--min-quality",
        type=_quality_threshold,
        default=DEFAULT_MIN_QUALITY,
    )
    parser.add_argument(
        "--allow-classic-sensor-stats-server-error",
        action="store_true",
        help=(
            "Approva esclusivamente l'errore noto Classic sensor_stats/server_error "
            "e lo stato partial che ne deriva."
        ),
    )
    parser.add_argument(
        "--allow-stale-for-rollback",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    result = verify_store(
        args.store.resolve(),
        min_quality=args.min_quality,
        allow_sensor_stats_server_error=args.allow_classic_sensor_stats_server_error,
        allow_stale_for_rollback=args.allow_stale_for_rollback,
    )
    print(json.dumps(result, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
    return 0 if result["approved"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
