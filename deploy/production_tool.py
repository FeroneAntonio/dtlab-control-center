"""Fail-closed, root-side lifecycle tool for the DTLab production web service.

The tool has no remote transport and never invokes collectors.  It promotes only an
immutable release and virtual environment already installed under the shared v2 roots.
``promote`` additionally requires both targets to be the current staging targets.

Every command is a dry run unless ``--apply`` and the exact current plan token are
provided.  Application code, snapshot objects and ticket data are never deleted.
"""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
import re
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time
import uuid
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

PRIVATE_ROOT = Path("/var/www/clients/client1/web75/private")
RELEASES_ROOT = PRIVATE_ROOT / "modbus-dashboard-releases"
VENVS_ROOT = PRIVATE_ROOT / "modbus-dashboard-venvs"
STAGING_RELEASE_LINK = PRIVATE_ROOT / "modbus-dashboard-staging-current"
STAGING_VENV_LINK = PRIVATE_ROOT / "modbus-dashboard-staging-venv-current"
STAGING_STORE = PRIVATE_ROOT / "modbus-dashboard-data-staging"
PRODUCTION_RELEASE_LINK = PRIVATE_ROOT / "modbus-dashboard-current"
PRODUCTION_VENV_LINK = PRIVATE_ROOT / "modbus-dashboard-venv-current"
PRODUCTION_STORE = PRIVATE_ROOT / "modbus-dashboard-data"
PRODUCTION_TICKET_ROOT = PRIVATE_ROOT / "modbus-dashboard-ticket-data"
PRODUCTION_TICKET_DATABASE = PRODUCTION_TICKET_ROOT / "tickets.sqlite3"
INACCESSIBLE_APPLICATION_ROOT = PRIVATE_ROOT / "modbus-dashboard"

SERVICE_NAME = "modbus-dashboard-v2.service"
STAGING_SERVICE_NAME = "modbus-dashboard-v2-staging.service"
UNIT_DESTINATION = Path("/etc/systemd/system") / SERVICE_NAME
UNIT_ARCHIVE_PATH = PurePosixPath("deploy") / SERVICE_NAME
STAGING_UNIT_DESTINATION = Path("/etc/systemd/system") / STAGING_SERVICE_NAME
STAGING_UNIT_ARCHIVE_PATH = PurePosixPath("deploy") / STAGING_SERVICE_NAME
INGEST_SERVICE_NAME = "modbus-dashboard-ticket-ingest.service"
INGEST_PATH_NAME = "modbus-dashboard-ticket-ingest.path"
INGEST_SERVICE_DESTINATION = Path("/etc/systemd/system") / INGEST_SERVICE_NAME
INGEST_PATH_DESTINATION = Path("/etc/systemd/system") / INGEST_PATH_NAME
INGEST_SERVICE_ARCHIVE_PATH = PurePosixPath("deploy") / INGEST_SERVICE_NAME
INGEST_PATH_ARCHIVE_PATH = PurePosixPath("deploy") / INGEST_PATH_NAME
BACKUP_ROOT = Path("/var/backups/dtlab-control-center-production")
LOCK_PATH = Path("/run/lock/dtlab-control-center-production.lock")
HEALTH_HOST = "127.0.0.1"
HEALTH_PORT = 8517
HEALTH_PATH = "/_stcore/health"
STAGING_HEALTH_PORT = 8518
GATE_SCRIPT = Path(__file__).resolve().parents[1] / "tools" / "verify_staging_snapshot.py"
STRICT_FRESHNESS_POLICY = "strict"
ROLLBACK_STALE_FRESHNESS_POLICY = "rollback_verified_stale_allowed"

DASHBOARD_USER = "web75"
DASHBOARD_GROUP = "dtlab-dashboard"
PUBLISH_USER = "dtlab-publish"

_RELEASE_ID = re.compile(r"^[a-f0-9]{16}$")
_SHA256 = re.compile(r"^[a-f0-9]{64}$")
_RELEASE_PREFIX = "dtlab-control-center-"
_VENV_MARKER = ".dtlab-venv.json"
_SNAPSHOT_FIELDS = frozenset(
    {
        "schema_version",
        "snapshot_id",
        "generated_at",
        "environment",
        "sync",
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
        "quality",
    }
)
_SNAPSHOT_LIST_FIELDS = _SNAPSHOT_FIELDS - {
    "schema_version",
    "snapshot_id",
    "generated_at",
    "environment",
    "sync",
    "quality",
}
_REQUIRED_CAPABILITIES = {
    "vmware_esxi": frozenset({"vm_inventory"}),
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
        {"alerts", "assets", "networks", "org_hierarchy", "vulnerability_assets"}
    ),
}


class ProductionToolError(RuntimeError):
    """A production preflight, activation, or restoration failed."""


@dataclass(frozen=True)
class Identities:
    root_uid: int
    dashboard_uid: int
    dashboard_gid: int
    publisher_uid: int = 0


@dataclass(frozen=True)
class LinkState:
    exists: bool
    target: str | None


@dataclass(frozen=True)
class UnitState:
    exists: bool
    content: bytes | None
    uid: int | None
    gid: int | None
    mode: int | None

    @property
    def sha256(self) -> str | None:
        return _sha256_bytes(self.content) if self.content is not None else None


@dataclass(frozen=True)
class ServiceState:
    active: bool
    enabled: bool
    main_pid: int = 0
    exec_main_status: int = 0
    result: str = "success"


@dataclass(frozen=True)
class DeploymentState:
    release_link: LinkState
    venv_link: LinkState
    unit: UnitState
    service: ServiceState
    ingest_service_unit: UnitState = UnitState(False, None, None, None, None)
    ingest_path_unit: UnitState = UnitState(False, None, None, None, None)
    ingest_path_state: ServiceState = ServiceState(False, False)


@dataclass(frozen=True)
class TargetInfo:
    release_id: str
    release: Path
    venv: Path
    content_sha256: str
    unit_bytes: bytes
    unit_sha256: str
    has_ticket_runtime: bool
    staging_unit_sha256: str = ""
    ingest_service_bytes: bytes = b""
    ingest_service_sha256: str = ""
    ingest_path_bytes: bytes = b""
    ingest_path_sha256: str = ""


@dataclass(frozen=True)
class TicketState:
    directory_exists: bool
    database_exists: bool
    directory_mode: int | None = None
    database_mode: int | None = None


@dataclass(frozen=True)
class StoreState:
    root: Path
    snapshot_sha256: str
    manifest_sha256: str
    snapshot_id: str
    object_name: str
    byte_length: int
    sync_state: str
    quality_score: int
    approved_exceptions: tuple[str, ...]
    manifest_archive_ready: bool
    manifest_bytes: bytes = field(repr=False)
    runtime_sync_state: str = "fresh"
    snapshot_age_seconds: int = 0
    freshness_policy: str = STRICT_FRESHNESS_POLICY
    gate_warnings: tuple[str, ...] = ()


@dataclass(frozen=True)
class StagingState:
    service: ServiceState
    unit_sha256: str


def _sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _json_object(content: bytes, *, label: str) -> dict[str, Any]:
    try:
        value = json.loads(content.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProductionToolError(f"{label}: JSON non valido.") from exc
    if not isinstance(value, dict):
        raise ProductionToolError(f"{label}: è richiesto un oggetto JSON.")
    return value


def _manifest_records(manifest: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    if manifest.get("manifest_version") != "1.0":
        raise ProductionToolError("release-manifest.json: versione non supportata.")
    content_sha256 = manifest.get("content_sha256")
    if not isinstance(content_sha256, str) or not _SHA256.fullmatch(content_sha256):
        raise ProductionToolError("release-manifest.json: content_sha256 non valido.")
    raw_files = manifest.get("files")
    if not isinstance(raw_files, dict) or not raw_files:
        raise ProductionToolError("release-manifest.json: elenco file assente.")

    records: dict[str, dict[str, Any]] = {}
    for raw_name, raw_record in raw_files.items():
        if not isinstance(raw_name, str):
            raise ProductionToolError("release-manifest.json: nome file non valido.")
        name = PurePosixPath(raw_name)
        if name.is_absolute() or ".." in name.parts or not name.parts:
            raise ProductionToolError("release-manifest.json: percorso file non sicuro.")
        if str(name) != raw_name or raw_name == "release-manifest.json":
            raise ProductionToolError("release-manifest.json: percorso file non canonico.")
        if not isinstance(raw_record, dict):
            raise ProductionToolError(f"Manifest non valido per {raw_name}.")
        digest = raw_record.get("sha256")
        byte_length = raw_record.get("bytes")
        if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
            raise ProductionToolError(f"SHA-256 non valido per {raw_name}.")
        if type(byte_length) is not int or byte_length < 0:
            raise ProductionToolError(f"Dimensione non valida per {raw_name}.")
        records[raw_name] = {"sha256": digest, "bytes": byte_length}

    canonical = json.dumps(records, sort_keys=True, separators=(",", ":")).encode()
    if _sha256_bytes(canonical) != content_sha256:
        raise ProductionToolError("release-manifest.json: content hash incoerente.")
    return records


def _lookup_identities() -> Identities:
    try:
        import grp
        import pwd
    except ImportError as exc:  # pragma: no cover - guarded by apply host in production
        raise ProductionToolError("Database account POSIX non disponibile.") from exc
    try:
        root = pwd.getpwnam("root")
        dashboard = pwd.getpwnam(DASHBOARD_USER)
        publisher = pwd.getpwnam(PUBLISH_USER)
        dashboard_group = grp.getgrnam(DASHBOARD_GROUP)
    except KeyError as exc:
        raise ProductionToolError("Account o gruppo produzione mancante.") from exc
    if root.pw_uid != 0:
        raise ProductionToolError("UID root inatteso.")
    return Identities(
        root_uid=root.pw_uid,
        dashboard_uid=dashboard.pw_uid,
        dashboard_gid=dashboard_group.gr_gid,
        publisher_uid=publisher.pw_uid,
    )


def _require_regular_directory(path: Path) -> os.stat_result:
    try:
        details = path.lstat()
    except OSError as exc:
        raise ProductionToolError(f"Directory mancante o non leggibile: {path}") from exc
    if not stat.S_ISDIR(details.st_mode) or path.is_symlink():
        raise ProductionToolError(f"Directory non regolare o symlink: {path}")
    return details


def _lexists(path: Path) -> bool:
    return os.path.lexists(path)


def _verify_store_directory(path: Path, identities: Identities) -> None:
    details = _require_regular_directory(path)
    if (
        details.st_uid != identities.publisher_uid
        or details.st_gid != identities.dashboard_gid
        or stat.S_IMODE(details.st_mode) != 0o750
    ):
        raise ProductionToolError(f"Directory snapshot store non sicura: {path}")


def _verify_publisher_file(path: Path, identities: Identities, *, label: str) -> bytes:
    if not _lexists(path):
        raise ProductionToolError(f"{label} mancante: {path}")
    details = path.lstat()
    if (
        not stat.S_ISREG(details.st_mode)
        or path.is_symlink()
        or details.st_uid != identities.publisher_uid
        or details.st_gid != identities.dashboard_gid
        or stat.S_IMODE(details.st_mode) != 0o640
    ):
        raise ProductionToolError(f"{label} non sicuro: {path}")
    return path.read_bytes()


def _contains_demo_truth(value: Any) -> bool:
    if isinstance(value, Mapping):
        if value.get("truth") == "demo":
            return True
        return any(_contains_demo_truth(nested) for nested in value.values())
    if isinstance(value, list):
        return any(_contains_demo_truth(nested) for nested in value)
    return False


def _parse_utc_timestamp(value: Any) -> datetime:
    if not isinstance(value, str):
        raise ValueError("timestamp non stringa")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp senza fuso")
    return parsed.astimezone(UTC)


def _evaluate_snapshot_gate(
    snapshot: Mapping[str, Any],
    *,
    allow_sensor_stats_server_error: bool,
    allow_stale_for_rollback: bool = False,
) -> tuple[str, str, int, int, tuple[str, ...], tuple[str, ...], str]:
    failures: set[str] = set()
    exceptions: set[str] = set()
    warnings: set[str] = set()
    if set(snapshot) != _SNAPSHOT_FIELDS or snapshot.get("schema_version") != "2.0.0":
        failures.add("snapshot_contract_invalid")
    if not isinstance(snapshot.get("environment"), Mapping):
        failures.add("snapshot_contract_invalid")
    if any(not isinstance(snapshot.get(field), list) for field in _SNAPSHOT_LIST_FIELDS):
        failures.add("snapshot_contract_invalid")
    sync = snapshot.get("sync")
    quality = snapshot.get("quality")
    sources = snapshot.get("sources")
    sync_fields = {
        "state",
        "publication_mode",
        "started_at",
        "completed_at",
        "max_age_seconds",
        "collector_version",
        "vpn_required",
        "last_known_good_snapshot_id",
    }
    if not isinstance(sync, Mapping) or set(sync) != sync_fields:
        failures.add("snapshot_contract_invalid")
        sync = {}
    if sync.get("publication_mode") != "real_only":
        failures.add("publication_mode_not_real_only")
    quality_score = quality.get("score") if isinstance(quality, Mapping) else None
    if type(quality_score) is not int or not 80 <= quality_score <= 100:
        failures.add("quality_below_threshold")
        quality_score = int(quality_score) if type(quality_score) is int else -1
    if not isinstance(sources, list):
        failures.add("sources_invalid")
        sources = []
    if any(isinstance(source, Mapping) and source.get("type") == "demo" for source in sources):
        failures.add("demo_source_present")
    if _contains_demo_truth(snapshot):
        failures.add("demo_evidence_present")

    source_types = {
        "vmware_esxi": "esxi",
        "cisco_cyber_vision": "classic",
        "cisco_cyber_vision_new_ui": "new_ui",
    }
    sensor_exception_observed = False
    for source_type, label in source_types.items():
        matching = [
            source
            for source in sources
            if isinstance(source, Mapping) and source.get("type") == source_type
        ]
        if len(matching) != 1:
            failures.add(f"{label}_source_missing_or_ambiguous")
            continue
        source = matching[0]
        capabilities = source.get("capabilities")
        if not isinstance(capabilities, Mapping):
            failures.add(f"{label}_capability_error")
            capabilities = {}
        if _REQUIRED_CAPABILITIES[source_type] - set(capabilities):
            failures.add(f"{label}_capability_missing")
        source_sensor_exception = False
        for name, capability in capabilities.items():
            if not isinstance(name, str) or not isinstance(capability, Mapping):
                failures.add(f"{label}_capability_error")
                continue
            status = capability.get("status")
            error_code = capability.get("error_code")
            if status == "available" and error_code is None:
                continue
            if (
                source_type == "vmware_esxi"
                and name == "host_network_scope"
                and status == "endpoint_unavailable"
                and error_code == "permission_scope"
            ):
                warnings.add("esxi_host_network_scope_permission_scope")
                continue
            if (
                source_type == "cisco_cyber_vision"
                and name == "sensor_stats"
                and status == "error"
                and error_code == "server_error"
                and allow_sensor_stats_server_error
            ):
                source_sensor_exception = True
                sensor_exception_observed = True
                exceptions.add("classic_sensor_stats_server_error")
                continue
            failures.add(f"{label}_capability_error")

        allowed_degradation = (
            source_type == "cisco_cyber_vision"
            and source_sensor_exception
            and source.get("status") == "degraded"
            and isinstance(source.get("error"), Mapping)
            and source["error"].get("code") == "partial_capabilities"
        )
        if source.get("status") != "connected" and not allowed_degradation:
            failures.add(f"{label}_source_unhealthy")
        if source.get("error") is not None and not allowed_degradation:
            failures.add(f"{label}_source_error")

    sync_state = sync.get("state")
    runtime_sync_state = str(sync_state)
    age_seconds = -1
    try:
        started_at = _parse_utc_timestamp(sync.get("started_at"))
        completed_at = _parse_utc_timestamp(sync.get("completed_at"))
        generated_at = _parse_utc_timestamp(snapshot.get("generated_at"))
        max_age_seconds = sync.get("max_age_seconds")
        if (
            completed_at < started_at
            or generated_at < completed_at
            or type(max_age_seconds) is not int
            or not 60 <= max_age_seconds <= 604800
        ):
            raise ValueError("sequenza temporale non valida")
        age_seconds = max(0, int((datetime.now(UTC) - completed_at).total_seconds()))
        if sync_state not in {"offline", "failed", "stale"} and age_seconds > max_age_seconds:
            runtime_sync_state = "stale"
    except (OverflowError, TypeError, ValueError):
        failures.add("snapshot_contract_invalid")

    rollback_stale_candidate = False
    if runtime_sync_state == "stale":
        if allow_stale_for_rollback and sync_state in {"fresh", "partial"}:
            rollback_stale_candidate = True
        else:
            failures.add("snapshot_stale_by_age")

    if sync_state == "partial":
        if not (allow_sensor_stats_server_error and sensor_exception_observed):
            failures.add("snapshot_partial_not_approved")
    elif sync_state != "fresh":
        failures.add("snapshot_not_fresh")
    if failures:
        raise ProductionToolError("Snapshot gate rifiutato: " + ",".join(sorted(failures)))
    freshness_policy = STRICT_FRESHNESS_POLICY
    if rollback_stale_candidate:
        freshness_policy = ROLLBACK_STALE_FRESHNESS_POLICY
        warnings.add(ROLLBACK_STALE_FRESHNESS_POLICY)
    return (
        str(sync_state),
        runtime_sync_state,
        age_seconds,
        int(quality_score),
        tuple(sorted(exceptions)),
        tuple(sorted(warnings)),
        freshness_policy,
    )


def _run_exact_snapshot_gate(
    root: Path,
    gate_python: Path,
    identities: Identities,
    *,
    allow_sensor_stats_server_error: bool,
    allow_stale_for_rollback: bool = False,
) -> dict[str, Any]:
    project_root = GATE_SCRIPT.parents[1]
    trusted_roots = (
        GATE_SCRIPT,
        project_root / "src" / "dtlab",
        project_root / "schemas" / "dtlab-snapshot-v2.schema.json",
    )
    candidates: list[Path] = []
    for trusted in trusted_roots:
        candidates.append(trusted)
        if trusted.is_dir() and not trusted.is_symlink():
            candidates.extend(trusted.rglob("*"))
    try:
        for candidate in candidates:
            details = candidate.lstat()
            if (
                candidate.is_symlink()
                or details.st_uid != identities.root_uid
                or stat.S_IMODE(details.st_mode) & 0o022
                or not (
                    stat.S_ISREG(details.st_mode) or stat.S_ISDIR(details.st_mode)
                )
            ):
                raise ProductionToolError(
                    f"Dipendenza verifier gate non attendibile: {candidate}"
                )
    except OSError as exc:
        raise ProductionToolError("Verifier gate snapshot assente.") from exc
    command = [
        str(gate_python),
        "-I",
        "-B",
        str(GATE_SCRIPT),
        "--store",
        str(root),
        "--min-quality",
        "80",
    ]
    if allow_sensor_stats_server_error:
        command.append("--allow-classic-sensor-stats-server-error")
    if allow_stale_for_rollback:
        command.append("--allow-stale-for-rollback")
    try:
        result = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
            user=identities.dashboard_uid,
            group=identities.dashboard_gid,
            extra_groups=(),
            env={
                "LANG": "C.UTF-8",
                "PATH": "/usr/bin:/bin",
                "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONNOUSERSITE": "1",
            },
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ProductionToolError("Verifier gate snapshot non eseguibile.") from exc
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise ProductionToolError("Output verifier gate snapshot non valido.") from exc
    if not isinstance(payload, dict):
        raise ProductionToolError("Output verifier gate snapshot non strutturato.")
    if (
        result.returncode != 0
        or payload.get("approved") is not True
        or payload.get("gate_version") != "1.1"
        or payload.get("manifest_verified") is not True
    ):
        failures = payload.get("failures")
        rendered = ",".join(failures) if isinstance(failures, list) else "gate_failed"
        raise ProductionToolError(f"Snapshot gate v1.1 rifiutato: {rendered}")
    return payload


def _inspect_store(
    root: Path,
    identities: Identities,
    *,
    allow_sensor_stats_server_error: bool,
    allow_missing_manifest_archive: bool,
    gate_python: Path | None = None,
    allow_stale_for_rollback: bool = False,
) -> StoreState:
    for directory in (
        root,
        root / "objects",
        root / "current",
        root / "previous",
        root / "last_known_good",
    ):
        _verify_store_directory(directory, identities)
    manifests = root / "manifests"
    manifests_ready = _lexists(manifests)
    if manifests_ready:
        _verify_store_directory(manifests, identities)
    elif not allow_missing_manifest_archive:
        raise ProductionToolError(f"Directory manifest immutabili mancante: {manifests}")

    manifest_path = root / "current" / "manifest.json"
    manifest_bytes = _verify_publisher_file(
        manifest_path,
        identities,
        label="Manifest snapshot current",
    )
    manifest = _json_object(manifest_bytes, label="manifest snapshot current")
    required = {
        "manifest_version",
        "snapshot_id",
        "sha256",
        "object_name",
        "byte_length",
        "trusted_origin",
    }
    if required - set(manifest):
        raise ProductionToolError("Manifest snapshot current incompleto.")
    digest = manifest.get("sha256")
    object_name = manifest.get("object_name")
    byte_length = manifest.get("byte_length")
    if (
        manifest.get("manifest_version") != "1.0"
        or manifest.get("trusted_origin") != "dtlab_collector"
        or not isinstance(digest, str)
        or not _SHA256.fullmatch(digest)
        or object_name != f"{digest}.json"
        or type(byte_length) is not int
        or byte_length < 0
    ):
        raise ProductionToolError("Manifest snapshot current non valido.")

    object_path = root / "objects" / str(object_name)
    object_bytes = _verify_publisher_file(
        object_path,
        identities,
        label="Oggetto snapshot",
    )
    if len(object_bytes) != byte_length or _sha256_bytes(object_bytes) != digest:
        raise ProductionToolError("Integrità oggetto snapshot non valida.")
    snapshot = _json_object(object_bytes, label="oggetto snapshot")
    if snapshot.get("snapshot_id") != manifest.get("snapshot_id"):
        raise ProductionToolError("Snapshot ID incoerente con il manifest.")
    (
        sync_state,
        runtime_sync_state,
        snapshot_age_seconds,
        quality_score,
        exceptions,
        gate_warnings,
        freshness_policy,
    ) = _evaluate_snapshot_gate(
        snapshot,
        allow_sensor_stats_server_error=allow_sensor_stats_server_error,
        allow_stale_for_rollback=allow_stale_for_rollback,
    )
    if gate_python is not None:
        exact_gate = _run_exact_snapshot_gate(
            root,
            gate_python,
            identities,
            allow_sensor_stats_server_error=allow_sensor_stats_server_error,
            allow_stale_for_rollback=allow_stale_for_rollback,
        )
        if exact_gate.get("manifest_sha256") != digest:
            raise ProductionToolError("Gate snapshot e oggetto verificato non coerenti.")
        exact_exceptions = exact_gate.get("approved_exceptions")
        exact_warnings = exact_gate.get("warnings")
        exact_freshness_policy = exact_gate.get("freshness_policy")
        exact_runtime_sync_state = exact_gate.get("runtime_sync_state")
        rollback_stale_verified = (
            allow_stale_for_rollback
            and exact_gate.get("sync_state") in {"fresh", "partial"}
            and exact_runtime_sync_state == "stale"
            and exact_freshness_policy == ROLLBACK_STALE_FRESHNESS_POLICY
            and isinstance(exact_warnings, list)
            and ROLLBACK_STALE_FRESHNESS_POLICY in exact_warnings
        )
        if (
            exact_gate.get("sync_state") not in {"fresh", "partial"}
            or (
                exact_runtime_sync_state not in {"fresh", "partial"}
                and not rollback_stale_verified
            )
            or type(exact_gate.get("snapshot_age_seconds")) is not int
            or type(exact_gate.get("quality_score")) is not int
            or not isinstance(exact_exceptions, list)
            or not all(isinstance(value, str) for value in exact_exceptions)
            or not isinstance(exact_warnings, list)
            or not all(isinstance(value, str) for value in exact_warnings)
            or exact_freshness_policy
            not in {STRICT_FRESHNESS_POLICY, ROLLBACK_STALE_FRESHNESS_POLICY}
            or (
                exact_freshness_policy == ROLLBACK_STALE_FRESHNESS_POLICY
                and not rollback_stale_verified
            )
            or (
                exact_runtime_sync_state != "stale"
                and exact_freshness_policy != STRICT_FRESHNESS_POLICY
            )
        ):
            raise ProductionToolError("Output gate snapshot approvato incompleto.")
        sync_state = str(exact_gate["sync_state"])
        runtime_sync_state = str(exact_gate["runtime_sync_state"])
        snapshot_age_seconds = int(exact_gate["snapshot_age_seconds"])
        quality_score = int(exact_gate["quality_score"])
        exceptions = tuple(sorted(exact_exceptions))
        gate_warnings = tuple(sorted(exact_warnings))
        freshness_policy = str(exact_freshness_policy)

    manifest_sha256 = _sha256_bytes(manifest_bytes)
    archive = manifests / f"{manifest_sha256}.json"
    archive_ready = _lexists(archive) if manifests_ready else False
    if archive_ready:
        archived_bytes = _verify_publisher_file(
            archive,
            identities,
            label="Manifest snapshot immutabile",
        )
        if archived_bytes != manifest_bytes:
            raise ProductionToolError("Manifest snapshot immutabile incoerente.")
    elif not allow_missing_manifest_archive:
        raise ProductionToolError("Manifest snapshot immutabile corrente mancante.")

    return StoreState(
        root=root,
        snapshot_sha256=digest,
        manifest_sha256=manifest_sha256,
        snapshot_id=str(manifest["snapshot_id"]),
        object_name=str(object_name),
        byte_length=byte_length,
        sync_state=sync_state,
        quality_score=quality_score,
        approved_exceptions=exceptions,
        manifest_archive_ready=archive_ready,
        manifest_bytes=manifest_bytes,
        runtime_sync_state=runtime_sync_state,
        snapshot_age_seconds=snapshot_age_seconds,
        freshness_policy=freshness_policy,
        gate_warnings=gate_warnings,
    )


def _ensure_production_manifest_archive(
    state: StoreState,
    identities: Identities,
) -> None:
    manifests = PRODUCTION_STORE / "manifests"
    if not _lexists(manifests):
        try:
            manifests.mkdir(mode=0o750)
        except FileExistsError:
            pass
        else:
            descriptor: int | None = None
            try:
                descriptor = os.open(
                    manifests,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                )
                before = os.fstat(descriptor)
                os.fchown(
                    descriptor,
                    identities.publisher_uid,
                    identities.dashboard_gid,
                )
                os.fchmod(descriptor, 0o750)
                after = os.fstat(descriptor)
                visible = manifests.lstat()
                if (
                    not stat.S_ISDIR(before.st_mode)
                    or before.st_uid != identities.root_uid
                    or (visible.st_dev, visible.st_ino)
                    != (after.st_dev, after.st_ino)
                    or manifests.is_symlink()
                ):
                    raise ProductionToolError(
                        "Directory manifest cambiata durante il bootstrap."
                    )
            except OSError as exc:
                raise ProductionToolError(
                    "Bootstrap directory manifest produzione fallito."
                ) from exc
            finally:
                if descriptor is not None:
                    os.close(descriptor)
    _verify_store_directory(manifests, identities)
    archive = manifests / f"{state.manifest_sha256}.json"
    if _lexists(archive):
        archived = _verify_publisher_file(
            archive,
            identities,
            label="Manifest snapshot immutabile",
        )
        if archived != state.manifest_bytes:
            raise ProductionToolError("Manifest immutabile produzione incoerente.")
        return
    temporary = manifests / f".{archive.name}.{uuid.uuid4().hex}.tmp"
    descriptor: int | None = None
    try:
        descriptor = os.open(
            temporary,
            os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW,
            0o600,
        )
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            handle.write(state.manifest_bytes)
            handle.flush()
            os.fsync(handle.fileno())
        os.fchown(descriptor, identities.publisher_uid, identities.dashboard_gid)
        os.fchmod(descriptor, 0o640)
        written = os.fstat(descriptor)
        visible = temporary.lstat()
        if (
            (visible.st_dev, visible.st_ino) != (written.st_dev, written.st_ino)
            or temporary.is_symlink()
        ):
            raise ProductionToolError("Temp manifest cambiato durante la scrittura.")
        os.replace(temporary, archive)
        installed = archive.lstat()
        if (
            (installed.st_dev, installed.st_ino) != (written.st_dev, written.st_ino)
            or archive.is_symlink()
            or installed.st_uid != identities.publisher_uid
            or installed.st_gid != identities.dashboard_gid
            or stat.S_IMODE(installed.st_mode) != 0o640
        ):
            raise ProductionToolError("Manifest immutabile installato non sicuro.")
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if _lexists(temporary):
            temporary.unlink()


def _require_matching_store_data(production: StoreState, staging: StoreState) -> None:
    if (
        production.snapshot_sha256 != staging.snapshot_sha256
        or production.manifest_sha256 != staging.manifest_sha256
        or production.snapshot_id != staging.snapshot_id
        or production.manifest_bytes != staging.manifest_bytes
    ):
        raise ProductionToolError(
            "Snapshot produzione non identico allo snapshot staging approvato."
        )


def _verify_root_tree_entry(path: Path, identities: Identities) -> None:
    details = path.lstat()
    if details.st_uid != identities.root_uid or details.st_gid != identities.dashboard_gid:
        raise ProductionToolError(f"Ownership root/dashboard inattesa: {path}")
    if path.is_symlink():
        return
    if not (stat.S_ISDIR(details.st_mode) or stat.S_ISREG(details.st_mode)):
        raise ProductionToolError(f"File speciale non ammesso: {path}")
    if stat.S_IMODE(details.st_mode) & 0o022:
        raise ProductionToolError(f"Percorso scrivibile da gruppo/altri: {path}")


def _verify_release(
    release_id: str,
    identities: Identities,
    *,
    require_ticket_runtime: bool,
) -> TargetInfo:
    release = RELEASES_ROOT / f"{_RELEASE_PREFIX}{release_id}"
    _require_regular_directory(release)
    _verify_root_tree_entry(release, identities)
    manifest_path = release / "release-manifest.json"
    if not manifest_path.is_file() or manifest_path.is_symlink():
        raise ProductionToolError("Manifest release installata assente o non regolare.")
    _verify_root_tree_entry(manifest_path, identities)
    manifest = _json_object(manifest_path.read_bytes(), label="release-manifest.json")
    records = _manifest_records(manifest)
    content_sha256 = str(manifest["content_sha256"])
    if content_sha256[:16] != release_id:
        raise ProductionToolError("Release ID incoerente con il manifest.")

    expected_files = set(records) | {"release-manifest.json"}
    actual_files: set[str] = set()
    expected_directories = {"."}
    for relative in expected_files:
        parent = PurePosixPath(relative).parent
        while str(parent) != ".":
            expected_directories.add(str(parent))
            parent = parent.parent
    actual_directories = {"."}

    for candidate in release.rglob("*"):
        relative = candidate.relative_to(release).as_posix()
        if candidate.is_symlink():
            raise ProductionToolError(f"Symlink non ammesso nella release: {relative}")
        _verify_root_tree_entry(candidate, identities)
        if candidate.is_dir():
            actual_directories.add(relative)
        elif candidate.is_file():
            actual_files.add(relative)

    if actual_files != expected_files or actual_directories != expected_directories:
        raise ProductionToolError("File set release diverso dal manifest.")
    for relative, record in records.items():
        candidate = release.joinpath(*PurePosixPath(relative).parts)
        if (
            candidate.stat().st_size != record["bytes"]
            or _sha256_file(candidate) != record["sha256"]
        ):
            raise ProductionToolError(f"File release non valido: {relative}")

    unit_key = str(UNIT_ARCHIVE_PATH)
    if unit_key not in records:
        raise ProductionToolError("Unità produzione assente dal manifest.")
    unit_path = release.joinpath(*UNIT_ARCHIVE_PATH.parts)
    unit_bytes = unit_path.read_bytes()
    has_ticket_runtime = _validate_production_unit(
        unit_bytes,
        require_ticket_runtime=require_ticket_runtime,
    )
    staging_unit_key = str(STAGING_UNIT_ARCHIVE_PATH)
    if staging_unit_key not in records:
        raise ProductionToolError("Unità staging assente dal manifest.")
    staging_unit_bytes = release.joinpath(*STAGING_UNIT_ARCHIVE_PATH.parts).read_bytes()
    if require_ticket_runtime:
        _validate_staging_unit_for_promotion(staging_unit_bytes)
    ingest_service_key = str(INGEST_SERVICE_ARCHIVE_PATH)
    ingest_path_key = str(INGEST_PATH_ARCHIVE_PATH)
    if (ingest_service_key in records) != (ingest_path_key in records):
        raise ProductionToolError("Release con unità ticket ingest parziali.")
    if ingest_service_key not in records:
        if require_ticket_runtime:
            raise ProductionToolError("Unità ticket ingest assenti dal manifest.")
        ingest_service_bytes = b""
        ingest_path_bytes = b""
    else:
        ingest_service_bytes = release.joinpath(*INGEST_SERVICE_ARCHIVE_PATH.parts).read_bytes()
        ingest_path_bytes = release.joinpath(*INGEST_PATH_ARCHIVE_PATH.parts).read_bytes()
        _validate_ingest_units(ingest_service_bytes, ingest_path_bytes)
    venv = _verify_venv(release_id, records, identities)
    return TargetInfo(
        release_id=release_id,
        release=release,
        venv=venv,
        content_sha256=content_sha256,
        unit_bytes=unit_bytes,
        unit_sha256=_sha256_bytes(unit_bytes),
        has_ticket_runtime=has_ticket_runtime,
        staging_unit_sha256=_sha256_bytes(staging_unit_bytes),
        ingest_service_bytes=ingest_service_bytes,
        ingest_service_sha256=(
            _sha256_bytes(ingest_service_bytes) if ingest_service_bytes else ""
        ),
        ingest_path_bytes=ingest_path_bytes,
        ingest_path_sha256=_sha256_bytes(ingest_path_bytes) if ingest_path_bytes else "",
    )


def _verify_venv(
    release_id: str,
    records: Mapping[str, Mapping[str, Any]],
    identities: Identities,
) -> Path:
    venv = VENVS_ROOT / release_id
    _require_regular_directory(venv)
    for candidate in [venv, *venv.rglob("*")]:
        _verify_root_tree_entry(candidate, identities)

    marker_path = venv / _VENV_MARKER
    python_path = venv / "bin" / "python"
    if not marker_path.is_file() or marker_path.is_symlink():
        raise ProductionToolError("Marker venv assente o non regolare.")
    if not python_path.exists() or not (python_path.is_file() or python_path.is_symlink()):
        raise ProductionToolError("Python del venv assente.")

    if "requirements-server.lock" in records:
        requirements_path = "requirements-server.lock"
    elif "requirements.lock" in records:
        requirements_path = "requirements.lock"
    else:
        raise ProductionToolError("Lockfile release assente.")
    expected_marker = {
        "marker_version": "1.0",
        "release_id": release_id,
        "requirements_path": requirements_path,
        "requirements_sha256": records[requirements_path]["sha256"],
    }
    marker = _json_object(marker_path.read_bytes(), label="marker venv")
    if marker != expected_marker:
        raise ProductionToolError("Marker venv incoerente con la release.")

    try:
        canonical_python = python_path.resolve(strict=True)
        python_details = canonical_python.lstat()
    except (OSError, RuntimeError) as exc:
        raise ProductionToolError("Interprete venv non risolvibile.") from exc
    if (
        not stat.S_ISREG(python_details.st_mode)
        or python_details.st_uid != identities.root_uid
        or stat.S_IMODE(python_details.st_mode) & 0o022
        or not stat.S_IMODE(python_details.st_mode) & stat.S_IXUSR
    ):
        raise ProductionToolError("Interprete venv non attendibile.")
    return venv


def _parse_unit(content: bytes) -> list[tuple[str, str, str]]:
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ProductionToolError("Unità produzione non UTF-8.") from exc
    section: str | None = None
    directives: list[tuple[str, str, str]] = []
    allowed_sections = {"Unit", "Service", "Path", "Install"}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1]
            if section not in allowed_sections:
                raise ProductionToolError(f"Sezione unità non ammessa: {section}")
            continue
        if section is None or "=" not in line or raw_line.rstrip().endswith("\\"):
            raise ProductionToolError("Sintassi unità produzione non ammessa.")
        key, value = line.split("=", 1)
        directives.append((section, key, value))
    if not directives or len(directives) != len(set(directives)):
        raise ProductionToolError("Unità produzione vuota o con direttive duplicate.")
    return directives


def _validate_production_unit(
    content: bytes,
    *,
    require_ticket_runtime: bool,
) -> bool:
    directives = set(_parse_unit(content))
    release_link = PRODUCTION_RELEASE_LINK.as_posix()
    venv_link = PRODUCTION_VENV_LINK.as_posix()
    store = PRODUCTION_STORE.as_posix()
    ticket_root = PRODUCTION_TICKET_ROOT.as_posix()
    host_ot_root = f"{PRIVATE_ROOT.as_posix()}/modbus-dashboard-host-ot-data"
    inaccessible = INACCESSIBLE_APPLICATION_ROOT.as_posix()

    required = {
        ("Unit", "Description", "DTLab Control Center v2"),
        ("Unit", "After", "network-online.target"),
        ("Unit", "Wants", "network-online.target"),
        ("Service", "Type", "simple"),
        ("Service", "User", DASHBOARD_USER),
        ("Service", "Group", DASHBOARD_GROUP),
        ("Service", "WorkingDirectory", release_link),
        ("Service", "Environment", f"PYTHONPATH={release_link}/src"),
        ("Service", "Environment", f"DTLAB_SNAPSHOT_STORE={store}"),
        ("Service", "Environment", "STREAMLIT_BROWSER_GATHER_USAGE_STATS=false"),
        (
            "Service",
            "ExecStart",
            f"{venv_link}/bin/python -m streamlit run app.py "
            "--server.address=127.0.0.1 --server.port=8517 --server.headless=true",
        ),
        ("Service", "Restart", "on-failure"),
        ("Service", "RestartSec", "3"),
        ("Service", "TimeoutStopSec", "20"),
        ("Service", "NoNewPrivileges", "true"),
        ("Service", "PrivateTmp", "true"),
        ("Service", "PrivateDevices", "true"),
        ("Service", "ProtectHome", "true"),
        ("Service", "ProtectSystem", "strict"),
        ("Service", "ProtectKernelTunables", "true"),
        ("Service", "ProtectKernelModules", "true"),
        ("Service", "ProtectControlGroups", "true"),
        ("Service", "RestrictSUIDSGID", "true"),
        ("Service", "LockPersonality", "true"),
        ("Service", "RestrictAddressFamilies", "AF_UNIX AF_INET AF_INET6"),
        ("Service", "ReadOnlyPaths", RELEASES_ROOT.as_posix()),
        ("Service", "ReadOnlyPaths", VENVS_ROOT.as_posix()),
        ("Service", "ReadOnlyPaths", store),
        ("Service", "InaccessiblePaths", inaccessible),
        ("Install", "WantedBy", "multi-user.target"),
    }
    ticket_directives = {
        (
            "Service",
            "Environment",
            f"DTLAB_TICKET_STORE={ticket_root}/tickets.sqlite3",
        ),
        ("Service", "ReadWritePaths", ticket_root),
    }
    host_ot_directives = {
        ("Service", "Environment", f"DTLAB_HOST_OT_EVENT_STORE={host_ot_root}"),
        ("Service", "ReadOnlyPaths", f"-{host_ot_root}"),
    }
    optional = {
        ("Service", "Environment", "DTLAB_UI_REFRESH_SECONDS=15"),
        ("Service", "UMask", "0027"),
        ("Service", "UMask", "0077"),
        *ticket_directives,
        *host_ot_directives,
    }
    allowed = required | optional
    unexpected = directives - allowed
    missing = required - directives
    if unexpected:
        rendered = ", ".join(f"{s}.{k}" for s, k, _ in sorted(unexpected))
        raise ProductionToolError(f"Direttive unità produzione non ammesse: {rendered}")
    if missing:
        rendered = ", ".join(f"{s}.{k}" for s, k, _ in sorted(missing))
        raise ProductionToolError(f"Unità produzione incompleta: {rendered}")
    present_ticket = ticket_directives & directives
    if present_ticket and present_ticket != ticket_directives:
        raise ProductionToolError("Configurazione ticket unità incompleta.")
    has_ticket_runtime = present_ticket == ticket_directives
    present_host_ot = host_ot_directives & directives
    if present_host_ot and present_host_ot != host_ot_directives:
        raise ProductionToolError("Configurazione copertura host OT incompleta.")
    has_host_ot_runtime = present_host_ot == host_ot_directives
    if require_ticket_runtime and not has_ticket_runtime:
        raise ProductionToolError("La promozione richiede il runtime ticket persistente.")
    if require_ticket_runtime and not has_host_ot_runtime:
        raise ProductionToolError("La promozione richiede la copertura sensore host OT.")
    umasks = {value for section, key, value in directives if (section, key) == ("Service", "UMask")}
    if len(umasks) != 1 or not umasks <= {"0027", "0077"}:
        raise ProductionToolError("UMask unità produzione non valida.")
    if require_ticket_runtime and umasks != {"0077"}:
        raise ProductionToolError("La promozione richiede UMask=0077.")
    return has_ticket_runtime


def _validate_staging_unit_for_promotion(content: bytes) -> None:
    staging_release = STAGING_RELEASE_LINK.as_posix()
    staging_venv = STAGING_VENV_LINK.as_posix()
    staging_store = STAGING_STORE.as_posix()
    private_root = PRIVATE_ROOT.as_posix()
    inaccessible = INACCESSIBLE_APPLICATION_ROOT.as_posix()
    ticket_root = f"{private_root}/modbus-dashboard-ticket-data-staging"
    host_ot_root = f"{private_root}/modbus-dashboard-host-ot-data-staging"
    expected = {
        ("Unit", "Description", "DTLab Control Center v2 staging"),
        ("Unit", "After", "network-online.target"),
        ("Unit", "Wants", "network-online.target"),
        ("Service", "Type", "simple"),
        ("Service", "User", DASHBOARD_USER),
        ("Service", "Group", DASHBOARD_GROUP),
        ("Service", "WorkingDirectory", staging_release),
        ("Service", "Environment", f"PYTHONPATH={staging_release}/src"),
        ("Service", "Environment", f"DTLAB_SNAPSHOT_STORE={staging_store}"),
        (
            "Service",
            "Environment",
            f"DTLAB_TICKET_STORE={ticket_root}/tickets.sqlite3",
        ),
        (
            "Service",
            "Environment",
            f"DTLAB_HOST_OT_EVENT_STORE={host_ot_root}",
        ),
        ("Service", "Environment", "DTLAB_UI_REFRESH_SECONDS=15"),
        (
            "Service",
            "Environment",
            "STREAMLIT_BROWSER_GATHER_USAGE_STATS=false",
        ),
        (
            "Service",
            "ExecStart",
            f"{staging_venv}/bin/python -m streamlit run app.py "
            "--server.address=127.0.0.1 --server.port=8518 --server.headless=true",
        ),
        ("Service", "Restart", "on-failure"),
        ("Service", "RestartSec", "3"),
        ("Service", "TimeoutStopSec", "20"),
        ("Service", "UMask", "0077"),
        ("Service", "NoNewPrivileges", "true"),
        ("Service", "PrivateTmp", "true"),
        ("Service", "PrivateDevices", "true"),
        ("Service", "ProtectHome", "true"),
        ("Service", "ProtectSystem", "strict"),
        ("Service", "ProtectKernelTunables", "true"),
        ("Service", "ProtectKernelModules", "true"),
        ("Service", "ProtectControlGroups", "true"),
        ("Service", "RestrictSUIDSGID", "true"),
        ("Service", "LockPersonality", "true"),
        ("Service", "RestrictAddressFamilies", "AF_UNIX AF_INET AF_INET6"),
        ("Service", "ReadOnlyPaths", RELEASES_ROOT.as_posix()),
        ("Service", "ReadOnlyPaths", VENVS_ROOT.as_posix()),
        ("Service", "ReadOnlyPaths", staging_store),
        ("Service", "ReadOnlyPaths", f"-{host_ot_root}"),
        ("Service", "ReadWritePaths", ticket_root),
        ("Service", "InaccessiblePaths", inaccessible),
        ("Install", "WantedBy", "multi-user.target"),
    }
    if set(_parse_unit(content)) != expected:
        raise ProductionToolError("Unità staging inclusa non pronta per promozione.")


def _validate_ingest_units(service_content: bytes, path_content: bytes) -> None:
    store = PRODUCTION_STORE.as_posix()
    release = PRODUCTION_RELEASE_LINK.as_posix()
    venv = PRODUCTION_VENV_LINK.as_posix()
    ticket_database = PRODUCTION_TICKET_DATABASE.as_posix()
    ticket_root = PRODUCTION_TICKET_ROOT.as_posix()
    inaccessible = INACCESSIBLE_APPLICATION_ROOT.as_posix()
    forbidden = (b"modbus-dashboard-data-staging", b"staging-current", b"0.0.0.0")
    if any(value in service_content + path_content for value in forbidden):
        raise ProductionToolError("Unità ticket ingest non isolate dalla produzione.")
    expected_service = {
        ("Unit", "Description", "DTLab production snapshot ticket ingest"),
        ("Unit", "After", "network-online.target"),
        ("Unit", "ConditionPathIsDirectory", f"{store}/manifests"),
        ("Service", "Type", "oneshot"),
        ("Service", "User", DASHBOARD_USER),
        ("Service", "Group", DASHBOARD_GROUP),
        ("Service", "WorkingDirectory", release),
        ("Service", "Environment", f"PYTHONPATH={release}/src"),
        ("Service", "Environment", f"DTLAB_SNAPSHOT_STORE={store}"),
        ("Service", "Environment", f"DTLAB_TICKET_STORE={ticket_database}"),
        (
            "Service",
            "ExecStart",
            f"{venv}/bin/python -m dtlab.services.ticket_ingest_worker",
        ),
        ("Service", "UMask", "0077"),
        ("Service", "NoNewPrivileges", "true"),
        ("Service", "PrivateTmp", "true"),
        ("Service", "PrivateDevices", "true"),
        ("Service", "ProtectHome", "true"),
        ("Service", "ProtectSystem", "strict"),
        ("Service", "ProtectKernelTunables", "true"),
        ("Service", "ProtectKernelModules", "true"),
        ("Service", "ProtectControlGroups", "true"),
        ("Service", "RestrictSUIDSGID", "true"),
        ("Service", "LockPersonality", "true"),
        ("Service", "RestrictAddressFamilies", "AF_UNIX"),
        ("Service", "ReadOnlyPaths", RELEASES_ROOT.as_posix()),
        ("Service", "ReadOnlyPaths", VENVS_ROOT.as_posix()),
        ("Service", "ReadOnlyPaths", store),
        ("Service", "ReadWritePaths", ticket_root),
        ("Service", "InaccessiblePaths", inaccessible),
    }
    expected_path = {
        ("Unit", "Description", "Watch DTLab production immutable snapshot manifests"),
        ("Path", "PathChanged", f"{store}/manifests"),
        ("Path", "Unit", INGEST_SERVICE_NAME),
        ("Install", "WantedBy", "multi-user.target"),
    }
    if set(_parse_unit(service_content)) != expected_service:
        raise ProductionToolError("Unità service ticket ingest incomplete o non canonica.")
    if set(_parse_unit(path_content)) != expected_path:
        raise ProductionToolError("Unità path ticket ingest incomplete o non canonica.")


def _capture_link(path: Path, *, allowed_root: Path) -> LinkState:
    try:
        details = path.lstat()
    except FileNotFoundError:
        return LinkState(False, None)
    if not stat.S_ISLNK(details.st_mode):
        raise ProductionToolError(f"Il puntatore non è un symlink: {path}")
    target = os.readlink(path)
    target_path = Path(target)
    if not target_path.is_absolute() or target_path.parent != allowed_root:
        raise ProductionToolError(f"Target symlink fuori dal root autorizzato: {path}")
    expected_name = (
        re.compile(rf"^{re.escape(_RELEASE_PREFIX)}[a-f0-9]{{16}}$")
        if allowed_root == RELEASES_ROOT
        else _RELEASE_ID
    )
    if not expected_name.fullmatch(target_path.name):
        raise ProductionToolError(f"Nome target symlink non valido: {path}")
    if not target_path.is_dir() or target_path.is_symlink():
        raise ProductionToolError(f"Target symlink assente o non regolare: {path}")
    return LinkState(True, target)


def _require_current_staging(target: TargetInfo) -> StagingState:
    release_state = _capture_link(STAGING_RELEASE_LINK, allowed_root=RELEASES_ROOT)
    venv_state = _capture_link(STAGING_VENV_LINK, allowed_root=VENVS_ROOT)
    if (
        not release_state.exists
        or release_state.target != str(target.release)
        or not venv_state.exists
        or venv_state.target != str(target.venv)
    ):
        raise ProductionToolError(
            "La promozione richiede release e venv correnti nello staging."
        )
    try:
        unit_details = STAGING_UNIT_DESTINATION.lstat()
    except OSError as exc:
        raise ProductionToolError("Unità staging installata mancante.") from exc
    if (
        not stat.S_ISREG(unit_details.st_mode)
        or STAGING_UNIT_DESTINATION.is_symlink()
        or unit_details.st_uid != 0
        or unit_details.st_gid != 0
        or stat.S_IMODE(unit_details.st_mode) != 0o644
    ):
        raise ProductionToolError("Unità staging installata non sicura.")
    unit_bytes = STAGING_UNIT_DESTINATION.read_bytes()
    _validate_staging_unit_for_promotion(unit_bytes)
    unit_sha256 = _sha256_bytes(unit_bytes)
    if unit_sha256 != target.staging_unit_sha256:
        raise ProductionToolError("Unità staging diversa dalla release da promuovere.")
    service = _capture_named_service(STAGING_SERVICE_NAME)
    if not _service_ready(service, expected_active=True, expected_enabled=True):
        raise ProductionToolError("Servizio staging non pronto per la promozione.")
    if not _http_health_ok(STAGING_HEALTH_PORT):
        raise ProductionToolError("Health staging non pronta per la promozione.")
    return StagingState(service=service, unit_sha256=unit_sha256)


def _capture_unit() -> UnitState:
    try:
        details = UNIT_DESTINATION.lstat()
    except FileNotFoundError:
        return UnitState(False, None, None, None, None)
    if not stat.S_ISREG(details.st_mode) or UNIT_DESTINATION.is_symlink():
        raise ProductionToolError("Destinazione unità produzione non regolare.")
    if details.st_uid != 0 or details.st_gid != 0 or stat.S_IMODE(details.st_mode) != 0o644:
        raise ProductionToolError("Ownership o permessi unità produzione inattesi.")
    content = UNIT_DESTINATION.read_bytes()
    _validate_production_unit(content, require_ticket_runtime=False)
    return UnitState(
        True,
        content,
        details.st_uid,
        details.st_gid,
        stat.S_IMODE(details.st_mode),
    )


def _capture_raw_unit(path: Path) -> UnitState:
    try:
        details = path.lstat()
    except FileNotFoundError:
        return UnitState(False, None, None, None, None)
    if (
        not stat.S_ISREG(details.st_mode)
        or path.is_symlink()
        or details.st_uid != 0
        or details.st_gid != 0
        or stat.S_IMODE(details.st_mode) != 0o644
    ):
        raise ProductionToolError(f"Unità systemd non sicura: {path}")
    return UnitState(
        True,
        path.read_bytes(),
        details.st_uid,
        details.st_gid,
        stat.S_IMODE(details.st_mode),
    )


def _run_systemctl(*arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            ["systemctl", *arguments],
            check=check,
            capture_output=True,
            text=True,
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ProductionToolError("Operazione systemd produzione non riuscita.") from exc


def _capture_named_service(service_name: str) -> ServiceState:
    active_result = _run_systemctl(
        "is-active", "--quiet", service_name, check=False
    )
    enabled_result = _run_systemctl(
        "is-enabled", "--quiet", service_name, check=False
    )
    show = _run_systemctl(
        "show",
        service_name,
        "--property=LoadState",
        "--property=MainPID",
        "--property=ExecMainStatus",
        "--property=Result",
        "--no-pager",
        check=False,
    )
    if show.returncode != 0:
        raise ProductionToolError("Impossibile verificare lo stato systemd.")
    values: dict[str, str] = {}
    for line in show.stdout.splitlines():
        key, separator, value = line.partition("=")
        if separator:
            values[key] = value
    required = {"LoadState", "Result"}
    if service_name.endswith(".service"):
        required.update({"MainPID", "ExecMainStatus"})
    if required - set(values):
        raise ProductionToolError("Stato systemd incompleto.")
    load_state = values["LoadState"]
    if load_state == "not-found":
        if active_result.returncode == 0 or enabled_result.returncode == 0:
            raise ProductionToolError("Stato systemd incoerente per unità assente.")
        return ServiceState(active=False, enabled=False)
    if load_state != "loaded":
        raise ProductionToolError(f"Unità systemd non caricabile: {load_state}")
    if active_result.returncode not in {0, 3} or enabled_result.returncode not in {0, 1}:
        raise ProductionToolError("Comando stato systemd non concluso correttamente.")
    try:
        main_pid = int(values.get("MainPID", "0"))
        exec_main_status = int(values.get("ExecMainStatus", "0"))
    except ValueError as exc:
        raise ProductionToolError("Stato numerico systemd non valido.") from exc
    return ServiceState(
        active=active_result.returncode == 0,
        enabled=enabled_result.returncode == 0,
        main_pid=main_pid,
        exec_main_status=exec_main_status,
        result=values.get("Result", "success"),
    )


def _capture_service() -> ServiceState:
    return _capture_named_service(SERVICE_NAME)


def _service_ready(
    state: ServiceState,
    *,
    expected_active: bool,
    expected_enabled: bool,
) -> bool:
    if state.active != expected_active or state.enabled != expected_enabled:
        return False
    if state.exec_main_status != 0 or state.result not in {"success", ""}:
        return False
    if expected_active:
        return state.main_pid > 0
    return state.main_pid == 0


def _http_health_ok(port: int) -> bool:
    connection: http.client.HTTPConnection | None = None
    try:
        connection = http.client.HTTPConnection(HEALTH_HOST, port, timeout=2)
        connection.request("GET", HEALTH_PATH)
        response = connection.getresponse()
        return response.status == 200 and response.read(128).strip().lower() == b"ok"
    except (OSError, http.client.HTTPException):
        return False
    finally:
        if connection is not None:
            connection.close()


def _capture_deployment() -> DeploymentState:
    ingest_service_unit = _capture_raw_unit(INGEST_SERVICE_DESTINATION)
    ingest_path_unit = _capture_raw_unit(INGEST_PATH_DESTINATION)
    if ingest_service_unit.exists != ingest_path_unit.exists:
        raise ProductionToolError("Installazione ticket ingest parziale.")
    if ingest_service_unit.content is not None and ingest_path_unit.content is not None:
        _validate_ingest_units(ingest_service_unit.content, ingest_path_unit.content)
    ingest_path_state = _capture_named_service(INGEST_PATH_NAME)
    ingest_service_state = _capture_named_service(INGEST_SERVICE_NAME)
    if not ingest_path_unit.exists and (ingest_path_state.active or ingest_path_state.enabled):
        raise ProductionToolError("Path ticket ingest attivo senza unità verificata.")
    if ingest_service_state.active:
        raise ProductionToolError(
            "Ticket ingest in esecuzione: attendere il completamento e riprovare."
        )
    return DeploymentState(
        release_link=_capture_link(PRODUCTION_RELEASE_LINK, allowed_root=RELEASES_ROOT),
        venv_link=_capture_link(PRODUCTION_VENV_LINK, allowed_root=VENVS_ROOT),
        unit=_capture_unit(),
        service=_capture_service(),
        ingest_service_unit=ingest_service_unit,
        ingest_path_unit=ingest_path_unit,
        ingest_path_state=ingest_path_state,
    )


def _ticket_paths() -> tuple[Path, ...]:
    return (
        PRODUCTION_TICKET_DATABASE,
        Path(f"{PRODUCTION_TICKET_DATABASE}-wal"),
        Path(f"{PRODUCTION_TICKET_DATABASE}-shm"),
    )


def _inspect_ticket_state(
    identities: Identities,
    *,
    allow_legacy_modes: bool = False,
) -> TicketState:
    if not _lexists(PRODUCTION_TICKET_ROOT):
        return TicketState(False, False)
    details = _require_regular_directory(PRODUCTION_TICKET_ROOT)
    allowed_directory_modes = {0o700, 0o750} if allow_legacy_modes else {0o700}
    if (
        details.st_uid != identities.dashboard_uid
        or details.st_gid != identities.dashboard_gid
        or stat.S_IMODE(details.st_mode) not in allowed_directory_modes
    ):
        raise ProductionToolError("Ownership o permessi ticket store produzione inattesi.")
    database_exists = _lexists(PRODUCTION_TICKET_DATABASE)
    database_mode: int | None = None
    allowed_file_modes = {0o600, 0o640} if allow_legacy_modes else {0o600}
    for path in _ticket_paths():
        if not _lexists(path):
            continue
        file_details = path.lstat()
        file_mode = stat.S_IMODE(file_details.st_mode)
        if (
            not stat.S_ISREG(file_details.st_mode)
            or path.is_symlink()
            or file_details.st_uid != identities.dashboard_uid
            or file_details.st_gid != identities.dashboard_gid
            or file_mode not in allowed_file_modes
            or not file_details.st_mode & stat.S_IWUSR
        ):
            raise ProductionToolError(f"File ticket produzione non sicuro: {path}")
        if path == PRODUCTION_TICKET_DATABASE:
            database_mode = file_mode
    if database_exists:
        try:
            uri = PRODUCTION_TICKET_DATABASE.resolve(strict=True).as_uri() + "?mode=ro"
            with sqlite3.connect(uri, uri=True, timeout=5) as connection:
                if connection.execute("PRAGMA quick_check").fetchone() != ("ok",):
                    raise ProductionToolError("Database ticket produzione non integro.")
        except sqlite3.Error as exc:
            raise ProductionToolError("Database ticket produzione non leggibile.") from exc
    return TicketState(
        True,
        database_exists,
        directory_mode=stat.S_IMODE(details.st_mode),
        database_mode=database_mode,
    )


def _narrow_ticket_path(
    path: Path,
    identities: Identities,
    *,
    directory: bool,
    allow_root_owner: bool = False,
) -> None:
    flags = os.O_RDONLY | os.O_NOFOLLOW
    if directory:
        flags |= os.O_DIRECTORY
    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags)
        before = os.fstat(descriptor)
        expected_type = stat.S_ISDIR if directory else stat.S_ISREG
        allowed_modes = {0o700, 0o750} if directory else {0o600, 0o640}
        owner_ok = before.st_uid == identities.dashboard_uid or (
            allow_root_owner and before.st_uid == identities.root_uid
        )
        group_ok = before.st_gid == identities.dashboard_gid or (
            allow_root_owner and before.st_uid == identities.root_uid
        )
        if (
            not expected_type(before.st_mode)
            or not owner_ok
            or not group_ok
            or stat.S_IMODE(before.st_mode) not in allowed_modes
        ):
            raise ProductionToolError(f"Percorso ticket non migrabile: {path}")
        os.fchown(descriptor, identities.dashboard_uid, identities.dashboard_gid)
        target_mode = 0o700 if directory else 0o600
        os.fchmod(descriptor, target_mode)
        after = os.fstat(descriptor)
        current = path.lstat()
        if (
            (current.st_dev, current.st_ino) != (after.st_dev, after.st_ino)
            or path.is_symlink()
            or after.st_uid != identities.dashboard_uid
            or after.st_gid != identities.dashboard_gid
            or stat.S_IMODE(after.st_mode) != target_mode
        ):
            raise ProductionToolError(f"Percorso ticket cambiato durante la migrazione: {path}")
    except OSError as exc:
        raise ProductionToolError(f"Migrazione sicura ticket fallita: {path}") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _ensure_ticket_directory(identities: Identities) -> TicketState:
    created = False
    if not _lexists(PRODUCTION_TICKET_ROOT):
        try:
            PRODUCTION_TICKET_ROOT.mkdir(mode=0o700)
            created = True
        except FileExistsError:
            created = False
        except OSError as exc:
            raise ProductionToolError("Creazione ticket store produzione fallita.") from exc
    else:
        _inspect_ticket_state(identities, allow_legacy_modes=True)
    _narrow_ticket_path(
        PRODUCTION_TICKET_ROOT,
        identities,
        directory=True,
        allow_root_owner=created,
    )
    for path in _ticket_paths():
        if _lexists(path):
            _narrow_ticket_path(path, identities, directory=False)
    return _inspect_ticket_state(identities)


def _deployment_payload(state: DeploymentState) -> dict[str, Any]:
    return {
        "release_link": {
            "exists": state.release_link.exists,
            "target": state.release_link.target,
        },
        "venv_link": {
            "exists": state.venv_link.exists,
            "target": state.venv_link.target,
        },
        "unit": {"exists": state.unit.exists, "sha256": state.unit.sha256},
        "service": {
            "active": state.service.active,
            "enabled": state.service.enabled,
            "exec_main_status": state.service.exec_main_status,
            "main_pid": state.service.main_pid,
            "result": state.service.result,
        },
        "ticket_ingest": {
            "path_state": {
                "active": state.ingest_path_state.active,
                "enabled": state.ingest_path_state.enabled,
                "exec_main_status": state.ingest_path_state.exec_main_status,
                "result": state.ingest_path_state.result,
            },
            "path_unit_sha256": state.ingest_path_unit.sha256,
            "service_unit_sha256": state.ingest_service_unit.sha256,
        },
    }


def _store_payload(state: StoreState | None) -> dict[str, Any] | None:
    if state is None:
        return None
    return {
        "approved_exceptions": list(state.approved_exceptions),
        "gate_warnings": list(state.gate_warnings),
        "manifest_archive_ready": state.manifest_archive_ready,
        "manifest_sha256": state.manifest_sha256,
        "quality_score": state.quality_score,
        "snapshot_age_seconds": state.snapshot_age_seconds,
        "snapshot_id": state.snapshot_id,
        "snapshot_sha256": state.snapshot_sha256,
        "freshness_policy": state.freshness_policy,
        "runtime_sync_state": state.runtime_sync_state,
        "sync_state": state.sync_state,
    }


def _plan_token_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Exclude only the continuously changing age counter from plan confirmation."""

    bound = dict(payload)
    for key in ("production_data", "staging_data"):
        data = payload.get(key)
        if isinstance(data, Mapping):
            bound_data = dict(data)
            bound_data.pop("snapshot_age_seconds", None)
            bound[key] = bound_data
    return bound


def _plan(
    action: str,
    target: TargetInfo,
    before: DeploymentState,
    ticket: TicketState,
    *,
    health_timeout: float,
    production_data: StoreState | None = None,
    staging_data: StoreState | None = None,
    staging_state: StagingState | None = None,
    allow_sensor_stats_server_error: bool = False,
) -> tuple[dict[str, Any], str]:
    operations = [
        f"verify immutable release {target.release}",
        f"verify immutable venv {target.venv}",
    ]
    if action == "promote":
        operations.extend(
            (
                "require exact release, venv and unit as healthy current staging targets",
                "require exact production snapshot SHA and manifest SHA as staging",
            )
        )
    elif (
        production_data is not None
        and production_data.freshness_policy == ROLLBACK_STALE_FRESHNESS_POLICY
    ):
        operations.append(
            "allow only a verified snapshot made stale by age during internal rollback"
        )
    operations.extend(
        [
            f"create/verify dashboard-owned ticket store {PRODUCTION_TICKET_ROOT}",
            f"capture unit, links, enabled and active state under {BACKUP_ROOT}",
            "create a consistent root-only SQLite backup when the database exists",
            f"atomically switch {PRODUCTION_RELEASE_LINK} and {PRODUCTION_VENV_LINK}",
            f"atomically install {UNIT_DESTINATION}",
            "atomically install/restore ticket ingest service and path units",
            f"restart only {SERVICE_NAME} and verify local health on port {HEALTH_PORT}",
            "run ticket ingest once, verify current snapshot, then enable its path unit",
            "restore unit, links and prior service state on any activation error",
        ]
    )
    payload = {
        "action": action,
        "before": _deployment_payload(before),
        "allow_classic_sensor_stats_server_error": allow_sensor_stats_server_error,
        "health_timeout_seconds": health_timeout,
        "operations": operations,
        "release": {
            "content_sha256": target.content_sha256,
            "id": target.release_id,
            "unit_sha256": target.unit_sha256,
            "ticket_ingest_path_sha256": target.ingest_path_sha256,
            "ticket_ingest_service_sha256": target.ingest_service_sha256,
        },
        "service": SERVICE_NAME,
        "production_data": _store_payload(production_data),
        "staging_data": _store_payload(staging_data),
        "staging_readiness": (
            {
                "service": {
                    "active": staging_state.service.active,
                    "enabled": staging_state.service.enabled,
                    "exec_main_status": staging_state.service.exec_main_status,
                    "main_pid": staging_state.service.main_pid,
                },
                "unit_sha256": staging_state.unit_sha256,
            }
            if staging_state is not None
            else None
        ),
        "ticket_state": {
            "database_exists": ticket.database_exists,
            "database_mode": ticket.database_mode,
            "directory_exists": ticket.directory_exists,
            "directory_mode": ticket.directory_mode,
        },
    }
    encoded = json.dumps(
        _plan_token_payload(payload),
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return payload, _sha256_bytes(encoded)


def _emit_plan(payload: Mapping[str, Any], token: str) -> None:
    print(
        json.dumps(
            {
                "apply": False,
                "confirm_plan": token,
                "plan": payload,
                "status": "dry-run",
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )


def _require_apply_host() -> None:
    if not sys.platform.startswith("linux"):
        raise ProductionToolError("--apply è consentito solo sull'host Linux produzione.")
    if os.geteuid() != 0:
        raise ProductionToolError("--apply richiede root.")


def _require_confirmation(args: argparse.Namespace, expected: str) -> None:
    if args.apply and args.confirm_plan != expected:
        raise ProductionToolError(
            "--apply richiede --confirm-plan uguale al token del dry-run corrente."
        )
    if not args.apply and args.confirm_plan is not None:
        raise ProductionToolError("--confirm-plan è ammesso soltanto con --apply.")


@contextmanager
def _production_lock() -> Iterator[None]:
    try:
        import fcntl
    except ImportError as exc:  # pragma: no cover - apply is Linux-only
        raise ProductionToolError("Lock POSIX produzione non disponibile.") from exc
    flags = os.O_CREAT | os.O_RDWR
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor: int | None = None
    try:
        descriptor = os.open(LOCK_PATH, flags, 0o600)
        details = os.fstat(descriptor)
        if (
            not stat.S_ISREG(details.st_mode)
            or details.st_uid != 0
            or details.st_gid != 0
            or stat.S_IMODE(details.st_mode) != 0o600
        ):
            raise ProductionToolError("Lock file produzione non root-only.")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise ProductionToolError("Un'altra operazione produzione è già attiva.") from exc
        yield
    except OSError as exc:
        raise ProductionToolError("Impossibile acquisire il lock produzione.") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _ensure_backup_root() -> None:
    parent = _require_regular_directory(BACKUP_ROOT.parent)
    if parent.st_uid != 0 or stat.S_IMODE(parent.st_mode) & 0o022:
        raise ProductionToolError("Parent backup produzione non attendibile.")
    if not BACKUP_ROOT.exists():
        try:
            BACKUP_ROOT.mkdir(mode=0o700)
            os.chown(BACKUP_ROOT, 0, 0)
            BACKUP_ROOT.chmod(0o700)
        except OSError as exc:
            raise ProductionToolError("Creazione root backup produzione fallita.") from exc
    details = _require_regular_directory(BACKUP_ROOT)
    if details.st_uid != 0 or details.st_gid != 0 or stat.S_IMODE(details.st_mode) != 0o700:
        raise ProductionToolError("Root backup produzione non root-only.")


def _new_backup_directory(action: str, release_id: str) -> Path:
    _ensure_backup_root()
    path = Path(tempfile.mkdtemp(prefix=f"{action}-{release_id}-", dir=BACKUP_ROOT))
    os.chown(path, 0, 0)
    path.chmod(0o700)
    return path


def _write_root_file(path: Path, content: bytes, *, mode: int = 0o600) -> None:
    temporary = path.parent / f".{path.name}.{uuid.uuid4().hex}.tmp"
    try:
        with temporary.open("xb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chown(temporary, 0, 0)
        temporary.chmod(mode)
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def _backup_database(destination: Path, identities: Identities) -> Path | None:
    ticket = _inspect_ticket_state(identities)
    if not ticket.database_exists:
        return None
    backup = destination / "tickets.sqlite3.backup"
    temporary = destination / f".tickets.sqlite3.{uuid.uuid4().hex}.tmp"
    source_connection: sqlite3.Connection | None = None
    target_connection: sqlite3.Connection | None = None
    try:
        source_uri = PRODUCTION_TICKET_DATABASE.resolve(strict=True).as_uri() + "?mode=ro"
        source_connection = sqlite3.connect(source_uri, uri=True, timeout=10)
        target_connection = sqlite3.connect(temporary)
        source_connection.backup(target_connection)
        check = target_connection.execute("PRAGMA quick_check").fetchone()
        if check != ("ok",):
            raise ProductionToolError("Backup SQLite produzione non integro.")
        target_connection.close()
        target_connection = None
        source_connection.close()
        source_connection = None
        with temporary.open("r+b") as handle:
            os.fsync(handle.fileno())
        os.chown(temporary, 0, 0)
        temporary.chmod(0o600)
        os.replace(temporary, backup)
        return backup
    except (OSError, sqlite3.Error) as exc:
        raise ProductionToolError("Backup SQLite produzione fallito.") from exc
    finally:
        if target_connection is not None:
            target_connection.close()
        if source_connection is not None:
            source_connection.close()
        if _lexists(temporary):
            temporary.unlink()


def _record_before_state(
    directory: Path,
    action: str,
    target: TargetInfo,
    before: DeploymentState,
) -> None:
    if before.unit.content is not None:
        _write_root_file(directory / "unit.before", before.unit.content)
    if before.ingest_service_unit.content is not None:
        _write_root_file(
            directory / "ticket-ingest.service.before",
            before.ingest_service_unit.content,
        )
    if before.ingest_path_unit.content is not None:
        _write_root_file(
            directory / "ticket-ingest.path.before",
            before.ingest_path_unit.content,
        )
    payload = {
        "action": action,
        "before": _deployment_payload(before),
        "database_restore_policy": "never_automatic",
        "release_id": target.release_id,
        "target_unit_sha256": target.unit_sha256,
    }
    _write_root_file(
        directory / "state.json",
        (json.dumps(payload, sort_keys=True, indent=2) + "\n").encode(),
    )


def _switch_link(path: Path, target: Path) -> None:
    current = _capture_link(
        path,
        allowed_root=RELEASES_ROOT if path == PRODUCTION_RELEASE_LINK else VENVS_ROOT,
    )
    if current.exists and current.target == str(target):
        return
    temporary = path.parent / f".{path.name}.{uuid.uuid4().hex}.tmp"
    try:
        os.symlink(str(target), temporary)
        os.replace(temporary, path)
    finally:
        if temporary.is_symlink():
            temporary.unlink()


def _restore_link(path: Path, previous: LinkState, *, allowed_root: Path) -> None:
    if previous.exists:
        if previous.target is None:
            raise ProductionToolError("Stato symlink precedente incompleto.")
        _switch_link(path, Path(previous.target))
        return
    current = _capture_link(path, allowed_root=allowed_root)
    if current.exists:
        path.unlink()


def _install_unit(content: bytes) -> None:
    _validate_production_unit(content, require_ticket_runtime=False)
    _install_raw_unit(UNIT_DESTINATION, content)


def _install_raw_unit(destination: Path, content: bytes) -> None:
    temporary = destination.parent / f".{destination.name}.{uuid.uuid4().hex}.tmp"
    try:
        with temporary.open("xb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chown(temporary, 0, 0)
        temporary.chmod(0o644)
        os.replace(temporary, destination)
    finally:
        if temporary.exists():
            temporary.unlink()


def _remove_raw_unit(destination: Path) -> None:
    if not _lexists(destination):
        return
    details = destination.lstat()
    if not stat.S_ISREG(details.st_mode) or destination.is_symlink():
        raise ProductionToolError(f"Unità da rimuovere non regolare: {destination}")
    destination.unlink()


def _install_ingest_units(target: TargetInfo) -> None:
    if target.ingest_service_bytes and target.ingest_path_bytes:
        _validate_ingest_units(target.ingest_service_bytes, target.ingest_path_bytes)
        _install_raw_unit(INGEST_SERVICE_DESTINATION, target.ingest_service_bytes)
        _install_raw_unit(INGEST_PATH_DESTINATION, target.ingest_path_bytes)
        return
    _remove_raw_unit(INGEST_SERVICE_DESTINATION)
    _remove_raw_unit(INGEST_PATH_DESTINATION)


def _restore_raw_unit(destination: Path, previous: UnitState) -> None:
    if previous.exists:
        if previous.content is None:
            raise ProductionToolError("Stato unità ticket ingest incompleto.")
        _install_raw_unit(destination, previous.content)
    else:
        _remove_raw_unit(destination)


def _restore_unit(previous: UnitState) -> None:
    if previous.exists:
        if previous.content is None:
            raise ProductionToolError("Stato unità precedente incompleto.")
        _install_unit(previous.content)
        return
    try:
        details = UNIT_DESTINATION.lstat()
    except FileNotFoundError:
        return
    if not stat.S_ISREG(details.st_mode) or UNIT_DESTINATION.is_symlink():
        raise ProductionToolError("Impossibile rimuovere unità produzione non regolare.")
    UNIT_DESTINATION.unlink()


def _wait_for_health(timeout: float) -> None:
    deadline = time.monotonic() + timeout
    last_error = "nessuna risposta"
    while time.monotonic() < deadline:
        if _http_health_ok(HEALTH_PORT):
            return
        last_error = "HTTP/servizio non pronto"
        time.sleep(0.5)
    raise ProductionToolError(f"Health produzione fallita: {last_error}")


def _store_identity_matches(left: StoreState, right: StoreState) -> bool:
    return (
        left.snapshot_sha256 == right.snapshot_sha256
        and left.manifest_sha256 == right.manifest_sha256
        and left.snapshot_id == right.snapshot_id
        and left.manifest_bytes == right.manifest_bytes
    )


def _wait_for_active_readiness(
    target: TargetInfo,
    expected_data: StoreState,
    identities: Identities,
    *,
    allow_sensor_stats_server_error: bool,
    allow_stale_for_rollback: bool,
    timeout: float,
) -> None:
    deadline = time.monotonic() + timeout
    last_error = "readiness non eseguita"
    while time.monotonic() < deadline:
        try:
            service = _capture_service()
            if not _service_ready(service, expected_active=True, expected_enabled=True):
                raise ProductionToolError("MainPID/ExecMainStatus non pronti.")
            release_link = _capture_link(
                PRODUCTION_RELEASE_LINK,
                allowed_root=RELEASES_ROOT,
            )
            venv_link = _capture_link(PRODUCTION_VENV_LINK, allowed_root=VENVS_ROOT)
            unit = _capture_unit()
            if (
                release_link.target != str(target.release)
                or venv_link.target != str(target.venv)
                or unit.sha256 != target.unit_sha256
            ):
                raise ProductionToolError("Link o unità produzione non coerenti.")
            data = _inspect_store(
                PRODUCTION_STORE,
                identities,
                allow_sensor_stats_server_error=allow_sensor_stats_server_error,
                allow_missing_manifest_archive=False,
                gate_python=target.venv / "bin" / "python",
                allow_stale_for_rollback=allow_stale_for_rollback,
            )
            if not _store_identity_matches(data, expected_data):
                raise ProductionToolError("Snapshot produzione cambiato durante il deploy.")
            _inspect_ticket_state(identities)
            if not _http_health_ok(HEALTH_PORT):
                raise ProductionToolError("Health Streamlit non pronta.")
            return
        except ProductionToolError as exc:
            last_error = str(exc)
        time.sleep(0.5)
    raise ProductionToolError(f"Readiness produzione fallita: {last_error}")


def _ticket_snapshot_ingested(snapshot_sha256: str) -> bool:
    if not _lexists(PRODUCTION_TICKET_DATABASE):
        return False
    try:
        uri = PRODUCTION_TICKET_DATABASE.resolve(strict=True).as_uri() + "?mode=ro"
        with sqlite3.connect(uri, uri=True, timeout=5) as connection:
            row = connection.execute(
                "SELECT 1 FROM snapshot_ingests WHERE snapshot_sha256 = ?",
                (snapshot_sha256,),
            ).fetchone()
    except (OSError, RuntimeError, sqlite3.Error):
        return False
    return row == (1,)


def _run_initial_ingest(snapshot_sha256: str, identities: Identities) -> None:
    _run_systemctl("start", INGEST_SERVICE_NAME)
    state = _capture_named_service(INGEST_SERVICE_NAME)
    if state.exec_main_status != 0 or state.result not in {"success", ""}:
        raise ProductionToolError("Esecuzione iniziale ticket ingest fallita.")
    _inspect_ticket_state(identities)
    if not _ticket_snapshot_ingested(snapshot_sha256):
        raise ProductionToolError("Snapshot corrente non registrato dal ticket ingest.")


def _set_ingest_path_state(*, enabled: bool, active: bool) -> None:
    if enabled:
        _run_systemctl("enable", INGEST_PATH_NAME)
    else:
        _run_systemctl("disable", INGEST_PATH_NAME, check=False)
    if active:
        _run_systemctl("start", INGEST_PATH_NAME)
    else:
        _run_systemctl("stop", INGEST_PATH_NAME, check=False)
    final = _capture_named_service(INGEST_PATH_NAME)
    if (
        final.enabled != enabled
        or final.active != active
        or final.exec_main_status != 0
        or final.result not in {"success", ""}
    ):
        raise ProductionToolError("Stato ticket ingest path non applicato.")


def _quiesce_ingest() -> None:
    _run_systemctl("disable", INGEST_PATH_NAME, check=False)
    _run_systemctl("stop", INGEST_PATH_NAME, check=False)
    _run_systemctl("stop", INGEST_SERVICE_NAME, check=False)
    path_state = _capture_named_service(INGEST_PATH_NAME)
    service_state = _capture_named_service(INGEST_SERVICE_NAME)
    if path_state.active or path_state.enabled or service_state.active:
        raise ProductionToolError("Ticket ingest non portato in stato quiescente.")


def _wait_for_ingest_idle(timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        state = _capture_named_service(INGEST_SERVICE_NAME)
        if not state.active:
            if state.exec_main_status != 0 or state.result not in {"success", ""}:
                raise ProductionToolError("Ticket ingest ripristinato con esito fallito.")
            return
        time.sleep(0.2)
    raise ProductionToolError("Ticket ingest non terminato entro il timeout di restore.")


def _verify_ingest_readiness(target: TargetInfo, snapshot_sha256: str) -> None:
    service_unit = _capture_raw_unit(INGEST_SERVICE_DESTINATION)
    path_unit = _capture_raw_unit(INGEST_PATH_DESTINATION)
    path_state = _capture_named_service(INGEST_PATH_NAME)
    if target.ingest_service_bytes:
        if (
            service_unit.sha256 != target.ingest_service_sha256
            or path_unit.sha256 != target.ingest_path_sha256
            or not path_state.active
            or not path_state.enabled
            or path_state.exec_main_status != 0
            or path_state.result not in {"success", ""}
            or not _ticket_snapshot_ingested(snapshot_sha256)
        ):
            raise ProductionToolError("Ticket ingest non pronto.")
    elif (
        service_unit.exists
        or path_unit.exists
        or path_state.active
        or path_state.enabled
    ):
        raise ProductionToolError("Ticket ingest storico non disattivato.")


def _restore_service_state(previous: ServiceState, health_timeout: float) -> None:
    _run_systemctl("daemon-reload")
    if previous.enabled:
        _run_systemctl("enable", SERVICE_NAME)
    else:
        _run_systemctl("disable", SERVICE_NAME, check=False)
    if previous.active:
        _run_systemctl("restart", SERVICE_NAME)
        _wait_for_health(health_timeout)
    else:
        _run_systemctl("stop", SERVICE_NAME, check=False)
    restored = _capture_service()
    if not _service_ready(
        restored,
        expected_active=previous.active,
        expected_enabled=previous.enabled,
    ):
        raise ProductionToolError("Stato systemd precedente non ripristinato.")


def _write_recovery_marker(
    directory: Path | None,
    *,
    status: str,
    error: BaseException | None = None,
) -> None:
    if directory is None:
        return
    payload = {
        "error_type": type(error).__name__ if error is not None else None,
        "service": SERVICE_NAME,
        "status": status,
    }
    _write_root_file(
        directory / "recovery.json",
        (json.dumps(payload, sort_keys=True, indent=2) + "\n").encode(),
    )


def _restore_transaction(
    before: DeploymentState,
    health_timeout: float,
    *,
    expected_data: StoreState | None = None,
    identities: Identities | None = None,
    allow_sensor_stats_server_error: bool = False,
    gate_python: Path | None = None,
) -> None:
    _quiesce_ingest()
    _restore_link(
        PRODUCTION_RELEASE_LINK,
        before.release_link,
        allowed_root=RELEASES_ROOT,
    )
    _restore_link(
        PRODUCTION_VENV_LINK,
        before.venv_link,
        allowed_root=VENVS_ROOT,
    )
    _restore_unit(before.unit)
    _restore_raw_unit(INGEST_SERVICE_DESTINATION, before.ingest_service_unit)
    _restore_raw_unit(INGEST_PATH_DESTINATION, before.ingest_path_unit)
    _restore_service_state(before.service, health_timeout)
    _set_ingest_path_state(
        enabled=before.ingest_path_state.enabled,
        active=before.ingest_path_state.active,
    )
    _wait_for_ingest_idle(health_timeout)
    restored = _capture_deployment()
    if (
        restored.release_link != before.release_link
        or restored.venv_link != before.venv_link
        or restored.unit != before.unit
        or restored.ingest_service_unit != before.ingest_service_unit
        or restored.ingest_path_unit != before.ingest_path_unit
        or restored.ingest_path_state.active != before.ingest_path_state.active
        or restored.ingest_path_state.enabled != before.ingest_path_state.enabled
        or restored.service.active != before.service.active
        or restored.service.enabled != before.service.enabled
    ):
        raise ProductionToolError("Stato applicativo precedente non ripristinato.")
    if expected_data is not None and identities is not None:
        restored_data = _inspect_store(
            PRODUCTION_STORE,
            identities,
            allow_sensor_stats_server_error=allow_sensor_stats_server_error,
            allow_missing_manifest_archive=False,
            gate_python=gate_python,
            # Recovery is itself an internal rollback. It may cross the age
            # boundary, but every integrity, origin, schema and quality gate stays on.
            allow_stale_for_rollback=True,
        )
        if not _store_identity_matches(restored_data, expected_data):
            raise ProductionToolError("Snapshot precedente non più coerente dopo il restore.")
        _inspect_ticket_state(identities)


def _activate(
    target: TargetInfo,
    before: DeploymentState,
    health_timeout: float,
    *,
    expected_data: StoreState | None = None,
    identities: Identities | None = None,
    allow_sensor_stats_server_error: bool = False,
    allow_stale_for_rollback: bool = False,
    recovery_directory: Path | None = None,
) -> None:
    mutation_started = False
    try:
        _write_recovery_marker(recovery_directory, status="mutation_starting")
        mutation_started = True
        _quiesce_ingest()
        _switch_link(PRODUCTION_RELEASE_LINK, target.release)
        _switch_link(PRODUCTION_VENV_LINK, target.venv)
        _install_unit(target.unit_bytes)
        _install_ingest_units(target)
        _run_systemctl("daemon-reload")
        if not before.service.enabled:
            _run_systemctl("enable", SERVICE_NAME)
        _run_systemctl("restart", SERVICE_NAME)
        if expected_data is not None and identities is not None:
            _wait_for_active_readiness(
                target,
                expected_data,
                identities,
                allow_sensor_stats_server_error=allow_sensor_stats_server_error,
                allow_stale_for_rollback=allow_stale_for_rollback,
                timeout=health_timeout,
            )
        else:
            _wait_for_health(health_timeout)
        if target.ingest_service_bytes:
            if identities is None or expected_data is None:
                raise ProductionToolError("Readiness ticket ingest senza dati verificati.")
            _run_initial_ingest(expected_data.snapshot_sha256, identities)
            _set_ingest_path_state(enabled=True, active=True)
            _verify_ingest_readiness(target, expected_data.snapshot_sha256)
        else:
            _set_ingest_path_state(enabled=False, active=False)
            _verify_ingest_readiness(
                target,
                expected_data.snapshot_sha256 if expected_data is not None else "",
            )
        if expected_data is not None and identities is not None:
            _wait_for_active_readiness(
                target,
                expected_data,
                identities,
                allow_sensor_stats_server_error=allow_sensor_stats_server_error,
                allow_stale_for_rollback=allow_stale_for_rollback,
                timeout=health_timeout,
            )
        _write_recovery_marker(recovery_directory, status="complete")
    except BaseException as original:
        if mutation_started:
            try:
                _restore_transaction(
                    before,
                    health_timeout,
                    expected_data=expected_data,
                    identities=identities,
                    allow_sensor_stats_server_error=allow_sensor_stats_server_error,
                    gate_python=target.venv / "bin" / "python",
                )
                _write_recovery_marker(
                    recovery_directory,
                    status="rolled_back",
                    error=original,
                )
            except BaseException as restoration:
                _write_recovery_marker(
                    recovery_directory,
                    status="restore_failed",
                    error=restoration,
                )
                raise ProductionToolError(
                    "Attivazione fallita e ripristino produzione non completato: "
                    f"{type(restoration).__name__}"
                ) from original
        raise


def _apply_operation(
    action: str,
    target: TargetInfo,
    before: DeploymentState,
    identities: Identities,
    *,
    health_timeout: float,
    production_data: StoreState,
    staging_data: StoreState | None,
    allow_sensor_stats_server_error: bool,
) -> dict[str, Any]:
    allow_stale_for_rollback = action == "rollback"
    backup_directory = _new_backup_directory(action, target.release_id)
    _record_before_state(backup_directory, action, target, before)
    activation_started = False
    try:
        _write_recovery_marker(backup_directory, status="preparation_starting")
        _quiesce_ingest()
        _ensure_ticket_directory(identities)
        _ensure_production_manifest_archive(production_data, identities)
        ready_data = _inspect_store(
            PRODUCTION_STORE,
            identities,
            allow_sensor_stats_server_error=allow_sensor_stats_server_error,
            allow_missing_manifest_archive=False,
            gate_python=target.venv / "bin" / "python",
            allow_stale_for_rollback=allow_stale_for_rollback,
        )
        if not _store_identity_matches(ready_data, production_data):
            raise ProductionToolError("Snapshot produzione cambiato durante il bootstrap.")
        if staging_data is not None:
            _require_matching_store_data(ready_data, staging_data)
        database_backup = _backup_database(backup_directory, identities)
        activation_started = True
        _activate(
            target,
            before,
            health_timeout,
            expected_data=ready_data,
            identities=identities,
            allow_sensor_stats_server_error=allow_sensor_stats_server_error,
            allow_stale_for_rollback=allow_stale_for_rollback,
            recovery_directory=backup_directory,
        )
    except BaseException as original:
        if not activation_started:
            try:
                _set_ingest_path_state(
                    enabled=before.ingest_path_state.enabled,
                    active=before.ingest_path_state.active,
                )
                _wait_for_ingest_idle(health_timeout)
                _write_recovery_marker(
                    backup_directory,
                    status="preparation_failed_runtime_restored",
                    error=original,
                )
            except BaseException as restoration:
                _write_recovery_marker(
                    backup_directory,
                    status="restore_failed",
                    error=restoration,
                )
                raise ProductionToolError(
                    "Preparazione fallita e ticket ingest non ripristinato: "
                    f"{type(restoration).__name__}"
                ) from original
        raise
    return {
        "action": action,
        "backup_directory": str(backup_directory),
        "database_backup": str(database_backup) if database_backup else None,
        "release_id": target.release_id,
        "service": SERVICE_NAME,
        "snapshot_age_seconds": ready_data.snapshot_age_seconds,
        "snapshot_sha256": ready_data.snapshot_sha256,
        "freshness_policy": ready_data.freshness_policy,
        "status": "applied",
    }


def _positive_timeout(value: str) -> float:
    try:
        timeout = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("timeout non numerico") from exc
    if not 1 <= timeout <= 60:
        raise argparse.ArgumentTypeError("timeout richiesto tra 1 e 60 secondi")
    return timeout


def _add_common_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--release-id", required=True)
    parser.add_argument("--health-timeout", type=_positive_timeout, default=30.0)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--confirm-plan")
    parser.add_argument(
        "--allow-classic-sensor-stats-server-error",
        action="store_true",
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Promozione e rollback fail-closed DTLab produzione."
    )
    commands = parser.add_subparsers(dest="action", required=True)
    _add_common_arguments(commands.add_parser("promote"))
    _add_common_arguments(commands.add_parser("rollback"))
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if sys.platform.startswith("linux") and os.geteuid() != 0:
            raise ProductionToolError(
                "Dry-run e apply produzione richiedono root per il gate privilege-dropped."
            )
        release_id = args.release_id.lower()
        if not _RELEASE_ID.fullmatch(release_id):
            raise ProductionToolError("--release-id deve contenere 16 cifre esadecimali.")
        identities = _lookup_identities()
        target = _verify_release(
            release_id,
            identities,
            require_ticket_runtime=args.action == "promote",
        )
        staging_state: StagingState | None = None
        staging_data: StoreState | None = None
        allow_stale_for_rollback = args.action == "rollback"
        if args.action == "promote":
            staging_state = _require_current_staging(target)
            staging_data = _inspect_store(
                STAGING_STORE,
                identities,
                allow_sensor_stats_server_error=(
                    args.allow_classic_sensor_stats_server_error
                ),
                allow_missing_manifest_archive=False,
                gate_python=target.venv / "bin" / "python",
            )
        production_data = _inspect_store(
            PRODUCTION_STORE,
            identities,
            allow_sensor_stats_server_error=(
                args.allow_classic_sensor_stats_server_error
            ),
            allow_missing_manifest_archive=True,
            gate_python=target.venv / "bin" / "python",
            allow_stale_for_rollback=allow_stale_for_rollback,
        )
        if staging_data is not None:
            _require_matching_store_data(production_data, staging_data)
        before = _capture_deployment()
        ticket = _inspect_ticket_state(identities, allow_legacy_modes=True)
        payload, token = _plan(
            args.action,
            target,
            before,
            ticket,
            health_timeout=args.health_timeout,
            production_data=production_data,
            staging_data=staging_data,
            staging_state=staging_state,
            allow_sensor_stats_server_error=(
                args.allow_classic_sensor_stats_server_error
            ),
        )
        _require_confirmation(args, token)
        if not args.apply:
            _emit_plan(payload, token)
            return 0
        _require_apply_host()
        with _production_lock():
            # Bind the mutation to the immutable bytes and exact state used by the token.
            current_target = _verify_release(
                release_id,
                identities,
                require_ticket_runtime=args.action == "promote",
            )
            if current_target != target or _capture_deployment() != before:
                raise ProductionToolError("Stato produzione cambiato dopo il piano.")
            current_ticket = _inspect_ticket_state(
                identities,
                allow_legacy_modes=True,
            )
            if current_ticket != ticket:
                raise ProductionToolError("Ticket state cambiato dopo il piano.")
            current_production_data = _inspect_store(
                PRODUCTION_STORE,
                identities,
                allow_sensor_stats_server_error=(
                    args.allow_classic_sensor_stats_server_error
                ),
                allow_missing_manifest_archive=True,
                gate_python=current_target.venv / "bin" / "python",
                allow_stale_for_rollback=allow_stale_for_rollback,
            )
            if (
                not _store_identity_matches(current_production_data, production_data)
                or current_production_data.manifest_archive_ready
                != production_data.manifest_archive_ready
            ):
                raise ProductionToolError("Snapshot produzione cambiato dopo il piano.")
            if args.action == "promote":
                current_staging_state = _require_current_staging(current_target)
                current_staging_data = _inspect_store(
                    STAGING_STORE,
                    identities,
                    allow_sensor_stats_server_error=(
                        args.allow_classic_sensor_stats_server_error
                    ),
                    allow_missing_manifest_archive=False,
                    gate_python=current_target.venv / "bin" / "python",
                )
                if (
                    current_staging_state != staging_state
                    or staging_data is None
                    or not _store_identity_matches(current_staging_data, staging_data)
                ):
                    raise ProductionToolError("Staging cambiato dopo il piano.")
                _require_matching_store_data(
                    current_production_data,
                    current_staging_data,
                )
            result = _apply_operation(
                args.action,
                current_target,
                before,
                identities,
                health_timeout=args.health_timeout,
                production_data=current_production_data,
                staging_data=current_staging_data if args.action == "promote" else None,
                allow_sensor_stats_server_error=(
                    args.allow_classic_sensor_stats_server_error
                ),
            )
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
        return 0
    except ProductionToolError as exc:
        print(
            json.dumps({"error": str(exc), "status": "failed"}, ensure_ascii=False),
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
