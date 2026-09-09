"""End-to-end VPN-side collection, normalization, validation, and publication."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import uuid
from collections.abc import Callable, Sequence
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from dtlab.adapters.cybervision import normalize_cybervision_collection
from dtlab.adapters.esxi import EsxiNormalizationError, normalize_esxi_inventory
from dtlab.collector.config import CollectorConfig, PublishConfig, load_config
from dtlab.collector.credentials import new_ui_token_is_configured, token_is_configured
from dtlab.collector.cybervision_client import CyberVisionClient, CyberVisionError
from dtlab.collector.cybervision_collection import collect_cybervision_raw
from dtlab.collector.esxi_client import EsxiCollectionError, collect_esxi_inventory
from dtlab.collector.raw_store import RawStore, RawStoreError
from dtlab.collector.remote_publish import RemoteSnapshotPublisher
from dtlab.services.assembly import (
    assemble_snapshot,
    unavailable_cybervision_source,
)
from dtlab.services.snapshot_store import AtomicSnapshotStore, SnapshotStoreError

_VPN_NAME = re.compile(r"^[\w .()-]{1,100}$", re.UNICODE)
PublishTarget = Literal["staging", "production"]
_PUBLISH_TARGETS = frozenset({"staging", "production"})
DEFAULT_SNAPSHOT_RETENTION = 240


class SyncError(RuntimeError):
    """A sync did not produce and commit a new validated snapshot."""


@dataclass(frozen=True)
class SyncResult:
    snapshot_id: str
    state: str
    manifest_sha256: str
    virtual_machines: int
    assets: int
    risk_scores: int
    remote_published: bool
    publish_target: PublishTarget | None


def _requested_publish_config(
    config: CollectorConfig,
    *,
    publish_target: PublishTarget | str | None,
    local_only: bool,
) -> PublishConfig | None:
    if local_only and publish_target is not None:
        raise SyncError("--local-only non è compatibile con un target di pubblicazione remoto.")
    if publish_target is None:
        return None
    if publish_target not in _PUBLISH_TARGETS:
        raise SyncError("Target di pubblicazione remoto non valido.")
    selected = config.publish if publish_target == "production" else config.publish_staging
    if selected is None:
        raise SyncError(f"Configurazione publish {publish_target} assente.")
    if not selected.enabled:
        raise SyncError(f"Pubblicazione {publish_target} disabilitata.")
    return selected


def vpn_is_connected(
    connection_name: str,
    *,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> bool:
    if not _VPN_NAME.fullmatch(connection_name):
        raise SyncError("Nome connessione VPN non valido.")
    escaped = connection_name.replace("'", "''")
    script = f"(Get-VpnConnection -Name '{escaped}' -ErrorAction Stop).ConnectionStatus"
    try:
        result = runner(
            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                script,
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise SyncError("Impossibile verificare lo stato VPN.") from exc
    return result.returncode == 0 and result.stdout.strip().lower() == "connected"


def _snapshot_id(completed_at: datetime) -> str:
    timestamp = completed_at.astimezone(UTC).strftime("%Y%m%dT%H%M%S.%fZ")
    return f"snapshot:dtlab:{timestamp}:{uuid.uuid4().hex[:8]}"


def _last_known_good_id(store: AtomicSnapshotStore) -> str | None:
    try:
        return str(store.load("last_known_good").snapshot["snapshot_id"])
    except SnapshotStoreError:
        return None


def _read_json(path: str | Path) -> dict[str, Any]:
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SyncError(f"JSON bootstrap non valido: {Path(path).name}") from exc
    if not isinstance(payload, dict):
        raise SyncError("Il JSON bootstrap deve essere un oggetto.")
    return payload


def run_sync(
    config: CollectorConfig,
    *,
    esxi_inventory_override: dict[str, Any] | None = None,
    cybervision_raw_override: dict[str, Any] | None = None,
    local_only: bool = False,
    publish_target: PublishTarget | str | None = None,
    require_vpn: bool = True,
    snapshot_retention: int = DEFAULT_SNAPSHOT_RETENTION,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> SyncResult:
    if not 3 <= snapshot_retention <= 10_000:
        raise SyncError("La retention snapshot deve essere compresa tra 3 e 10000 cicli.")
    remote_publish_config = _requested_publish_config(
        config,
        publish_target=publish_target,
        local_only=local_only,
    )
    started_at = clock()
    if started_at.tzinfo is None:
        raise SyncError("Il clock deve produrre timestamp timezone-aware.")
    if require_vpn and not vpn_is_connected(config.vpn_connection_name):
        raise SyncError("VPN DTLAB non connessa; ultimo snapshot valido mantenuto.")

    raw_store = RawStore(config.raw_directory)
    try:
        raw_esxi = (
            esxi_inventory_override
            if esxi_inventory_override is not None
            else collect_esxi_inventory(config.esxi)
        )
    except EsxiCollectionError as exc:
        raise SyncError("Inventario ESXi non acquisito; ultimo snapshot valido mantenuto.") from exc
    raw_store.write("esxi", raw_esxi, collected_at=started_at)
    try:
        esxi = normalize_esxi_inventory(raw_esxi, fetched_at=clock())
    except EsxiNormalizationError as exc:
        raise SyncError("Inventario ESXi non valido; ultimo snapshot valido mantenuto.") from exc

    cybervision = None
    cv_error_code = "credential_unavailable"
    cv_status = "not_configured"
    try:
        if cybervision_raw_override is not None:
            raw_cybervision = cybervision_raw_override
        elif token_is_configured():
            raw_cybervision = collect_cybervision_raw(
                CyberVisionClient(config.cybervision),
                new_ui_enabled=new_ui_token_is_configured(),
            )
        else:
            raw_cybervision = None
        if raw_cybervision is not None:
            raw_store.write("cybervision", raw_cybervision, collected_at=clock())
            cybervision = normalize_cybervision_collection(raw_cybervision)
    except CyberVisionError as exc:
        cv_error_code = exc.code
        cv_status = "unavailable"
    except Exception as exc:
        cv_error_code = "normalization_failed"
        cv_status = "unavailable"
        if cybervision_raw_override is not None:
            raise SyncError("Fixture Cyber Vision non normalizzabile.") from exc

    completed_at = clock()
    store = AtomicSnapshotStore(config.local_store, create_layout=True)
    cv_unavailable = (
        unavailable_cybervision_source(
            completed_at.astimezone(UTC).isoformat().replace("+00:00", "Z"),
            code=cv_error_code,
            status=cv_status,
        )
        if cybervision is None
        else None
    )
    snapshot = assemble_snapshot(
        esxi,
        cybervision=cybervision,
        cybervision_unavailable_source=cv_unavailable,
        started_at=started_at,
        completed_at=completed_at,
        snapshot_id=_snapshot_id(completed_at),
        last_known_good_snapshot_id=_last_known_good_id(store),
    )
    manifest = store.publish(snapshot, published_at=completed_at)

    remote_published = False
    if remote_publish_config is not None:
        RemoteSnapshotPublisher(remote_publish_config).publish(store, manifest)
        remote_published = True

    # Retention must never turn an already committed snapshot into a reported sync failure.
    with suppress(OSError, SnapshotStoreError):
        store.prune_objects(retain=snapshot_retention)
    with suppress(OSError, RawStoreError):
        raw_store.prune(now=completed_at)

    return SyncResult(
        snapshot_id=snapshot["snapshot_id"],
        state=snapshot["sync"]["state"],
        manifest_sha256=manifest["sha256"],
        virtual_machines=len(snapshot["virtual_machines"]),
        assets=len(snapshot["assets"]),
        risk_scores=len(snapshot["risk_scores"]),
        remote_published=remote_published,
        publish_target=(publish_target if publish_target in _PUBLISH_TARGETS else None),
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Sincronizza DTLab in sola lettura.")
    parser.add_argument(
        "--config",
        default="config/dtlab.local.toml",
        help="File TOML locale senza credenziali.",
    )
    parser.add_argument("--esxi-inventory", help="Bootstrap da inventario ESXi JSON.")
    parser.add_argument("--cybervision-raw", help="Fixture raw Cyber Vision JSON.")
    publish_mode = parser.add_mutually_exclusive_group()
    publish_mode.add_argument("--local-only", action="store_true")
    publish_mode.add_argument(
        "--publish-target",
        choices=("staging", "production"),
        help="Target remoto esplicito; se omesso il sync resta solo locale.",
    )
    parser.add_argument("--skip-vpn-check", action="store_true")
    parser.add_argument(
        "--snapshot-retention",
        type=int,
        default=DEFAULT_SNAPSHOT_RETENTION,
        help="Cicli snapshot locali da conservare (default: 240).",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    config = load_config(args.config)
    result = run_sync(
        config,
        esxi_inventory_override=(_read_json(args.esxi_inventory) if args.esxi_inventory else None),
        cybervision_raw_override=(
            _read_json(args.cybervision_raw) if args.cybervision_raw else None
        ),
        local_only=args.local_only,
        publish_target=args.publish_target,
        require_vpn=not args.skip_vpn_check,
        snapshot_retention=args.snapshot_retention,
    )
    print(
        json.dumps(
            {
                "snapshot_id": result.snapshot_id,
                "state": result.state,
                "virtual_machines": result.virtual_machines,
                "assets": result.assets,
                "risk_scores": result.risk_scores,
                "remote_published": result.remote_published,
                "publish_target": result.publish_target,
                "manifest_sha256": result.manifest_sha256,
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
