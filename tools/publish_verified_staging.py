"""Publish one explicitly verified local ``current`` snapshot to staging only."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import re
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from dtlab.collector.config import CollectorConfig, PublishConfig, load_config  # noqa: E402
from dtlab.collector.remote_publish import (  # noqa: E402
    RemotePublishError,
    RemoteSnapshotPublisher,
)
from dtlab.services.snapshot_store import (  # noqa: E402
    AtomicSnapshotStore,
    SnapshotStoreError,
    StoredSnapshot,
)
from tools.verify_staging_snapshot import evaluate_snapshot  # noqa: E402

MINIMUM_QUALITY = 80
TARGET = "staging"
POINTER = "current"
_PLAN_VERSION = "1.0"
_SHA256 = re.compile(r"^[a-f0-9]{64}$")


class PublishVerifiedStagingError(RuntimeError):
    """A staging publication was rejected before a safe commit could be made."""

    def __init__(self, code: str, *, exit_code: int = 1):
        super().__init__(code)
        self.code = code
        self.exit_code = exit_code


def _read_only_store(root: Path) -> AtomicSnapshotStore:
    if not root.is_dir():
        raise PublishVerifiedStagingError("snapshot_store_invalid")
    return AtomicSnapshotStore(root, create_layout=False)


def _load_current(store: AtomicSnapshotStore) -> StoredSnapshot:
    try:
        return store.load(POINTER)
    except (OSError, SnapshotStoreError) as exc:
        raise PublishVerifiedStagingError("snapshot_store_invalid") from exc


def _staging_config(config: CollectorConfig) -> PublishConfig:
    staging = config.publish_staging
    if staging is None:
        raise PublishVerifiedStagingError("staging_configuration_missing")
    if not staging.enabled:
        raise PublishVerifiedStagingError("staging_publication_disabled")
    return staging


def _gate(
    stored: StoredSnapshot,
    *,
    allow_sensor_stats_server_error: bool,
) -> dict[str, Any]:
    result = evaluate_snapshot(
        stored,
        min_quality=MINIMUM_QUALITY,
        allow_sensor_stats_server_error=allow_sensor_stats_server_error,
    )
    if not result["approved"]:
        raise PublishVerifiedStagingError("snapshot_gate_rejected")
    return result


def _require_expected_manifest(stored: StoredSnapshot, expected: str) -> None:
    if stored.pointer != POINTER or stored.manifest["sha256"] != expected:
        raise PublishVerifiedStagingError("current_manifest_sha256_mismatch")


def _plan_token(
    config: CollectorConfig,
    staging: PublishConfig,
    stored: StoredSnapshot,
    *,
    allow_sensor_stats_server_error: bool,
) -> str:
    """Bind confirmation to the snapshot, gate policy, local store, and staging config."""

    material = {
        "action": "publish_verified_current",
        "allow_classic_sensor_stats_server_error": allow_sensor_stats_server_error,
        "local_store": str(config.local_store.resolve()),
        "manifest": stored.manifest,
        "minimum_quality": MINIMUM_QUALITY,
        "plan_version": _PLAN_VERSION,
        "pointer": POINTER,
        "staging": {
            "enabled": staging.enabled,
            "manage_ownership": staging.manage_ownership,
            "remote_account": staging.remote_account,
            "remote_group": staging.remote_group,
            "remote_owner": staging.remote_owner,
            "remote_store": str(staging.remote_store),
            "ssh_alias": staging.ssh_alias,
        },
        "target": TARGET,
    }
    encoded = json.dumps(
        material,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def _safe_result(
    *,
    status: str,
    stored: StoredSnapshot,
    gate: dict[str, Any],
    allow_sensor_stats_server_error: bool,
    confirm_plan: str | None = None,
) -> dict[str, Any]:
    result = {
        "allow_classic_sensor_stats_server_error": allow_sensor_stats_server_error,
        "approved_exceptions": gate["approved_exceptions"],
        "gate_version": gate["gate_version"],
        "manifest_sha256": stored.manifest["sha256"],
        "minimum_quality": MINIMUM_QUALITY,
        "pointer": POINTER,
        "quality_score": gate["quality_score"],
        "source_results": gate["source_results"],
        "status": status,
        "sync_state": gate["sync_state"],
        "target": TARGET,
        "warnings": gate["warnings"],
    }
    if confirm_plan is not None:
        result["confirm_plan"] = confirm_plan
    return result


def publish_verified_staging(
    config_path: Path,
    *,
    expected_manifest_sha256: str,
    allow_sensor_stats_server_error: bool = False,
    apply: bool = False,
    confirm_plan: str | None = None,
) -> dict[str, Any]:
    """Verify and optionally publish local ``current`` using only the staging config."""

    expected = expected_manifest_sha256.casefold()
    if not _SHA256.fullmatch(expected):
        raise PublishVerifiedStagingError("expected_manifest_sha256_invalid", exit_code=2)
    if apply and confirm_plan is None:
        raise PublishVerifiedStagingError("apply_requires_confirm_plan", exit_code=2)
    if not apply and confirm_plan is not None:
        raise PublishVerifiedStagingError("confirm_plan_requires_apply", exit_code=2)

    try:
        config = load_config(config_path)
    except (OSError, ValueError) as exc:
        raise PublishVerifiedStagingError("configuration_invalid") from exc
    staging = _staging_config(config)

    store = _read_only_store(config.local_store)
    verified = _load_current(store)
    _require_expected_manifest(verified, expected)
    gate = _gate(
        verified,
        allow_sensor_stats_server_error=allow_sensor_stats_server_error,
    )
    token = _plan_token(
        config,
        staging,
        verified,
        allow_sensor_stats_server_error=allow_sensor_stats_server_error,
    )

    if not apply:
        return _safe_result(
            status="dry-run",
            stored=verified,
            gate=gate,
            allow_sensor_stats_server_error=allow_sensor_stats_server_error,
            confirm_plan=token,
        )
    if not hmac.compare_digest(confirm_plan or "", token):
        raise PublishVerifiedStagingError("confirm_plan_mismatch", exit_code=2)

    # Re-read after every gate and confirmation check. RemoteSnapshotPublisher performs
    # the same manifest equality check once more before its first remote mutation.
    current = _load_current(store)
    _require_expected_manifest(current, expected)
    if current.manifest != verified.manifest:
        raise PublishVerifiedStagingError("current_pointer_changed")
    current_gate = _gate(
        current,
        allow_sensor_stats_server_error=allow_sensor_stats_server_error,
    )

    try:
        RemoteSnapshotPublisher(staging).publish(store, current.manifest)
    except RemotePublishError as exc:
        raise PublishVerifiedStagingError("staging_publication_failed") from exc

    return _safe_result(
        status="published",
        stored=current,
        gate=current_gate,
        allow_sensor_stats_server_error=allow_sensor_stats_server_error,
    )


def _manifest_sha256(value: str) -> str:
    normalized = value.casefold()
    if not _SHA256.fullmatch(normalized):
        raise argparse.ArgumentTypeError("SHA-256 manifest non valido")
    return normalized


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Pubblica un current verificato esclusivamente sul target staging."
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=Path("config/dtlab.local.toml"),
        help="Configurazione locale contenente il target staging.",
    )
    parser.add_argument(
        "--expected-manifest-sha256",
        type=_manifest_sha256,
        required=True,
    )
    parser.add_argument(
        "--allow-classic-sensor-stats-server-error",
        action="store_true",
        help="Approva soltanto l'eccezione nota Classic sensor_stats/server_error.",
    )
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--confirm-plan")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        result = publish_verified_staging(
            args.config,
            expected_manifest_sha256=args.expected_manifest_sha256,
            allow_sensor_stats_server_error=(args.allow_classic_sensor_stats_server_error),
            apply=args.apply,
            confirm_plan=args.confirm_plan,
        )
    except PublishVerifiedStagingError as exc:
        print(
            json.dumps(
                {"error": exc.code, "status": "error", "target": TARGET},
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            ),
            file=sys.stderr,
        )
        return exc.exit_code
    print(json.dumps(result, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
