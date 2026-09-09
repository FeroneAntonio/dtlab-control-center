"""Continuously collect DTLab read-only data and publish only gate-approved snapshots."""

from __future__ import annotations

import argparse
import errno
import json
import sys
import time
from collections.abc import Sequence
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from types import TracebackType
from typing import BinaryIO

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
from dtlab.collector.sync import SyncError, run_sync  # noqa: E402
from dtlab.services.snapshot_store import (  # noqa: E402
    AtomicSnapshotStore,
    SnapshotStoreError,
    StoredSnapshot,
)
from tools.verify_staging_snapshot import evaluate_snapshot  # noqa: E402

_TARGETS = ("staging", "production")


class LiveSyncError(RuntimeError):
    """A live cycle was rejected before any remote publication."""


class LiveSyncAlreadyRunning(LiveSyncError):
    """Another process owns the same local-store live-sync lock."""


class TargetPublishError(LiveSyncError):
    """One target failed after zero or more earlier targets committed atomically."""

    def __init__(
        self,
        failed_target: str,
        published_targets: Sequence[str],
        cause: RemotePublishError,
    ) -> None:
        self.failed_target = failed_target
        committed_targets = list(published_targets)
        if cause.committed is True and failed_target not in committed_targets:
            committed_targets.append(failed_target)
        self.published_targets = tuple(committed_targets)
        self.commit_unknown_targets = (
            (failed_target,) if cause.committed is None else ()
        )
        super().__init__(f"publish_{failed_target}_failed:{cause}")


class LiveSyncProcessLock:
    """Non-blocking advisory lock held for the whole collector/publisher process."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._handle: BinaryIO | None = None

    def __enter__(self) -> LiveSyncProcessLock:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        handle = self.path.open("a+b")
        handle.seek(0, 2)
        if handle.tell() == 0:
            handle.write(b"\0")
            handle.flush()
        handle.seek(0)
        try:
            if sys.platform == "win32":
                import msvcrt

                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            handle.close()
            if exc.errno in {errno.EACCES, errno.EAGAIN, errno.EDEADLK}:
                raise LiveSyncAlreadyRunning("live_sync_already_running") from exc
            raise LiveSyncError("live_sync_lock_unavailable") from exc
        self._handle = handle
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        del exc_type, exc_value, traceback
        handle = self._handle
        self._handle = None
        if handle is None:
            return
        try:
            handle.seek(0)
            if sys.platform == "win32":
                import msvcrt

                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        finally:
            handle.close()


def _publish_config(config: CollectorConfig, target: str) -> PublishConfig:
    selected = config.publish_staging if target == "staging" else config.publish
    if selected is None or not selected.enabled:
        raise LiveSyncError(f"publish_{target}_disabled")
    return selected


def _selected_publish_configs(
    config: CollectorConfig,
    targets: Sequence[str],
) -> tuple[tuple[str, PublishConfig], ...]:
    unknown = sorted(set(targets) - set(_TARGETS))
    if unknown:
        raise LiveSyncError("publish_target_invalid")
    if len(set(targets)) != len(targets):
        raise LiveSyncError("publish_target_duplicate")
    return tuple((target, _publish_config(config, target)) for target in targets)


def _evaluate_stored_snapshot(
    stored: StoredSnapshot,
    *,
    min_quality: int,
    allow_classic_sensor_stats_server_error: bool,
    now: datetime | None = None,
) -> dict[str, object]:
    gate = evaluate_snapshot(
        stored,
        min_quality=min_quality,
        allow_sensor_stats_server_error=allow_classic_sensor_stats_server_error,
        now=now,
    )
    if not gate["approved"]:
        raise LiveSyncError("snapshot_gate_rejected:" + ",".join(gate["failures"]))
    return gate


def _published_at(manifest: dict[str, object]) -> datetime:
    value = str(manifest.get("published_at") or "")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise SnapshotStoreError("published_at archivio non valido") from exc
    if parsed.tzinfo is None:
        raise SnapshotStoreError("published_at archivio privo di fuso orario")
    return parsed.astimezone(UTC)


def _approved_archive_backlog(
    store: AtomicSnapshotStore,
    current: StoredSnapshot,
    *,
    min_quality: int,
    allow_classic_sensor_stats_server_error: bool,
) -> tuple[tuple[StoredSnapshot, ...], dict[str, int]]:
    approved: list[StoredSnapshot] = []
    scanned = 0
    rejected = 0
    invalid = 0
    for manifest_name in store.archived_manifest_names():
        try:
            stored = store.load_archive(manifest_name)
        except SnapshotStoreError:
            invalid += 1
            continue
        if stored.manifest == current.manifest:
            continue
        scanned += 1
        try:
            gate = evaluate_snapshot(
                stored,
                min_quality=min_quality,
                allow_sensor_stats_server_error=(
                    allow_classic_sensor_stats_server_error
                ),
                # Historical snapshots are assessed at their immutable publication
                # time.  Only current is allowed to use the real wall clock.
                now=_published_at(stored.manifest),
            )
        except SnapshotStoreError:
            invalid += 1
            continue
        if gate["approved"]:
            approved.append(stored)
        else:
            rejected += 1
    approved.sort(
        key=lambda stored: (
            _published_at(stored.manifest),
            str(stored.manifest["snapshot_id"]),
        )
    )
    return tuple(approved), {
        "archives_scanned": scanned,
        "archives_approved": len(approved),
        "archives_rejected": rejected,
        "archives_invalid": invalid,
    }


def _publish_approved_snapshot(
    config: CollectorConfig,
    stored: StoredSnapshot,
    archives: Sequence[StoredSnapshot],
    selected_configs: Sequence[tuple[str, PublishConfig]],
) -> tuple[list[str], dict[str, dict[str, int]]]:
    published: list[str] = []
    counts: dict[str, dict[str, int]] = {}
    store = AtomicSnapshotStore(config.local_store, create_layout=False)
    for target, publish_config in selected_configs:
        try:
            summary = RemoteSnapshotPublisher(publish_config).publish_batch(
                store,
                archives,
                stored,
            )
        except RemotePublishError as exc:
            raise TargetPublishError(target, published, exc) from exc
        published.append(target)
        counts[target] = asdict(summary)
    return published, counts


def run_cycle(
    config: CollectorConfig,
    *,
    targets: Sequence[str],
    min_quality: int = 80,
    allow_classic_sensor_stats_server_error: bool = False,
    snapshot_retention: int = 240,
) -> dict[str, object]:
    """Collect locally, verify the immutable object, then publish exact approved bytes."""

    selected_configs = _selected_publish_configs(config, targets)

    result = run_sync(
        config,
        local_only=True,
        snapshot_retention=snapshot_retention,
    )
    store = AtomicSnapshotStore(
        config.local_store,
        create_layout=False,
    )
    stored = store.load("current")
    if (
        stored.manifest["sha256"] != result.manifest_sha256
        or stored.manifest["snapshot_id"] != result.snapshot_id
    ):
        raise LiveSyncError("local_store_changed_during_cycle")
    gate = _evaluate_stored_snapshot(
        stored,
        min_quality=min_quality,
        allow_classic_sensor_stats_server_error=allow_classic_sensor_stats_server_error,
    )
    archives: tuple[StoredSnapshot, ...] = ()
    archive_counts = {
        "archives_scanned": 0,
        "archives_approved": 0,
        "archives_rejected": 0,
        "archives_invalid": 0,
    }
    if selected_configs:
        archives, archive_counts = _approved_archive_backlog(
            store,
            stored,
            min_quality=min_quality,
            allow_classic_sensor_stats_server_error=(
                allow_classic_sensor_stats_server_error
            ),
        )
    published, publication_counts = _publish_approved_snapshot(
        config,
        stored,
        archives,
        selected_configs,
    )

    return {
        "mode": "collect_and_publish" if targets else "collect_only",
        "quality_score": gate["quality_score"],
        "sync_state": result.state,
        "approved_exception_count": len(gate["approved_exceptions"]),
        "published_targets": published,
        **archive_counts,
        "publication_counts": publication_counts,
    }


def publish_current(
    config: CollectorConfig,
    *,
    targets: Sequence[str],
    min_quality: int = 80,
    allow_classic_sensor_stats_server_error: bool = False,
) -> dict[str, object]:
    """Gate and publish the existing current snapshot without running collection."""

    if not targets:
        raise LiveSyncError("publish_target_required")
    selected_configs = _selected_publish_configs(config, targets)
    store = AtomicSnapshotStore(config.local_store, create_layout=False)
    stored = store.load("current")
    # Intentionally omit ``now``: current must pass against the actual wall clock.
    gate = _evaluate_stored_snapshot(
        stored,
        min_quality=min_quality,
        allow_classic_sensor_stats_server_error=allow_classic_sensor_stats_server_error,
    )
    archives, archive_counts = _approved_archive_backlog(
        store,
        stored,
        min_quality=min_quality,
        allow_classic_sensor_stats_server_error=(
            allow_classic_sensor_stats_server_error
        ),
    )
    published, publication_counts = _publish_approved_snapshot(
        config,
        stored,
        archives,
        selected_configs,
    )
    return {
        "mode": "publish_current",
        "quality_score": gate["quality_score"],
        "sync_state": stored.snapshot["sync"]["state"],
        "approved_exception_count": len(gate["approved_exceptions"]),
        "published_targets": published,
        **archive_counts,
        "publication_counts": publication_counts,
    }


def _lock_path(config: CollectorConfig) -> Path:
    return config.local_store.parent / f".{config.local_store.name}.live-sync.lock"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Aggiornamento DTLab near-real-time con gate fail-closed."
    )
    parser.add_argument("--config", default="config/dtlab.local.toml")
    parser.add_argument(
        "--target",
        action="append",
        choices=_TARGETS,
        dest="targets",
        help="Target atomico; ripetere per pubblicare su staging e produzione.",
    )
    parser.add_argument(
        "--publish-current",
        action="store_true",
        help=(
            "Non raccoglie dati: verifica e pubblica lo snapshot current già presente; "
            "richiede almeno un --target esplicito."
        ),
    )
    parser.add_argument("--interval", type=int, default=60)
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--min-quality", type=int, default=80)
    parser.add_argument(
        "--snapshot-retention",
        type=int,
        default=240,
        help="Numero di cicli immutabili locali conservati per il recupero outage.",
    )
    parser.add_argument(
        "--allow-classic-sensor-stats-server-error",
        action="store_true",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if not 15 <= args.interval <= 3600:
        raise SystemExit("--interval deve essere compreso tra 15 e 3600 secondi")
    if not 3 <= args.snapshot_retention <= 10_000:
        raise SystemExit("--snapshot-retention deve essere compreso tra 3 e 10000")
    targets = tuple(args.targets or ())
    if len(set(targets)) != len(targets):
        raise SystemExit("ogni --target può essere specificato una sola volta")
    if args.publish_current and not targets:
        raise SystemExit("--publish-current richiede almeno un --target esplicito")
    if targets and not args.publish_current:
        raise SystemExit("--target richiede --publish-current; la raccolta predefinita è locale")
    config = load_config(args.config)
    try:
        with LiveSyncProcessLock(_lock_path(config)):
            while True:
                try:
                    common = {
                        "targets": targets,
                        "min_quality": args.min_quality,
                        "allow_classic_sensor_stats_server_error": (
                            args.allow_classic_sensor_stats_server_error
                        ),
                    }
                    if args.publish_current:
                        output = publish_current(config, **common)
                    else:
                        output = run_cycle(
                            config,
                            snapshot_retention=args.snapshot_retention,
                            **common,
                        )
                    print(json.dumps(output, ensure_ascii=False), flush=True)
                except (LiveSyncError, RemotePublishError, SnapshotStoreError, SyncError) as exc:
                    published_targets = (
                        list(exc.published_targets)
                        if isinstance(exc, TargetPublishError)
                        else []
                    )
                    commit_unknown_targets = (
                        list(exc.commit_unknown_targets)
                        if isinstance(exc, TargetPublishError)
                        else []
                    )
                    print(
                        json.dumps(
                            {
                                "status": (
                                    "commit_unknown"
                                    if commit_unknown_targets
                                    else "partially_published"
                                    if published_targets
                                    else "not_published"
                                ),
                                "reason": str(exc),
                                "published_targets": published_targets,
                                "failed_target": (
                                    exc.failed_target
                                    if isinstance(exc, TargetPublishError)
                                    else None
                                ),
                                "commit_unknown_targets": commit_unknown_targets,
                            }
                        ),
                        flush=True,
                    )
                    if args.once:
                        return 2
                if args.once:
                    return 0
                time.sleep(args.interval)
    except LiveSyncAlreadyRunning as exc:
        print(
            json.dumps(
                {
                    "status": "already_running",
                    "reason": str(exc),
                    "published_targets": [],
                }
            ),
            flush=True,
        )
        return 3
    except LiveSyncError as exc:
        print(
            json.dumps(
                {
                    "status": "not_published",
                    "reason": str(exc),
                    "published_targets": [],
                }
            ),
            flush=True,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
