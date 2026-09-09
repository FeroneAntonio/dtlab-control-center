"""Autonomous, idempotent snapshot-to-ticket ingestion worker.

The UI may still invoke the same ingest function for immediate feedback, but this
worker is the authoritative server-side backfill path.  It scans every immutable
manifest so systemd path-event coalescing cannot lose intermediate snapshots.
"""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

from dtlab.services.signal_ingest import ingest_snapshot
from dtlab.services.snapshot_store import AtomicSnapshotStore, SnapshotStoreError, StoredSnapshot
from dtlab.services.ticket_store import TicketStore, TicketStoreError


@dataclass(frozen=True, slots=True)
class WorkerRunResult:
    archives_seen: int
    snapshots_loaded: int
    snapshots_ingested: int
    snapshots_already_ingested: int
    signals_seen: int
    signals_created: int
    observations_created: int
    archive_errors: tuple[str, ...]
    current_snapshot_sha256: str


def _load_candidates(
    snapshot_store: AtomicSnapshotStore,
    *,
    ingested_digests: frozenset[str],
) -> tuple[list[StoredSnapshot], list[str], StoredSnapshot, int]:
    candidates: dict[str, StoredSnapshot] = {}
    errors: list[str] = []
    seen_digests: set[str] = set()
    already_ingested = 0
    archive_names = snapshot_store.archived_manifest_names()
    for manifest_name in archive_names:
        try:
            manifest = snapshot_store.probe_archive_manifest(manifest_name)
        except SnapshotStoreError as exc:
            errors.append(f"{manifest_name}: {exc}")
            continue
        digest = str(manifest["sha256"])
        if digest in seen_digests:
            continue
        seen_digests.add(digest)
        if digest in ingested_digests:
            already_ingested += 1
            continue
        try:
            candidates[digest] = snapshot_store.load_archive(manifest_name)
        except SnapshotStoreError as exc:
            errors.append(f"{manifest_name}: {exc}")

    # Current is mandatory and loaded independently.  A damaged historical archive
    # is reported but cannot prevent ingestion of the current verified state.
    current = snapshot_store.load("current")
    current_digest = str(current.manifest["sha256"])
    if current_digest not in ingested_digests:
        candidates.setdefault(current_digest, current)
    elif current_digest not in seen_digests:
        already_ingested += 1
    ordered = sorted(
        candidates.values(),
        key=lambda stored: (
            str(stored.snapshot["generated_at"]),
            str(stored.manifest["sha256"]),
        ),
    )
    return ordered, errors, current, already_ingested


def ingest_available_snapshots(
    snapshot_store_path: str | Path,
    ticket_store_path: str | Path,
) -> WorkerRunResult:
    """Ingest all unseen immutable snapshots without relying on a browser session."""

    snapshot_store = AtomicSnapshotStore(snapshot_store_path, create_layout=False)
    ticket_store = TicketStore(ticket_store_path)
    archive_count = len(snapshot_store.archived_manifest_names())
    ingested_digests = frozenset(
        str(item["snapshot_sha256"]) for item in ticket_store.list_snapshot_ingests(limit=10000)
    )
    candidates, errors, current, already_ingested = _load_candidates(
        snapshot_store,
        ingested_digests=ingested_digests,
    )

    ingested = 0
    signals_seen = 0
    signals_created = 0
    observations_created = 0
    for stored in candidates:
        digest = str(stored.manifest["sha256"])
        if ticket_store.snapshot_ingested(digest):
            already_ingested += 1
            continue
        result = ingest_snapshot(
            ticket_store,
            stored.snapshot,
            expected_sha256=digest,
        )
        # Another process may win the transaction between the read and the ingest.
        if result.signals_seen == 0 and ticket_store.snapshot_ingested(digest):
            # Empty snapshots are still newly ingested.  Determine this from the
            # pre-check: this invocation attempted it, so count it as committed.
            ingested += 1
        else:
            ingested += 1
        signals_seen += result.signals_seen
        signals_created += result.signals_created
        observations_created += result.occurrences_created

    return WorkerRunResult(
        archives_seen=archive_count,
        snapshots_loaded=len(candidates),
        snapshots_ingested=ingested,
        snapshots_already_ingested=already_ingested,
        signals_seen=signals_seen,
        signals_created=signals_created,
        observations_created=observations_created,
        archive_errors=tuple(errors),
        current_snapshot_sha256=str(current.manifest["sha256"]),
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Ingerisce tutti gli snapshot DTLab non ancora processati nel ticket store."
    )
    parser.add_argument(
        "--snapshot-store",
        default=os.environ.get("DTLAB_SNAPSHOT_STORE"),
        help="Root dello snapshot store (o DTLAB_SNAPSHOT_STORE).",
    )
    parser.add_argument(
        "--ticket-store",
        default=os.environ.get("DTLAB_TICKET_STORE"),
        help="File SQLite ticketing (o DTLAB_TICKET_STORE).",
    )
    parser.add_argument(
        "--fail-on-archive-error",
        action="store_true",
        help="Restituisce errore se un archivio storico è corrotto, dopo aver processato current.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if not args.snapshot_store or not args.ticket_store:
        print(
            json.dumps(
                {"ok": False, "error": "snapshot_store_and_ticket_store_required"},
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 2
    try:
        result = ingest_available_snapshots(args.snapshot_store, args.ticket_store)
    except (OSError, ValueError, sqlite3.Error, SnapshotStoreError, TicketStoreError) as exc:
        print(
            json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False, sort_keys=True),
            file=sys.stderr,
        )
        return 2
    payload = {"ok": not result.archive_errors, **asdict(result)}
    print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
    if result.archive_errors:
        for error in result.archive_errors:
            print(f"archive_warning: {error}", file=sys.stderr)
    return int(bool(args.fail_on_archive_error and result.archive_errors))


if __name__ == "__main__":
    raise SystemExit(main())
