from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime, timedelta

import dtlab.services.ticket_ingest_worker as worker_module
from dtlab.services.snapshot_store import AtomicSnapshotStore
from dtlab.services.ticket_ingest_worker import ingest_available_snapshots, main
from dtlab.services.ticket_store import TicketStore, TicketStoreError
from tests.factories import valid_snapshot

PUBLISHED_AT = datetime(2026, 8, 3, 12, 0, tzinfo=UTC)


def _publish_series(root, count: int = 3) -> None:
    store = AtomicSnapshotStore(root)
    base = valid_snapshot()
    first_generated_at = datetime.fromisoformat(
        str(base["generated_at"]).replace("Z", "+00:00")
    ).astimezone(UTC)
    for index in range(count):
        snapshot = deepcopy(base)
        snapshot["snapshot_id"] = f"snapshot:worker:{index:04d}"
        snapshot["generated_at"] = (
            (first_generated_at + timedelta(minutes=index)).isoformat().replace("+00:00", "Z")
        )
        store.publish(snapshot, published_at=PUBLISHED_AT + timedelta(minutes=index))


def test_worker_backfills_every_archived_snapshot_and_is_idempotent(tmp_path) -> None:
    snapshot_root = tmp_path / "snapshots"
    ticket_path = tmp_path / "tickets" / "tickets.sqlite3"
    _publish_series(snapshot_root)

    first = ingest_available_snapshots(snapshot_root, ticket_path)
    second = ingest_available_snapshots(snapshot_root, ticket_path)
    ticket_store = TicketStore(ticket_path)

    assert first.archives_seen == 3
    assert first.snapshots_loaded == 3
    assert first.snapshots_ingested == 3
    assert first.archive_errors == ()
    assert second.snapshots_ingested == 0
    assert second.snapshots_loaded == 0
    assert second.snapshots_already_ingested == 3
    assert len(ticket_store.list_snapshot_ingests()) == 3


def test_corrupt_historical_archive_does_not_block_verified_current(tmp_path) -> None:
    snapshot_root = tmp_path / "snapshots"
    ticket_path = tmp_path / "tickets.sqlite3"
    _publish_series(snapshot_root, count=1)
    corrupt = snapshot_root / "manifests" / ("a" * 64 + ".json")
    corrupt.write_text("{}", encoding="utf-8")

    result = ingest_available_snapshots(snapshot_root, ticket_path)

    assert result.snapshots_ingested == 1
    assert len(result.archive_errors) == 1
    assert TicketStore(ticket_path).snapshot_ingested(result.current_snapshot_sha256)


def test_cli_requires_explicit_store_paths(capsys) -> None:
    assert main([]) == 2
    assert "snapshot_store_and_ticket_store_required" in capsys.readouterr().err


def test_cli_reports_archive_warning_without_failing_by_default(tmp_path, capsys) -> None:
    snapshot_root = tmp_path / "snapshots"
    ticket_path = tmp_path / "tickets.sqlite3"
    _publish_series(snapshot_root, count=1)
    (snapshot_root / "manifests" / ("b" * 64 + ".json")).write_text(
        "{}",
        encoding="utf-8",
    )

    code = main(
        [
            "--snapshot-store",
            str(snapshot_root),
            "--ticket-store",
            str(ticket_path),
        ]
    )

    captured = capsys.readouterr()
    assert code == 0
    assert '"ok": false' in captured.out
    assert "archive_warning" in captured.err


def test_cli_reports_ticket_store_failures_as_structured_error(monkeypatch, capsys) -> None:
    def fail_ingest(*_args, **_kwargs):
        raise TicketStoreError("ticket store unavailable")

    monkeypatch.setattr(worker_module, "ingest_available_snapshots", fail_ingest)

    code = main(["--snapshot-store", "snapshot-store", "--ticket-store", "tickets.sqlite3"])

    captured = capsys.readouterr()
    assert code == 2
    assert '"ok": false' in captured.err
    assert "ticket store unavailable" in captured.err
