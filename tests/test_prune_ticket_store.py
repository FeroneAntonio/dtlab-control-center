from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path

import pytest

from dtlab.services.ticket_store import TicketStore
from scripts.prune_ticket_store import prune_ticket_store


def _build_store(path: Path) -> None:
    TicketStore(path)
    with sqlite3.connect(path) as connection:
        for index in range(4):
            signal_id = f"signal:{index}"
            ticket_id = f"ticket:{index}"
            timestamp = f"2026-08-03T1{5 - index}:00:00Z"
            signal_type = "host_modbus_write" if index == 2 else "event"
            payload = (
                {"event": {"source": {"classification": "security_test"}}}
                if index == 2
                else {"record": index}
            )
            connection.execute(
                """
                INSERT INTO signals(
                    id, fingerprint, signal_type, snapshot_sha256, source_id,
                    source_record_id, evidence_json, severity, title, description,
                    occurred_at, first_observed_at, last_observed_at, asset_ids_json,
                    recommended_action, payload_json, occurrence_count, created_at,
                    updated_at
                ) VALUES (?, ?, ?, ?, NULL, NULL, '{}', 'high', ?, ?, ?, ?, ?, '[]',
                          NULL, ?, 1, ?, ?)
                """,
                (
                    signal_id,
                    f"{index:064x}",
                    signal_type,
                    f"{index + 10:064x}",
                    f"Signal {index}",
                    f"Description {index}",
                    timestamp,
                    timestamp,
                    timestamp,
                    json.dumps(payload),
                    timestamp,
                    timestamp,
                ),
            )
            connection.execute(
                """
                INSERT INTO signal_occurrences(
                    signal_id, snapshot_sha256, observed_at, occurred_at,
                    payload_hash, payload_json, created_at
                ) VALUES (?, ?, ?, ?, ?, '{}', ?)
                """,
                (signal_id, f"{index + 10:064x}", timestamp, timestamp, f"{index:064x}", timestamp),
            )
            connection.execute(
                """
                INSERT INTO tickets(
                    id, signal_id, title, description, status, priority, owner,
                    created_by, created_at, updated_at, sla_due_at, resolved_at, closed_at
                ) VALUES (?, ?, ?, ?, 'new', 'p2', NULL, 'test', ?, ?, ?, NULL, NULL)
                """,
                (ticket_id, signal_id, f"Ticket {index}", "test", timestamp, timestamp, timestamp),
            )
            connection.execute(
                "INSERT INTO ticket_comments VALUES (?, ?, 'test', 'comment', ?)",
                (f"comment:{index}", ticket_id, timestamp),
            )
            connection.execute(
                """
                INSERT INTO ticket_tasks(
                    id, ticket_id, title, description, status, position, owner,
                    due_at, completed_at, created_at, updated_at
                ) VALUES (?, ?, 'task', NULL, 'pending', 1, NULL, NULL, NULL, ?, ?)
                """,
                (f"task:{index}", ticket_id, timestamp, timestamp),
            )
            connection.execute(
                "INSERT INTO audit_events(ticket_id, actor, action, occurred_at, details_json) "
                "VALUES (?, 'test', 'created', ?, '{}')",
                (ticket_id, timestamp),
            )

        connection.execute(
            """
            INSERT INTO signals(
                id, fingerprint, signal_type, snapshot_sha256, source_id,
                source_record_id, evidence_json, severity, title, description,
                occurred_at, first_observed_at, last_observed_at, asset_ids_json,
                recommended_action, payload_json, occurrence_count, created_at, updated_at
            ) VALUES ('signal:orphan', ?, 'event', ?, NULL, NULL, '{}', 'low', 'Orphan',
                      'Orphan', ?, ?, ?, '[]', NULL, '{}', 1, ?, ?)
            """,
            ("e" * 64, "d" * 64, *("2026-08-03T09:00:00Z",) * 5),
        )
        connection.execute(
            """
            INSERT INTO signal_occurrences(
                signal_id, snapshot_sha256, observed_at, occurred_at,
                payload_hash, payload_json, created_at
            ) VALUES ('signal:orphan', ?, ?, ?, ?, '{}', ?)
            """,
            ("d" * 64, *("2026-08-03T09:00:00Z",) * 2, "c" * 64, "2026-08-03T09:00:00Z"),
        )
        connection.execute(
            "INSERT INTO snapshot_ingests VALUES (?, 'snapshot:1', ?, 5, ?)",
            ("f" * 64, "2026-08-03T15:00:00Z", "2026-08-03T15:01:00Z"),
        )


def _count(connection: sqlite3.Connection, table: str) -> int:
    return int(connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])


def test_dry_run_is_default_and_protected_ticket_replaces_oldest_in_bound(tmp_path: Path) -> None:
    database = tmp_path / "tickets.sqlite3"
    _build_store(database)

    result = prune_ticket_store(database, retain=2)

    assert result["status"] == "dry-run"
    assert result["tickets_kept"] == 2
    assert result["tickets_to_delete"] == 2
    assert result["protected_security_test_ticket_id"] == "ticket:2"
    assert not (tmp_path / "backups").exists()
    with sqlite3.connect(database) as connection:
        assert _count(connection, "tickets") == 4
        assert _count(connection, "signals") == 5


def test_apply_prunes_dependencies_and_orphans_but_preserves_ingest_ledger(tmp_path: Path) -> None:
    database = tmp_path / "tickets.sqlite3"
    backups = tmp_path / "safe-backups"
    _build_store(database)

    result = prune_ticket_store(database, retain=1, apply=True, backup_dir=backups)

    assert result["status"] == "applied"
    assert result["tickets_kept"] == 1
    assert result["protected_security_test_ticket_id"] == "ticket:2"
    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT id FROM tickets").fetchall() == [("ticket:2",)]
        assert connection.execute("SELECT id FROM signals").fetchall() == [("signal:2",)]
        assert _count(connection, "signal_occurrences") == 1
        assert _count(connection, "ticket_comments") == 1
        assert _count(connection, "ticket_tasks") == 1
        assert _count(connection, "audit_events") == 1
        assert _count(connection, "snapshot_ingests") == 1
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute("DELETE FROM audit_events")

    backup = Path(result["backup"]["backup_path"])
    manifest = json.loads(Path(result["backup"]["manifest_path"]).read_text(encoding="utf-8"))
    assert manifest["backup_sha256"] == hashlib.sha256(backup.read_bytes()).hexdigest()
    with sqlite3.connect(backup) as connection:
        assert _count(connection, "tickets") == 4
        assert _count(connection, "snapshot_ingests") == 1
        assert connection.execute("PRAGMA quick_check").fetchone() == ("ok",)


def test_apply_rolls_back_every_delete_and_restores_audit_guard_on_error(tmp_path: Path) -> None:
    database = tmp_path / "tickets.sqlite3"
    _build_store(database)
    with sqlite3.connect(database) as connection:
        connection.executescript(
            """
            CREATE TRIGGER reject_signal_prune
            BEFORE DELETE ON signals
            BEGIN
                SELECT RAISE(ABORT, 'injected prune failure');
            END;
            """
        )

    with pytest.raises(sqlite3.IntegrityError, match="injected prune failure"):
        prune_ticket_store(database, retain=1, apply=True, backup_dir=tmp_path / "backups")

    with sqlite3.connect(database) as connection:
        assert _count(connection, "tickets") == 4
        assert _count(connection, "signals") == 5
        assert _count(connection, "signal_occurrences") == 5
        assert _count(connection, "ticket_comments") == 4
        assert _count(connection, "ticket_tasks") == 4
        assert _count(connection, "audit_events") == 4
        assert _count(connection, "snapshot_ingests") == 1
        trigger = connection.execute(
            "SELECT 1 FROM sqlite_schema WHERE type = 'trigger' AND name = 'audit_events_no_delete'"
        ).fetchone()
        assert trigger == (1,)
