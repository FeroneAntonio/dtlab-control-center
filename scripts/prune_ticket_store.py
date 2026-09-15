"""Safely prune the DTLab SQLite ticket store.

The command is a read-only dry run unless ``--apply`` is supplied.  It never
manages services: quiescing producers, when required, is an operator action.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sqlite3
import stat
import sys
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

DEFAULT_RETAIN = 50
AUDIT_DELETE_TRIGGER = "audit_events_no_delete"
REQUIRED_TABLES = frozenset(
    {
        "signals",
        "signal_occurrences",
        "snapshot_ingests",
        "tickets",
        "ticket_comments",
        "ticket_tasks",
        "audit_events",
    }
)


class PruneError(RuntimeError):
    """The store failed a safety check or could not be pruned safely."""


@dataclass(frozen=True)
class PrunePlan:
    ticket_ids: tuple[str, ...]
    kept_ticket_ids: frozenset[str]
    kept_signal_ids: frozenset[str]
    protected_ticket_id: str | None
    signals_to_delete: int
    occurrences_to_delete: int

    @property
    def tickets_to_delete(self) -> int:
        return len(self.ticket_ids) - len(self.kept_ticket_ids)

    def summary(self, *, retain: int) -> dict[str, Any]:
        return {
            "retain_requested": retain,
            "tickets_before": len(self.ticket_ids),
            "tickets_kept": len(self.kept_ticket_ids),
            "tickets_to_delete": self.tickets_to_delete,
            "protected_security_test_ticket_id": self.protected_ticket_id,
            "signals_to_delete": self.signals_to_delete,
            "signal_occurrences_to_delete": self.occurrences_to_delete,
        }


def _database_path(value: Path | str) -> Path:
    raw = Path(value).expanduser()
    if str(raw) == ":memory:":
        raise PruneError("':memory:' is not a persistent ticket store")
    try:
        path = raw.resolve(strict=True)
        details = raw.lstat()
    except OSError as exc:
        raise PruneError(f"ticket store is not accessible: {raw}") from exc
    if raw.is_symlink() or not stat.S_ISREG(details.st_mode):
        raise PruneError("ticket store must be a regular file, not a symlink")
    return path


def _connect(database: Path, *, read_only: bool) -> sqlite3.Connection:
    mode = "ro" if read_only else "rw"
    connection = sqlite3.connect(
        f"{database.as_uri()}?mode={mode}",
        uri=True,
        timeout=30,
        isolation_level=None,
    )
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 30000")
    return connection


def _check_integrity(connection: sqlite3.Connection) -> None:
    quick = [str(row[0]) for row in connection.execute("PRAGMA quick_check")]
    if quick != ["ok"]:
        raise PruneError(f"SQLite quick_check failed: {quick[:3]}")
    integrity = [str(row[0]) for row in connection.execute("PRAGMA integrity_check")]
    if integrity != ["ok"]:
        raise PruneError(f"SQLite integrity_check failed: {integrity[:3]}")
    foreign_keys = connection.execute("PRAGMA foreign_key_check").fetchall()
    if foreign_keys:
        first = tuple(foreign_keys[0])
        raise PruneError(f"SQLite foreign_key_check failed: {first}")


def _require_schema(connection: sqlite3.Connection) -> str:
    tables = {
        str(row[0])
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
        )
    }
    missing = sorted(REQUIRED_TABLES - tables)
    if missing:
        raise PruneError(f"not a compatible DTLab ticket store; missing: {', '.join(missing)}")
    row = connection.execute(
        "SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = ?",
        (AUDIT_DELETE_TRIGGER,),
    ).fetchone()
    if row is None or not str(row[0] or "").strip():
        raise PruneError(f"required trigger is missing: {AUDIT_DELETE_TRIGGER}")
    return str(row[0])


def _is_security_test_host_signal(row: sqlite3.Row) -> bool:
    if str(row["signal_type"]) != "host_modbus_write":
        return False
    try:
        payload = json.loads(str(row["payload_json"]))
        classification = payload["event"]["source"]["classification"]
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        raise PruneError(
            f"cannot classify host_modbus_write signal linked to ticket {row['id']}"
        ) from exc
    return classification == "security_test"


def plan_prune(connection: sqlite3.Connection, *, retain: int) -> PrunePlan:
    if retain < 0:
        raise PruneError("retain must be zero or greater")
    rows = connection.execute(
        """
        SELECT tickets.id, tickets.signal_id, tickets.updated_at,
               signals.signal_type, signals.payload_json
        FROM tickets
        JOIN signals ON signals.id = tickets.signal_id
        ORDER BY tickets.updated_at DESC, tickets.id
        """
    ).fetchall()
    ticket_ids = tuple(str(row["id"]) for row in rows)
    kept_ticket_ids = {str(row["id"]) for row in rows[:retain]}
    protected_ticket_id = next(
        (str(row["id"]) for row in rows if _is_security_test_host_signal(row)),
        None,
    )
    if protected_ticket_id is not None and protected_ticket_id not in kept_ticket_ids:
        # Keep the requested bound exact: the protected ticket replaces the
        # oldest member of the normal UI-ordered window.  With --retain 0 the
        # protection rule deliberately wins and exactly one ticket is kept.
        if kept_ticket_ids:
            kept_ticket_ids.remove(str(rows[retain - 1]["id"]))
        kept_ticket_ids.add(protected_ticket_id)
    kept_signal_ids = {
        str(row["signal_id"]) for row in rows if str(row["id"]) in kept_ticket_ids
    }
    signal_ids = {
        str(row[0]) for row in connection.execute("SELECT id FROM signals").fetchall()
    }
    occurrences_to_delete = sum(
        1
        for row in connection.execute("SELECT signal_id FROM signal_occurrences").fetchall()
        if str(row[0]) not in kept_signal_ids
    )
    return PrunePlan(
        ticket_ids=ticket_ids,
        kept_ticket_ids=frozenset(kept_ticket_ids),
        kept_signal_ids=frozenset(kept_signal_ids),
        protected_ticket_id=protected_ticket_id,
        signals_to_delete=len(signal_ids - kept_signal_ids),
        occurrences_to_delete=occurrences_to_delete,
    )


def _snapshot_ingests(connection: sqlite3.Connection) -> list[tuple[Any, ...]]:
    return [
        tuple(row)
        for row in connection.execute(
            """
            SELECT snapshot_sha256, snapshot_id, generated_at, signals_seen, ingested_at
            FROM snapshot_ingests
            ORDER BY snapshot_sha256
            """
        ).fetchall()
    ]


def _apply_plan(
    connection: sqlite3.Connection,
    plan: PrunePlan,
    *,
    audit_trigger_sql: str,
) -> dict[str, int]:
    connection.execute(
        "CREATE TEMP TABLE dtlab_prune_kept_tickets (id TEXT PRIMARY KEY) WITHOUT ROWID"
    )
    connection.executemany(
        "INSERT INTO dtlab_prune_kept_tickets(id) VALUES (?)",
        ((ticket_id,) for ticket_id in plan.kept_ticket_ids),
    )
    deleted: dict[str, int] = {}
    for table in ("ticket_comments", "ticket_tasks"):
        cursor = connection.execute(
            f"DELETE FROM {table} "
            "WHERE ticket_id NOT IN (SELECT id FROM dtlab_prune_kept_tickets)"
        )
        deleted[table] = cursor.rowcount

    connection.execute(f'DROP TRIGGER "{AUDIT_DELETE_TRIGGER}"')
    cursor = connection.execute(
        "DELETE FROM audit_events "
        "WHERE ticket_id NOT IN (SELECT id FROM dtlab_prune_kept_tickets)"
    )
    deleted["audit_events"] = cursor.rowcount
    connection.execute(audit_trigger_sql)

    cursor = connection.execute(
        "DELETE FROM tickets "
        "WHERE id NOT IN (SELECT id FROM dtlab_prune_kept_tickets)"
    )
    deleted["tickets"] = cursor.rowcount
    cursor = connection.execute(
        "DELETE FROM signal_occurrences "
        "WHERE signal_id NOT IN (SELECT signal_id FROM tickets)"
    )
    deleted["signal_occurrences"] = cursor.rowcount
    cursor = connection.execute(
        "DELETE FROM signals WHERE id NOT IN (SELECT signal_id FROM tickets)"
    )
    deleted["signals"] = cursor.rowcount
    connection.execute("DROP TABLE dtlab_prune_kept_tickets")

    if deleted["tickets"] != plan.tickets_to_delete:
        raise PruneError("ticket count changed while applying the prune plan")
    if deleted["signals"] != plan.signals_to_delete:
        raise PruneError("signal deletion count differs from the prune plan")
    if deleted["signal_occurrences"] != plan.occurrences_to_delete:
        raise PruneError("occurrence deletion count differs from the prune plan")
    if connection.execute(
        "SELECT 1 FROM sqlite_schema WHERE type = 'trigger' AND name = ?",
        (AUDIT_DELETE_TRIGGER,),
    ).fetchone() is None:
        raise PruneError(f"failed to restore trigger: {AUDIT_DELETE_TRIGGER}")
    return deleted


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _atomic_write(path: Path, content: bytes) -> None:
    temporary = path.parent / f".{path.name}.{uuid.uuid4().hex}.tmp"
    try:
        with temporary.open("xb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        if os.name != "nt":
            temporary.chmod(0o600)
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def create_backup(database: Path, backup_dir: Path | None = None) -> dict[str, Any]:
    destination = (backup_dir or database.parent / "backups").expanduser()
    destination.mkdir(parents=True, exist_ok=True)
    if destination.is_symlink() or not destination.is_dir():
        raise PruneError("backup directory must be a regular directory, not a symlink")
    destination = destination.resolve(strict=True)
    if os.name != "nt":
        destination.chmod(0o700)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    backup = destination / f"{database.stem}-{timestamp}-{uuid.uuid4().hex[:8]}.pre-prune.sqlite3"
    temporary = destination / f".{backup.name}.{uuid.uuid4().hex}.tmp"
    source: sqlite3.Connection | None = None
    target: sqlite3.Connection | None = None
    try:
        source = _connect(database, read_only=True)
        target = sqlite3.connect(temporary)
        source.backup(target)
        _check_integrity(target)
        target.close()
        target = None
        source.close()
        source = None
        with temporary.open("r+b") as handle:
            os.fsync(handle.fileno())
        if os.name != "nt":
            temporary.chmod(0o600)
        os.replace(temporary, backup)
    except (OSError, sqlite3.Error) as exc:
        raise PruneError("could not create a consistent SQLite backup") from exc
    finally:
        if target is not None:
            target.close()
        if source is not None:
            source.close()
        if temporary.exists():
            temporary.unlink()

    manifest = {
        "schema_version": "dtlab-ticket-store-prune-backup-v1",
        "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "source_database": str(database),
        "backup_file": backup.name,
        "backup_size_bytes": backup.stat().st_size,
        "backup_sha256": _sha256(backup),
        "verification": {
            "foreign_key_check": "ok",
            "integrity_check": "ok",
            "quick_check": "ok",
        },
    }
    manifest_path = backup.with_suffix(backup.suffix + ".manifest.json")
    _atomic_write(
        manifest_path,
        (json.dumps(manifest, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode(),
    )
    return {**manifest, "backup_path": str(backup), "manifest_path": str(manifest_path)}


def prune_ticket_store(
    database: Path | str,
    *,
    retain: int = DEFAULT_RETAIN,
    apply: bool = False,
    backup_dir: Path | None = None,
) -> dict[str, Any]:
    if retain < 0:
        raise PruneError("retain must be zero or greater")
    database_path = _database_path(database)
    with _connect(database_path, read_only=True) as connection:
        _require_schema(connection)
        _check_integrity(connection)
        dry_plan = plan_prune(connection, retain=retain)
    if not apply:
        return {
            "status": "dry-run",
            "database": str(database_path),
            **dry_plan.summary(retain=retain),
            "snapshot_ingests": "unchanged",
        }

    backup = create_backup(database_path, backup_dir)
    connection = _connect(database_path, read_only=False)
    try:
        connection.execute("BEGIN IMMEDIATE")
        try:
            audit_trigger_sql = _require_schema(connection)
            _check_integrity(connection)
            before_ingests = _snapshot_ingests(connection)
            plan = plan_prune(connection, retain=retain)
            deleted = _apply_plan(
                connection,
                plan,
                audit_trigger_sql=audit_trigger_sql,
            )
            if _snapshot_ingests(connection) != before_ingests:
                raise PruneError("snapshot_ingests changed unexpectedly")
            _check_integrity(connection)
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
    finally:
        connection.close()
    return {
        "status": "applied",
        "database": str(database_path),
        **plan.summary(retain=retain),
        "deleted": deleted,
        "snapshot_ingests": "unchanged",
        "backup": backup,
    }


def _non_negative(value: str) -> int:
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if number < 0:
        raise argparse.ArgumentTypeError("must be zero or greater")
    return number


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", "--db", required=True, type=Path)
    parser.add_argument("--retain", type=_non_negative, default=DEFAULT_RETAIN)
    parser.add_argument(
        "--apply",
        action="store_true",
        help="apply the plan after creating a verified SQLite backup",
    )
    parser.add_argument(
        "--backup-dir",
        type=Path,
        help="backup directory (default: <database-directory>/backups)",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        result = prune_ticket_store(
            args.database,
            retain=args.retain,
            apply=args.apply,
            backup_dir=args.backup_dir,
        )
    except (OSError, sqlite3.Error, PruneError) as exc:
        print(json.dumps({"status": "error", "error": str(exc)}), file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
