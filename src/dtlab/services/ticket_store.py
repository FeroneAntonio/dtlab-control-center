"""Persistent, thread-safe operational store for DTLab signals and tickets.

The ticket database is deliberately separate from the immutable snapshot store.  A
snapshot remains evidence; this module stores the mutable analyst workflow and keeps
an append-only audit trail for every ticket mutation.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import uuid
from collections.abc import Callable, Iterable, Mapping
from contextlib import closing, suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from dtlab.services.operational_settings import (
    BusinessHoursPolicy,
    OperationalSettingsStore,
    add_business_hours,
)

TICKET_STATUSES = frozenset(
    {
        "new",
        "acknowledged",
        "investigating",
        "remediating",
        "waiting_ot",
        "resolved",
        "closed",
        "false_positive",
        "accepted_risk",
        "suppressed",
    }
)
TICKET_PRIORITIES = frozenset({"p1", "p2", "p3", "p4"})
TASK_STATUSES = frozenset({"pending", "completed", "skipped"})

# Operational SLA policy.  A ticket deadline is anchored to ``created_at`` so a
# priority change cannot silently reset the elapsed response window.  Changing
# priority is the only operation that recalculates the persisted deadline and the
# old/new values are recorded together in the append-only audit trail.
SLA_POLICY_HOURS: dict[str, int] = {"p1": 4, "p2": 8, "p3": 24, "p4": 72}
SLA_DUE_SOON_FRACTION = 0.25
SLA_STATES = frozenset({"on_time", "due_soon", "overdue", "stopped"})
SLA_STOPPED_STATUSES = frozenset(
    {"closed", "false_positive", "accepted_risk", "suppressed"}
)

_TRANSITIONS: dict[str, frozenset[str]] = {
    "new": frozenset(
        {"acknowledged", "investigating", "false_positive", "accepted_risk", "suppressed"}
    ),
    "acknowledged": frozenset(
        {"investigating", "false_positive", "accepted_risk", "suppressed"}
    ),
    "investigating": frozenset(
        {"remediating", "waiting_ot", "resolved", "false_positive", "accepted_risk", "suppressed"}
    ),
    "remediating": frozenset({"investigating", "waiting_ot", "resolved"}),
    "waiting_ot": frozenset({"investigating", "remediating", "resolved"}),
    "resolved": frozenset({"closed", "investigating"}),
    "closed": frozenset({"investigating"}),
    "false_positive": frozenset({"investigating"}),
    "accepted_risk": frozenset({"investigating"}),
    "suppressed": frozenset({"investigating"}),
}


class TicketStoreError(RuntimeError):
    """Base class for operational-store failures."""


class SignalNotFoundError(TicketStoreError):
    """A requested signal does not exist."""


class TicketNotFoundError(TicketStoreError):
    """A requested ticket does not exist."""


class TaskNotFoundError(TicketStoreError):
    """A requested checklist task does not exist."""


class InvalidTransitionError(TicketStoreError):
    """A ticket lifecycle transition is not permitted."""


class TicketValidationError(TicketStoreError):
    """A caller supplied invalid operational data."""


@dataclass(frozen=True, slots=True)
class SignalInput:
    """One source-owned signal occurrence prepared from a validated snapshot."""

    fingerprint: str
    signal_type: str
    snapshot_sha256: str
    evidence: Mapping[str, Any]
    severity: str
    title: str
    description: str
    occurred_at: str | None
    observed_at: str
    asset_ids: tuple[str, ...]
    recommended_action: str | None
    payload: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class IngestStats:
    """Result of an atomic batch ingest."""

    signals_seen: int
    signals_created: int
    occurrences_created: int


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _utc_text(value: datetime) -> str:
    if value.tzinfo is None:
        raise TicketValidationError("I timestamp operativi devono includere il fuso orario.")
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _utc_datetime(value: object, label: str) -> datetime:
    text = _required_text(value, label, max_length=64)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise TicketValidationError(f"{label} non è un timestamp ISO-8601 valido.") from exc
    if parsed.tzinfo is None:
        raise TicketValidationError(f"{label} deve includere il fuso orario.")
    return parsed.astimezone(UTC)


def _sla_due_at(
    priority: object,
    created_at: object,
    *,
    business_hours: BusinessHoursPolicy | None = None,
) -> str:
    normalized = _normalize_priority(priority)
    anchor = _utc_datetime(created_at, "Data creazione ticket")
    if business_hours is not None:
        return _utc_text(
            add_business_hours(anchor, SLA_POLICY_HOURS[normalized], business_hours)
        )
    return _utc_text(anchor + timedelta(hours=SLA_POLICY_HOURS[normalized]))


def derive_ticket_sla(
    ticket: Mapping[str, Any],
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Derive the UTC SLA state without mutating the persisted ticket.

    ``due_soon`` is the final quarter of the priority window (P1: 1h, P2: 2h,
    P3: 6h, P4: 18h).  Terminal dispositions stop the counter at their persisted
    decision timestamp; ``resolved`` deliberately keeps running until closure.
    """

    priority = _normalize_priority(ticket.get("priority"))
    raw_due_at = ticket.get("sla_due_at") or _sla_due_at(
        priority,
        ticket.get("created_at"),
    )
    due_at = _utc_datetime(raw_due_at, "Deadline SLA")
    evaluated_at = now or _utc_now()
    if evaluated_at.tzinfo is None:
        raise TicketValidationError("L'istante di valutazione SLA deve includere il fuso orario.")
    evaluated_at = evaluated_at.astimezone(UTC)

    status = str(ticket.get("status") or "").strip().lower()
    stopped_at: datetime | None = None
    if status in SLA_STOPPED_STATUSES:
        raw_stopped_at = (
            ticket.get("closed_at") if status == "closed" else ticket.get("resolved_at")
        )
        raw_stopped_at = raw_stopped_at or ticket.get("updated_at")
        stopped_at = _utc_datetime(raw_stopped_at, "Data arresto SLA")
        reference = stopped_at
        state = "stopped"
    else:
        reference = evaluated_at
        remaining = due_at - reference
        due_soon_window = timedelta(
            hours=SLA_POLICY_HOURS[priority] * SLA_DUE_SOON_FRACTION
        )
        if remaining.total_seconds() <= 0:
            state = "overdue"
        elif remaining <= due_soon_window:
            state = "due_soon"
        else:
            state = "on_time"

    remaining_seconds = int((due_at - reference).total_seconds())
    return {
        "state": state,
        "due_at": _utc_text(due_at),
        "evaluated_at": _utc_text(evaluated_at),
        "remaining_seconds": remaining_seconds,
        "policy_hours": SLA_POLICY_HOURS[priority],
        "stopped_at": _utc_text(stopped_at) if stopped_at else None,
        "stop_reason": status if stopped_at else None,
    }


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _payload_hash(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical_json(_semantic_payload(value)).encode("utf-8")).hexdigest()


def _semantic_payload(value: Any, *, inside_evidence: bool = False) -> Any:
    """Remove collection-time noise while preserving source-owned signal changes.

    ``fetched_at`` and ``observed_at`` inside an evidence envelope describe the
    polling cycle, not a change to the OT fact.  They remain available in the
    stored payload, but do not create a new full evidence version by themselves.
    """

    if isinstance(value, Mapping):
        normalized: dict[str, Any] = {}
        for raw_key, nested in value.items():
            key = str(raw_key)
            if inside_evidence and key in {"fetched_at", "observed_at"}:
                continue
            normalized[key] = _semantic_payload(
                nested,
                inside_evidence=inside_evidence or key == "evidence",
            )
        return normalized
    if isinstance(value, (list, tuple)):
        return [_semantic_payload(item, inside_evidence=inside_evidence) for item in value]
    return value


def _required_text(value: object, label: str, *, max_length: int = 4096) -> str:
    text = str(value).strip() if value is not None else ""
    if not text:
        raise TicketValidationError(f"{label} obbligatorio.")
    if len(text) > max_length:
        raise TicketValidationError(f"{label} supera {max_length} caratteri.")
    return text


def _optional_text(value: object, *, max_length: int = 4096) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    if len(text) > max_length:
        raise TicketValidationError(f"Valore testuale oltre {max_length} caratteri.")
    return text


def _normalize_priority(value: object) -> str:
    priority = _required_text(value, "Priorità", max_length=2).lower()
    if priority not in TICKET_PRIORITIES:
        raise TicketValidationError(
            "Priorità non valida; valori ammessi: " + ", ".join(sorted(TICKET_PRIORITIES))
        )
    return priority


def _normalize_status(value: object) -> str:
    status = _required_text(value, "Stato", max_length=32).lower()
    if status not in TICKET_STATUSES:
        raise TicketValidationError(
            "Stato non valido; valori ammessi: " + ", ".join(sorted(TICKET_STATUSES))
        )
    return status


def _task_definitions(
    tasks: Iterable[Mapping[str, Any]],
) -> list[tuple[str, str | None]]:
    definitions: list[tuple[str, str | None]] = []
    requested_titles: set[str] = set()
    for raw_task in tasks:
        if not isinstance(raw_task, Mapping):
            raise TicketValidationError("Definizione task non valida.")
        title = _required_text(raw_task.get("title"), "Titolo task", max_length=1024)
        if title in requested_titles:
            continue
        requested_titles.add(title)
        description = _optional_text(raw_task.get("description"), max_length=16384)
        definitions.append((title, description))
    return definitions


class TicketStore:
    """SQLite-backed operational API safe for concurrent Streamlit threads.

    A new connection is opened for every public operation.  Writes are serialized
    inside the process and SQLite WAL/busy-timeout coordinates additional readers or
    processes.  No mutable connection object is shared between Streamlit threads.
    """

    def __init__(
        self,
        database_path: str | Path,
        *,
        clock: Callable[[], datetime] = _utc_now,
        use_operational_settings: bool = False,
    ) -> None:
        raw_path = str(database_path)
        if raw_path == ":memory:":
            raise TicketValidationError(
                "Usare un file SQLite persistente; ':memory:' non è supportato dal ticket store."
            )
        self.database_path = Path(database_path).expanduser().resolve()
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self._clock = clock
        self._use_operational_settings = use_operational_settings
        self._write_lock = threading.RLock()
        self._initialize()
        with suppress(OSError):
            self.database_path.chmod(0o600)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self.database_path,
            timeout=10,
            isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 10000")
        return connection

    def _initialize(self) -> None:
        schema = """
        CREATE TABLE IF NOT EXISTS signals (
            id TEXT PRIMARY KEY,
            fingerprint TEXT NOT NULL UNIQUE,
            signal_type TEXT NOT NULL,
            snapshot_sha256 TEXT NOT NULL,
            source_id TEXT,
            source_record_id TEXT,
            evidence_json TEXT NOT NULL,
            severity TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            occurred_at TEXT,
            first_observed_at TEXT NOT NULL,
            last_observed_at TEXT NOT NULL,
            asset_ids_json TEXT NOT NULL,
            recommended_action TEXT,
            payload_json TEXT NOT NULL,
            occurrence_count INTEGER NOT NULL CHECK (occurrence_count >= 1),
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS signal_occurrences (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            signal_id TEXT NOT NULL REFERENCES signals(id) ON DELETE RESTRICT,
            snapshot_sha256 TEXT NOT NULL,
            observed_at TEXT NOT NULL,
            occurred_at TEXT,
            payload_hash TEXT NOT NULL,
            payload_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(signal_id, snapshot_sha256, payload_hash)
        );

        CREATE TABLE IF NOT EXISTS snapshot_ingests (
            snapshot_sha256 TEXT PRIMARY KEY,
            snapshot_id TEXT NOT NULL,
            generated_at TEXT NOT NULL,
            signals_seen INTEGER NOT NULL CHECK (signals_seen >= 0),
            ingested_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS tickets (
            id TEXT PRIMARY KEY,
            signal_id TEXT NOT NULL UNIQUE REFERENCES signals(id) ON DELETE RESTRICT,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            status TEXT NOT NULL CHECK (
                status IN (
                    'new', 'acknowledged', 'investigating', 'remediating',
                    'waiting_ot', 'resolved', 'closed', 'false_positive',
                    'accepted_risk', 'suppressed'
                )
            ),
            priority TEXT NOT NULL CHECK (priority IN ('p1', 'p2', 'p3', 'p4')),
            owner TEXT,
            created_by TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            sla_due_at TEXT NOT NULL,
            resolved_at TEXT,
            closed_at TEXT
        );

        CREATE TABLE IF NOT EXISTS ticket_comments (
            id TEXT PRIMARY KEY,
            ticket_id TEXT NOT NULL REFERENCES tickets(id) ON DELETE RESTRICT,
            author TEXT NOT NULL,
            body TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS ticket_tasks (
            id TEXT PRIMARY KEY,
            ticket_id TEXT NOT NULL REFERENCES tickets(id) ON DELETE RESTRICT,
            title TEXT NOT NULL,
            description TEXT,
            status TEXT NOT NULL CHECK (status IN ('pending', 'completed', 'skipped')),
            position INTEGER NOT NULL CHECK (position >= 1),
            owner TEXT,
            due_at TEXT,
            completed_at TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(ticket_id, position)
        );

        CREATE TABLE IF NOT EXISTS audit_events (
            sequence INTEGER PRIMARY KEY AUTOINCREMENT,
            ticket_id TEXT NOT NULL REFERENCES tickets(id) ON DELETE RESTRICT,
            actor TEXT NOT NULL,
            action TEXT NOT NULL,
            occurred_at TEXT NOT NULL,
            details_json TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_signals_last_observed
            ON signals(last_observed_at DESC);
        CREATE INDEX IF NOT EXISTS idx_snapshot_ingests_generated
            ON snapshot_ingests(generated_at, snapshot_sha256);
        CREATE INDEX IF NOT EXISTS idx_tickets_status_owner
            ON tickets(status, owner, updated_at DESC);
        CREATE INDEX IF NOT EXISTS idx_ticket_comments_ticket
            ON ticket_comments(ticket_id, created_at, id);
        CREATE INDEX IF NOT EXISTS idx_ticket_tasks_ticket
            ON ticket_tasks(ticket_id, position);
        CREATE INDEX IF NOT EXISTS idx_audit_ticket
            ON audit_events(ticket_id, sequence);

        CREATE TRIGGER IF NOT EXISTS audit_events_no_update
        BEFORE UPDATE ON audit_events
        BEGIN
            SELECT RAISE(ABORT, 'audit_events is append-only');
        END;

        CREATE TRIGGER IF NOT EXISTS audit_events_no_delete
        BEFORE DELETE ON audit_events
        BEGIN
            SELECT RAISE(ABORT, 'audit_events is append-only');
        END;
        """
        with self._write_lock, closing(self._connect()) as connection:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute("PRAGMA synchronous = FULL")
            connection.executescript(schema)
            self._migrate_ticket_sla(connection)

    @staticmethod
    def _migrate_ticket_sla(connection: sqlite3.Connection) -> None:
        """Idempotently add and backfill ``sla_due_at`` for pre-SLA databases."""

        connection.execute("BEGIN IMMEDIATE")
        try:
            columns = {
                str(row[1])
                for row in connection.execute("PRAGMA table_info(tickets)").fetchall()
            }
            if "sla_due_at" not in columns:
                connection.execute("ALTER TABLE tickets ADD COLUMN sla_due_at TEXT")
            rows = connection.execute(
                """
                SELECT id, priority, created_at
                FROM tickets
                WHERE sla_due_at IS NULL OR TRIM(sla_due_at) = ''
                """
            ).fetchall()
            for row in rows:
                connection.execute(
                    "UPDATE tickets SET sla_due_at = ? WHERE id = ?",
                    (_sla_due_at(row["priority"], row["created_at"]), row["id"]),
                )
        except Exception:
            connection.rollback()
            raise
        connection.commit()

    def _now(self) -> str:
        return _utc_text(self._clock())

    def _sla_due_at_for(self, priority: object, created_at: object) -> str:
        policy = self._business_hours_policy()
        return _sla_due_at(priority, created_at, business_hours=policy)

    def _business_hours_policy(self) -> BusinessHoursPolicy | None:
        if not self._use_operational_settings:
            return None
        return OperationalSettingsStore(self.database_path).get_business_hours()

    @staticmethod
    def _begin(connection: sqlite3.Connection) -> None:
        connection.execute("BEGIN IMMEDIATE")

    @staticmethod
    def _audit(
        connection: sqlite3.Connection,
        *,
        ticket_id: str,
        actor: str,
        action: str,
        occurred_at: str,
        details: Mapping[str, Any],
    ) -> None:
        connection.execute(
            """
            INSERT INTO audit_events(ticket_id, actor, action, occurred_at, details_json)
            VALUES (?, ?, ?, ?, ?)
            """,
            (ticket_id, actor, action, occurred_at, _canonical_json(details)),
        )

    @staticmethod
    def _signal_from_row(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": row["id"],
            "fingerprint": row["fingerprint"],
            "signal_type": row["signal_type"],
            "snapshot_sha256": row["snapshot_sha256"],
            "source_id": row["source_id"],
            "source_record_id": row["source_record_id"],
            "evidence": json.loads(row["evidence_json"]),
            "severity": row["severity"],
            "title": row["title"],
            "description": row["description"],
            "occurred_at": row["occurred_at"],
            "first_observed_at": row["first_observed_at"],
            "last_observed_at": row["last_observed_at"],
            "asset_ids": json.loads(row["asset_ids_json"]),
            "recommended_action": row["recommended_action"],
            "payload": json.loads(row["payload_json"]),
            "occurrence_count": row["occurrence_count"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    @staticmethod
    def _ticket_from_row(row: sqlite3.Row) -> dict[str, Any]:
        row_keys = set(row.keys())
        sla_due_at = row["sla_due_at"] if "sla_due_at" in row_keys else None
        if not sla_due_at:
            sla_due_at = _sla_due_at(row["priority"], row["created_at"])
        return {
            "id": row["id"],
            "signal_id": row["signal_id"],
            "title": row["title"],
            "description": row["description"],
            "status": row["status"],
            "priority": row["priority"],
            "owner": row["owner"],
            "created_by": row["created_by"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "sla_due_at": sla_due_at,
            "resolved_at": row["resolved_at"],
            "closed_at": row["closed_at"],
        }

    @staticmethod
    def _comment_from_row(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": row["id"],
            "ticket_id": row["ticket_id"],
            "author": row["author"],
            "body": row["body"],
            "created_at": row["created_at"],
        }

    @staticmethod
    def _task_from_row(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": row["id"],
            "ticket_id": row["ticket_id"],
            "title": row["title"],
            "description": row["description"],
            "status": row["status"],
            "position": row["position"],
            "owner": row["owner"],
            "due_at": row["due_at"],
            "completed_at": row["completed_at"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    @staticmethod
    def _audit_from_row(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "sequence": row["sequence"],
            "ticket_id": row["ticket_id"],
            "actor": row["actor"],
            "action": row["action"],
            "occurred_at": row["occurred_at"],
            "details": json.loads(row["details_json"]),
        }

    def ingest_signals(self, signals: Iterable[SignalInput]) -> IngestStats:
        """Atomically ingest signal occurrences and return deduplication statistics."""

        batch = tuple(signals)
        if not batch:
            return IngestStats(signals_seen=0, signals_created=0, occurrences_created=0)
        now = self._now()
        created_signals = 0
        created_occurrences = 0
        with self._write_lock, closing(self._connect()) as connection:
            self._begin(connection)
            try:
                for signal in batch:
                    signal_created, occurrence_created = self._upsert_signal(
                        connection,
                        signal,
                        now=now,
                    )
                    created_signals += int(signal_created)
                    created_occurrences += int(occurrence_created)
            except Exception:
                connection.rollback()
                raise
            connection.commit()
        return IngestStats(
            signals_seen=len(batch),
            signals_created=created_signals,
            occurrences_created=created_occurrences,
        )

    def snapshot_ingested(self, snapshot_sha256: str) -> bool:
        """Return whether a verified snapshot was committed to the operational store."""

        digest = _required_text(snapshot_sha256, "SHA snapshot", max_length=64).lower()
        if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
            raise TicketValidationError("Lo SHA dello snapshot deve essere SHA-256 esadecimale.")
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT 1 FROM snapshot_ingests WHERE snapshot_sha256 = ?",
                (digest,),
            ).fetchone()
        return row is not None

    def list_snapshot_ingests(self, *, limit: int = 1000) -> list[dict[str, Any]]:
        """List committed snapshot ingests, newest first, for readiness and audit."""

        if limit < 1 or limit > 10000:
            raise TicketValidationError("Il limite ingest deve essere compreso tra 1 e 10000.")
        with closing(self._connect()) as connection:
            rows = connection.execute(
                """
                SELECT snapshot_sha256, snapshot_id, generated_at, signals_seen, ingested_at
                FROM snapshot_ingests
                ORDER BY generated_at DESC, snapshot_sha256 DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def ingest_snapshot_signals(
        self,
        signals: Iterable[SignalInput],
        *,
        snapshot_sha256: str,
        snapshot_id: str,
        generated_at: str,
    ) -> IngestStats:
        """Atomically ingest one immutable snapshot and its completion marker.

        The marker makes crash retry and concurrent UI/worker ingestion idempotent.
        It is written in the same SQLite transaction as every signal observation.
        """

        batch = tuple(signals)
        digest = _required_text(snapshot_sha256, "SHA snapshot", max_length=64).lower()
        if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
            raise TicketValidationError("Lo SHA dello snapshot deve essere SHA-256 esadecimale.")
        normalized_snapshot_id = _required_text(snapshot_id, "Snapshot ID", max_length=1024)
        normalized_generated_at = _required_text(
            generated_at,
            "Timestamp snapshot",
            max_length=64,
        )
        if any(signal.snapshot_sha256.lower() != digest for signal in batch):
            raise TicketValidationError(
                "Tutti i segnali devono appartenere allo snapshot dichiarato."
            )

        now = self._now()
        created_signals = 0
        created_observations = 0
        with self._write_lock, closing(self._connect()) as connection:
            self._begin(connection)
            try:
                already_ingested = connection.execute(
                    "SELECT 1 FROM snapshot_ingests WHERE snapshot_sha256 = ?",
                    (digest,),
                ).fetchone()
                if already_ingested is not None:
                    connection.rollback()
                    return IngestStats(0, 0, 0)
                for signal in batch:
                    signal_created, observation_created = self._upsert_signal(
                        connection,
                        signal,
                        now=now,
                    )
                    created_signals += int(signal_created)
                    created_observations += int(observation_created)
                connection.execute(
                    """
                    INSERT INTO snapshot_ingests(
                        snapshot_sha256, snapshot_id, generated_at, signals_seen, ingested_at
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        digest,
                        normalized_snapshot_id,
                        normalized_generated_at,
                        len(batch),
                        now,
                    ),
                )
            except Exception:
                connection.rollback()
                raise
            connection.commit()
        return IngestStats(
            signals_seen=len(batch),
            signals_created=created_signals,
            occurrences_created=created_observations,
        )

    def _upsert_signal(
        self,
        connection: sqlite3.Connection,
        signal: SignalInput,
        *,
        now: str,
    ) -> tuple[bool, bool]:
        fingerprint = _required_text(signal.fingerprint, "Fingerprint", max_length=128).lower()
        invalid_fingerprint = len(fingerprint) != 64 or any(
            character not in "0123456789abcdef" for character in fingerprint
        )
        if invalid_fingerprint:
            raise TicketValidationError(
                "La fingerprint del segnale deve essere SHA-256 esadecimale."
            )
        snapshot_digest = _required_text(
            signal.snapshot_sha256,
            "SHA snapshot",
            max_length=64,
        ).lower()
        if len(snapshot_digest) != 64 or any(
            character not in "0123456789abcdef" for character in snapshot_digest
        ):
            raise TicketValidationError("Lo SHA dello snapshot deve essere SHA-256 esadecimale.")
        signal_type = _required_text(signal.signal_type, "Tipo segnale", max_length=64)
        evidence = dict(signal.evidence)
        source_id = _optional_text(evidence.get("source_id"), max_length=512)
        source_record_id = _optional_text(evidence.get("source_record_id"), max_length=1024)
        severity = _required_text(signal.severity, "Severità", max_length=32).lower()
        title = _required_text(signal.title, "Titolo", max_length=1024)
        description = _required_text(signal.description, "Descrizione", max_length=16384)
        occurred_at = _optional_text(signal.occurred_at, max_length=64)
        observed_at = _required_text(signal.observed_at, "Timestamp osservazione", max_length=64)
        asset_ids = tuple(
            sorted(
                {
                    _required_text(item, "Asset ID", max_length=1024)
                    for item in signal.asset_ids
                }
            )
        )
        recommended_action = _optional_text(signal.recommended_action, max_length=16384)
        payload = dict(signal.payload)
        payload_json = _canonical_json(payload)
        payload_digest = _payload_hash(payload)
        signal_id = f"signal:{fingerprint}"
        existing = connection.execute(
            "SELECT * FROM signals WHERE fingerprint = ?",
            (fingerprint,),
        ).fetchone()
        signal_created = existing is None
        if signal_created:
            connection.execute(
                """
                INSERT INTO signals(
                    id, fingerprint, signal_type, snapshot_sha256, source_id,
                    source_record_id, evidence_json, severity, title, description,
                    occurred_at, first_observed_at, last_observed_at, asset_ids_json,
                    recommended_action, payload_json, occurrence_count, created_at,
                    updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
                """,
                (
                    signal_id,
                    fingerprint,
                    signal_type,
                    snapshot_digest,
                    source_id,
                    source_record_id,
                    _canonical_json(evidence),
                    severity,
                    title,
                    description,
                    occurred_at,
                    observed_at,
                    observed_at,
                    _canonical_json(list(asset_ids)),
                    recommended_action,
                    payload_json,
                    now,
                    now,
                ),
            )
        if not signal_created and str(existing["snapshot_sha256"]) == snapshot_digest:
            return False, False

        semantic_changed = signal_created or (
            payload_digest != _payload_hash(json.loads(str(existing["payload_json"])))
        )
        if semantic_changed:
            connection.execute(
                """
                INSERT OR IGNORE INTO signal_occurrences(
                    signal_id, snapshot_sha256, observed_at, occurred_at,
                    payload_hash, payload_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    signal_id,
                    snapshot_digest,
                    observed_at,
                    occurred_at,
                    payload_digest,
                    payload_json,
                    now,
                ),
            )
        observation_created = True
        if not signal_created:
            first_observed = min(str(existing["first_observed_at"]), observed_at)
            last_observed = max(str(existing["last_observed_at"]), observed_at)
            connection.execute(
                """
                UPDATE signals
                SET snapshot_sha256 = ?, source_id = ?, source_record_id = ?,
                    evidence_json = ?, severity = ?, title = ?, description = ?,
                    occurred_at = ?, first_observed_at = ?, last_observed_at = ?,
                    asset_ids_json = ?, recommended_action = ?, payload_json = ?,
                    occurrence_count = occurrence_count + 1,
                    updated_at = CASE WHEN ? THEN ? ELSE updated_at END
                WHERE id = ?
                """,
                (
                    snapshot_digest,
                    source_id,
                    source_record_id,
                    _canonical_json(evidence),
                    severity,
                    title,
                    description,
                    occurred_at,
                    first_observed,
                    last_observed,
                    _canonical_json(list(asset_ids)),
                    recommended_action,
                    payload_json,
                    int(semantic_changed),
                    now,
                    signal_id,
                ),
            )
        return signal_created, observation_created

    def get_signal(self, signal_id: str) -> dict[str, Any]:
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT * FROM signals WHERE id = ?",
                (_required_text(signal_id, "Signal ID", max_length=128),),
            ).fetchone()
        if row is None:
            raise SignalNotFoundError(f"Segnale non trovato: {signal_id}")
        return self._signal_from_row(row)

    def list_signals(
        self,
        *,
        signal_type: str | None = None,
        severity: str | None = None,
        without_ticket: bool = False,
        limit: int = 200,
    ) -> list[dict[str, Any]]:
        if limit < 1 or limit > 1000:
            raise TicketValidationError("Il limite segnali deve essere compreso tra 1 e 1000.")
        clauses: list[str] = []
        parameters: list[Any] = []
        if signal_type:
            clauses.append("signals.signal_type = ?")
            parameters.append(_required_text(signal_type, "Tipo segnale", max_length=64))
        if severity:
            clauses.append("signals.severity = ?")
            parameters.append(_required_text(severity, "Severità", max_length=32).lower())
        if without_ticket:
            clauses.append("tickets.id IS NULL")
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        parameters.append(limit)
        with closing(self._connect()) as connection:
            rows = connection.execute(
                """
                SELECT signals.*
                FROM signals
                LEFT JOIN tickets ON tickets.signal_id = signals.id
                """
                + where
                + " ORDER BY signals.last_observed_at DESC, signals.id LIMIT ?",
                parameters,
            ).fetchall()
        return [self._signal_from_row(row) for row in rows]

    def create_ticket_from_signal(
        self,
        signal_id: str,
        *,
        actor: str,
        priority: str = "p3",
        owner: str | None = None,
        title: str | None = None,
        description: str | None = None,
    ) -> dict[str, Any]:
        """Explicitly create one idempotent ticket for an existing signal."""

        signal_id = _required_text(signal_id, "Signal ID", max_length=128)
        actor = _required_text(actor, "Attore", max_length=256)
        priority = _normalize_priority(priority)
        owner = _optional_text(owner, max_length=256)
        now = self._now()
        sla_due_at = self._sla_due_at_for(priority, now)
        with self._write_lock, closing(self._connect()) as connection:
            self._begin(connection)
            try:
                signal = connection.execute(
                    "SELECT * FROM signals WHERE id = ?",
                    (signal_id,),
                ).fetchone()
                if signal is None:
                    raise SignalNotFoundError(f"Segnale non trovato: {signal_id}")
                existing = connection.execute(
                    "SELECT * FROM tickets WHERE signal_id = ?",
                    (signal_id,),
                ).fetchone()
                if existing is not None:
                    connection.commit()
                    return self._ticket_from_row(existing)
                ticket_id = f"ticket:{uuid.uuid4().hex}"
                ticket_title = _optional_text(title, max_length=1024) or str(signal["title"])
                ticket_description = (
                    _optional_text(description, max_length=16384) or str(signal["description"])
                )
                connection.execute(
                    """
                    INSERT INTO tickets(
                        id, signal_id, title, description, status, priority, owner,
                        created_by, created_at, updated_at, sla_due_at, resolved_at, closed_at
                    ) VALUES (?, ?, ?, ?, 'new', ?, ?, ?, ?, ?, ?, NULL, NULL)
                    """,
                    (
                        ticket_id,
                        signal_id,
                        ticket_title,
                        ticket_description,
                        priority,
                        owner,
                        actor,
                        now,
                        now,
                        sla_due_at,
                    ),
                )
                self._audit(
                    connection,
                    ticket_id=ticket_id,
                    actor=actor,
                    action="ticket.created",
                    occurred_at=now,
                    details={
                        "signal_id": signal_id,
                        "status": "new",
                        "priority": priority,
                        "owner": owner,
                        "sla_due_at": sla_due_at,
                        "sla_policy_hours": SLA_POLICY_HOURS[priority],
                    },
                )
                row = connection.execute(
                    "SELECT * FROM tickets WHERE id = ?",
                    (ticket_id,),
                ).fetchone()
            except Exception:
                connection.rollback()
                raise
            connection.commit()
        assert row is not None
        return self._ticket_from_row(row)

    def create_ticket_with_tasks(
        self,
        signal_id: str,
        *,
        actor: str,
        tasks: Iterable[Mapping[str, Any]],
        priority: str = "p3",
        owner: str | None = None,
        title: str | None = None,
        description: str | None = None,
    ) -> tuple[dict[str, Any], int]:
        """Create a ticket and its initial checklist in one idempotent transaction."""

        signal_id = _required_text(signal_id, "Signal ID", max_length=128)
        actor = _required_text(actor, "Attore", max_length=256)
        priority = _normalize_priority(priority)
        owner = _optional_text(owner, max_length=256)
        definitions = _task_definitions(tasks)
        now = self._now()
        sla_due_at = self._sla_due_at_for(priority, now)
        added = 0
        with self._write_lock, closing(self._connect()) as connection:
            self._begin(connection)
            try:
                signal = connection.execute(
                    "SELECT * FROM signals WHERE id = ?",
                    (signal_id,),
                ).fetchone()
                if signal is None:
                    raise SignalNotFoundError(f"Segnale non trovato: {signal_id}")
                ticket_row = connection.execute(
                    "SELECT * FROM tickets WHERE signal_id = ?",
                    (signal_id,),
                ).fetchone()
                if ticket_row is None:
                    ticket_id = f"ticket:{uuid.uuid4().hex}"
                    ticket_title = _optional_text(title, max_length=1024) or str(
                        signal["title"]
                    )
                    ticket_description = _optional_text(
                        description, max_length=16384
                    ) or str(signal["description"])
                    connection.execute(
                        """
                        INSERT INTO tickets(
                            id, signal_id, title, description, status, priority, owner,
                            created_by, created_at, updated_at, sla_due_at,
                            resolved_at, closed_at
                        ) VALUES (?, ?, ?, ?, 'new', ?, ?, ?, ?, ?, ?, NULL, NULL)
                        """,
                        (
                            ticket_id,
                            signal_id,
                            ticket_title,
                            ticket_description,
                            priority,
                            owner,
                            actor,
                            now,
                            now,
                            sla_due_at,
                        ),
                    )
                    self._audit(
                        connection,
                        ticket_id=ticket_id,
                        actor=actor,
                        action="ticket.created",
                        occurred_at=now,
                        details={
                            "signal_id": signal_id,
                            "status": "new",
                            "priority": priority,
                            "owner": owner,
                            "sla_due_at": sla_due_at,
                            "sla_policy_hours": SLA_POLICY_HOURS[priority],
                        },
                    )
                else:
                    ticket_id = str(ticket_row["id"])

                existing_titles = {
                    str(row[0])
                    for row in connection.execute(
                        "SELECT title FROM ticket_tasks WHERE ticket_id = ?",
                        (ticket_id,),
                    ).fetchall()
                }
                position = int(
                    connection.execute(
                        "SELECT COALESCE(MAX(position), 0) FROM ticket_tasks WHERE ticket_id = ?",
                        (ticket_id,),
                    ).fetchone()[0]
                )
                for task_title, task_description in definitions:
                    if task_title in existing_titles:
                        continue
                    position += 1
                    task_id = f"task:{uuid.uuid4().hex}"
                    connection.execute(
                        """
                        INSERT INTO ticket_tasks(
                            id, ticket_id, title, description, status, position, owner,
                            due_at, completed_at, created_at, updated_at
                        ) VALUES (?, ?, ?, ?, 'pending', ?, ?, NULL, NULL, ?, ?)
                        """,
                        (
                            task_id,
                            ticket_id,
                            task_title,
                            task_description,
                            position,
                            owner,
                            now,
                            now,
                        ),
                    )
                    self._audit(
                        connection,
                        ticket_id=ticket_id,
                        actor=actor,
                        action="ticket.task_added",
                        occurred_at=now,
                        details={
                            "task_id": task_id,
                            "position": position,
                            "title": task_title,
                        },
                    )
                    existing_titles.add(task_title)
                    added += 1
                if added:
                    connection.execute(
                        "UPDATE tickets SET updated_at = ? WHERE id = ?",
                        (now, ticket_id),
                    )
                row = connection.execute(
                    "SELECT * FROM tickets WHERE id = ?",
                    (ticket_id,),
                ).fetchone()
            except Exception:
                connection.rollback()
                raise
            connection.commit()
        assert row is not None
        return self._ticket_from_row(row), added

    def get_ticket(self, ticket_id: str) -> dict[str, Any]:
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT * FROM tickets WHERE id = ?",
                (_required_text(ticket_id, "Ticket ID", max_length=128),),
            ).fetchone()
        if row is None:
            raise TicketNotFoundError(f"Ticket non trovato: {ticket_id}")
        return self._ticket_from_row(row)

    def get_ticket_for_signal(self, signal_id: str) -> dict[str, Any] | None:
        """Return the unique ticket linked to a signal, when one exists.

        Automatic policies use this exact lookup instead of scanning a truncated
        ticket list.  The database ``UNIQUE(signal_id)`` constraint remains the
        authoritative concurrency guard.
        """

        normalized_signal_id = _required_text(signal_id, "Signal ID", max_length=128)
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT * FROM tickets WHERE signal_id = ?",
                (normalized_signal_id,),
            ).fetchone()
        return self._ticket_from_row(row) if row is not None else None

    def list_tickets(
        self,
        *,
        status: str | None = None,
        owner: str | None = None,
        limit: int = 200,
    ) -> list[dict[str, Any]]:
        if limit < 1 or limit > 1000:
            raise TicketValidationError("Il limite ticket deve essere compreso tra 1 e 1000.")
        clauses: list[str] = []
        parameters: list[Any] = []
        if status:
            clauses.append("status = ?")
            parameters.append(_normalize_status(status))
        if owner:
            clauses.append("owner = ?")
            parameters.append(_required_text(owner, "Owner", max_length=256))
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        parameters.append(limit)
        with closing(self._connect()) as connection:
            rows = connection.execute(
                "SELECT * FROM tickets"
                + where
                + " ORDER BY updated_at DESC, id LIMIT ?",
                parameters,
            ).fetchall()
        return [self._ticket_from_row(row) for row in rows]

    def transition_ticket(
        self,
        ticket_id: str,
        to_status: str,
        *,
        actor: str,
        note: str | None = None,
    ) -> dict[str, Any]:
        ticket_id = _required_text(ticket_id, "Ticket ID", max_length=128)
        target = _normalize_status(to_status)
        actor = _required_text(actor, "Attore", max_length=256)
        note = _optional_text(note, max_length=16384)
        if target in {"resolved", "false_positive", "accepted_risk", "suppressed"} and not note:
            raise TicketValidationError(
                f"Una nota decisionale è obbligatoria per lo stato {target}."
            )
        now = self._now()
        with self._write_lock, closing(self._connect()) as connection:
            self._begin(connection)
            try:
                row = connection.execute(
                    "SELECT * FROM tickets WHERE id = ?",
                    (ticket_id,),
                ).fetchone()
                if row is None:
                    raise TicketNotFoundError(f"Ticket non trovato: {ticket_id}")
                current = str(row["status"])
                if target not in _TRANSITIONS[current]:
                    raise InvalidTransitionError(
                        f"Transizione ticket non valida: {current} -> {target}"
                    )
                resolved_at = row["resolved_at"]
                closed_at = row["closed_at"]
                if target in {"resolved", "false_positive", "accepted_risk", "suppressed"}:
                    resolved_at = now
                if target == "closed":
                    closed_at = now
                if target == "investigating" and current in {
                    "resolved",
                    "closed",
                    "false_positive",
                    "accepted_risk",
                    "suppressed",
                }:
                    resolved_at = None
                    closed_at = None
                connection.execute(
                    """
                    UPDATE tickets
                    SET status = ?, updated_at = ?, resolved_at = ?, closed_at = ?
                    WHERE id = ?
                    """,
                    (target, now, resolved_at, closed_at, ticket_id),
                )
                self._audit(
                    connection,
                    ticket_id=ticket_id,
                    actor=actor,
                    action="ticket.status_changed",
                    occurred_at=now,
                    details={"from": current, "to": target, "note": note},
                )
                updated = connection.execute(
                    "SELECT * FROM tickets WHERE id = ?",
                    (ticket_id,),
                ).fetchone()
            except Exception:
                connection.rollback()
                raise
            connection.commit()
        assert updated is not None
        return self._ticket_from_row(updated)

    def assign_ticket(
        self,
        ticket_id: str,
        owner: str | None,
        *,
        actor: str,
    ) -> dict[str, Any]:
        return self._update_ticket_field(
            ticket_id,
            field="owner",
            value=_optional_text(owner, max_length=256),
            actor=actor,
            action="ticket.assigned",
        )

    def set_ticket_priority(
        self,
        ticket_id: str,
        priority: str,
        *,
        actor: str,
    ) -> dict[str, Any]:
        return self._update_ticket_field(
            ticket_id,
            field="priority",
            value=_normalize_priority(priority),
            actor=actor,
            action="ticket.priority_changed",
        )

    def recalculate_open_sla_deadlines(self, *, actor: str) -> int:
        """Apply the current business calendar to every non-terminal ticket."""

        actor = _required_text(actor, "Attore", max_length=256)
        now = self._now()
        business_hours = self._business_hours_policy()
        changed = 0
        with self._write_lock, closing(self._connect()) as connection:
            self._begin(connection)
            try:
                placeholders = ",".join("?" for _ in SLA_STOPPED_STATUSES)
                rows = connection.execute(
                    f"SELECT * FROM tickets WHERE status NOT IN ({placeholders})",
                    tuple(sorted(SLA_STOPPED_STATUSES)),
                ).fetchall()
                for row in rows:
                    next_due_at = _sla_due_at(
                        row["priority"],
                        row["created_at"],
                        business_hours=business_hours,
                    )
                    previous_due_at = str(row["sla_due_at"])
                    if next_due_at == previous_due_at:
                        continue
                    connection.execute(
                        "UPDATE tickets SET sla_due_at = ?, updated_at = ? WHERE id = ?",
                        (next_due_at, now, row["id"]),
                    )
                    self._audit(
                        connection,
                        ticket_id=str(row["id"]),
                        actor=actor,
                        action="ticket.sla_calendar_recalculated",
                        occurred_at=now,
                        details={
                            "from_sla_due_at": previous_due_at,
                            "to_sla_due_at": next_due_at,
                            "sla_anchor": "ticket.created_at",
                            "sla_policy_hours": SLA_POLICY_HOURS[str(row["priority"])],
                        },
                    )
                    changed += 1
            except Exception:
                connection.rollback()
                raise
            connection.commit()
        return changed

    def update_ticket_governance(
        self,
        ticket_id: str,
        *,
        owner: str | None,
        priority: str,
        actor: str,
    ) -> dict[str, Any]:
        """Atomically update assignment and priority with one audited commit."""

        ticket_id = _required_text(ticket_id, "Ticket ID", max_length=128)
        actor = _required_text(actor, "Attore", max_length=256)
        owner = _optional_text(owner, max_length=256)
        priority = _normalize_priority(priority)
        now = self._now()
        business_hours = self._business_hours_policy()
        with self._write_lock, closing(self._connect()) as connection:
            self._begin(connection)
            try:
                row = self._require_ticket(connection, ticket_id)
                changed = False
                if row["owner"] != owner:
                    connection.execute(
                        "UPDATE tickets SET owner = ? WHERE id = ?",
                        (owner, ticket_id),
                    )
                    self._audit(
                        connection,
                        ticket_id=ticket_id,
                        actor=actor,
                        action="ticket.assigned",
                        occurred_at=now,
                        details={"from": row["owner"], "to": owner},
                    )
                    changed = True
                if row["priority"] != priority:
                    previous_due_at = str(row["sla_due_at"])
                    next_due_at = _sla_due_at(
                        priority,
                        row["created_at"],
                        business_hours=business_hours,
                    )
                    connection.execute(
                        "UPDATE tickets SET priority = ?, sla_due_at = ? WHERE id = ?",
                        (priority, next_due_at, ticket_id),
                    )
                    self._audit(
                        connection,
                        ticket_id=ticket_id,
                        actor=actor,
                        action="ticket.priority_changed",
                        occurred_at=now,
                        details={
                            "from": row["priority"],
                            "to": priority,
                            "from_sla_due_at": previous_due_at,
                            "to_sla_due_at": next_due_at,
                            "sla_anchor": "ticket.created_at",
                            "sla_policy_hours": SLA_POLICY_HOURS[priority],
                        },
                    )
                    changed = True
                if changed:
                    connection.execute(
                        "UPDATE tickets SET updated_at = ? WHERE id = ?",
                        (now, ticket_id),
                    )
                updated = connection.execute(
                    "SELECT * FROM tickets WHERE id = ?",
                    (ticket_id,),
                ).fetchone()
            except Exception:
                connection.rollback()
                raise
            connection.commit()
        assert updated is not None
        return self._ticket_from_row(updated)

    def _update_ticket_field(
        self,
        ticket_id: str,
        *,
        field: str,
        value: str | None,
        actor: str,
        action: str,
    ) -> dict[str, Any]:
        if field not in {"owner", "priority"}:
            raise TicketValidationError("Campo ticket non aggiornabile.")
        ticket_id = _required_text(ticket_id, "Ticket ID", max_length=128)
        actor = _required_text(actor, "Attore", max_length=256)
        now = self._now()
        business_hours = (
            self._business_hours_policy() if field == "priority" else None
        )
        with self._write_lock, closing(self._connect()) as connection:
            self._begin(connection)
            try:
                row = connection.execute(
                    "SELECT * FROM tickets WHERE id = ?",
                    (ticket_id,),
                ).fetchone()
                if row is None:
                    raise TicketNotFoundError(f"Ticket non trovato: {ticket_id}")
                previous = row[field]
                if previous != value:
                    details: dict[str, Any] = {"from": previous, "to": value}
                    if field == "priority":
                        assert value is not None
                        next_due_at = _sla_due_at(
                            value,
                            row["created_at"],
                            business_hours=business_hours,
                        )
                        connection.execute(
                            """
                            UPDATE tickets
                            SET priority = ?, sla_due_at = ?, updated_at = ?
                            WHERE id = ?
                            """,
                            (value, next_due_at, now, ticket_id),
                        )
                        details.update(
                            {
                                "from_sla_due_at": row["sla_due_at"],
                                "to_sla_due_at": next_due_at,
                                "sla_anchor": "ticket.created_at",
                                "sla_policy_hours": SLA_POLICY_HOURS[value],
                            }
                        )
                    else:
                        connection.execute(
                            f"UPDATE tickets SET {field} = ?, updated_at = ? WHERE id = ?",
                            (value, now, ticket_id),
                        )
                    self._audit(
                        connection,
                        ticket_id=ticket_id,
                        actor=actor,
                        action=action,
                        occurred_at=now,
                        details=details,
                    )
                updated = connection.execute(
                    "SELECT * FROM tickets WHERE id = ?",
                    (ticket_id,),
                ).fetchone()
            except Exception:
                connection.rollback()
                raise
            connection.commit()
        assert updated is not None
        return self._ticket_from_row(updated)

    def add_comment(self, ticket_id: str, *, author: str, body: str) -> dict[str, Any]:
        ticket_id = _required_text(ticket_id, "Ticket ID", max_length=128)
        author = _required_text(author, "Autore", max_length=256)
        body = _required_text(body, "Commento", max_length=32768)
        comment_id = f"comment:{uuid.uuid4().hex}"
        now = self._now()
        with self._write_lock, closing(self._connect()) as connection:
            self._begin(connection)
            try:
                self._require_ticket(connection, ticket_id)
                connection.execute(
                    """
                    INSERT INTO ticket_comments(id, ticket_id, author, body, created_at)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (comment_id, ticket_id, author, body, now),
                )
                connection.execute(
                    "UPDATE tickets SET updated_at = ? WHERE id = ?",
                    (now, ticket_id),
                )
                self._audit(
                    connection,
                    ticket_id=ticket_id,
                    actor=author,
                    action="ticket.comment_added",
                    occurred_at=now,
                    details={"comment_id": comment_id},
                )
                row = connection.execute(
                    "SELECT * FROM ticket_comments WHERE id = ?",
                    (comment_id,),
                ).fetchone()
            except Exception:
                connection.rollback()
                raise
            connection.commit()
        assert row is not None
        return self._comment_from_row(row)

    def add_task(
        self,
        ticket_id: str,
        *,
        actor: str,
        title: str,
        description: str | None = None,
        owner: str | None = None,
        due_at: str | None = None,
    ) -> dict[str, Any]:
        ticket_id = _required_text(ticket_id, "Ticket ID", max_length=128)
        actor = _required_text(actor, "Attore", max_length=256)
        title = _required_text(title, "Titolo task", max_length=1024)
        description = _optional_text(description, max_length=16384)
        owner = _optional_text(owner, max_length=256)
        due_at = _optional_text(due_at, max_length=64)
        task_id = f"task:{uuid.uuid4().hex}"
        now = self._now()
        with self._write_lock, closing(self._connect()) as connection:
            self._begin(connection)
            try:
                self._require_ticket(connection, ticket_id)
                position = int(
                    connection.execute(
                        """
                        SELECT COALESCE(MAX(position), 0) + 1
                        FROM ticket_tasks WHERE ticket_id = ?
                        """,
                        (ticket_id,),
                    ).fetchone()[0]
                )
                connection.execute(
                    """
                    INSERT INTO ticket_tasks(
                        id, ticket_id, title, description, status, position, owner,
                        due_at, completed_at, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, 'pending', ?, ?, ?, NULL, ?, ?)
                    """,
                    (
                        task_id,
                        ticket_id,
                        title,
                        description,
                        position,
                        owner,
                        due_at,
                        now,
                        now,
                    ),
                )
                connection.execute(
                    "UPDATE tickets SET updated_at = ? WHERE id = ?",
                    (now, ticket_id),
                )
                self._audit(
                    connection,
                    ticket_id=ticket_id,
                    actor=actor,
                    action="ticket.task_added",
                    occurred_at=now,
                    details={"task_id": task_id, "position": position, "title": title},
                )
                row = connection.execute(
                    "SELECT * FROM ticket_tasks WHERE id = ?",
                    (task_id,),
                ).fetchone()
            except Exception:
                connection.rollback()
                raise
            connection.commit()
        assert row is not None
        return self._task_from_row(row)

    def ensure_tasks(
        self,
        ticket_id: str,
        *,
        actor: str,
        tasks: Iterable[Mapping[str, Any]],
        owner: str | None = None,
    ) -> int:
        """Atomically add missing task titles for idempotent playbook initialization."""

        ticket_id = _required_text(ticket_id, "Ticket ID", max_length=128)
        actor = _required_text(actor, "Attore", max_length=256)
        owner = _optional_text(owner, max_length=256)
        definitions = _task_definitions(tasks)

        now = self._now()
        added = 0
        with self._write_lock, closing(self._connect()) as connection:
            self._begin(connection)
            try:
                self._require_ticket(connection, ticket_id)
                existing_titles = {
                    str(row[0])
                    for row in connection.execute(
                        "SELECT title FROM ticket_tasks WHERE ticket_id = ?",
                        (ticket_id,),
                    ).fetchall()
                }
                position = int(
                    connection.execute(
                        "SELECT COALESCE(MAX(position), 0) FROM ticket_tasks WHERE ticket_id = ?",
                        (ticket_id,),
                    ).fetchone()[0]
                )
                for title, description in definitions:
                    if title in existing_titles:
                        continue
                    position += 1
                    task_id = f"task:{uuid.uuid4().hex}"
                    connection.execute(
                        """
                        INSERT INTO ticket_tasks(
                            id, ticket_id, title, description, status, position, owner,
                            due_at, completed_at, created_at, updated_at
                        ) VALUES (?, ?, ?, ?, 'pending', ?, ?, NULL, NULL, ?, ?)
                        """,
                        (
                            task_id,
                            ticket_id,
                            title,
                            description,
                            position,
                            owner,
                            now,
                            now,
                        ),
                    )
                    self._audit(
                        connection,
                        ticket_id=ticket_id,
                        actor=actor,
                        action="ticket.task_added",
                        occurred_at=now,
                        details={"task_id": task_id, "position": position, "title": title},
                    )
                    existing_titles.add(title)
                    added += 1
                if added:
                    connection.execute(
                        "UPDATE tickets SET updated_at = ? WHERE id = ?",
                        (now, ticket_id),
                    )
            except Exception:
                connection.rollback()
                raise
            connection.commit()
        return added

    def update_task_status(
        self,
        task_id: str,
        status: str,
        *,
        actor: str,
    ) -> dict[str, Any]:
        task_id = _required_text(task_id, "Task ID", max_length=128)
        status = _required_text(status, "Stato task", max_length=32).lower()
        if status not in TASK_STATUSES:
            raise TicketValidationError(
                "Stato task non valido; valori ammessi: " + ", ".join(sorted(TASK_STATUSES))
            )
        actor = _required_text(actor, "Attore", max_length=256)
        now = self._now()
        with self._write_lock, closing(self._connect()) as connection:
            self._begin(connection)
            try:
                row = connection.execute(
                    "SELECT * FROM ticket_tasks WHERE id = ?",
                    (task_id,),
                ).fetchone()
                if row is None:
                    raise TaskNotFoundError(f"Task non trovato: {task_id}")
                previous = str(row["status"])
                completed_at = None if status == "pending" else now
                if previous != status:
                    connection.execute(
                        """
                        UPDATE ticket_tasks
                        SET status = ?, completed_at = ?, updated_at = ?
                        WHERE id = ?
                        """,
                        (status, completed_at, now, task_id),
                    )
                    connection.execute(
                        "UPDATE tickets SET updated_at = ? WHERE id = ?",
                        (now, row["ticket_id"]),
                    )
                    self._audit(
                        connection,
                        ticket_id=str(row["ticket_id"]),
                        actor=actor,
                        action="ticket.task_status_changed",
                        occurred_at=now,
                        details={"task_id": task_id, "from": previous, "to": status},
                    )
                updated = connection.execute(
                    "SELECT * FROM ticket_tasks WHERE id = ?",
                    (task_id,),
                ).fetchone()
            except Exception:
                connection.rollback()
                raise
            connection.commit()
        assert updated is not None
        return self._task_from_row(updated)

    @staticmethod
    def _require_ticket(connection: sqlite3.Connection, ticket_id: str) -> sqlite3.Row:
        row = connection.execute(
            "SELECT * FROM tickets WHERE id = ?",
            (ticket_id,),
        ).fetchone()
        if row is None:
            raise TicketNotFoundError(f"Ticket non trovato: {ticket_id}")
        return row

    def export_ticket(self, ticket_id: str) -> dict[str, Any]:
        """Return a deterministic, JSON-compatible ticket evidence document."""

        ticket_id = _required_text(ticket_id, "Ticket ID", max_length=128)
        with closing(self._connect()) as connection:
            connection.execute("BEGIN")
            try:
                ticket_row = connection.execute(
                    "SELECT * FROM tickets WHERE id = ?",
                    (ticket_id,),
                ).fetchone()
                if ticket_row is None:
                    raise TicketNotFoundError(f"Ticket non trovato: {ticket_id}")
                signal_row = connection.execute(
                    "SELECT * FROM signals WHERE id = ?",
                    (ticket_row["signal_id"],),
                ).fetchone()
                occurrence_rows = connection.execute(
                    """
                    SELECT snapshot_sha256, observed_at, occurred_at, payload_hash,
                           payload_json, created_at
                    FROM signal_occurrences
                    WHERE signal_id = ?
                    ORDER BY observed_at, snapshot_sha256, payload_hash
                    """,
                    (ticket_row["signal_id"],),
                ).fetchall()
                comment_rows = connection.execute(
                    """
                    SELECT * FROM ticket_comments
                    WHERE ticket_id = ? ORDER BY created_at, id
                    """,
                    (ticket_id,),
                ).fetchall()
                task_rows = connection.execute(
                    """
                    SELECT * FROM ticket_tasks
                    WHERE ticket_id = ? ORDER BY position, id
                    """,
                    (ticket_id,),
                ).fetchall()
                audit_rows = connection.execute(
                    """
                    SELECT * FROM audit_events
                    WHERE ticket_id = ? ORDER BY sequence
                    """,
                    (ticket_id,),
                ).fetchall()
            except Exception:
                connection.rollback()
                raise
            connection.commit()
        assert signal_row is not None
        return {
            "schema_version": "dtlab-ticket-v1",
            "ticket": self._ticket_from_row(ticket_row),
            "signal": self._signal_from_row(signal_row),
            "occurrences": [
                {
                    "snapshot_sha256": row["snapshot_sha256"],
                    "observed_at": row["observed_at"],
                    "occurred_at": row["occurred_at"],
                    "payload_hash": row["payload_hash"],
                    "payload": json.loads(row["payload_json"]),
                    "created_at": row["created_at"],
                }
                for row in occurrence_rows
            ],
            "comments": [self._comment_from_row(row) for row in comment_rows],
            "tasks": [self._task_from_row(row) for row in task_rows],
            "audit": [self._audit_from_row(row) for row in audit_rows],
        }

    def export_ticket_json(self, ticket_id: str) -> str:
        """Serialize :meth:`export_ticket` deterministically for download or API use."""

        return (
            json.dumps(
                self.export_ticket(ticket_id),
                ensure_ascii=False,
                sort_keys=True,
                indent=2,
            )
            + "\n"
        )
