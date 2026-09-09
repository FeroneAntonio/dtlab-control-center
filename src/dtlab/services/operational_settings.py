"""Persistent operational configuration for operators, business hours and SIEM."""

from __future__ import annotations

import json
import socket
import sqlite3
import ssl
import threading
import uuid
from contextlib import closing
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, time, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


@dataclass(frozen=True, slots=True)
class BusinessHoursPolicy:
    enabled: bool = True
    timezone: str = "Europe/Rome"
    start: str = "09:00"
    end: str = "18:00"
    weekdays: tuple[int, ...] = (0, 1, 2, 3, 4)

    def validate(self) -> BusinessHoursPolicy:
        try:
            ZoneInfo(self.timezone)
        except ZoneInfoNotFoundError as exc:
            raise ValueError("Fuso orario non riconosciuto") from exc
        start = time.fromisoformat(self.start)
        end = time.fromisoformat(self.end)
        if start >= end:
            raise ValueError("L'orario di apertura deve precedere quello di chiusura")
        if not self.weekdays or any(day not in range(7) for day in self.weekdays):
            raise ValueError("Selezionare almeno un giorno lavorativo valido")
        return self

    @property
    def zone(self) -> ZoneInfo:
        return ZoneInfo(self.timezone)


DEFAULT_BUSINESS_HOURS = BusinessHoursPolicy()
DEFAULT_SYSLOG = {
    "enabled": False,
    "host": "",
    "port": 6514,
    "protocol": "TCP+TLS",
    "format": "CEF Extended Time Precision",
    "include_cisco": True,
    "include_host_ot": True,
    "include_tickets": True,
}


def add_business_hours(
    anchor: datetime,
    hours: int,
    policy: BusinessHoursPolicy,
) -> datetime:
    """Return a UTC deadline after consuming working time in the configured zone."""

    policy.validate()
    if anchor.tzinfo is None:
        raise ValueError("L'istante iniziale deve includere il fuso orario")
    if hours < 0:
        raise ValueError("Le ore SLA non possono essere negative")
    if not policy.enabled:
        return anchor.astimezone(UTC) + timedelta(hours=hours)

    current = anchor.astimezone(policy.zone)
    remaining = timedelta(hours=hours)
    start_at = time.fromisoformat(policy.start)
    end_at = time.fromisoformat(policy.end)
    weekdays = set(policy.weekdays)
    while remaining.total_seconds() > 0:
        if current.weekday() not in weekdays:
            current = datetime.combine(
                current.date() + timedelta(days=1), start_at, policy.zone
            )
            continue
        opening = datetime.combine(current.date(), start_at, policy.zone)
        closing_time = datetime.combine(current.date(), end_at, policy.zone)
        if current < opening:
            current = opening
        if current >= closing_time:
            current = datetime.combine(
                current.date() + timedelta(days=1), start_at, policy.zone
            )
            continue
        available = closing_time - current
        consumed = min(available, remaining)
        current += consumed
        remaining -= consumed
    return current.astimezone(UTC)


def is_business_open(moment: datetime, policy: BusinessHoursPolicy) -> bool:
    if not policy.enabled:
        return True
    policy.validate()
    local = moment.astimezone(policy.zone)
    return (
        local.weekday() in policy.weekdays
        and time.fromisoformat(policy.start) <= local.time().replace(tzinfo=None)
        < time.fromisoformat(policy.end)
    )


class OperationalSettingsStore:
    def __init__(self, database_path: str | Path) -> None:
        self.database_path = Path(database_path).expanduser().resolve()
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path, timeout=10, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout = 10000")
        return connection

    def _initialize(self) -> None:
        now = datetime.now(UTC).isoformat().replace("+00:00", "Z")
        with self._lock, closing(self._connect()) as connection:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS operational_settings (
                    key TEXT PRIMARY KEY,
                    payload_json TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    updated_by TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS operators (
                    id TEXT PRIMARY KEY,
                    display_name TEXT NOT NULL UNIQUE,
                    role TEXT NOT NULL,
                    active INTEGER NOT NULL CHECK(active IN (0, 1)),
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                """
            )
            connection.execute(
                """
                INSERT OR IGNORE INTO operators(
                    id, display_name, role, active, created_at, updated_at
                ) VALUES (?, ?, ?, 1, ?, ?)
                """,
                ("operator:dtlab", "Operatore DTLab", "Analista OT", now, now),
            )

    def _get(self, key: str, default: dict) -> dict:
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT payload_json FROM operational_settings WHERE key = ?", (key,)
            ).fetchone()
        return dict(default) if row is None else json.loads(str(row["payload_json"]))

    def _set(self, key: str, payload: dict, *, actor: str) -> None:
        now = datetime.now(UTC).isoformat().replace("+00:00", "Z")
        encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        with self._lock, closing(self._connect()) as connection:
            connection.execute(
                """
                INSERT INTO operational_settings(key, payload_json, updated_at, updated_by)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET
                    payload_json=excluded.payload_json,
                    updated_at=excluded.updated_at,
                    updated_by=excluded.updated_by
                """,
                (key, encoded, now, actor.strip() or "system"),
            )

    def get_business_hours(self) -> BusinessHoursPolicy:
        payload = self._get("business_hours", asdict(DEFAULT_BUSINESS_HOURS))
        payload["weekdays"] = tuple(int(day) for day in payload.get("weekdays", (0, 1, 2, 3, 4)))
        return BusinessHoursPolicy(**payload).validate()

    def set_business_hours(self, policy: BusinessHoursPolicy, *, actor: str) -> None:
        policy.validate()
        payload = asdict(policy)
        payload["weekdays"] = list(policy.weekdays)
        self._set("business_hours", payload, actor=actor)

    def get_syslog(self) -> dict:
        return self._get("syslog", DEFAULT_SYSLOG)

    def set_syslog(self, payload: dict, *, actor: str) -> None:
        normalized = dict(DEFAULT_SYSLOG)
        normalized.update(payload)
        normalized["host"] = str(normalized["host"]).strip()
        normalized["port"] = int(normalized["port"])
        if not 1 <= normalized["port"] <= 65535:
            raise ValueError("Porta Syslog non valida")
        if normalized["protocol"] not in {"UDP", "TCP", "TCP+TLS"}:
            raise ValueError("Protocollo Syslog non valido")
        if normalized["enabled"] and not normalized["host"]:
            raise ValueError("Inserire il receiver prima di abilitare Syslog")
        self._set("syslog", normalized, actor=actor)

    def list_operators(self, *, active_only: bool = False) -> list[dict]:
        where = " WHERE active = 1" if active_only else ""
        with closing(self._connect()) as connection:
            rows = connection.execute(
                "SELECT * FROM operators" + where + " ORDER BY active DESC, display_name"
            ).fetchall()
        return [
            {
                "id": row["id"],
                "display_name": row["display_name"],
                "role": row["role"],
                "active": bool(row["active"]),
            }
            for row in rows
        ]

    def save_operator(
        self, display_name: str, role: str, *, active: bool = True
    ) -> dict:
        display_name = display_name.strip()
        role = role.strip()
        if not display_name or not role:
            raise ValueError("Nome e ruolo operatore sono obbligatori")
        if len(display_name) > 128 or len(role) > 128:
            raise ValueError("Nome o ruolo operatore troppo lungo")
        now = datetime.now(UTC).isoformat().replace("+00:00", "Z")
        identifier = "operator:" + uuid.uuid5(uuid.NAMESPACE_URL, display_name.casefold()).hex
        with self._lock, closing(self._connect()) as connection:
            connection.execute(
                """
                INSERT INTO operators(id, display_name, role, active, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(display_name) DO UPDATE SET
                    role=excluded.role, active=excluded.active, updated_at=excluded.updated_at
                """,
                (identifier, display_name, role, int(active), now, now),
            )
        return next(item for item in self.list_operators() if item["display_name"] == display_name)


def probe_syslog_endpoint(config: dict, *, timeout: float = 3.0) -> str:
    host = str(config.get("host") or "").strip()
    port = int(config.get("port") or 0)
    protocol = str(config.get("protocol") or "")
    if not host or not 1 <= port <= 65535:
        raise ValueError("Receiver Syslog incompleto")
    if protocol == "UDP":
        socket.getaddrinfo(host, port, type=socket.SOCK_DGRAM)
        return (
            "DNS/indirizzo valido; UDP non consente di confermare il receiver "
            "senza inviare dati."
        )
    with socket.create_connection((host, port), timeout=timeout) as connection:
        if protocol == "TCP+TLS":
            context = ssl.create_default_context()
            with context.wrap_socket(connection, server_hostname=host):
                return "Handshake TCP+TLS completato."
    return "Connessione TCP completata."
