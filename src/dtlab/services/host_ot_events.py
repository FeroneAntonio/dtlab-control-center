"""Validate and ingest authenticated host-side PLC Modbus evidence.

Authentication is intentionally outside this module: the HTTP receiver verifies
HMAC and replay controls before calling :func:`ingest_host_ot_event`.  This layer
then applies a strict content contract, fixes the evidence source to a non-Cisco
namespace and feeds the existing idempotent signal/ticket engine.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

from dtlab.contract import find_secret_leaks
from dtlab.services.ticket_policy import (
    HOST_OT_SIGNAL_TYPE,
    HOST_OT_SOURCE_ID,
    HOST_OT_SOURCE_SCOPE,
    HostOtTicketPolicyResult,
    apply_host_ot_ticket_policy,
)
from dtlab.services.ticket_store import (
    IngestStats,
    SignalInput,
    SignalNotFoundError,
    TicketStore,
)

HOST_OT_EVENT_SCHEMA_VERSION = "dtlab-host-ot-event-v1"
MAX_HOST_OT_EVENT_BYTES = 512 * 1024
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SHUTDOWN_REGISTERS = frozenset({3, 4, 16})
_NON_CISCO_NOTE = (
    "Rilevazione host-side DTLab; non restituita da Cisco Cyber Vision."
)


class HostOtEventValidationError(ValueError):
    """An authenticated host event failed its content contract."""

    def __init__(self, errors: list[str] | tuple[str, ...]):
        self.errors = tuple(dict.fromkeys(errors))
        super().__init__("Evento host OT non valido:\n- " + "\n- ".join(self.errors))


@dataclass(frozen=True, slots=True)
class HostOtIngestResult:
    """Result of one standalone authenticated event ingest."""

    document_sha256: str
    event_type: str
    signal_id: str | None
    ticket_id: str | None
    signals_seen: int
    signals_created: int
    occurrences_created: int
    ticket_created: bool
    ticket_escalated: bool
    tasks_added: int


def host_ot_event_schema_path() -> Path:
    return (
        Path(__file__).resolve().parents[3]
        / "schemas"
        / "dtlab-host-ot-event-v1.schema.json"
    )


@lru_cache(maxsize=1)
def load_host_ot_event_schema() -> dict[str, Any]:
    return json.loads(host_ot_event_schema_path().read_text(encoding="utf-8"))


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def canonical_host_ot_event_bytes(event: Mapping[str, Any]) -> bytes:
    """Return the canonical event document bytes used for its evidence SHA."""

    validate_host_ot_event(event)
    return (_canonical_json(event) + "\n").encode("utf-8")


def host_ot_event_sha256(event: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_host_ot_event_bytes(event)).hexdigest()


def _format_jsonschema_error(error: Any) -> str:
    path = ".".join(str(part) for part in error.absolute_path) or "$"
    return f"{path}: {error.message}"


def _parse_time(value: object, label: str, errors: list[str]) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        errors.append(f"{label}: timestamp senza fuso orario")
        return None
    return parsed.astimezone(UTC)


def _register_values(event: Mapping[str, Any]) -> dict[int, set[int]]:
    """Expand only complete, explicitly supplied register values."""

    modbus = event.get("modbus")
    if not isinstance(modbus, Mapping):
        return {}
    result: dict[int, set[int]] = {}
    for raw_write in modbus.get("writes", []):
        if not isinstance(raw_write, Mapping) or raw_write.get("values_truncated") is True:
            continue
        address = raw_write.get("address")
        values = raw_write.get("values")
        if not isinstance(address, int) or not isinstance(values, list):
            continue
        for offset, value in enumerate(values):
            if isinstance(value, int):
                result.setdefault(address + offset, set()).add(value)
    return result


def is_shutdown_sequence(event: Mapping[str, Any]) -> bool:
    registers = _register_values(event)
    return all(0 in registers.get(address, set()) for address in _SHUTDOWN_REGISTERS)


def _semantic_errors(event: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    event_id = event.get("event_id")
    if event.get("episode_id") != event_id:
        errors.append("episode_id: deve coincidere con event_id")
    evidence = event.get("evidence")
    if isinstance(evidence, Mapping) and evidence.get("source_record_id") != event_id:
        errors.append("evidence.source_record_id: deve coincidere con event_id")

    first = _parse_time(event.get("first_observed_at"), "first_observed_at", errors)
    last = _parse_time(event.get("last_observed_at"), "last_observed_at", errors)
    if first is not None and last is not None and last < first:
        errors.append("last_observed_at: precedente a first_observed_at")

    if event.get("event_type") == "heartbeat":
        return errors

    modbus = event.get("modbus")
    outcome = event.get("outcome")
    detection = event.get("detection")
    if not all(isinstance(value, Mapping) for value in (modbus, outcome, detection)):
        return errors
    assert isinstance(modbus, Mapping)
    assert isinstance(outcome, Mapping)
    assert isinstance(detection, Mapping)

    writes = [item for item in modbus.get("writes", []) if isinstance(item, Mapping)]
    reported_codes = set(modbus.get("function_codes", []))
    observed_codes = {item.get("function_code") for item in writes}
    if reported_codes != observed_codes:
        errors.append("modbus.function_codes: incoerente con i bucket writes")

    bucket_count = sum(int(item.get("count") or 0) for item in writes)
    dropped = int(modbus.get("dropped_operation_buckets") or 0)
    request_count = int(modbus.get("request_count") or 0)
    if bucket_count + dropped != request_count:
        errors.append(
            "modbus.request_count: deve uguagliare count bucket + dropped_operation_buckets"
        )

    states = outcome.get("states")
    if isinstance(states, Mapping):
        outcome_count = sum(
            int(states.get(name) or 0) for name in ("processed", "rejected", "unknown")
        )
        if outcome_count != request_count:
            errors.append("outcome.states: il totale deve uguagliare request_count")

    shutdown = is_shutdown_sequence(event)
    expected = {
        "classification": "process_shutdown_sequence" if shutdown else "modbus_write",
        "severity": "critical" if shutdown else "high",
        "priority": "p1" if shutdown else "p2",
    }
    for field, value in expected.items():
        if detection.get(field) != value:
            errors.append(f"detection.{field}: atteso '{value}' dai valori osservati")

    truth = evidence.get("truth") if isinstance(evidence, Mapping) else None
    states = states if isinstance(states, Mapping) else {}
    if truth == "endpoint_request_observed" and (
        states.get("processed") or states.get("rejected")
    ):
        errors.append(
            "evidence.truth: request_observed non può dichiarare esiti processed/rejected"
        )
    if truth == "endpoint_server_processed" and not states.get("processed"):
        errors.append("evidence.truth: nessuna richiesta processed presente")
    if truth == "endpoint_server_rejected" and not states.get("rejected"):
        errors.append("evidence.truth: nessuna richiesta rejected presente")
    return errors


def validate_host_ot_event(event: Mapping[str, Any]) -> Mapping[str, Any]:
    """Validate one already-authenticated event and return it unchanged.

    This function validates content, not HMAC, freshness windows or replay state.
    Those transport controls belong to the receiver and must run first.
    """

    if not isinstance(event, Mapping):
        raise HostOtEventValidationError(["$: è richiesto un oggetto JSON"])
    try:
        serialized = (_canonical_json(event) + "\n").encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise HostOtEventValidationError([f"$: documento non serializzabile ({exc})"]) from exc
    errors: list[str] = []
    if len(serialized) > MAX_HOST_OT_EVENT_BYTES:
        errors.append(
            f"$: documento oltre {MAX_HOST_OT_EVENT_BYTES} byte ({len(serialized)})"
        )
    validator = Draft202012Validator(
        load_host_ot_event_schema(),
        format_checker=FormatChecker(),
    )
    errors.extend(
        _format_jsonschema_error(error)
        for error in sorted(validator.iter_errors(event), key=lambda item: list(item.path))
    )
    if not errors:
        errors.extend(_semantic_errors(event))
    errors.extend(find_secret_leaks(event))
    if errors:
        raise HostOtEventValidationError(errors)
    return event


def _fingerprint(event: Mapping[str, Any]) -> str:
    identity = {
        "signal_type": HOST_OT_SIGNAL_TYPE,
        "source_id": HOST_OT_SOURCE_ID,
        "source_record_id": event["episode_id"],
    }
    return hashlib.sha256(_canonical_json(identity).encode("utf-8")).hexdigest()


def _source_path_label(event: Mapping[str, Any]) -> str:
    """Describe the observed path without turning every write into PLC-to-PLC."""

    source = event["source"]
    destination = event["destination"]
    classification = source["classification"]
    if classification == "plc_self" or source["ip"] == destination["ip"]:
        return "PLC→PLC"
    if classification == "security_test":
        return "Kali/test di sicurezza→PLC"
    if classification == "authorized_hmi":
        return "HMI autorizzata→PLC"
    return "sorgente sconosciuta→PLC"


def _description(event: Mapping[str, Any], *, shutdown: bool) -> str:
    source = event["source"]
    destination = event["destination"]
    modbus = event["modbus"]
    evidence = event["evidence"]
    register_pairs: list[str] = []
    for write in modbus["writes"]:
        if write["values_truncated"]:
            register_pairs.append(f"{write['address']}=<valori troncati>")
            continue
        for offset, value in enumerate(write["values"][:8]):
            register_pairs.append(f"{write['address'] + offset}={value}")
    if len(register_pairs) > 16:
        register_pairs = [*register_pairs[:16], "…"]
    kind = "sequenza di arresto" if shutdown else "scrittura Modbus"
    source_endpoint = source["ip"]
    if source["port"] is not None:
        source_endpoint = f"{source_endpoint}:{source['port']}"
    return (
        f"Rilevata {kind} {_source_path_label(event)} da {source_endpoint} verso "
        f"{destination['ip']}:502, Unit ID "
        f"{destination['unit_id']}, FC {','.join(map(str, modbus['function_codes']))}, "
        f"registri {', '.join(register_pairs)}. Stato evidenza: {evidence['truth']}."
    )


def signal_from_host_ot_event(
    event: Mapping[str, Any],
    *,
    document_sha256: str | None = None,
) -> tuple[str, SignalInput | None]:
    """Normalize a verified event into a standalone signal.

    Heartbeats are validated and hashed but deliberately produce no operational
    signal or ticket.  The receiver remains responsible for persisting their raw
    authenticated envelope and updating sensor-health state.
    """

    validate_host_ot_event(event)
    digest = hashlib.sha256((_canonical_json(event) + "\n").encode("utf-8")).hexdigest()
    if document_sha256 is not None:
        expected = str(document_sha256).strip().lower()
        if not _SHA256.fullmatch(expected):
            raise HostOtEventValidationError(["document_sha256: SHA-256 non valido"])
        if expected != digest:
            raise HostOtEventValidationError(
                ["document_sha256: non corrisponde al documento canonico"]
            )
    if event["event_type"] == "heartbeat":
        return digest, None

    shutdown = is_shutdown_sequence(event)
    raw_evidence = event["evidence"]
    notes = [str(note) for note in raw_evidence["notes"]]
    if _NON_CISCO_NOTE not in notes:
        notes.append(_NON_CISCO_NOTE)
    evidence = {
        "source_id": HOST_OT_SOURCE_ID,
        "source_record_id": str(event["episode_id"]),
        "truth": "observed",
        "observed_at": str(event["last_observed_at"]),
        "fetched_at": str(event["last_observed_at"]),
        "completeness": (
            1.0
            if raw_evidence["truth"]
            in {"endpoint_server_processed", "endpoint_server_rejected"}
            else 0.8
        ),
        "notes": notes,
    }
    path_label = _source_path_label(event)
    title = (
        f"Sequenza Modbus di arresto {path_label} rilevata"
        if shutdown
        else f"Scrittura Modbus {path_label} rilevata"
    )
    payload = {
        "source_scope": HOST_OT_SOURCE_SCOPE,
        "source_attribution": "dtlab_host_sensor_not_cisco",
        "event": dict(event),
    }
    signal = SignalInput(
        fingerprint=_fingerprint(event),
        signal_type=HOST_OT_SIGNAL_TYPE,
        snapshot_sha256=digest,
        evidence=evidence,
        severity="critical" if shutdown else "high",
        title=title,
        description=_description(event, shutdown=shutdown),
        occurred_at=str(event["first_observed_at"]),
        observed_at=str(event["last_observed_at"]),
        asset_ids=(str(event["destination"]["asset_id"]),),
        recommended_action=(
            "Confermare autorizzazione, stato del processo e rollback con il referente OT; "
            "non eseguire remediation automatica."
        ),
        payload=payload,
    )
    return digest, signal


def ingest_host_ot_event(
    store: TicketStore,
    event: Mapping[str, Any],
    *,
    document_sha256: str | None = None,
) -> HostOtIngestResult:
    """Ingest one authenticated event and apply the narrow automatic ticket policy."""

    digest, signal = signal_from_host_ot_event(
        event,
        document_sha256=document_sha256,
    )
    if signal is None:
        return HostOtIngestResult(
            document_sha256=digest,
            event_type="heartbeat",
            signal_id=None,
            ticket_id=None,
            signals_seen=0,
            signals_created=0,
            occurrences_created=0,
            ticket_created=False,
            ticket_escalated=False,
            tasks_added=0,
        )

    signal_id = f"signal:{signal.fingerprint}"
    try:
        existing = store.get_signal(signal_id)
    except SignalNotFoundError:
        existing = None
    if existing is not None:
        existing_payload = existing.get("payload")
        existing_event = (
            existing_payload.get("event")
            if isinstance(existing_payload, Mapping)
            else None
        )
        existing_revision = (
            existing_event.get("revision")
            if isinstance(existing_event, Mapping)
            else None
        )
        incoming_revision = event["revision"]
        if isinstance(existing_revision, int) and incoming_revision < existing_revision:
            raise HostOtEventValidationError(
                ["revision: precedente alla revisione già acquisita per l'episodio"]
            )
        if (
            isinstance(existing_revision, int)
            and incoming_revision == existing_revision
            and existing.get("snapshot_sha256") != digest
        ):
            raise HostOtEventValidationError(
                ["revision: documento diverso per una revisione episodio già acquisita"]
            )

    stats: IngestStats = store.ingest_signals((signal,))
    policy: HostOtTicketPolicyResult = apply_host_ot_ticket_policy(store, signal_id)
    return HostOtIngestResult(
        document_sha256=digest,
        event_type="modbus_write",
        signal_id=signal_id,
        ticket_id=str(policy.ticket["id"]),
        signals_seen=stats.signals_seen,
        signals_created=stats.signals_created,
        occurrences_created=stats.occurrences_created,
        ticket_created=policy.created,
        ticket_escalated=policy.escalated,
        tasks_added=policy.tasks_added,
    )
