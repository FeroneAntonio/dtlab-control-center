"""Operational signal inbox and persistent ticket workflow views."""

from __future__ import annotations

import json
import os
import sqlite3
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pandas as pd
import streamlit as st

from dtlab.services.exports import build_signal_evidence_bundle, build_ticket_register_csv
from dtlab.services.operational_settings import OperationalSettingsStore
from dtlab.services.playbooks import tasks_for_signal
from dtlab.services.signal_ingest import SnapshotIngestResult, ingest_snapshot
from dtlab.services.ticket_store import (
    SLA_POLICY_HOURS,
    TASK_STATUSES,
    TICKET_PRIORITIES,
    TICKET_STATUSES,
    TicketStore,
    TicketStoreError,
    derive_ticket_sla,
)
from dtlab.ui.components import empty_state, format_local_time, metric_card, page_intro
from dtlab.ui.context import DashboardContext

_SIGNAL_TYPE_LABELS = {
    "event": "Evento Cisco",
    "finding": "Finding DTLab",
    "baseline_difference": "Differenza baseline",
    "vulnerability": "Vulnerabilità",
    "new_ui_alert": "Alert Cisco New UI",
    "new_ui_vulnerability": "Vulnerabilità Cisco New UI",
    "host_modbus_write": "Rilevazione host PLC",
}
_SEVERITY_LABELS = {
    "critical": "Critica",
    "high": "Alta",
    "medium": "Media",
    "low": "Bassa",
    "info": "Informativa",
    "unknown": "Non classificata",
}
_SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
    "unknown": 5,
}
_STATUS_LABELS = {
    "new": "Nuovo",
    "acknowledged": "Preso in carico",
    "investigating": "In analisi",
    "remediating": "In remediation",
    "waiting_ot": "In attesa OT",
    "resolved": "Risolto",
    "closed": "Chiuso",
    "false_positive": "Falso positivo",
    "accepted_risk": "Rischio accettato",
    "suppressed": "Soppresso",
}
_TASK_STATUS_LABELS = {
    "pending": "Da fare",
    "completed": "Completata",
    "skipped": "Non applicabile",
}
_ALLOWED_TRANSITIONS: dict[str, tuple[str, ...]] = {
    "new": (
        "acknowledged",
        "investigating",
        "false_positive",
        "accepted_risk",
        "suppressed",
    ),
    "acknowledged": (
        "investigating",
        "false_positive",
        "accepted_risk",
        "suppressed",
    ),
    "investigating": (
        "remediating",
        "waiting_ot",
        "resolved",
        "false_positive",
        "accepted_risk",
        "suppressed",
    ),
    "remediating": ("investigating", "waiting_ot", "resolved"),
    "waiting_ot": ("investigating", "remediating", "resolved"),
    "resolved": ("closed", "investigating"),
    "closed": ("investigating",),
    "false_positive": ("investigating",),
    "accepted_risk": ("investigating",),
    "suppressed": ("investigating",),
}
_TERMINAL_STATUSES = frozenset({"closed", "false_positive", "accepted_risk", "suppressed"})
_DECISION_STATUSES = _TERMINAL_STATUSES | {"resolved"}
_NOTE_REQUIRED_STATUSES = frozenset({"resolved", "false_positive", "accepted_risk", "suppressed"})
_EVIDENCE_COLLECTIONS = {"event": "events", "finding": "findings"}
_SOURCE_OWNED_JSON_TYPES = frozenset({"new_ui_alert", "new_ui_vulnerability", "host_modbus_write"})
_SLA_LABELS = {
    "on_time": "In tempo",
    "due_soon": "In scadenza",
    "overdue": "Scaduto",
    "stopped": "Fermato",
}


def default_ticket_store_path() -> Path:
    """Return the explicitly configured persistent operational database path."""

    configured = os.environ.get("DTLAB_TICKET_STORE")
    if configured:
        return Path(configured).expanduser().resolve()
    project_root = Path(__file__).resolve().parents[4]
    return project_root / "runtime" / "tickets" / "tickets.sqlite3"


@st.cache_resource(show_spinner=False)
def _cached_ticket_store(database_path: str) -> TicketStore:
    return TicketStore(database_path, use_operational_settings=True)


def get_ticket_store(database_path: str | Path | None = None) -> TicketStore:
    """Return the shared persistent store for UI pages and command-center KPIs."""

    resolved = Path(database_path or default_ticket_store_path()).expanduser().resolve()
    return _cached_ticket_store(str(resolved))


def sync_ticket_store(
    context: DashboardContext,
) -> tuple[TicketStore, SnapshotIngestResult]:
    """Idempotently ingest the verified canonical snapshot into the shared store."""

    store = get_ticket_store()
    result = ingest_snapshot(
        store,
        context.canonical_snapshot,
        expected_sha256=str(context.manifest["sha256"]),
    )
    return store, result


def _operator_value(store: TicketStore) -> str:
    settings = OperationalSettingsStore(store.database_path)
    operators = settings.list_operators(active_only=True)
    labels = [str(item["display_name"]) for item in operators]
    preferred = os.environ.get("DTLAB_DEFAULT_OPERATOR", "").strip()
    if preferred and preferred not in labels:
        labels.append(preferred)
    if not labels:
        st.warning("Nessun operatore attivo. Configurarlo in Amministrazione operativa.")
        return ""
    selected = st.selectbox(
        "Operatore attivo",
        labels,
        key="dtlab_operator",
        help="Identità operativa persistente usata per owner, commenti e audit trail.",
    )
    value = str(selected).strip()
    record = next((item for item in operators if item["display_name"] == value), None)
    st.caption(
        f"Ruolo: {record['role'] if record else 'configurazione esterna'} · "
        "registrato nell'audit applicativo. L'autenticazione centralizzata resta un passo futuro."
    )
    return value


def _load_operational_store(
    context: DashboardContext,
) -> tuple[TicketStore, SnapshotIngestResult] | None:
    """Open the persistent store and idempotently ingest the verified snapshot."""

    try:
        store, result = sync_ticket_store(context)
    except (KeyError, OSError, ValueError, sqlite3.Error, TicketStoreError) as exc:
        st.error(
            "Operazioni non disponibili in modalità fail-closed: lo snapshot non è "
            f"verificabile o il ticket store persistente non è scrivibile. Dettaglio: {exc}"
        )
        return None
    return store, result


def _normalized_search(value: object) -> str:
    return str(value or "").strip().casefold()


def _query_parameter(name: str) -> str | None:
    """Read one optional deep-link value without trusting or persisting it."""

    try:
        value: Any = st.query_params.get(name)
    except (AttributeError, KeyError):
        return None
    if isinstance(value, list):
        value = value[-1] if value else None
    text = str(value).strip() if value is not None else ""
    return text or None


def signal_is_actionable(signal: Mapping[str, Any]) -> bool:
    """Keep historical/excluded findings as evidence without putting them in the inbox."""

    signal_type = signal.get("signal_type")
    payload = signal.get("payload")
    if signal_type == "new_ui_alert":
        if not isinstance(payload, Mapping):
            return True
        status = str(payload.get("status") or "").strip().casefold()
        # An absent/unknown status remains visible for safe manual triage.  Only
        # source-confirmed non-active states leave the default operational inbox.
        return status not in {"cleared", "muted"}
    if signal_type != "finding":
        return True
    if not isinstance(payload, Mapping):
        return True
    status = str(payload.get("status") or "").strip().casefold()
    return not bool(payload.get("exclude_from_operational_kpis")) and status not in {
        "accepted",
        "resolved",
        "closed",
    }


def signal_needs_review(
    signal: Mapping[str, Any],
    ticket: Mapping[str, Any] | None,
) -> bool:
    """Return true for unhandled or semantically changed persistent conditions."""

    if ticket is None:
        return True
    if ticket.get("status") not in _DECISION_STATUSES:
        return False
    # Events and baseline differences are point-in-time facts.  Re-reading the same
    # cached fact must never reopen a ticket; a new fact receives a new fingerprint.
    if signal.get("signal_type") not in {
        "finding",
        "vulnerability",
        "new_ui_alert",
        "new_ui_vulnerability",
    }:
        return False
    decision_at = ticket.get("closed_at") or ticket.get("resolved_at")
    changed_at = signal.get("updated_at")
    decision_time = pd.to_datetime(decision_at, utc=True, errors="coerce")
    changed_time = pd.to_datetime(changed_at, utc=True, errors="coerce")
    if pd.isna(decision_time) or pd.isna(changed_time):
        return False
    return bool(changed_time > decision_time)


def _filter_signals(
    signals: Sequence[Mapping[str, Any]],
    *,
    search: str = "",
    signal_types: Sequence[str] = (),
    severities: Sequence[str] = (),
    without_ticket: bool = False,
    ticket_signal_ids: frozenset[str] = frozenset(),
    include_historical: bool = True,
) -> list[dict[str, Any]]:
    needle = _normalized_search(search)
    selected_types = set(signal_types)
    selected_severities = set(severities)
    filtered: list[dict[str, Any]] = []
    for raw_signal in signals:
        signal = dict(raw_signal)
        if not include_historical and not signal_is_actionable(signal):
            continue
        if selected_types and signal.get("signal_type") not in selected_types:
            continue
        if selected_severities and signal.get("severity") not in selected_severities:
            continue
        if without_ticket and signal.get("id") in ticket_signal_ids:
            continue
        searchable = " ".join(
            str(value or "")
            for value in (
                signal.get("id"),
                signal.get("title"),
                signal.get("description"),
                signal.get("source_id"),
                signal.get("source_record_id"),
                " ".join(str(item) for item in signal.get("asset_ids", [])),
            )
        ).casefold()
        if needle and needle not in searchable:
            continue
        filtered.append(signal)
    return filtered


def _filter_tickets(
    tickets: Sequence[Mapping[str, Any]],
    *,
    search: str = "",
    statuses: Sequence[str] = (),
    priorities: Sequence[str] = (),
    owners: Sequence[str] = (),
    sla_states: Sequence[str] = (),
    signals_by_id: Mapping[str, Mapping[str, Any]] | None = None,
    now: datetime | None = None,
) -> list[dict[str, Any]]:
    needle = _normalized_search(search)
    selected_statuses = set(statuses)
    selected_priorities = set(priorities)
    selected_owners = set(owners)
    selected_sla_states = set(sla_states)
    signal_index = signals_by_id or {}
    filtered: list[dict[str, Any]] = []
    for raw_ticket in tickets:
        ticket = dict(raw_ticket)
        if selected_statuses and ticket.get("status") not in selected_statuses:
            continue
        if selected_priorities and ticket.get("priority") not in selected_priorities:
            continue
        owner = str(ticket.get("owner") or "")
        if selected_owners and owner not in selected_owners:
            continue
        if selected_sla_states and derive_ticket_sla(ticket, now=now)["state"] not in (
            selected_sla_states
        ):
            continue
        signal = signal_index.get(str(ticket.get("signal_id")), {})
        searchable = " ".join(
            str(value or "")
            for value in (
                ticket.get("id"),
                ticket.get("title"),
                ticket.get("description"),
                ticket.get("owner"),
                ticket.get("created_by"),
                signal.get("source_record_id"),
                " ".join(str(item) for item in signal.get("asset_ids", [])),
            )
        ).casefold()
        if needle and needle not in searchable:
            continue
        filtered.append(ticket)
    return filtered


def _priority_for_severity(severity: object) -> str:
    return {
        "critical": "p1",
        "high": "p2",
        "medium": "p3",
        "low": "p4",
        "info": "p4",
    }.get(str(severity or "").casefold(), "p3")


def _bounded_count(value: int, *, truncated: bool) -> int | str:
    return f"≥{value}" if truncated else value


def _format_duration(seconds: int) -> str:
    total_minutes = max(0, abs(seconds)) // 60
    if total_minutes == 0:
        return "meno di 1 min"
    days, remaining_minutes = divmod(total_minutes, 24 * 60)
    hours, minutes = divmod(remaining_minutes, 60)
    parts: list[str] = []
    if days:
        parts.append(f"{days} g")
    if hours:
        parts.append(f"{hours} h")
    if minutes and len(parts) < 2:
        parts.append(f"{minutes} min")
    return " ".join(parts)


def _sla_remaining_label(sla: Mapping[str, Any]) -> str:
    seconds = int(sla["remaining_seconds"])
    duration = _format_duration(seconds)
    state = str(sla["state"])
    if state == "overdue":
        return f"Scaduto da {duration}"
    if state == "stopped":
        if seconds < 0:
            return f"Fermato {duration} oltre deadline"
        return f"Fermato con {duration} residue"
    return f"Restano {duration}"


def _ticket_register_rows(
    tickets: Sequence[Mapping[str, Any]],
    *,
    sla_by_ticket_id: Mapping[str, Mapping[str, Any]],
    signals_by_id: Mapping[str, Mapping[str, Any]],
    resurfaced_ids: frozenset[str] | set[str],
) -> list[dict[str, Any]]:
    """Build UI rows without assuming all session objects already carry SLA fields."""

    rows: list[dict[str, Any]] = []
    for ticket in tickets:
        ticket_id = str(ticket.get("id"))
        signal_id = str(ticket.get("signal_id"))
        sla = sla_by_ticket_id.get(ticket_id)
        if sla is None:
            sla = derive_ticket_sla(ticket)
        signal = signals_by_id.get(signal_id, {})
        status = str(ticket.get("status") or "")
        rows.append(
            {
                "Priorità": str(ticket.get("priority") or "").upper(),
                "Stato": _STATUS_LABELS.get(status, status or "N/D"),
                "Titolo": ticket.get("title") or ticket_id,
                "Owner": ticket.get("owner") or "Non assegnato",
                "SLA": _SLA_LABELS[str(sla["state"])],
                "Tempo SLA": _sla_remaining_label(sla),
                "Deadline SLA": format_local_time(sla["due_at"]),
                "Aggiornato": format_local_time(ticket.get("updated_at")),
                "Riemerso": "Sì" if ticket_id in resurfaced_ids else "No",
                "Tipo segnale": _SIGNAL_TYPE_LABELS.get(
                    str(signal.get("signal_type") or ""),
                    "N/D",
                ),
            }
        )
    return rows


def _signal_sort_key(signal: Mapping[str, Any]) -> tuple[int, int]:
    parsed = pd.to_datetime(signal.get("last_observed_at"), utc=True, errors="coerce")
    timestamp_order = 2**63 - 1 if pd.isna(parsed) else -int(parsed.value)
    return _SEVERITY_ORDER.get(str(signal.get("severity")), 99), timestamp_order


def _requires_transition_note(status: str) -> bool:
    return status in _NOTE_REQUIRED_STATUSES


def _safe_file_stem(value: object) -> str:
    stem = "".join(
        character if character.isalnum() or character in {"-", "_", "."} else "-"
        for character in str(value)
    )
    return stem.strip("-._") or "dtlab"


def _current_evidence_record_id(
    snapshot: Mapping[str, Any],
    signal: Mapping[str, Any],
) -> str | None:
    """Return a current record only when its identity is explicitly equal."""

    collection = _EVIDENCE_COLLECTIONS.get(str(signal.get("signal_type")))
    payload = signal.get("payload")
    if collection is None or not isinstance(payload, Mapping):
        return None
    record_id = payload.get("id")
    records = snapshot.get(collection)
    if not isinstance(record_id, str) or not isinstance(records, list):
        return None
    if any(isinstance(record, Mapping) and record.get("id") == record_id for record in records):
        return record_id
    return None


def _source_owned_signal_evidence_json(signal: Mapping[str, Any]) -> bytes:
    """Export one source-owned signal exactly as stored, without inference."""

    signal_type = str(signal.get("signal_type") or "")
    if signal_type not in _SOURCE_OWNED_JSON_TYPES:
        raise ValueError("Export JSON source-owned non disponibile per questo segnale")
    correlation_policy = (
        "host_sensor_only_no_cisco_attribution"
        if signal_type == "host_modbus_write"
        else "source_owned_only_no_classic_inference"
    )
    evidence = {
        "export_type": "dtlab_source_owned_signal_evidence",
        "signal_type": signal_type,
        "signal_id": signal.get("id"),
        "snapshot_sha256": signal.get("snapshot_sha256"),
        "source_id": signal.get("source_id"),
        "source_record_id": signal.get("source_record_id"),
        "asset_ids": signal.get("asset_ids", []),
        "occurred_at": signal.get("occurred_at"),
        "observed_at": signal.get("last_observed_at"),
        "evidence": signal.get("evidence", {}),
        "payload": signal.get("payload", {}),
        "correlation_policy": correlation_policy,
    }
    return (
        json.dumps(evidence, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def _ensure_playbook_tasks(
    store: TicketStore,
    *,
    ticket_id: str,
    signal_type: str,
    actor: str,
    owner: str | None,
) -> int:
    """Atomically add only missing manual-first playbook steps."""

    return store.ensure_tasks(
        ticket_id,
        actor=actor,
        tasks=(
            {"title": task.title, "description": task.description}
            for task in tasks_for_signal(signal_type)
        ),
        owner=owner,
    )


def _signal_label(signal: Mapping[str, Any]) -> str:
    signal_type = _SIGNAL_TYPE_LABELS.get(
        str(signal.get("signal_type")), str(signal.get("signal_type") or "Segnale")
    )
    severity = _SEVERITY_LABELS.get(
        str(signal.get("severity")), str(signal.get("severity") or "N/D")
    )
    return f"{severity} · {signal_type} · {signal.get('title') or signal.get('id')}"


def _ticket_label(ticket: Mapping[str, Any], *, now: datetime | None = None) -> str:
    status = _STATUS_LABELS.get(str(ticket.get("status")), str(ticket.get("status")))
    priority = str(ticket.get("priority") or "").upper()
    sla = derive_ticket_sla(ticket, now=now)
    return (
        f"{priority} · {_SLA_LABELS[sla['state']]} · {status} · "
        f"{ticket.get('title') or ticket.get('id')}"
    )


def _render_ingest_caption(result: SnapshotIngestResult) -> None:
    if result.signals_created or result.occurrences_created:
        st.success(
            f"Snapshot verificato acquisito: {result.signals_created} nuovi segnali, "
            f"{result.occurrences_created} nuove osservazioni snapshot."
        )
    else:
        st.caption(
            f"Inbox allineata allo snapshot {result.snapshot_sha256[:12]} · deduplicazione attiva."
        )


def _render_signal_evidence_download(
    context: DashboardContext,
    signal: Mapping[str, Any],
    *,
    key_suffix: str,
) -> None:
    signal_type = str(signal.get("signal_type"))
    record_id = _current_evidence_record_id(context.canonical_snapshot, signal)
    if signal_type in _SOURCE_OWNED_JSON_TYPES:
        is_host_detection = signal_type == "host_modbus_write"
        st.caption(
            "Evidence JSON host-side: conserva richiesta, regole, registri e provenienza "
            "senza attribuirli a Cisco Cyber Vision."
            if is_host_detection
            else "Evidence JSON source-owned: conserva il profilo Cisco New UI esplicito "
            "senza ricostruire collegamenti con Device Classic."
        )
        st.download_button(
            "Scarica evidence JSON host PLC"
            if is_host_detection
            else "Scarica evidence JSON New UI",
            data=_source_owned_signal_evidence_json(signal),
            file_name=f"{_safe_file_stem(signal.get('id'))}-evidence.json",
            mime="application/json",
            icon=":material/download:",
            use_container_width=True,
            key=f"signal-evidence-{key_suffix}",
        )
        return
    if signal_type not in _EVIDENCE_COLLECTIONS:
        st.caption(
            "L'evidence bundle ZIP dedicato è disponibile per eventi e finding. "
            "Le altre tipologie restano integralmente nel JSON del ticket."
        )
        return
    if record_id is None:
        st.info(
            "Il record sorgente non è presente nello snapshot corrente: nessuna "
            "correlazione viene ricostruita per inferenza. Il ticket conserva le "
            "osservazioni snapshot storiche."
        )
        return
    try:
        bundle = build_signal_evidence_bundle(
            context.canonical_snapshot,
            signal_type=signal_type,
            signal_id=record_id,
            mode="technical",
        )
    except ValueError as exc:
        st.warning(f"Evidence bundle non disponibile: {exc}")
        return
    st.download_button(
        "Scarica evidence bundle",
        data=bundle,
        file_name=f"{_safe_file_stem(record_id)}-evidence.zip",
        mime="application/zip",
        icon=":material/download:",
        use_container_width=True,
        key=f"signal-evidence-{key_suffix}",
    )


def _render_signal_detail(
    context: DashboardContext,
    store: TicketStore,
    signal: Mapping[str, Any],
    ticket_by_signal: Mapping[str, Mapping[str, Any]],
    operator: str,
) -> None:
    st.subheader("Dettaglio segnale")
    first, second = st.columns([1.35, 0.65])
    with first:
        st.markdown(f"#### {signal.get('title') or 'Segnale senza titolo'}")
        st.write(signal.get("description") or "Nessuna descrizione restituita.")
        if str(signal.get("signal_type")) == "host_modbus_write":
            payload = signal.get("payload")
            host_payload = payload if isinstance(payload, Mapping) else {}
            raw_event = host_payload.get("event")
            event = raw_event if isinstance(raw_event, Mapping) else host_payload
            raw_evidence = event.get("evidence")
            event_evidence = raw_evidence if isinstance(raw_evidence, Mapping) else {}
            raw_source = event.get("source")
            event_source = raw_source if isinstance(raw_source, Mapping) else {}
            raw_destination = event.get("destination")
            event_destination = raw_destination if isinstance(raw_destination, Mapping) else {}
            raw_modbus = event.get("modbus")
            event_modbus = raw_modbus if isinstance(raw_modbus, Mapping) else {}
            truth = str(
                event_evidence.get("truth")
                or event.get("truth")
                or event.get("observation_mode")
                or ""
            )
            source_ip = str(event_source.get("ip") or event.get("source_ip") or "N/D")
            destination_ip = str(
                event_destination.get("ip") or event.get("destination_ip") or "N/D"
            )
            registers = (
                event_modbus.get("writes") or event.get("registers") or event.get("writes") or []
            )
            st.error(
                "Rilevazione endpoint PLC: comportamento Modbus da verificare. "
                "Questa evidenza non è stata restituita da Cisco Cyber Vision."
            )
            st.caption(
                f"Percorso osservato {source_ip} → {destination_ip} · "
                f"verità {truth or 'host-side'} · dettagli registri {registers or 'N/D'}"
            )
        if not signal_is_actionable(signal):
            st.warning(
                "Record conservato come evidenza storica o escluso dai KPI operativi; "
                "non entra nella coda predefinita."
            )
        if signal.get("recommended_action"):
            st.info(f"Azione raccomandata dalla sorgente: {signal['recommended_action']}")
        st.caption(
            "Asset correlati esplicitamente: "
            + (", ".join(signal.get("asset_ids", [])) or "nessuno dichiarato")
        )
    with second:
        st.metric("Snapshot osservati", int(signal.get("occurrence_count") or 0))
        st.markdown(
            f"**Ultima osservazione**  \n{format_local_time(signal.get('last_observed_at'))}"
        )
        st.markdown(
            f"**Fonte**  \n{signal.get('source_id') or 'N/D'}  \n"
            f"**Record fonte**  \n{signal.get('source_record_id') or 'N/D'}"
        )

    existing_ticket = ticket_by_signal.get(str(signal.get("id")))
    action_tab, evidence_tab, payload_tab = st.tabs(
        ["Presa in carico", "Evidenze", "Record sorgente"]
    )
    with action_tab:
        st.markdown("#### Decisione esplicita")
        if existing_ticket:
            resurfaced = signal_needs_review(signal, existing_ticket)
            if resurfaced:
                st.warning(
                    "Il segnale è stato osservato dopo la decisione del ticket: richiede "
                    "una nuova valutazione manuale."
                )
                if st.button(
                    "Riapri ticket in analisi",
                    key=f"reopen-ticket-{signal['id']}",
                    disabled=not operator,
                    use_container_width=True,
                    type="primary",
                ):
                    try:
                        store.transition_ticket(
                            str(existing_ticket["id"]),
                            "investigating",
                            actor=operator,
                            note="Segnale osservato dopo la precedente decisione.",
                        )
                    except TicketStoreError as exc:
                        st.error(f"Ticket non riaperto: {exc}")
                    else:
                        st.rerun()
            else:
                st.success(
                    f"Ticket già creato: {existing_ticket['id']} · "
                    f"{_STATUS_LABELS.get(existing_ticket['status'], existing_ticket['status'])}."
                )
            existing_tasks = store.export_ticket(str(existing_ticket["id"]))["tasks"]
            if not existing_tasks:
                st.warning("Il ticket non contiene ancora la checklist operativa.")
                if st.button(
                    "Inizializza checklist manual-first",
                    key=f"repair-playbook-{signal['id']}",
                    disabled=not operator,
                    use_container_width=True,
                ):
                    try:
                        _ensure_playbook_tasks(
                            store,
                            ticket_id=str(existing_ticket["id"]),
                            signal_type=str(signal["signal_type"]),
                            actor=operator,
                            owner=existing_ticket.get("owner"),
                        )
                    except TicketStoreError as exc:
                        st.error(f"Checklist non inizializzata: {exc}")
                    else:
                        st.rerun()
        else:
            default_priority = _priority_for_severity(signal.get("severity"))
            with st.form(f"create-ticket-{signal['id']}"):
                form_columns = st.columns(2)
                with form_columns[0]:
                    priority = st.selectbox(
                        "Priorità iniziale",
                        sorted(TICKET_PRIORITIES),
                        index=sorted(TICKET_PRIORITIES).index(default_priority),
                        format_func=str.upper,
                    )
                with form_columns[1]:
                    owner = st.text_input(
                        "Owner iniziale (opzionale)",
                        placeholder="Team o persona responsabile",
                    )
                st.caption(
                    "La creazione aggiunge una checklist manual-first. Nessuna remediation, "
                    "modifica a PLC, VM o rete viene eseguita automaticamente."
                )
                submitted = st.form_submit_button(
                    "Crea ticket e checklist",
                    type="primary",
                    disabled=not operator,
                    use_container_width=True,
                )
            if not operator:
                st.warning(
                    "Inserire un'etichetta operatore per registrare l'azione nell'audit "
                    "applicativo. L'etichetta non è un'identità autenticata."
                )
            if submitted:
                try:
                    _ticket, _tasks_added = store.create_ticket_with_tasks(
                        str(signal["id"]),
                        actor=operator,
                        tasks=(
                            {"title": task.title, "description": task.description}
                            for task in tasks_for_signal(str(signal["signal_type"]))
                        ),
                        priority=priority,
                        owner=owner or None,
                    )
                except TicketStoreError as exc:
                    st.error(f"Ticket non creato: {exc}")
                else:
                    st.success("Ticket creato e checklist operativa inizializzata.")
                    st.rerun()
    with evidence_tab:
        st.json(
            {
                "snapshot_sha256": signal.get("snapshot_sha256"),
                "source_id": signal.get("source_id"),
                "source_record_id": signal.get("source_record_id"),
                "asset_ids": signal.get("asset_ids", []),
                "evidence": signal.get("evidence", {}),
            },
            expanded=False,
        )
        _render_signal_evidence_download(
            context,
            signal,
            key_suffix=_safe_file_stem(signal.get("id")),
        )
    with payload_tab:
        st.json(signal.get("payload", {}), expanded=False)


def render_signals(context: DashboardContext) -> None:
    """Render the deduplicated operational inbox."""

    page_intro(
        context,
        "Operazioni",
        "Segnalazioni",
        "Inbox deduplicata di eventi, finding, differenze baseline, vulnerabilità e "
        "rilevazioni host PLC. Le detection PLC ad alta severità aprono un ticket di "
        "triage automatico; ogni remediation resta una decisione esplicita dell'operatore.",
    )
    loaded = _load_operational_store(context)
    if loaded is None:
        return
    store, ingest_result = loaded
    operator = _operator_value(store)
    _render_ingest_caption(ingest_result)

    signals = store.list_signals(limit=1000)
    tickets = store.list_tickets(limit=1000)
    signals_truncated = len(signals) == 1000
    tickets_truncated = len(tickets) == 1000
    if signals_truncated or tickets_truncated:
        st.warning(
            "Vista operativa limitata ai 1.000 record più recenti per raccolta; i conteggi "
            "con prefisso ≥ sono limiti inferiori. Usare ricerca/esportazione per il dettaglio."
        )
    ticket_by_signal = {str(ticket["signal_id"]): ticket for ticket in tickets}
    actionable = [signal for signal in signals if signal_is_actionable(signal)]
    unassigned = [
        signal
        for signal in actionable
        if signal_needs_review(signal, ticket_by_signal.get(str(signal["id"])))
    ]
    review_signal_ids = frozenset(str(signal["id"]) for signal in unassigned)
    handled_signal_ids = frozenset(
        str(signal["id"]) for signal in actionable if signal["id"] not in review_signal_ids
    )
    recurring = sum(int(signal.get("occurrence_count") or 0) > 1 for signal in actionable)
    priority_signals = sum(signal.get("severity") in {"critical", "high"} for signal in unassigned)
    metric_columns = st.columns(4)
    for column, label, value, meta in (
        (
            metric_columns[0],
            "Segnali",
            _bounded_count(len(actionable), truncated=signals_truncated),
            "Azionabili e deduplicati",
        ),
        (
            metric_columns[1],
            "Da valutare",
            _bounded_count(len(unassigned), truncated=signals_truncated or tickets_truncated),
            "Senza ticket o riemersi",
        ),
        (
            metric_columns[2],
            "Critici / alti",
            _bounded_count(priority_signals, truncated=signals_truncated or tickets_truncated),
            "Ancora da valutare",
        ),
        (
            metric_columns[3],
            "Riosservati",
            _bounded_count(recurring, truncated=signals_truncated),
            "Presenti in più snapshot",
        ),
    ):
        with column:
            metric_card(label, value, meta)

    st.subheader("Coda operativa")
    filter_columns = st.columns([1.5, 1, 1, 0.65, 0.65])
    with filter_columns[0]:
        search = st.text_input(
            "Cerca",
            placeholder="Titolo, descrizione, record, asset…",
            key="signals-search",
        )
    available_types = sorted({str(signal["signal_type"]) for signal in signals})
    with filter_columns[1]:
        selected_types = st.multiselect(
            "Tipo",
            available_types,
            format_func=lambda value: _SIGNAL_TYPE_LABELS.get(value, value),
            key="signals-types",
        )
    available_severities = sorted(
        {str(signal["severity"]) for signal in signals},
        key=lambda value: _SEVERITY_ORDER.get(value, 99),
    )
    with filter_columns[2]:
        selected_severities = st.multiselect(
            "Severità",
            available_severities,
            format_func=lambda value: _SEVERITY_LABELS.get(value, value),
            key="signals-severities",
        )
    with filter_columns[3]:
        only_without_ticket = st.toggle(
            "Solo da valutare",
            value=True,
            key="signals-without-ticket",
        )
    with filter_columns[4]:
        include_historical = st.toggle(
            "Includi storici",
            value=False,
            key="signals-include-historical",
            help="Mostra finding accettati, risolti o esclusi dai KPI senza perderne l'evidenza.",
        )

    filtered = _filter_signals(
        signals,
        search=search,
        signal_types=selected_types,
        severities=selected_severities,
        without_ticket=only_without_ticket,
        ticket_signal_ids=handled_signal_ids,
        include_historical=include_historical,
    )
    filtered.sort(key=_signal_sort_key)
    if not filtered:
        empty_state(
            "Nessun segnale nei filtri",
            "Modificare i filtri oppure mostrare anche i segnali già presi in carico.",
        )
        return
    st.dataframe(
        pd.DataFrame(
            {
                "Severità": _SEVERITY_LABELS.get(signal["severity"], signal["severity"]),
                "Tipo": _SIGNAL_TYPE_LABELS.get(signal["signal_type"], signal["signal_type"]),
                "Titolo": signal["title"],
                "Ultima osservazione": format_local_time(signal["last_observed_at"]),
                "Snapshot osservati": signal["occurrence_count"],
                "Asset espliciti": len(signal["asset_ids"]),
                "Ambito": "Operativo" if signal_is_actionable(signal) else "Storico",
                "Ticket": (
                    "Riemerso"
                    if signal["id"] in review_signal_ids and signal["id"] in ticket_by_signal
                    else "Aperto"
                    if signal["id"] in ticket_by_signal
                    else "Da valutare"
                ),
            }
            for signal in filtered
        ),
        use_container_width=True,
        hide_index=True,
        height=min(520, 76 + 36 * len(filtered)),
    )
    signal_options = [signal["id"] for signal in filtered]
    requested_signal = _query_parameter("signal")
    selected_signal_id = st.selectbox(
        "Apri segnalazione",
        signal_options,
        index=(signal_options.index(requested_signal) if requested_signal in signal_options else 0),
        format_func=lambda signal_id: _signal_label(
            next(signal for signal in filtered if signal["id"] == signal_id)
        ),
        key="selected-signal",
    )
    selected_signal = next(signal for signal in filtered if signal["id"] == selected_signal_id)
    _render_signal_detail(context, store, selected_signal, ticket_by_signal, operator)


def _render_ticket_governance(
    store: TicketStore,
    ticket_document: Mapping[str, Any],
    operator: str,
) -> None:
    ticket = ticket_document["ticket"]
    st.markdown("#### Assegnazione e priorità")
    st.caption(
        "P1–P4 è la convenzione ITSM adottata e formalizzata da DTLab, non una "
        "classificazione proprietaria Cisco. "
        f"Policy SLA DTLab: P1 {SLA_POLICY_HOURS['p1']} h · P2 {SLA_POLICY_HOURS['p2']} h · "
        f"P3 {SLA_POLICY_HOURS['p3']} h · P4 {SLA_POLICY_HOURS['p4']} h. La deadline è "
        "ancorata alla creazione; un cambio priorità la ricalcola e registra valori "
        "precedenti e nuovi nell'audit."
    )
    with st.form(f"governance-{ticket['id']}"):
        columns = st.columns(2)
        with columns[0]:
            owner = st.text_input(
                "Owner",
                value=ticket.get("owner") or "",
                placeholder="Team o persona responsabile",
            )
        with columns[1]:
            priorities = sorted(TICKET_PRIORITIES)
            priority = st.selectbox(
                "Priorità",
                priorities,
                index=priorities.index(ticket["priority"]),
                format_func=str.upper,
            )
        submitted = st.form_submit_button(
            "Salva assegnazione",
            disabled=not operator,
            use_container_width=True,
        )
    if submitted:
        try:
            store.update_ticket_governance(
                ticket["id"],
                owner=owner or None,
                priority=priority,
                actor=operator,
            )
        except TicketStoreError as exc:
            st.error(f"Aggiornamento non salvato: {exc}")
        else:
            st.success("Assegnazione aggiornata e registrata nell'audit.")
            st.rerun()

    transitions = _ALLOWED_TRANSITIONS[str(ticket["status"])]
    st.markdown("#### Cambia stato")
    with st.form(f"transition-{ticket['id']}"):
        target = st.selectbox(
            "Nuovo stato",
            list(transitions),
            format_func=lambda value: _STATUS_LABELS[value],
        )
        note = st.text_area(
            "Nota decisionale",
            placeholder="Motivazione, approvazione OT, verifica o condizione di riapertura",
            help="Obbligatoria per risoluzione, falso positivo, rischio accettato e soppressione.",
        )
        transition_submitted = st.form_submit_button(
            "Registra transizione",
            disabled=not operator,
            use_container_width=True,
        )
    if transition_submitted:
        if _requires_transition_note(target) and not note.strip():
            st.error("Inserire una nota decisionale per questo stato.")
        else:
            try:
                store.transition_ticket(ticket["id"], target, actor=operator, note=note or None)
            except TicketStoreError as exc:
                st.error(f"Transizione non registrata: {exc}")
            else:
                st.success("Stato aggiornato e registrato nell'audit append-only.")
                st.rerun()


def _render_ticket_tasks(
    store: TicketStore,
    ticket_document: Mapping[str, Any],
    operator: str,
) -> None:
    ticket = ticket_document["ticket"]
    tasks = ticket_document["tasks"]
    st.caption(
        "Checklist manual-first: completare una voce registra il lavoro, ma non esegue "
        "azioni automatiche su PLC, rete, Cisco Cyber Vision o VMware."
    )
    if not tasks:
        st.info("Nessuna attività presente. Aggiungere una voce operativa manuale.")
    task_statuses = sorted(TASK_STATUSES)
    for task in tasks:
        with st.expander(
            f"{task['position']}. {task['title']} · "
            f"{_TASK_STATUS_LABELS.get(task['status'], task['status'])}",
            expanded=task["status"] == "pending",
        ):
            st.write(task.get("description") or "Nessuna descrizione.")
            st.caption(
                f"Owner: {task.get('owner') or 'non assegnato'} · "
                f"Scadenza: {format_local_time(task.get('due_at'))}"
            )
            with st.form(f"task-status-{task['id']}"):
                status = st.selectbox(
                    "Esito attività",
                    task_statuses,
                    index=task_statuses.index(task["status"]),
                    format_func=lambda value: _TASK_STATUS_LABELS[value],
                    key=f"task-status-value-{task['id']}",
                )
                submitted = st.form_submit_button(
                    "Aggiorna attività",
                    disabled=not operator,
                    use_container_width=True,
                )
            if submitted:
                if status == task["status"]:
                    st.info("Selezionare un esito diverso prima di aggiornare l'attività.")
                else:
                    try:
                        store.update_task_status(task["id"], status, actor=operator)
                    except TicketStoreError as exc:
                        st.error(f"Attività non aggiornata: {exc}")
                    else:
                        st.rerun()

    st.markdown("#### Aggiungi attività manuale")
    with st.form(f"add-task-{ticket['id']}"):
        title = st.text_input("Titolo attività", placeholder="Verifica o azione approvata")
        description = st.text_area(
            "Descrizione",
            placeholder="Pre-check, referente OT, rollback ed evidenza attesa",
        )
        columns = st.columns(2)
        with columns[0]:
            owner = st.text_input("Owner attività (opzionale)")
        with columns[1]:
            due_at = st.text_input(
                "Scadenza ISO 8601 (opzionale)", placeholder="2026-08-04T14:00:00+02:00"
            )
        add_submitted = st.form_submit_button(
            "Aggiungi alla checklist",
            disabled=not operator,
            use_container_width=True,
        )
    if add_submitted:
        if not title.strip():
            st.error("Il titolo dell'attività è obbligatorio.")
        else:
            try:
                store.add_task(
                    ticket["id"],
                    actor=operator,
                    title=title,
                    description=description or None,
                    owner=owner or None,
                    due_at=due_at or None,
                )
            except TicketStoreError as exc:
                st.error(f"Attività non aggiunta: {exc}")
            else:
                st.rerun()


def _render_ticket_comments(
    store: TicketStore,
    ticket_document: Mapping[str, Any],
    operator: str,
) -> None:
    comments = ticket_document["comments"]
    if comments:
        for comment in comments:
            st.markdown(f"**{comment['author']}** · {format_local_time(comment['created_at'])}")
            st.write(comment["body"])
            st.divider()
    else:
        st.info("Nessun commento registrato.")
    ticket_id = ticket_document["ticket"]["id"]
    with st.form(f"comment-{ticket_id}"):
        body = st.text_area(
            "Nuovo commento",
            placeholder="Osservazione, decisione, approvazione o risultato della verifica",
        )
        submitted = st.form_submit_button(
            "Registra commento",
            disabled=not operator,
            use_container_width=True,
        )
    if submitted:
        if not body.strip():
            st.error("Il commento non può essere vuoto.")
        else:
            try:
                store.add_comment(ticket_id, author=operator, body=body)
            except TicketStoreError as exc:
                st.error(f"Commento non registrato: {exc}")
            else:
                st.rerun()


def _render_ticket_timeline(ticket_document: Mapping[str, Any]) -> None:
    audit = ticket_document["audit"]
    if not audit:
        st.info("Nessun evento di audit registrato.")
        return
    st.dataframe(
        pd.DataFrame(
            {
                "Sequenza": event["sequence"],
                "Quando": format_local_time(event["occurred_at"]),
                "Operatore": event["actor"],
                "Azione": event["action"],
                "Dettagli": ", ".join(
                    f"{key}={value}" for key, value in event.get("details", {}).items()
                ),
            }
            for event in audit
        ),
        use_container_width=True,
        hide_index=True,
        height=min(520, 76 + 36 * len(audit)),
    )


def _render_ticket_detail(
    context: DashboardContext,
    store: TicketStore,
    ticket_id: str,
    operator: str,
) -> None:
    document = store.export_ticket(ticket_id)
    ticket = document["ticket"]
    signal = document["signal"]
    sla = derive_ticket_sla(ticket)
    st.subheader("Workspace ticket")
    header_columns = st.columns([1.4, 0.6])
    with header_columns[0]:
        st.markdown(f"### {ticket['title']}")
        st.write(ticket["description"])
        st.caption(
            f"{ticket['id']} · Creato da {ticket['created_by']} · "
            f"Aggiornato {format_local_time(ticket['updated_at'])}"
        )
        if str(signal.get("signal_type")) == "host_modbus_write":
            st.error(
                "Origine evidenza: sensore host PLC. Non è un evento Cisco Cyber Vision; "
                "il ticket è stato aperto automaticamente dalla policy di detection."
            )
    with header_columns[1]:
        st.metric("Priorità", ticket["priority"].upper())
        st.markdown(f"**Stato:** {_STATUS_LABELS[ticket['status']]}")
        st.markdown(f"**Owner:** {ticket.get('owner') or 'Non assegnato'}")
        st.markdown(f"**SLA:** {_SLA_LABELS[sla['state']]}")
        st.caption(f"Deadline {format_local_time(sla['due_at'])} · {_sla_remaining_label(sla)}")

    if signal_needs_review(signal, ticket):
        st.warning(
            "Segnale riosservato dopo la decisione: riaprire manualmente il ticket dalla "
            "scheda Governance prima di proseguire."
        )
    if signal.get("recommended_action"):
        st.info(f"Azione raccomandata dalla sorgente: {signal['recommended_action']}")
    st.caption(
        f"Segnale: {_SIGNAL_TYPE_LABELS.get(signal['signal_type'], signal['signal_type'])} · "
        f"{signal['id']} · {signal['occurrence_count']} osservazioni snapshot · "
        "asset espliciti: " + (", ".join(signal.get("asset_ids", [])) or "nessuno dichiarato")
    )

    overview, checklist, comments, evidence, timeline = st.tabs(
        ["Governance", "Checklist", "Commenti", "Evidenze", "Audit"]
    )
    with overview:
        _render_ticket_governance(store, document, operator)
    with checklist:
        _render_ticket_tasks(store, document, operator)
    with comments:
        _render_ticket_comments(store, document, operator)
    with evidence:
        st.caption(
            "Snapshot osservati = numero di cicli che hanno visto la condizione. "
            "La lista seguente conserva solo le versioni complete in cui il contenuto "
            "sorgente è cambiato semanticamente."
        )
        st.json(
            {
                "snapshot_sha256": signal["snapshot_sha256"],
                "source_id": signal.get("source_id"),
                "source_record_id": signal.get("source_record_id"),
                "asset_ids": signal.get("asset_ids", []),
                "occurrences": document["occurrences"],
            },
            expanded=False,
        )
        st.download_button(
            "Scarica ticket JSON",
            data=store.export_ticket_json(ticket_id).encode("utf-8"),
            file_name=f"{_safe_file_stem(ticket_id)}.json",
            mime="application/json",
            icon=":material/download:",
            use_container_width=True,
            key=f"ticket-json-{_safe_file_stem(ticket_id)}",
        )
        _render_signal_evidence_download(
            context,
            signal,
            key_suffix=f"ticket-{_safe_file_stem(ticket_id)}",
        )
    with timeline:
        _render_ticket_timeline(document)


def render_tickets(context: DashboardContext) -> None:
    """Render the persistent ticket register and governed analyst workspace."""

    page_intro(
        context,
        "Operazioni",
        "Ticket e remediation",
        "Registro persistente per assegnazione, SLA operativo, checklist manuali, decisioni "
        "e audit append-only: le evidenze restano separate dallo snapshot immutabile.",
    )
    loaded = _load_operational_store(context)
    if loaded is None:
        return
    store, ingest_result = loaded
    operator = _operator_value(store)
    _render_ingest_caption(ingest_result)

    tickets = store.list_tickets(limit=1000)
    signals = store.list_signals(limit=1000)
    tickets_truncated = len(tickets) == 1000
    signals_truncated = len(signals) == 1000
    if tickets_truncated or signals_truncated:
        st.warning(
            "Registro limitato ai 1.000 record più recenti per raccolta; i conteggi con "
            "prefisso ≥ sono limiti inferiori."
        )
    signals_by_id = {str(signal["id"]): signal for signal in signals}
    active = [ticket for ticket in tickets if ticket["status"] not in _TERMINAL_STATUSES]
    sla_now = datetime.now(UTC)
    sla_by_ticket_id = {
        str(ticket["id"]): derive_ticket_sla(ticket, now=sla_now) for ticket in tickets
    }
    overdue = [
        ticket for ticket in tickets if sla_by_ticket_id[str(ticket["id"])]["state"] == "overdue"
    ]
    due_soon = [
        ticket for ticket in tickets if sla_by_ticket_id[str(ticket["id"])]["state"] == "due_soon"
    ]
    resurfaced_ids = {
        str(ticket["id"])
        for ticket in tickets
        if signal_needs_review(signals_by_id.get(str(ticket["signal_id"]), {}), ticket)
    }
    metric_columns = [*st.columns(4), *st.columns(3)]
    for column, label, value, meta in (
        (
            metric_columns[0],
            "Ticket attivi",
            _bounded_count(len(active), truncated=tickets_truncated),
            "Inclusi risolti da chiudere",
        ),
        (
            metric_columns[1],
            "P1 / P2 · DTLab",
            _bounded_count(
                sum(ticket["priority"] in {"p1", "p2"} for ticket in active),
                truncated=tickets_truncated,
            ),
            "Convenzione ITSM interna",
        ),
        (
            metric_columns[2],
            "Non assegnati",
            _bounded_count(
                sum(not ticket.get("owner") for ticket in active),
                truncated=tickets_truncated,
            ),
            "Richiedono ownership",
        ),
        (
            metric_columns[3],
            "Riemersi",
            _bounded_count(len(resurfaced_ids), truncated=tickets_truncated or signals_truncated),
            "Dopo una decisione",
        ),
        (
            metric_columns[4],
            "SLA scaduti",
            _bounded_count(len(overdue), truncated=tickets_truncated),
            "Richiedono escalation",
        ),
        (
            metric_columns[5],
            "SLA in scadenza",
            _bounded_count(len(due_soon), truncated=tickets_truncated),
            "Ultimo 25% della finestra",
        ),
        (
            metric_columns[6],
            "Chiusi / terminali",
            _bounded_count(len(tickets) - len(active), truncated=tickets_truncated),
            "Decisione tracciata",
        ),
    ):
        with column:
            metric_card(label, value, meta)

    if not tickets:
        empty_state(
            "Nessun ticket creato",
            "Aprire Segnalazioni e prendere in carico esplicitamente un segnale verificato.",
        )
        return

    st.subheader("Registro ticket")
    filter_columns = st.columns([1.5, 1, 0.8, 1, 1])
    with filter_columns[0]:
        search = st.text_input(
            "Cerca",
            placeholder="Titolo, ID, owner, asset…",
            key="tickets-search",
        )
    available_statuses = sorted(
        {str(ticket["status"]) for ticket in tickets}, key=lambda value: _STATUS_LABELS[value]
    )
    with filter_columns[1]:
        selected_statuses = st.multiselect(
            "Stato",
            available_statuses,
            format_func=lambda value: _STATUS_LABELS[value],
            key="tickets-statuses",
        )
    with filter_columns[2]:
        selected_priorities = st.multiselect(
            "Priorità",
            sorted({str(ticket["priority"]) for ticket in tickets}),
            format_func=str.upper,
            key="tickets-priorities",
        )
    available_owners = sorted({str(ticket["owner"]) for ticket in tickets if ticket.get("owner")})
    with filter_columns[3]:
        selected_owners = st.multiselect("Owner", available_owners, key="tickets-owners")
    available_sla_states = sorted(
        {str(sla["state"]) for sla in sla_by_ticket_id.values()},
        key=lambda state: list(_SLA_LABELS).index(state),
    )
    with filter_columns[4]:
        selected_sla_states = st.multiselect(
            "SLA",
            available_sla_states,
            format_func=lambda state: _SLA_LABELS[state],
            key="tickets-sla-states",
        )
    filtered = _filter_tickets(
        tickets,
        search=search,
        statuses=selected_statuses,
        priorities=selected_priorities,
        owners=selected_owners,
        sla_states=selected_sla_states,
        signals_by_id=signals_by_id,
        now=sla_now,
    )
    if not filtered:
        empty_state("Nessun ticket nei filtri", "Modificare ricerca o filtri operativi.")
        return
    st.download_button(
        "Scarica registro filtrato CSV",
        data=build_ticket_register_csv(
            filtered,
            signals_by_id=signals_by_id,
            evaluated_at=sla_now,
        ),
        file_name="registro-ticket-sla.csv",
        mime="text/csv",
        icon=":material/download:",
        key="tickets-register-csv",
    )
    st.dataframe(
        pd.DataFrame(
            _ticket_register_rows(
                filtered,
                sla_by_ticket_id=sla_by_ticket_id,
                signals_by_id=signals_by_id,
                resurfaced_ids=resurfaced_ids,
            )
        ),
        use_container_width=True,
        hide_index=True,
        height=min(520, 76 + 36 * len(filtered)),
    )
    ticket_options = [ticket["id"] for ticket in filtered]
    requested_ticket = _query_parameter("ticket")
    selected_ticket_id = st.selectbox(
        "Apri ticket",
        ticket_options,
        index=(ticket_options.index(requested_ticket) if requested_ticket in ticket_options else 0),
        format_func=lambda ticket_id: _ticket_label(
            next(ticket for ticket in filtered if ticket["id"] == ticket_id),
            now=sla_now,
        ),
        key="selected-ticket",
    )
    _render_ticket_detail(context, store, selected_ticket_id, operator)


assert set(_ALLOWED_TRANSITIONS) == set(TICKET_STATUSES)
