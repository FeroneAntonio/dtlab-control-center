"""Monitoraggio pages: command center, topology, assets, and flows."""

from __future__ import annotations

import json
import os
import sqlite3
from collections import Counter
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from dtlab.services.exports import build_asset_profile_json, build_export_bundle
from dtlab.services.host_ot_status import load_sensor_statuses, sensor_coverage
from dtlab.services.ticket_store import TicketStoreError
from dtlab.ui.components import (
    baseline_detection_banner,
    empty_state,
    format_age,
    format_local_time,
    metric_card,
    page_intro,
    safe,
    source_status,
    truth_badge,
)
from dtlab.ui.context import DashboardContext
from dtlab.ui.detection_readiness import build_detection_readiness
from dtlab.ui.operational_index import asset_workflow_records, build_operational_index
from dtlab.ui.table_tools import render_filterable_table
from dtlab.ui.topology import (
    flow_topology,
    integrated_topology,
    security_topology_summary,
    verified_identity_link_ids,
    vmware_topology,
)
from dtlab.ui.views.operations import sync_ticket_store

_BAND_LABEL = {"low": "Basso", "medium": "Medio", "high": "Alto"}
_DIRECTION_LABEL = {
    "left_to_right": "Sinistra → destra",
    "right_to_left": "Destra → sinistra",
    "undetermined": "Non determinata",
    "unknown": "Sconosciuta",
}
_SEVERITY_RANK = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
    "unknown": 5,
}
_SEVERITY_LABEL = {
    "critical": "Critico",
    "high": "Alto",
    "medium": "Medio",
    "low": "Basso",
    "info": "Informativo",
    "unknown": "Da classificare",
}
_OPERATIONAL_SENSOR_STATES = frozenset({"active", "online", "operational", "running"})
_SIGNAL_TYPE_LABEL = {
    "event": "Evento Cisco",
    "finding": "Finding DTLab",
    "baseline_difference": "Differenza baseline",
    "vulnerability": "Vulnerabilità",
    "new_ui_alert": "Alert Cisco New UI",
    "new_ui_vulnerability": "Vulnerabilità Cisco New UI",
    "host_modbus_write": "Rilevazione host PLC",
}
_SIGNAL_ACTION = {
    "event": "Correlare asset, flow e baseline nello stesso intervallo temporale.",
    "finding": "Verificare il finding con il referente operativo e documentare l'esito.",
    "baseline_difference": "Verificare la differenza nella baseline Cisco prima di classificarla.",
    "vulnerability": "Valutare la soluzione Cisco e l'impatto sull'asset OT.",
    "new_ui_alert": "Aprire l'alert New UI e verificare gli asset esplicitamente associati.",
    "new_ui_vulnerability": "Verificare l'associazione New UI e la mitigazione applicabile.",
    "host_modbus_write": (
        "Verificare registri e autorizzazione OT nel ticket creato dalla policy host-side."
    ),
}
_TICKET_STATUS_LABEL = {
    "new": "Nuovo",
    "acknowledged": "Preso in carico",
    "investigating": "In analisi",
    "remediating": "In remediation",
    "waiting_ot": "In attesa OT",
    "resolved": "Risolto da chiudere",
    "closed": "Chiuso",
    "false_positive": "Falso positivo",
    "accepted_risk": "Rischio accettato",
    "suppressed": "Soppresso",
    "da_valutare": "Da valutare",
}
_SLA_LABEL = {
    "on_time": "In tempo",
    "due_soon": "In scadenza",
    "overdue": "Scaduto",
    "stopped": "Fermato",
}
_TOPOLOGY_CHART_CONFIG = {
    "displayModeBar": True,
    "displaylogo": False,
    "responsive": True,
    "scrollZoom": False,
    "modeBarButtonsToRemove": ["select2d", "lasso2d", "toImage"],
}


def _cybervision_window(context: DashboardContext) -> str:
    source = context.cybervision_source or {}
    window = source.get("details", {}).get("collection_window", {})
    start = format_local_time(window.get("from"))
    end = format_local_time(window.get("to"))
    return f"{start} → {end}"


def _source_table(context: DashboardContext) -> list[dict[str, Any]]:
    return [
        {
            "Sorgente": source["label"],
            "Stato": source_status(source),
            "Versione": source["version"] or "—",
            "Ultimo successo": format_local_time(source["last_success_at"]),
            "Record": sum(source["record_counts"].values()),
            "Verità": truth_badge(source),
        }
        for source in context.snapshot["sources"]
        if source["type"]
        in {
            "vmware_esxi",
            "cisco_cyber_vision",
            "cisco_cyber_vision_new_ui",
            "other",
        }
    ]


def _priority_signals(snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    """Build a truthful, read-only queue from source records already in the snapshot."""

    assets = {asset["id"]: asset["name"] for asset in snapshot.get("assets", [])}
    signals: list[dict[str, Any]] = []

    def add(
        *,
        signal_id: str,
        kind: str,
        title: str,
        severity: str,
        detail: str,
        action: str,
        observed_at: str | None,
    ) -> None:
        normalized_severity = str(severity or "unknown").lower()
        if normalized_severity not in _SEVERITY_RANK:
            normalized_severity = "unknown"
        parsed = pd.to_datetime(observed_at, utc=True, errors="coerce")
        timestamp_order = -1 if pd.isna(parsed) else int(parsed.value)
        signals.append(
            {
                "id": signal_id,
                "kind": kind,
                "title": title,
                "severity": normalized_severity,
                "severity_label": _SEVERITY_LABEL[normalized_severity],
                "detail": detail,
                "action": action,
                "observed_at": observed_at,
                "_priority_rank": _SEVERITY_RANK[normalized_severity],
                "_timestamp_order": timestamp_order,
            }
        )

    for event in snapshot.get("events", []):
        linked_assets = [
            assets[asset_id] for asset_id in event.get("asset_ids", []) if asset_id in assets
        ]
        context = " · ".join(
            value
            for value in (
                event.get("category"),
                event.get("center_label") or event.get("center_id"),
                ", ".join(linked_assets) if linked_assets else None,
                format_local_time(event.get("occurred_at")),
            )
            if value
        )
        add(
            signal_id=str(event["id"]),
            kind="Evento Cisco",
            title=str(event.get("title") or "Evento Cyber Vision"),
            severity=str(event.get("severity") or "unknown"),
            detail=context,
            action="Aprire l'evento e correlare asset, flow e baseline nello stesso intervallo.",
            observed_at=event.get("occurred_at"),
        )

    for finding in snapshot.get("findings", []):
        if finding.get("exclude_from_operational_kpis") or finding.get("status") in {
            "accepted",
            "resolved",
        }:
            continue
        add(
            signal_id=str(finding["id"]),
            kind="Finding ambiente",
            title=str(finding.get("title") or "Finding ambiente"),
            severity=str(finding.get("severity") or "unknown"),
            detail=" · ".join(
                value
                for value in (
                    finding.get("description"),
                    format_local_time(finding.get("last_detected_at")),
                )
                if value
            ),
            action=str(
                finding.get("recommended_action")
                or "Verificare il finding con il referente operativo."
            ),
            observed_at=finding.get("last_detected_at"),
        )

    for difference in snapshot.get("baseline_differences", []):
        linked_assets = [
            assets[asset_id] for asset_id in difference.get("asset_ids", []) if asset_id in assets
        ]
        add(
            signal_id=str(difference["id"]),
            kind="Differenza baseline",
            title=str(difference.get("description") or difference.get("difference_type")),
            severity="medium",
            detail=" · ".join(
                value
                for value in (
                    difference.get("difference_type"),
                    ", ".join(linked_assets) if linked_assets else None,
                    format_local_time(difference.get("detected_at")),
                )
                if value
            ),
            action="Verificare la differenza nella baseline Cisco prima di classificarla.",
            observed_at=difference.get("detected_at"),
        )

    for vulnerability in snapshot.get("vulnerabilities", []):
        asset_name = assets.get(vulnerability.get("asset_id"), "Asset non risolto")
        cvss = vulnerability.get("cvss_score")
        detail_parts = [asset_name]
        if vulnerability.get("external_id"):
            detail_parts.append(str(vulnerability["external_id"]))
        if cvss is not None:
            detail_parts.append(f"CVSS {cvss:g}")
        solution = vulnerability.get("details", {}).get("solution")
        add(
            signal_id=str(vulnerability["id"]),
            kind="Vulnerabilità associata",
            title=str(vulnerability.get("title") or "Vulnerabilità Cyber Vision"),
            severity=str(vulnerability.get("severity") or "unknown"),
            detail=" · ".join(detail_parts),
            action=str(solution or "Valutare la soluzione Cisco e l'impatto sull'asset OT."),
            observed_at=vulnerability.get("published_at"),
        )

    signals.sort(
        key=lambda item: (
            item["_priority_rank"],
            -item["_timestamp_order"],
            item["kind"],
            item["id"],
        )
    )
    for signal in signals:
        signal.pop("_priority_rank")
        signal.pop("_timestamp_order")
    return signals


def _render_live_strip(context: DashboardContext) -> None:
    snapshot = context.snapshot
    state = context.effective_state
    state_label = {
        "fresh": "Live",
        "partial": "Parziale",
        "stale": "Obsoleto",
        "offline": "Offline",
        "failed": "Errore",
    }.get(state, state)
    window = _cybervision_window(context)
    if window == "— → —":
        window = "N/D"
    st.markdown(
        "<section class='dt-live-strip' aria-label='Stato live del cockpit'>"
        f"<div class='dt-live-state {safe(state)}'><span class='dt-live-pulse'></span>"
        f"<span><b>{safe(state_label)}</b><small>Snapshot verificato</small></span></div>"
        "<div class='dt-live-item'><small>Freschezza</small>"
        f"<b>{safe(format_age(context.age_seconds))}</b></div>"
        "<div class='dt-live-item'><small>Finestra Cisco</small>"
        f"<b>{safe(window)}</b></div>"
        "<div class='dt-live-item'><small>Pubblicazione</small>"
        f"<b>{safe(snapshot['sync']['publication_mode'])}</b></div>"
        "</section>",
        unsafe_allow_html=True,
    )


def _render_cockpit_kpis(
    context: DashboardContext,
    highest: dict[str, Any] | None,
    asset_by_id: dict[str, dict[str, Any]],
    workflow: dict[str, int] | None,
) -> None:
    snapshot = context.snapshot
    asset_count: Any = (
        len(snapshot["assets"]) if context.cybervision_capability_available("devices") else "N/D"
    )
    event_count: Any = (
        len(snapshot["events"])
        if context.cybervision_capability_available("event_severities")
        else "N/D"
    )
    score_value = f"{highest['score']:g}/100" if highest else "N/D"
    score_meta = (
        f"{asset_by_id.get(highest['asset_id'], {}).get('name', 'Asset')} · "
        f"{_BAND_LABEL.get(highest['band'], highest['band'])}"
        if highest
        else "Nessuno score Cisco acquisito"
    )
    workflow_prefix = "≥" if workflow is not None and workflow.get("truncated") else ""
    cards = (
        (
            "Da valutare",
            (f"{workflow_prefix}{workflow['unassigned']}" if workflow is not None else "N/D"),
            (
                f"{workflow['without_ticket']} senza ticket · {workflow['resurfaced']} riemersi"
                if workflow is not None
                else "Ticket store non disponibile"
            ),
            "attention",
        ),
        (
            "Ticket attivi",
            f"{workflow_prefix}{workflow['active']}" if workflow is not None else "N/D",
            (
                f"{workflow['unowned']} senza owner"
                if workflow is not None
                else "Ticket store non disponibile"
            ),
            "workflow",
        ),
        (
            "Priorità DTLab P1 / P2",
            (f"{workflow_prefix}{workflow['high_priority']}" if workflow is not None else "N/D"),
            "Convenzione ITSM interna · ticket elevati attivi" if workflow is not None else "N/D",
            "workflow",
        ),
        (
            "SLA critici",
            (f"{workflow_prefix}{workflow['sla_overdue']}" if workflow is not None else "N/D"),
            (
                f"{workflow['sla_due_soon']} in scadenza"
                if workflow is not None
                else "Ticket store non disponibile"
            ),
            "attention",
        ),
        ("Score Cisco massimo", score_value, score_meta, "primary"),
        ("Asset Cyber Vision", asset_count, "Device Classic restituiti dalla API", "neutral"),
        ("Eventi recenti", event_count, "Widget Cisco cached", "neutral"),
        (
            "Qualità dati",
            f"{snapshot['quality']['score']:g}%",
            "Metrica DTLab, separata dal rischio",
            "quality",
        ),
    )
    markup = ["<section class='dt-kpi-grid' aria-label='Indicatori principali'>"]
    for label, value, meta, tone in cards:
        markup.append(
            f"<article class='dt-cockpit-kpi {tone}'>"
            f"<span>{safe(label)}</span><strong>{safe(value)}</strong><small>{safe(meta)}</small>"
            "</article>"
        )
    markup.append("</section>")
    st.markdown("".join(markup), unsafe_allow_html=True)


def _load_operational_index(context: DashboardContext) -> dict[str, Any] | None:
    """Synchronize once, then project the persistent workflow without side effects."""

    try:
        store, _result = sync_ticket_store(context)
        signals = store.list_signals(limit=1000)
        tickets = store.list_tickets(limit=1000)
        return build_operational_index(signals, tickets)
    except (KeyError, OSError, ValueError, sqlite3.Error, TicketStoreError):
        return None


def _ticket_workflow_summary(context: DashboardContext) -> dict[str, int] | None:
    """Backward-compatible summary used by tests and lightweight integrations."""

    operational = _load_operational_index(context)
    return dict(operational["summary"]) if operational is not None else None


def host_ot_topology_rows(operational: dict[str, Any] | None) -> list[dict[str, Any]]:
    """Project explicit PLC host detections without turning them into Cisco flows."""

    if operational is None:
        return []
    ticket_by_signal = operational.get("ticket_by_signal", {})
    rows: list[dict[str, Any]] = []
    for signal in operational.get("signals", []):
        if str(signal.get("signal_type")) != "host_modbus_write":
            continue
        payload = signal.get("payload") if isinstance(signal.get("payload"), dict) else {}
        event = payload.get("event") if isinstance(payload.get("event"), dict) else payload
        source = event.get("source") if isinstance(event.get("source"), dict) else {}
        destination = event.get("destination") if isinstance(event.get("destination"), dict) else {}
        modbus = event.get("modbus") if isinstance(event.get("modbus"), dict) else {}
        detection = event.get("detection") if isinstance(event.get("detection"), dict) else {}
        source_ip = str(source.get("ip") or event.get("source_ip") or "N/D")
        destination_ip = str(destination.get("ip") or event.get("destination_ip") or "N/D")
        writes = modbus.get("writes") or event.get("writes") or event.get("registers") or []
        function_codes = modbus.get("function_codes") or []
        function_code = event.get("function_code")
        if function_code is None and isinstance(function_codes, list) and function_codes:
            function_code = ",".join(str(value) for value in function_codes)
        if function_code is None and isinstance(writes, list) and writes:
            first_write = writes[0]
            if isinstance(first_write, dict):
                function_code = first_write.get("function_code")
        ticket = ticket_by_signal.get(str(signal.get("id")), {})
        origin = str(event.get("origin") or source.get("classification") or "")
        is_self = source_ip == destination_ip or origin in {"self_originated", "plc_self"}
        rows.append(
            {
                "Relazione": f"{source_ip} → {destination_ip}",
                "Self PLC": "Sì" if is_self else "No",
                "Function Code": f"FC{function_code}" if function_code is not None else "N/D",
                "Registri / valori": json.dumps(writes, ensure_ascii=False, sort_keys=True),
                "Classificazione": detection.get("classification")
                or detection.get("rule_id")
                or event.get("classification")
                or event.get("rule_id")
                or "Scrittura Modbus da verificare",
                "Severità": _SEVERITY_LABEL.get(
                    str(signal.get("severity") or "unknown"), "Da classificare"
                ),
                "Ticket": ticket.get("id") or "In riconciliazione",
                "Priorità": str(ticket.get("priority") or "N/D").upper(),
                "Ultima osservazione": format_local_time(signal.get("last_observed_at")),
                "Fonte": "Sensore host PLC · non Cisco",
            }
        )
    return rows


def _route_href(route: str, **parameters: object) -> str:
    query = urlencode(
        {key: str(value) for key, value in parameters.items() if value not in {None, ""}}
    )
    return f"/{route}?{query}" if query else f"/{route}"


def _render_operational_journey() -> None:
    steps = (
        ("01", "Rileva", "Topologia e telemetria", "topology"),
        ("02", "Contestualizza", "Asset 360 e rischio", "assets"),
        ("03", "Valuta", "Inbox deduplicata", "signals"),
        ("04", "Agisci", "Ticket, SLA e checklist", "tickets"),
        ("05", "Dimostra", "Evidenze con SHA-256", "evidence"),
    )
    markup = [
        "<nav class='dt-journey' aria-label='Flusso operativo DTLab'>",
    ]
    for number, title, detail, route in steps:
        markup.append(
            f"<a class='dt-journey-step' href='{safe(_route_href(route))}'>"
            f"<span>{safe(number)}</span><b>{safe(title)}</b><small>{safe(detail)}</small></a>"
        )
    markup.append("</nav>")
    st.markdown("".join(markup), unsafe_allow_html=True)


def _render_operational_item(item: dict[str, Any]) -> None:
    ticket_id = item.get("ticket_id")
    href = (
        _route_href("tickets", ticket=ticket_id)
        if ticket_id
        else _route_href("signals", signal=item["signal_id"])
    )
    signal_type = _SIGNAL_TYPE_LABEL.get(item["signal_type"], item["signal_type"])
    priority = (
        str(item["priority"]).upper()
        if item.get("priority")
        else _SEVERITY_LABEL.get(str(item.get("severity")), "Da classificare")
    )
    status = _TICKET_STATUS_LABEL.get(item["status"], item["status"])
    owner = str(item.get("owner") or "Non assegnato")
    sla_state = item.get("sla_state")
    sla = _SLA_LABEL.get(str(sla_state), "Senza deadline")
    if item.get("resurfaced"):
        sla = f"Riemerso · {sla}"
    assets = len(item.get("asset_ids") or [])
    detail = str(item.get("description") or "Nessuna descrizione sorgente.")
    action = str(
        item.get("recommended_action")
        or _SIGNAL_ACTION.get(
            str(item.get("signal_type")),
            "Aprire il workspace, verificare le evidenze e documentare la decisione.",
        )
    )
    observed = format_local_time(item.get("last_observed_at"))
    st.markdown(
        f"<article class='dt-priority-card {safe(item['severity'])}'>"
        "<div class='dt-priority-head'>"
        f"<span class='dt-priority-kind'>{safe(signal_type)} · {safe(status)}</span>"
        f"<span class='dt-priority-level'>{safe(priority)}</span></div>"
        f"<h3>{safe(item['title'])}</h3><p>{safe(detail)}</p>"
        f"<div class='dt-operational-meta'><span>Owner <b>{safe(owner)}</b></span>"
        f"<span>SLA <b>{safe(sla)}</b></span><span>Asset <b>{assets}</b></span></div>"
        f"<div class='dt-operational-meta'><span>Osservato <b>{safe(observed)}</b></span>"
        f"<span>Rilevazioni <b>{safe(item.get('occurrence_count', 1))}</b></span></div>"
        "<div class='dt-priority-action'><b>Prossimo passo</b>"
        f"<span>{safe(action)}</span></div>"
        f"<a class='dt-action-link' href='{safe(href)}'>Apri il workspace →</a>"
        "</article>",
        unsafe_allow_html=True,
    )


def _render_signal(signal: dict[str, Any]) -> None:
    st.markdown(
        f"<article class='dt-priority-card {safe(signal['severity'])}'>"
        "<div class='dt-priority-head'>"
        f"<span class='dt-priority-kind'>{safe(signal['kind'])}</span>"
        f"<span class='dt-priority-level'>{safe(signal['severity_label'])}</span>"
        "</div>"
        f"<h3>{safe(signal['title'])}</h3>"
        f"<p>{safe(signal['detail'])}</p>"
        "<div class='dt-priority-action'><b>Passo operativo</b>"
        f"<span>{safe(signal['action'])}</span></div>"
        "</article>",
        unsafe_allow_html=True,
    )


def _render_infrastructure_summary(context: DashboardContext) -> None:
    snapshot = context.snapshot
    vms = snapshot["virtual_machines"]
    powered_on = sum(vm["power_state"] == "powered_on" for vm in vms)
    target = next(
        (vm for vm in vms if vm["operational_context"]["official_target"]),
        None,
    )
    sensor_available = context.cybervision_capability_available("sensors")
    sensor_value: Any = "N/D"
    if sensor_available:
        operational = sum(
            str(sensor.get("status") or "").strip().casefold() in _OPERATIONAL_SENSOR_STATES
            for sensor in snapshot["sensors"]
        )
        sensor_value = f"{operational}/{len(snapshot['sensors'])}"
    cards = (
        ("VM powered on", f"{powered_on}/{len(vms)}", "Inventario ESXi read-only"),
        (
            "Target operativo",
            target["name"].removeprefix("[Relatech] ") if target else "N/D",
            "Conferma operatore",
        ),
        ("Sensori operativi", sensor_value, "Stato dichiarato da Cisco"),
        (
            "Telemetria acquisita",
            f"{len(snapshot['activities'])} attività · {len(snapshot['flows'])} flow",
            "Ultima finestra Cisco",
        ),
    )
    markup = ["<section class='dt-infra-grid' aria-label='Riepilogo infrastruttura'>"]
    for label, value, meta in cards:
        markup.append(
            "<article class='dt-infra-item'>"
            f"<span>{safe(label)}</span><strong>{safe(value)}</strong><small>{safe(meta)}</small>"
            "</article>"
        )
    markup.append("</section>")
    st.markdown("".join(markup), unsafe_allow_html=True)


def _host_ot_sensor_coverage() -> list[dict[str, object]]:
    configured = os.environ.get("DTLAB_HOST_OT_EVENT_STORE", "").strip()
    if not configured:
        return []
    try:
        statuses = load_sensor_statuses(Path(configured).expanduser().resolve())
    except OSError:
        return []
    evaluated = [sensor_coverage(status) for status in statuses]
    return sorted(
        evaluated,
        key=lambda item: str(item.get("received_at") or ""),
        reverse=True,
    )


def _render_host_ot_sensor_coverage() -> None:
    """Show coverage only after the receiver has authenticated its first record."""

    statuses = _host_ot_sensor_coverage()
    if not statuses:
        return
    status = statuses[0]
    sensor_id = str(status.get("sensor_id") or "sensore PLC")
    received_at = format_local_time(status.get("received_at"))
    age = status.get("age_seconds")
    age_label = format_age(int(age)) if isinstance(age, int) else "età non valida"
    event_label = (
        "heartbeat" if status.get("event_type") == "heartbeat" else "evento Modbus autenticato"
    )
    if status.get("coverage_state") == "active":
        st.success(
            f"Copertura host PLC attiva · {sensor_id} · ultimo {event_label} "
            f"ricevuto {age_label} fa ({received_at})."
        )
    else:
        st.error(
            f"Copertura host PLC non recente · {sensor_id} · ultima ricezione "
            f"{received_at}. L'assenza di nuovi alert non può essere interpretata "
            "come assenza di attacchi."
        )
    st.caption(
        "Stato derivato dal sensore endpoint PLC autenticato; è separato dai dati "
        "Cisco Cyber Vision."
    )


def render_command_center(context: DashboardContext) -> None:
    snapshot = context.snapshot
    page_intro(
        context,
        "Monitoraggio",
        "DTLab Command Center",
        "Freschezza, rischio Cisco, segnali operativi e infrastruttura in una sola vista.",
    )
    scores = snapshot["risk_scores"]
    asset_by_id = {asset["id"]: asset for asset in snapshot["assets"]}
    highest = max(scores, key=lambda item: item["score"], default=None)
    operational = _load_operational_index(context)
    workflow = operational["summary"] if operational is not None else None

    _render_live_strip(context)
    _render_host_ot_sensor_coverage()
    _render_cockpit_kpis(context, highest, asset_by_id, workflow)
    baseline_detection_banner(
        build_detection_readiness(snapshot),
        show_unattributed_only=False,
    )
    _render_operational_journey()

    st.markdown(
        "<div class='dt-section-heading'><div><span>Priorità operative</span>"
        "<h2>Segnali da verificare</h2></div>"
        "<p>Coda persistente ordinata per SLA, riemersione, priorità e severità. "
        "I ticket host-side possono aprirsi automaticamente; nessuna remediation è automatica."
        "</p></div>",
        unsafe_allow_html=True,
    )
    if operational is None:
        st.warning(
            "Ticket store non disponibile: la homepage mostra la coda read-only ricostruita "
            "dallo snapshot verificato. Le operazioni restano fail-closed."
        )
        fallback_signals = _priority_signals(snapshot)
        if not fallback_signals:
            empty_state(
                "Nessun segnale prioritario",
                "L'ultimo snapshot non contiene eventi, finding aperti, differenze "
                "o CVE associate.",
            )
        else:
            summary = Counter(signal["kind"] for signal in fallback_signals)
            st.markdown(
                "<div class='dt-signal-summary'>"
                + "".join(
                    f"<span>{safe(kind)} <b>{count}</b></span>"
                    for kind, count in sorted(summary.items())
                )
                + "</div>",
                unsafe_allow_html=True,
            )
            signal_columns = st.columns(2)
            for index, signal in enumerate(fallback_signals[:6]):
                with signal_columns[index % 2]:
                    _render_signal(signal)
    elif not operational["queue"]:
        empty_state(
            "Coda operativa vuota",
            "Non risultano segnali da valutare né ticket attivi nello store persistente.",
        )
    else:
        queue = operational["queue"]
        summary = Counter(
            _SIGNAL_TYPE_LABEL.get(item["signal_type"], item["signal_type"]) for item in queue
        )
        st.markdown(
            "<div class='dt-signal-summary'>"
            + "".join(
                f"<span>{safe(kind)} <b>{count}</b></span>"
                for kind, count in sorted(summary.items())
            )
            + "</div>",
            unsafe_allow_html=True,
        )
        signal_columns = st.columns(2)
        for index, item in enumerate(queue[:8]):
            with signal_columns[index % 2]:
                _render_operational_item(item)
        st.caption(
            f"Mostrate {min(8, len(queue))} priorità su {len(queue)}. "
            "Il registro completo resta disponibile in Segnalazioni e Ticket."
        )

    st.markdown(
        "<div class='dt-section-heading compact'><div><span>Postura e attività</span>"
        "<h2>Indicatori Cisco</h2></div>"
        "<p>Valori sorgente, senza score DTLab sostitutivi.</p></div>",
        unsafe_allow_html=True,
    )
    left, right = st.columns(2)
    with left:
        st.markdown("#### Distribuzione rischio per-device")
        if not scores:
            empty_state(
                "Risk score non disponibile",
                "Verrà mostrato solo dopo una lettura autenticata di Cisco Cyber Vision.",
            )
        else:
            counts = Counter(score["band"] for score in scores)
            figure = go.Figure(
                go.Bar(
                    x=["Basso 0–39", "Medio 40–69", "Alto 70–100"],
                    y=[counts["low"], counts["medium"], counts["high"]],
                    marker_color=["#3f866f", "#d38600", "#ba1a1a"],
                    text=[counts["low"], counts["medium"], counts["high"]],
                    textposition="auto",
                )
            )
            figure.update_layout(
                height=250,
                margin={"l": 8, "r": 8, "t": 8, "b": 28},
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                yaxis={"title": None, "gridcolor": "#dce5e2", "rangemode": "tozero"},
                xaxis={"fixedrange": True},
                font={"family": "Inter, sans-serif", "color": "#17201e", "size": 11},
                showlegend=False,
            )
            st.plotly_chart(figure, use_container_width=True, config={"displayModeBar": False})
            st.caption(
                "Punteggi per-device Cisco Cyber Vision. Un valore più alto indica "
                "rischio maggiore."
            )
    with right:
        st.markdown("#### Eventi per severità")
        events = snapshot["events"]
        if not events:
            empty_state(
                "Eventi non disponibili",
                "L'ultimo snapshot non contiene eventi Cisco recenti.",
            )
        else:
            event_counts = Counter(str(event.get("severity") or "unknown") for event in events)
            labels = ["Critici", "Alti", "Medi", "Bassi", "Informativi", "N/D"]
            keys = ["critical", "high", "medium", "low", "info", "unknown"]
            figure = go.Figure(
                go.Pie(
                    labels=labels,
                    values=[event_counts[key] for key in keys],
                    hole=0.64,
                    marker={
                        "colors": [
                            "#ba1a1a",
                            "#d65f00",
                            "#d38600",
                            "#3f866f",
                            "#185abc",
                            "#6f7976",
                        ]
                    },
                    textinfo="value",
                    hovertemplate="%{label}: %{value}<extra></extra>",
                )
            )
            figure.update_layout(
                height=250,
                margin={"l": 8, "r": 8, "t": 8, "b": 8},
                paper_bgcolor="rgba(0,0,0,0)",
                font={"family": "Inter, sans-serif", "color": "#17201e", "size": 11},
                legend={"orientation": "h", "y": -0.05},
            )
            st.plotly_chart(figure, use_container_width=True, config={"displayModeBar": False})

    st.markdown(
        "<div class='dt-section-heading compact'><div><span>Infrastruttura</span>"
        "<h2>Ambiente e sorgenti</h2></div>"
        "<p>Inventario read-only e ultimo successo per connettore.</p></div>",
        unsafe_allow_html=True,
    )
    _render_infrastructure_summary(context)
    st.dataframe(
        pd.DataFrame(_source_table(context)),
        use_container_width=True,
        hide_index=True,
    )


def _render_security_topology_summary(snapshot: dict[str, Any]) -> None:
    summary = security_topology_summary(snapshot)
    if summary["role_assertion"]["status"] == "unknown":
        return
    vm_names = ", ".join(str(name).removeprefix("[Relatech] ") for name in summary["vm_names"])
    asset_names = ", ".join(summary["asset_names"]) or "Identità Cisco non confermata"
    counterparties = (
        ", ".join(summary["counterparty_names"]) or "Nessuna controparte nel flow osservato"
    )
    state = summary["activity_state"]
    role_confirmed = summary["role_assertion"]["status"] == "operator_confirmed"
    identity_title = (
        "Host di security testing confermato"
        if role_confirmed
        else "Host di security testing previsto"
    )
    if state == "communication_observed":
        activity_title = "Comunicazione Cisco osservata"
        activity_detail = f"{summary['observed_flow_count']} flow · Controparti: {counterparties}"
    elif state == "unavailable":
        activity_title = "N/D"
        activity_detail = (
            "Snapshot obsoleto: nessuna conclusione sulla finestra corrente"
            if summary["telemetry_state"] == "stale"
            else "Telemetria flow non utilizzabile: nessuna conclusione possibile"
        )
    else:
        activity_title = "Nessun flow associato restituito"
        activity_detail = (
            "Capability utilizzabile nella finestra; non prova assenza di comunicazioni"
        )
    related_records = (
        f"{summary['observed_event_count']} eventi associati · "
        f"{summary['observed_activity_count']} attività generiche"
    )
    identity_label = {
        "confirmed": "Identità Cisco confermata",
        "proposed": "Identità Cisco proposta",
        "ambiguous": "Identità Cisco ambigua",
        "none": "Nessuna identità Cisco",
    }.get(summary["identity_state"], "Identità Cisco N/D")
    telemetry_label = {
        "available": "Telemetria aggiornata",
        "partial": "Telemetria flow disponibile · snapshot parziale",
        "stale": "Telemetria obsoleta",
        "unavailable": "Telemetria non disponibile",
        "unknown": "Telemetria N/D",
    }.get(summary["telemetry_state"], "Telemetria N/D")
    asset_link = ""
    if summary["identity_state"] == "confirmed" and summary["asset_ids"]:
        asset_url = _route_href("assets", asset=summary["asset_ids"][0])
        asset_link = (
            f'<a class="primary" href="{safe(asset_url)}" target="_self">'
            "Apri Asset 360 e workflow →</a>"
        )
    st.markdown(
        f"""
<section class="dt-security-topology {safe(state)}" aria-label="Stato host di security testing">
  <div class="dt-security-identity">
    <span class="dt-security-icon" aria-hidden="true">▲</span>
    <div><small>{safe(identity_title)}</small><strong>{safe(vm_names)}</strong>
    <span>Asset: {safe(asset_names)}</span></div>
  </div>
  <div class="dt-security-state">
    <small>Attività nella finestra</small><strong>{safe(activity_title)}</strong>
    <span>{safe(activity_detail)}<br>{safe(related_records)}</span>
  </div>
  <div class="dt-security-action">
    <small>Provenienza e interpretazione</small><strong>{safe(identity_label)}</strong>
    <span>{safe(telemetry_label)} · escluso dallo score aggregato;
    eventuali segnali restano triageabili.</span>
    <div class="dt-security-links">{asset_link}
      <a href="/signals" target="_self">Verifica segnalazioni →</a>
      <a href="/scenario-lab" target="_self">Scenario Lab · SIMULAZIONE →</a>
    </div>
  </div>
</section>
""",
        unsafe_allow_html=True,
    )
    baseline_detection_banner(
        build_detection_readiness(snapshot),
        show_unattributed_only=False,
    )


def render_topology(context: DashboardContext) -> None:
    snapshot = context.snapshot
    host_ot_sensors = _host_ot_sensor_coverage()
    cybervision_source_ids = {
        str(source["id"])
        for source in snapshot["sources"]
        if source.get("id") and source.get("type") == "cisco_cyber_vision"
    }

    def flow_source_owned(flow: dict[str, Any]) -> bool:
        evidence = flow.get("evidence")
        return bool(
            isinstance(evidence, dict)
            and str(evidence.get("source_id")) in cybervision_source_ids
            and str(evidence.get("truth") or "").casefold() in {"real", "observed", "stale"}
        )

    verified_graph_flows = [flow for flow in snapshot["flows"] if flow_source_owned(flow)]
    operator_source_ids = {
        str(source["id"])
        for source in snapshot["sources"]
        if source.get("id") and source.get("type") == "operator"
    }
    verified_identity_ids = verified_identity_link_ids(snapshot)
    page_intro(
        context,
        "Monitoraggio",
        "Topologia verificabile",
        "Tre livelli separati: configurazione VMware, comunicazioni Cyber Vision e "
        "correlazioni esplicite fra le due sorgenti.",
    )
    _render_security_topology_summary(snapshot)
    default_mode = "Vista integrata" if snapshot["assets"] else "VMware osservata"
    mode = st.segmented_control(
        "Livello topologico",
        ["Vista integrata", "VMware osservata", "OT Cyber Vision"],
        default=default_mode,
        selection_mode="single",
    )
    node_labels = {"": "Tutti i nodi"}
    if mode in {"Vista integrata", "VMware osservata"}:
        node_labels.update(
            {
                vm["id"]: f"VM · {vm['name'].removeprefix('[Relatech] ')}"
                for vm in snapshot["virtual_machines"]
            }
        )
    if mode in {"Vista integrata", "OT Cyber Vision"}:
        node_labels.update(
            {asset["id"]: f"Asset · {asset['name']}" for asset in snapshot["assets"]}
        )
    if mode == "Vista integrata":
        node_labels.update(
            {
                f"host-ot:{status['sensor_id']}": (
                    f"Host OT / EDR · {status['sensor_id']} · "
                    f"{'attivo' if status.get('coverage_state') == 'active' else 'non recente'}"
                )
                for status in host_ot_sensors
                if status.get("sensor_id")
            }
        )
    highlight_id = st.selectbox(
        "Evidenzia nodo",
        options=list(node_labels),
        format_func=lambda value: node_labels[value],
        help="Nella vista integrata evidenzia anche l'identità VMware↔Cisco confermata.",
    )
    selected_protocols: list[str] = []
    if mode != "VMware osservata":
        protocols = sorted(
            {str(flow["protocol"]) for flow in verified_graph_flows if flow.get("protocol")}
        )
        if protocols:
            selected_protocols = st.multiselect(
                "Filtra protocolli nel grafico",
                protocols,
                placeholder="Tutti i protocolli",
            )
    filtered_flows = [
        flow
        for flow in verified_graph_flows
        if not selected_protocols or str(flow.get("protocol")) in selected_protocols
    ]
    topology_snapshot = {**snapshot, "flows": filtered_flows}
    if mode == "VMware osservata":
        st.plotly_chart(
            vmware_topology(
                snapshot["virtual_machines"],
                snapshot["networks"],
                highlight_id=highlight_id or None,
            ),
            use_container_width=True,
            config=_TOPOLOGY_CHART_CONFIG,
        )
        st.caption(
            "Le linee provano solo VM ↔ port group. VLAN, subnet e capacità di cattura "
            "non sono dedotte dai nomi."
        )
    elif mode == "OT Cyber Vision":
        if not snapshot["assets"]:
            empty_state(
                "Topologia OT non disponibile",
                "Senza API Cyber Vision autenticata non vengono inventati asset o flow.",
            )
        else:
            st.plotly_chart(
                flow_topology(
                    snapshot["assets"],
                    filtered_flows,
                    virtual_machines=snapshot["virtual_machines"],
                    identity_links=snapshot["identity_links"],
                    cybervision_source_ids=cybervision_source_ids,
                    operator_source_ids=operator_source_ids,
                    highlight_id=highlight_id or None,
                ),
                use_container_width=True,
                config=_TOPOLOGY_CHART_CONFIG,
            )
            st.caption(
                "Le linee sono flow con evidenza Cisco verificata nella finestra "
                f"{_cybervision_window(context)}; non rappresentano una storia illimitata."
            )
    else:
        if not snapshot["assets"]:
            empty_state(
                "Vista integrata in attesa di Cyber Vision",
                "La parte VMware è reale; servono asset Cisco per risolvere le identità.",
            )
        else:
            st.plotly_chart(
                integrated_topology(
                    topology_snapshot,
                    highlight_id=highlight_id or None,
                    host_ot_sensors=host_ot_sensors,
                ),
                use_container_width=True,
                config=_TOPOLOGY_CHART_CONFIG,
            )
            confirmed = len(verified_identity_ids)
            proposed = sum(link["status"] == "proposed" for link in snapshot["identity_links"])
            st.caption(
                f"Identità confermate verificabili: {confirmed} · proposte: {proposed}. "
                "Le proposte sono tratteggiate e non diventano fatti silenziosamente. "
                "Host OT / EDR è una sorgente endpoint separata da Cisco e compare solo "
                "quando esiste uno stato sensore autenticato."
            )
    if selected_protocols:
        st.caption(
            f"Filtro grafico: {len(filtered_flows)}/{len(verified_graph_flows)} flow verificati · "
            f"protocolli {', '.join(selected_protocols)}. Le tabelle conservano tutti i record."
        )

    host_detection_rows = host_ot_topology_rows(_load_operational_index(context))
    if host_detection_rows:
        st.subheader("Relazioni host-side PLC")
        st.error(
            "Il sensore endpoint ha osservato comportamento Modbus da verificare. "
            "Le relazioni PLC → PLC sono mostrate separatamente dai flow Cisco e sono "
            "collegate al ticket operativo."
        )
        render_filterable_table(
            st,
            host_detection_rows,
            key="topology-host-ot-detections",
            filename_stem="dtlab-topology-host-ot-detections",
            filter_columns=("Self PLC", "Function Code", "Severità", "Priorità"),
            search_placeholder="Cerca IP, registro, regola o ticket…",
        )
        st.caption(
            "Fonte: DTLab PLC Host Audit. Queste righe non sono eventi né flow "
            "restituiti da Cisco Cyber Vision."
        )

    st.subheader("Relazioni verificabili")
    vmware_tab, flow_tab, identity_tab = st.tabs(
        ["Connessioni VMware", "Flow OT", "Identità VMware ↔ Cisco"]
    )
    network_by_id = {network["id"]: network for network in snapshot["networks"]}
    with vmware_tab:
        vmware_rows = []
        for vm in snapshot["virtual_machines"]:
            for interface in vm["interfaces"]:
                vmware_rows.append(
                    {
                        "VM": vm["name"].removeprefix("[Relatech] "),
                        "Adapter": interface["label"],
                        "Port group": network_by_id.get(interface["network_id"], {}).get(
                            "name", "N/D"
                        ),
                        "IP guest": ", ".join(interface["ip_addresses"]) or "N/D",
                        "Connessa": "Sì" if interface["connected"] else "No",
                        "Verità": truth_badge(vm),
                    }
                )
        render_filterable_table(
            st,
            vmware_rows,
            key="topology-vmware-connections",
            filename_stem="dtlab-topology-vmware-connections",
            filter_columns=("Port group", "Connessa"),
            search_placeholder="Cerca VM, adapter, port group o IP…",
        )

    with flow_tab:
        security_summary = security_topology_summary(snapshot)
        security_asset_ids = set(security_summary["asset_ids"])
        flow_rows = []
        for flow in snapshot["flows"]:
            source_owned = flow_source_owned(flow)
            flow_rows.append(
                {
                    "Endpoint A": flow.get("left_label") or flow.get("left_ip") or "N/D",
                    "Porta A": (
                        str(flow["left_port"]) if flow.get("left_port") is not None else "N/D"
                    ),
                    "Endpoint B": flow.get("right_label") or flow.get("right_ip") or "N/D",
                    "Porta B": (
                        str(flow["right_port"]) if flow.get("right_port") is not None else "N/D"
                    ),
                    "Protocollo": flow.get("protocol") or "N/D",
                    "Direzione": _DIRECTION_LABEL.get(
                        str(flow.get("direction") or "unknown"), "N/D"
                    ),
                    "Host security test": (
                        "Sì"
                        if security_asset_ids.intersection(
                            {
                                str(flow.get("left_asset_id")),
                                str(flow.get("right_asset_id")),
                            }
                        )
                        else "No"
                    ),
                    "Primo riscontro": format_local_time(flow.get("first_seen_at")),
                    "Ultimo riscontro": format_local_time(flow.get("last_seen_at")),
                    "Pacchetti": flow.get("packet_count") or 0,
                    "Byte": flow.get("byte_count") or 0,
                    "Fonte Cisco verificata": "Sì" if source_owned else "No",
                    "Verità": truth_badge(flow),
                }
            )
        render_filterable_table(
            st,
            flow_rows,
            key="topology-cisco-flows",
            filename_stem="dtlab-topology-cisco-flows",
            filter_columns=(
                "Protocollo",
                "Direzione",
                "Host security test",
                "Fonte Cisco verificata",
            ),
            search_placeholder="Cerca endpoint, porta, protocollo o timestamp…",
        )

    with identity_tab:
        vm_by_id = {vm["id"]: vm for vm in snapshot["virtual_machines"]}
        asset_by_id = {asset["id"]: asset for asset in snapshot["assets"]}
        identity_rows = [
            {
                "VM": vm_by_id.get(link["virtual_machine_id"], {})
                .get("name", link["virtual_machine_id"])
                .removeprefix("[Relatech] "),
                "Asset Cisco": asset_by_id.get(link["asset_id"], {}).get("name", link["asset_id"]),
                "Stato": (
                    "Confermata"
                    if str(link.get("id")) in verified_identity_ids
                    else "Conferma non verificabile"
                    if link["status"] == "confirmed"
                    else {
                        "proposed": "Proposta",
                        "ambiguous": "Ambigua",
                    }.get(link["status"], link["status"])
                ),
                "Metodo": link["method"],
                "Confidenza": f"{float(link['confidence']) * 100:.0f}%",
                "Verità": truth_badge(link),
            }
            for link in snapshot["identity_links"]
        ]
        render_filterable_table(
            st,
            identity_rows,
            key="topology-identity-links",
            filename_stem="dtlab-topology-identity-links",
            filter_columns=("Stato", "Metodo", "Verità"),
            search_placeholder="Cerca VM, asset, stato o metodo…",
        )


def _asset_rows(snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    scores = {score["asset_id"]: score for score in snapshot["risk_scores"]}
    vulnerabilities = Counter(
        vulnerability["asset_id"] for vulnerability in snapshot["vulnerabilities"]
    )
    rows = []
    for asset in snapshot["assets"]:
        score = scores.get(asset["id"])
        rows.append(
            {
                "ID": asset["id"],
                "Nome": asset["name"],
                "Tipo": asset["device_type"],
                "Vendor": asset["vendor"] or "N/D",
                "IP": ", ".join(asset["ip_addresses"]) or "N/D",
                "Protocolli osservati (finestra)": ", ".join(asset["protocols"]) or "N/D",
                "Score Cisco": score["score"] if score else None,
                "Fascia": _BAND_LABEL.get(score["band"], "N/D") if score else "N/D",
                "Vulnerabilità associate": vulnerabilities[asset["id"]],
                "Ultima attività": format_local_time(asset["last_seen_at"]),
                "Verità": truth_badge(asset),
            }
        )
    return rows


def _query_parameter(name: str) -> str | None:
    try:
        value: Any = st.query_params.get(name)
    except (AttributeError, KeyError):
        return None
    if isinstance(value, list):
        value = value[-1] if value else None
    text = str(value).strip() if value is not None else ""
    return text or None


def _safe_export_stem(value: object) -> str:
    stem = "".join(
        character if character.isalnum() or character in {"-", "_", "."} else "-"
        for character in str(value)
    )
    return (stem.strip("-._") or "dtlab-asset")[:120]


@st.cache_data(show_spinner=False, max_entries=64, ttl=3600)
def _asset_export_payloads(
    canonical_snapshot: dict[str, Any],
    asset_id: str,
) -> tuple[bytes, bytes]:
    return (
        build_asset_profile_json(
            canonical_snapshot,
            asset_id=asset_id,
            mode="technical",
        ),
        build_export_bundle(
            canonical_snapshot,
            mode="technical",
            asset_id=asset_id,
        ),
    )


def render_assets(context: DashboardContext) -> None:
    snapshot = context.snapshot
    page_intro(
        context,
        "Monitoraggio",
        "Asset OT",
        "Inventario Cyber Vision con score, vulnerabilità e protocolli osservati nei "
        "flow della finestra acquisita.",
    )
    if not snapshot["assets"]:
        empty_state(
            "Inventario Cyber Vision non disponibile",
            "Le VM VMware restano consultabili nella pagina Ambiente VMware.",
        )
        return
    rows = _asset_rows(snapshot)
    filtered = render_filterable_table(
        st,
        rows,
        key="assets-inventory",
        filename_stem="dtlab-assets",
        filter_columns=("Tipo", "Vendor", "Fascia"),
        search_placeholder="Cerca nome, IP, vendor o protocollo…",
        hidden_columns=("ID",),
        height=360,
    )
    if not filtered:
        return

    st.subheader("Dettaglio asset")
    asset_options = [row["ID"] for row in filtered]
    requested_asset = _query_parameter("asset")
    selected_id = st.selectbox(
        "Asset",
        asset_options,
        index=(asset_options.index(requested_asset) if requested_asset in asset_options else 0),
        format_func=lambda value: next(row["Nome"] for row in filtered if row["ID"] == value),
    )
    asset = next(item for item in snapshot["assets"] if item["id"] == selected_id)
    score = next(
        (item for item in snapshot["risk_scores"] if item["asset_id"] == selected_id),
        None,
    )
    metrics = st.columns(4)
    with metrics[0]:
        metric_card("Score Cisco", f"{score['score']:g}/100" if score else "N/D", "Per-device")
    with metrics[1]:
        metric_card("Fascia", _BAND_LABEL.get(score["band"], "N/D") if score else "N/D", "Cisco")
    with metrics[2]:
        metric_card(
            "Ultima attività",
            format_local_time(asset["last_seen_at"]),
            "Timestamp Cisco",
        )
    with metrics[3]:
        metric_card("Verità", truth_badge(asset), asset["evidence"]["source_record_id"])

    details, evidence = st.columns([1.2, 0.8])
    with details:
        st.markdown("#### Identità tecnica")
        st.json(
            {
                "nome": asset["name"],
                "tipo": asset["device_type"],
                "categoria": asset["category"],
                "vendor": asset["vendor"],
                "ip": asset["ip_addresses"],
                "mac": asset["mac_addresses"],
                "zona": asset["zone"],
                "protocolli_osservati_nella_finestra": asset["protocols"],
            },
            expanded=True,
        )
    with evidence:
        st.markdown("#### Provenienza")
        st.json(asset["evidence"], expanded=True)

    if score:
        st.markdown("#### Fattori del rischio Cisco")
        if score["factors"]:
            render_filterable_table(
                st,
                score["factors"],
                key=f"asset-risk-factors-{selected_id}",
                filename_stem="dtlab-asset-risk-factors",
                search_placeholder="Cerca nei fattori Cisco…",
            )
        else:
            st.caption("Fattori non restituiti dall'endpoint di dettaglio.")
        if score.get("details"):
            st.markdown("#### Contesto score Cisco")
            st.json(score["details"], expanded=False)

    associated_vulnerabilities = [
        item for item in snapshot["vulnerabilities"] if item["asset_id"] == selected_id
    ]
    associated_flows = [
        item
        for item in snapshot["flows"]
        if selected_id in {item["left_asset_id"], item["right_asset_id"]}
    ]
    with st.expander(f"Vulnerabilità associate ({len(associated_vulnerabilities)})"):
        if associated_vulnerabilities:
            render_filterable_table(
                st,
                associated_vulnerabilities,
                key=f"asset-vulnerabilities-{selected_id}",
                filename_stem="dtlab-asset-vulnerabilities",
                filter_columns=("severity", "status"),
                search_placeholder="Cerca CVE, titolo o stato…",
            )
        else:
            st.caption("Nessuna associazione restituita.")
    vulnerability_ids = list(
        dict.fromkeys(
            str(item["external_id"])
            for item in associated_vulnerabilities
            if item.get("external_id")
        )
    )
    if vulnerability_ids:
        dossier_id = st.selectbox(
            "Apri dossier CVE correlato",
            vulnerability_ids,
            key=f"asset-cve-link-{selected_id}",
        )
        st.markdown(
            f"<a class='dt-action-link' href='"
            f"{safe(_route_href('vulnerabilities', cve=dossier_id))}'>"
            f"Apri il dossier {safe(dossier_id)} →</a>",
            unsafe_allow_html=True,
        )
    with st.expander(f"Flow correlati ({len(associated_flows)})"):
        if associated_flows:
            render_filterable_table(
                st,
                associated_flows,
                key=f"asset-flows-{selected_id}",
                filename_stem="dtlab-asset-flows",
                filter_columns=("protocol", "direction"),
                search_placeholder="Cerca endpoint, IP, porta o protocollo…",
            )
        else:
            st.caption("Nessun flow correlato.")

    st.divider()
    st.subheader("Asset 360 · correlazioni operative")
    st.caption(
        "Ogni collegamento sotto usa esclusivamente ID espliciti presenti nello snapshot "
        "o nel ticket store. Nomi e indirizzi simili non vengono correlati automaticamente."
    )
    identity_tab, security_tab, operations_tab, evidence_tab = st.tabs(
        ["Cisco ↔ VMware", "Eventi", "Operazioni", "Evidenze"]
    )

    with identity_tab:
        links = [link for link in snapshot["identity_links"] if link["asset_id"] == selected_id]
        vm_by_id = {vm["id"]: vm for vm in snapshot["virtual_machines"]}
        if not links:
            empty_state(
                "Nessuna identità VMware collegata",
                "Il portale non deduce una VM da nome, IP o MAC senza una relazione esplicita.",
            )
        else:
            identity_rows = []
            for link in links:
                vm = vm_by_id.get(link["virtual_machine_id"], {})
                context_details = vm.get("operational_context", {})
                identity_rows.append(
                    {
                        "VM": str(vm.get("name") or link["virtual_machine_id"]).removeprefix(
                            "[Relatech] "
                        ),
                        "IP primario": vm.get("primary_ip") or "N/D",
                        "Power state": vm.get("power_state") or "N/D",
                        "Ruolo": context_details.get("purpose") or "N/D",
                        "Target ufficiale": (
                            "Sì" if context_details.get("official_target") else "No"
                        ),
                        "Stato link": link.get("status") or "N/D",
                        "Metodo": link.get("method") or "N/D",
                        "Confidenza": f"{float(link.get('confidence') or 0) * 100:.0f}%",
                        "Verità": truth_badge(link),
                    }
                )
            render_filterable_table(
                st,
                identity_rows,
                key=f"asset-identity-{selected_id}",
                filename_stem="dtlab-asset-cisco-vmware-identity",
                filter_columns=("Stato link", "Target ufficiale", "Power state"),
                search_placeholder="Cerca VM, IP, ruolo o metodo…",
            )

        explicit_activities = [
            item for item in snapshot["activities"] if selected_id in item["asset_ids"]
        ]
        with st.expander(f"Attività esplicitamente associate ({len(explicit_activities)})"):
            if explicit_activities:
                render_filterable_table(
                    st,
                    explicit_activities,
                    key=f"asset-activities-{selected_id}",
                    filename_stem="dtlab-asset-activities",
                    search_placeholder="Cerca protocollo, endpoint o timestamp…",
                )
            else:
                st.caption("Nessuna attività con questo asset tra gli ID sorgente.")

    with security_tab:
        asset_events = [event for event in snapshot["events"] if selected_id in event["asset_ids"]]
        flow_ids = {flow["id"] for flow in associated_flows}
        baseline_differences = [
            difference
            for difference in snapshot["baseline_differences"]
            if selected_id in difference["asset_ids"] or difference.get("flow_id") in flow_ids
        ]
        st.markdown(f"#### Eventi Cisco correlati ({len(asset_events)})")
        if asset_events:
            render_filterable_table(
                st,
                asset_events,
                key=f"asset-events-{selected_id}",
                filename_stem="dtlab-asset-events",
                filter_columns=("severity", "category"),
                search_placeholder="Cerca titolo, categoria o severità…",
            )
        else:
            st.info("Nessun evento Cisco referenzia esplicitamente questo asset.")
        st.markdown(f"#### Differenze baseline correlate ({len(baseline_differences)})")
        if baseline_differences:
            render_filterable_table(
                st,
                baseline_differences,
                key=f"asset-baseline-{selected_id}",
                filename_stem="dtlab-asset-baseline-differences",
                filter_columns=("difference_type",),
                search_placeholder="Cerca differenza, valore o flow…",
            )
        else:
            st.info("Nessuna differenza baseline collegata all'asset o ai suoi flow.")

    with operations_tab:
        operational = _load_operational_index(context)
        if operational is None:
            empty_state(
                "Workflow non disponibile",
                "Il ticket store persistente non è leggibile; nessuna relazione viene ricostruita.",
            )
        else:
            asset_signals, asset_tickets = asset_workflow_records(
                operational,
                asset_id=selected_id,
            )
            st.markdown(f"#### Segnalazioni esplicite ({len(asset_signals)})")
            if asset_signals:
                render_filterable_table(
                    st,
                    asset_signals,
                    key=f"asset-signals-{selected_id}",
                    filename_stem="dtlab-asset-signals",
                    filter_columns=("signal_type", "severity"),
                    search_placeholder="Cerca segnalazione, severità o record sorgente…",
                )
            else:
                st.info("Nessuna segnalazione persistente dichiara questo asset.")
            st.markdown(f"#### Ticket collegati ({len(asset_tickets)})")
            if asset_tickets:
                ticket_rows = []
                for ticket in asset_tickets:
                    sla = operational["sla_by_ticket"].get(str(ticket["id"]), {})
                    ticket_rows.append(
                        {
                            "ID": ticket["id"],
                            "Titolo": ticket["title"],
                            "Priorità": str(ticket["priority"]).upper(),
                            "Stato": _TICKET_STATUS_LABEL.get(ticket["status"], ticket["status"]),
                            "Owner": ticket.get("owner") or "Non assegnato",
                            "SLA": _SLA_LABEL.get(str(sla.get("state")), "N/D"),
                            "Deadline": format_local_time(sla.get("due_at")),
                        }
                    )
                render_filterable_table(
                    st,
                    ticket_rows,
                    key=f"asset-tickets-{selected_id}",
                    filename_stem="dtlab-asset-tickets",
                    filter_columns=("Priorità", "Stato", "Owner", "SLA"),
                    search_placeholder="Cerca ticket, owner, stato o priorità…",
                )
                ticket_options = [str(ticket["id"]) for ticket in asset_tickets]
                selected_ticket = st.selectbox(
                    "Apri ticket collegato",
                    ticket_options,
                    format_func=lambda ticket_id: next(
                        f"{str(ticket['priority']).upper()} · "
                        f"{_TICKET_STATUS_LABEL.get(ticket['status'], ticket['status'])} · "
                        f"{ticket['title']}"
                        for ticket in asset_tickets
                        if str(ticket["id"]) == ticket_id
                    ),
                    key=f"asset-ticket-link-{selected_id}",
                )
                st.markdown(
                    f"<a class='dt-action-link' href='"
                    f"{safe(_route_href('tickets', ticket=selected_ticket))}'>"
                    "Apri il workspace ticket →</a>",
                    unsafe_allow_html=True,
                )
            else:
                st.info("Nessun ticket deriva dalle segnalazioni esplicite dell'asset.")

    with evidence_tab:
        canonical_snapshot = context.canonical_snapshot
        profile, evidence_bundle = _asset_export_payloads(
            canonical_snapshot,
            selected_id,
        )
        stem = _safe_export_stem(selected_id)
        st.caption(
            "Il profilo JSON è strettamente limitato ai riferimenti espliciti dell'asset. "
            "Lo ZIP filtra le collezioni asset-level ma conserva anche provenienza e "
            "contesto globale dello snapshot (sorgenti, inventario, reti e baseline); il "
            "manifest contiene SHA-256 e identità verificabile."
        )
        export_columns = st.columns(2)
        with export_columns[0]:
            st.download_button(
                "Scarica profilo Asset 360 · JSON",
                data=profile,
                file_name=f"asset-360-{stem}.json",
                mime="application/json",
                icon=":material/data_object:",
                use_container_width=True,
                key=f"asset-profile-download-{selected_id}",
            )
        with export_columns[1]:
            st.download_button(
                "Scarica dossier evidenze · ZIP",
                data=evidence_bundle,
                file_name=f"asset-evidence-{stem}.zip",
                mime="application/zip",
                icon=":material/folder_zip:",
                use_container_width=True,
                key=f"asset-bundle-download-{selected_id}",
            )
        st.markdown(
            f"<a class='dt-action-link' href='{safe(_route_href('evidence'))}'>"
            "Apri Evidenze e report (anche export pubblico redatto) →</a>",
            unsafe_allow_html=True,
        )


def render_flows(context: DashboardContext) -> None:
    snapshot = context.snapshot
    page_intro(
        context,
        "Monitoraggio",
        "Attività e flow",
        "Attività aggregate e singoli flow Cisco, con componenti, contatori e timestamp.",
    )
    assets = {asset["id"]: asset["name"] for asset in snapshot["assets"]}
    st.caption(
        "Finestra temporale acquisita: "
        f"{_cybervision_window(context)}. Le attività e i flow elencati sono relativi "
        "a questo periodo."
    )
    source_details = (context.cybervision_source or {}).get("details", {})
    dashboard_metrics = (
        source_details.get("dashboard_metrics", {}) if isinstance(source_details, dict) else {}
    )
    protocol_metrics = (
        dashboard_metrics.get("protocol_distribution", {})
        if isinstance(dashboard_metrics, dict)
        else {}
    )
    protocol_totals = protocol_metrics.get("total") if isinstance(protocol_metrics, dict) else []
    if context.cybervision_capability_available("protocol_distribution") and protocol_totals:
        st.subheader("Distribuzione protocolli Cisco")
        st.caption(
            "Conteggi attività del dashboard Cisco cached. Non sono la stessa cosa dei "
            "flow della finestra temporale mostrati sotto."
        )
        protocol_rows = [
            {
                "Protocollo": item.get("tag_label") or item.get("tag_id") or "N/D",
                "Attività": item.get("count"),
            }
            for item in protocol_totals
        ]
        render_filterable_table(
            st,
            protocol_rows,
            key="flows-protocol-distribution",
            filename_stem="dtlab-cisco-protocol-distribution",
            search_placeholder="Cerca protocollo…",
        )
    activity_tab, flow_tab = st.tabs(["Attività aggregate", "Flow"])
    with activity_tab:
        if not snapshot["activities"]:
            empty_state(
                "Attività non disponibili",
                "La capability Cisco non ha restituito attività aggregate utilizzabili.",
            )
        else:
            activity_rows = []
            for activity in snapshot["activities"]:
                details = activity["details"]
                endpoints = [
                    details.get("left_label"),
                    details.get("right_label"),
                ]
                activity_rows.append(
                    {
                        "Estremi Cisco": " ↔ ".join(str(value) for value in endpoints if value)
                        or ", ".join(
                            assets.get(asset_id, asset_id) for asset_id in activity["asset_ids"]
                        )
                        or "N/D",
                        "Direzione": _DIRECTION_LABEL.get(details.get("direction"), "Sconosciuta"),
                        "Stato Cisco": details.get("status") or "N/D",
                        "Tag": ", ".join(details.get("tags", [])) or "N/D",
                        "Variabili": details.get("variables_count"),
                        "Nuovi accessi variabili": details.get("new_variable_access"),
                        "Differenze": details.get("differences_count"),
                        "Pacchetti": activity["packet_count"],
                        "Byte": activity["byte_count"],
                        "Flow": activity["flow_count"],
                        "Eventi": activity["event_count"],
                        "Prima osservazione": format_local_time(activity["first_seen_at"]),
                        "Ultima osservazione": format_local_time(activity["last_seen_at"]),
                        "Verità": truth_badge(activity),
                    }
                )
            render_filterable_table(
                st,
                activity_rows,
                key="flows-activities",
                filename_stem="dtlab-cisco-activities",
                filter_columns=("Direzione", "Stato Cisco"),
                search_placeholder="Cerca estremi, tag o stato…",
                height=520,
            )

    with flow_tab:
        if not snapshot["flows"]:
            empty_state(
                "Flow non disponibili",
                "Zero righe non viene interpretato come assenza di comunicazioni se la "
                "capability Cyber Vision non è disponibile.",
            )
        else:
            rows = []
            for flow in snapshot["flows"]:
                rows.append(
                    {
                        "Lato sinistro": assets.get(
                            flow["left_asset_id"],
                            flow["left_label"] or flow["left_ip"] or "N/D",
                        ),
                        "Porta sinistra": flow["left_port"],
                        "Direzione": _DIRECTION_LABEL.get(
                            flow["direction"], flow["direction_raw"] or "Sconosciuta"
                        ),
                        "Lato destro": assets.get(
                            flow["right_asset_id"],
                            flow["right_label"] or flow["right_ip"] or "N/D",
                        ),
                        "Porta destra": flow["right_port"],
                        "Protocollo": flow["protocol"],
                        "Pacchetti": flow["packet_count"],
                        "Byte": flow["byte_count"],
                        "Prima osservazione": format_local_time(flow["first_seen_at"]),
                        "Ultima osservazione": format_local_time(flow["last_seen_at"]),
                        "Verità": truth_badge(flow),
                    }
                )
            render_filterable_table(
                st,
                rows,
                key="flows-records",
                filename_stem="dtlab-cisco-flows",
                filter_columns=("Protocollo", "Direzione"),
                search_placeholder="Cerca endpoint, porta o protocollo…",
                height=520,
            )
