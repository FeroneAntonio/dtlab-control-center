"""Operational administration for SIEM, operators and business calendars."""

from __future__ import annotations

from datetime import UTC, datetime, time

import pandas as pd
import streamlit as st

from dtlab.services.operational_settings import (
    BusinessHoursPolicy,
    OperationalSettingsStore,
    is_business_open,
    probe_syslog_endpoint,
)
from dtlab.ui.components import metric_card, page_intro
from dtlab.ui.context import DashboardContext
from dtlab.ui.views.operations import get_ticket_store

_DAY_LABELS = {
    0: "Lunedì",
    1: "Martedì",
    2: "Mercoledì",
    3: "Giovedì",
    4: "Venerdì",
    5: "Sabato",
    6: "Domenica",
}
_ROLES = ("Analista OT", "Operatore OT", "Responsabile SOC", "Amministratore")


def _actor(settings: OperationalSettingsStore) -> str:
    operators = settings.list_operators(active_only=True)
    labels = [str(item["display_name"]) for item in operators]
    if not labels:
        return "system"
    return str(st.selectbox("Operatore che applica le modifiche", labels, key="admin-actor"))


def render_administration(context: DashboardContext) -> None:
    page_intro(
        context,
        "Piattaforma",
        "Amministrazione operativa",
        "Configurazione persistente di operatori, calendario SLA e predisposizione Syslog.",
    )
    ticket_store = get_ticket_store()
    settings = OperationalSettingsStore(ticket_store.database_path)
    actor = _actor(settings)
    operators = settings.list_operators()
    business = settings.get_business_hours()
    syslog = settings.get_syslog()

    cards = st.columns(4)
    with cards[0]:
        metric_card(
            "Operatori attivi",
            sum(bool(item["active"]) for item in operators),
            "Anagrafica persistente",
        )
    with cards[1]:
        metric_card(
            "Orario aziendale",
            "Aperto" if is_business_open(datetime.now(UTC), business) else "Chiuso",
            f"{business.timezone} · {business.start}-{business.end}",
        )
    with cards[2]:
        metric_card(
            "Syslog",
            "Predisposto" if syslog.get("host") else "Da configurare",
            "CEF / TCP / UDP / TLS",
        )
    with cards[3]:
        metric_card("Retention raw", "100", "Pulizia automatica ogni minuto")

    operator_tab, hours_tab, syslog_tab = st.tabs(
        ["Operatori", "Orari e SLA", "Syslog / SIEM"]
    )

    with operator_tab:
        st.subheader("Anagrafica operatori")
        st.caption(
            "Gli operatori attivi sono selezionabili nei ticket e diventano l'attore "
            "persistito nell'audit trail."
        )
        st.dataframe(
            pd.DataFrame(
                [
                    {
                        "Operatore": item["display_name"],
                        "Ruolo": item["role"],
                        "Stato": "Attivo" if item["active"] else "Disattivato",
                    }
                    for item in operators
                ]
            ),
            hide_index=True,
            use_container_width=True,
        )
        with st.form("operator-form", clear_on_submit=True):
            left, middle, right = st.columns([2, 2, 1])
            with left:
                display_name = st.text_input("Nome o identificativo aziendale")
            with middle:
                role = st.selectbox("Ruolo", _ROLES)
            with right:
                active = st.toggle("Attivo", value=True)
            save_operator = st.form_submit_button(
                "Salva operatore", icon=":material/person_add:", use_container_width=True
            )
        if save_operator:
            try:
                settings.save_operator(display_name, role, active=active)
            except ValueError as exc:
                st.error(str(exc))
            else:
                st.success("Operatore salvato. È ora disponibile nei ticket.")
                st.rerun()

    with hours_tab:
        st.subheader("Calendario aziendale per gli SLA")
        st.caption(
            "Le nuove deadline consumano soltanto ore lavorative. Salvando, le deadline "
            "dei ticket ancora aperti vengono ricalcolate e registrate nell'audit."
        )
        with st.form("business-hours-form"):
            enabled = st.toggle("Applica orario aziendale agli SLA", value=business.enabled)
            col_a, col_b, col_c = st.columns(3)
            with col_a:
                timezone_name = st.text_input("Fuso orario", value=business.timezone)
            with col_b:
                start_value = st.time_input(
                    "Apertura", value=time.fromisoformat(business.start), step=900
                )
            with col_c:
                end_value = st.time_input(
                    "Chiusura", value=time.fromisoformat(business.end), step=900
                )
            weekdays = st.multiselect(
                "Giorni lavorativi",
                list(_DAY_LABELS),
                default=list(business.weekdays),
                format_func=lambda day: _DAY_LABELS[day],
            )
            save_hours = st.form_submit_button(
                "Salva calendario e ricalcola SLA",
                icon=":material/schedule:",
                use_container_width=True,
            )
        if save_hours:
            try:
                policy = BusinessHoursPolicy(
                    enabled=enabled,
                    timezone=timezone_name.strip(),
                    start=start_value.strftime("%H:%M"),
                    end=end_value.strftime("%H:%M"),
                    weekdays=tuple(sorted(weekdays)),
                ).validate()
                settings.set_business_hours(policy, actor=actor)
                changed = ticket_store.recalculate_open_sla_deadlines(actor=actor)
            except (ValueError, OSError) as exc:
                st.error(str(exc))
            else:
                st.success(f"Calendario salvato; {changed} deadline aperte ricalcolate.")
                st.rerun()

    with syslog_tab:
        st.subheader("Predisposizione Syslog per SIEM")
        st.info(
            "Questa pagina salva e collauda il receiver. Non dichiara attivo un feed live: "
            "l'invio continuo verrà abilitato dopo il collaudo con il SIEM aziendale."
        )
        with st.form("syslog-form"):
            prepared = st.toggle(
                "Configurazione pronta per il forwarder",
                value=bool(syslog.get("enabled")),
            )
            col_host, col_port = st.columns([3, 1])
            with col_host:
                host = st.text_input(
                    "Host o IP receiver",
                    value=str(syslog.get("host") or ""),
                    placeholder="siem.azienda.local",
                )
            with col_port:
                port = st.number_input(
                    "Porta", min_value=1, max_value=65535, value=int(syslog.get("port", 6514))
                )
            col_protocol, col_format = st.columns(2)
            protocols = ["TCP+TLS", "TCP", "UDP"]
            formats = ["CEF Extended Time Precision", "CEF"]
            with col_protocol:
                protocol = st.selectbox(
                    "Protocollo",
                    protocols,
                    index=protocols.index(str(syslog.get("protocol", "TCP+TLS"))),
                )
            with col_format:
                format_name = st.selectbox(
                    "Formato",
                    formats,
                    index=formats.index(str(syslog.get("format", formats[0]))),
                )
            include_cisco = st.checkbox(
                "Eventi Cisco normalizzati", value=bool(syslog.get("include_cisco", True))
            )
            include_host_ot = st.checkbox(
                "Eventi Host OT / EDR", value=bool(syslog.get("include_host_ot", True))
            )
            include_tickets = st.checkbox(
                "Ticket e audit operatore", value=bool(syslog.get("include_tickets", True))
            )
            save_syslog = st.form_submit_button(
                "Salva configurazione", icon=":material/save:", use_container_width=True
            )
        candidate = {
            "enabled": prepared,
            "host": host,
            "port": int(port),
            "protocol": protocol,
            "format": format_name,
            "include_cisco": include_cisco,
            "include_host_ot": include_host_ot,
            "include_tickets": include_tickets,
        }
        if save_syslog:
            try:
                settings.set_syslog(candidate, actor=actor)
            except ValueError as exc:
                st.error(str(exc))
            else:
                st.success("Configurazione Syslog salvata in modo persistente.")
                st.rerun()
        if st.button(
            "Verifica raggiungibilità receiver",
            icon=":material/network_ping:",
            disabled=not bool(host.strip()),
        ):
            try:
                result = probe_syslog_endpoint(candidate)
            except (OSError, ValueError) as exc:
                st.error(f"Receiver non raggiungibile: {exc}")
            else:
                st.success(result)
