"""Streamlit entry point and grouped navigation."""

from __future__ import annotations

from pathlib import Path

import streamlit as st

from dtlab.services.snapshot_store import SnapshotStoreError
from dtlab.ui.context import DashboardContext, default_store_path, load_dashboard_context
from dtlab.ui.live import file_revision, render_live_watcher
from dtlab.ui.theme import apply_theme
from dtlab.ui.views.administration import render_administration
from dtlab.ui.views.lab import render_scenario_lab
from dtlab.ui.views.monitoring import (
    render_assets,
    render_command_center,
    render_flows,
    render_topology,
)
from dtlab.ui.views.new_ui_inventory import render_new_ui_inventory
from dtlab.ui.views.operations import (
    default_ticket_store_path,
    render_signals,
    render_tickets,
)
from dtlab.ui.views.platform import (
    render_evidence,
    render_sensors,
    render_sources,
    render_vmware,
)
from dtlab.ui.views.security import (
    render_baseline,
    render_events,
    render_risk,
    render_vulnerabilities,
)


def _load_context(path: str) -> DashboardContext:
    return load_dashboard_context(Path(path))


def _page(function, context: DashboardContext):
    return lambda: function(context)


def run() -> None:
    st.set_page_config(
        page_title="DTLab Control Center",
        page_icon=":material/security:",
        layout="wide",
        initial_sidebar_state="auto",
    )
    apply_theme()
    st.logo(
        str(Path(__file__).resolve().parents[3] / "assets" / "dtlab-logo.svg"),
        size="large",
    )
    store_path = default_store_path()
    ticket_store_path = default_ticket_store_path()
    try:
        context = _load_context(str(store_path))
    except SnapshotStoreError:
        st.error(
            "Nessuno snapshot verificato disponibile. Il portale resta fail-closed e non "
            "carica dati demo."
        )
        st.info(
            "Avviare il collector DTLab oppure ripristinare un manifest last-known-good valido."
        )
        st.stop()

    with st.sidebar:
        if st.button(
            "Aggiorna dati",
            icon=":material/refresh:",
            use_container_width=True,
        ):
            st.rerun()
        render_live_watcher(
            str(store_path),
            str(context.manifest["sha256"]),
            context.pointer,
            context.effective_state,
            str(context.canonical_snapshot["sync"]["completed_at"]),
            int(context.canonical_snapshot["sync"]["max_age_seconds"]),
            str(context.canonical_snapshot["sync"]["state"]),
            ticket_store_path=str(ticket_store_path),
            displayed_ticket_revision=file_revision(ticket_store_path),
        )

    pages = {
        "Centro operativo": [
            st.Page(
                _page(render_command_center, context),
                title="Command Center",
                icon=":material/dashboard:",
                url_path="command-center",
                default=True,
            ),
            st.Page(
                _page(render_signals, context),
                title="Segnalazioni",
                icon=":material/inbox:",
                url_path="signals",
            ),
            st.Page(
                _page(render_tickets, context),
                title="Ticket e remediation",
                icon=":material/confirmation_number:",
                url_path="tickets",
            ),
        ],
        "Monitoraggio": [
            st.Page(
                _page(render_topology, context),
                title="Topologia",
                icon=":material/account_tree:",
                url_path="topology",
            ),
            st.Page(
                _page(render_assets, context),
                title="Asset",
                icon=":material/memory:",
                url_path="assets",
            ),
            st.Page(
                _page(render_new_ui_inventory, context),
                title="Inventario New UI",
                icon=":material/inventory_2:",
                url_path="new-ui-inventory",
            ),
            st.Page(
                _page(render_flows, context),
                title="Attività e flow",
                icon=":material/route:",
                url_path="flows",
            ),
        ],
        "Sicurezza": [
            st.Page(
                _page(render_risk, context),
                title="Risk score Cisco",
                icon=":material/speed:",
                url_path="risk",
            ),
            st.Page(
                _page(render_events, context),
                title="Eventi",
                icon=":material/notification_important:",
                url_path="events",
            ),
            st.Page(
                _page(render_vulnerabilities, context),
                title="Vulnerabilità",
                icon=":material/bug_report:",
                url_path="vulnerabilities",
            ),
            st.Page(
                _page(render_baseline, context),
                title="Baseline",
                icon=":material/compare_arrows:",
                url_path="baseline",
            ),
        ],
        "Piattaforma": [
            st.Page(
                _page(render_administration, context),
                title="Amministrazione operativa",
                icon=":material/admin_panel_settings:",
                url_path="administration",
            ),
            st.Page(
                _page(render_sensors, context),
                title="Sensori e DPI",
                icon=":material/sensors:",
                url_path="sensors",
            ),
            st.Page(
                _page(render_vmware, context),
                title="Ambiente VMware",
                icon=":material/dns:",
                url_path="vmware",
            ),
            st.Page(
                _page(render_sources, context),
                title="Sorgenti e qualità",
                icon=":material/database:",
                url_path="sources",
            ),
            st.Page(
                _page(render_evidence, context),
                title="Evidenze e report",
                icon=":material/folder_zip:",
                url_path="evidence",
            ),
        ],
        "Scenario Lab · simulazione": [
            st.Page(
                _page(render_scenario_lab, context),
                title="BeerFactory Lab",
                icon=":material/science:",
                url_path="scenario-lab",
            ),
        ],
    }
    navigation = st.navigation(pages, position="sidebar", expanded=True)
    navigation.run()
