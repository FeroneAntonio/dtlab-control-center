"""Source-owned Cisco Cyber Vision New UI inventory views."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import streamlit as st

from dtlab.ui.components import empty_state, format_local_time, metric_card, page_intro
from dtlab.ui.context import DashboardContext
from dtlab.ui.table_tools import render_filterable_table


def _capability_available(source: Mapping[str, Any], name: str) -> bool:
    status = source.get("capabilities", {}).get(name, {}).get("status")
    return status in {"available", "partial", "truncated"}


def _capability_status(source: Mapping[str, Any], name: str) -> str:
    return str(source.get("capabilities", {}).get(name, {}).get("status") or "unknown")


def _interface_text(interfaces: list[dict[str, Any]]) -> str:
    values = []
    for interface in interfaces:
        address = interface.get("ip") or "N/D"
        mac = interface.get("mac") or "N/D"
        marker = "primaria" if interface.get("is_primary") is True else None
        values.append(" · ".join(item for item in (address, mac, marker) if item))
    return " | ".join(values) or "N/D"


def _asset_rows(assets: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "Profilo New UI": asset["name"],
            "Tipo": asset["type"],
            "Vendor": asset["vendor"] or "N/D",
            "Interfacce": _interface_text(asset["network_interfaces"]),
            "Gruppo funzionale": asset["functional_group_name"] or "N/D",
            "Alert attivi": (
                asset["active_alert_count"]
                if asset["active_alert_count"] is not None
                else "N/D"
            ),
            "Vulnerabilità": (
                asset["vulnerability_count"]
                if asset["vulnerability_count"] is not None
                else "N/D"
            ),
            "Sensori associati": ", ".join(
                association["label"] or association["id"]
                for association in asset["sensor_associations"]
            )
            or "N/D",
            "PCAP associati": len(asset["pcap_associations"]),
            "Ultima attività": format_local_time(asset["last_active_at"]),
        }
        for asset in assets
    ]


def _alert_rows(alert_assets: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "Asset": asset["asset_name"],
            "Stato": alert.get("status") or asset.get("query_status") or "N/D",
            "Severità": alert["severity"] or "N/D",
            "Categoria": alert["category"] or "N/D",
            "Tipo": alert["alert_type"] or "N/D",
            "Trigger": alert["trigger"] or "N/D",
            "Ultima occorrenza": format_local_time(alert["last_occurrence"]),
        }
        for asset in alert_assets
        for alert in asset["alerts"]
    ]


def _vulnerability_rows(
    vulnerability_assets: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    return [
        {
            "Asset": asset["asset_name"],
            "ID": vulnerability["cve_id"] or "N/D",
            "Nome": vulnerability["name"] or "N/D",
            "Fonte": vulnerability["source"] or "N/D",
            "CSRS (valore API)": vulnerability["csrs_score"] or "N/D",
            "CVSS (valore API)": vulnerability["cvss_score"] or "N/D",
        }
        for asset in vulnerability_assets
        for vulnerability in asset["vulnerabilities"]
    ]


def render_new_ui_inventory(context: DashboardContext) -> None:
    page_intro(
        context,
        "Monitoraggio",
        "Inventario New UI",
        "Profili asset, reti OT, gerarchia, alert e vulnerabilità dalla API New UI "
        "read-only, separati dai Device Classic.",
    )
    source = context.cybervision_new_ui_source
    if not source or source["status"] in {"not_configured", "unavailable"}:
        empty_state(
            "Cisco New UI non disponibile",
            "Serve il token New UI con ruolo Auditor oppure la capability non è "
            "disponibile sul Center. I dati Classic restano indipendenti.",
        )
        return
    details = source.get("details", {})
    assets = details.get("assets", [])
    alert_assets = details.get("alert_assets", [])
    vulnerability_assets = details.get("vulnerability_assets", [])
    networks = details.get("networks", [])
    hierarchy = details.get("org_hierarchy", [])
    alert_query_statuses = details.get("alert_query_statuses", {})
    alerts = _alert_rows(alert_assets)
    vulnerabilities = _vulnerability_rows(vulnerability_assets)

    columns = st.columns(4)
    metrics = (
        ("Profili asset", len(assets), "Non sommati ai Device Classic"),
        (
            "Alert New UI",
            len(alerts) if _capability_available(source, "alerts") else "N/D",
            "Record dettagliati restituiti",
        ),
        (
            "Vulnerabilità New UI",
            (
                len(vulnerabilities)
                if _capability_available(source, "vulnerability_assets")
                else "N/D"
            ),
            "CSRS e CVSS separati",
        ),
        ("Reti OT", len(networks), f"{len(hierarchy)} livelli gerarchia"),
    )
    for column, (label, value, meta) in zip(columns, metrics, strict=True):
        with column:
            metric_card(label, value, meta)

    st.info(
        "I profili New UI hanno identificativi diversi dai Device Classic. Il portale li "
        "presenta come inventario sorgente e non altera topologia, flow o risk score Classic."
    )
    asset_tab, network_tab, security_tab = st.tabs(
        ["Profili asset", "Reti e gerarchia", "Alert e vulnerabilità"]
    )
    with asset_tab:
        if not _capability_available(source, "assets"):
            empty_state(
                "Profili New UI non disponibili",
                "La capability asset non ha completato l'ultima acquisizione.",
            )
        elif not assets:
            empty_state(
                "Nessun profilo New UI",
                "La capability è disponibile e ha restituito zero asset.",
            )
        else:
            render_filterable_table(
                st,
                _asset_rows(assets),
                key="new-ui-assets",
                filename_stem="dtlab-new-ui-assets",
                filter_columns=("Tipo", "Vendor", "Gruppo funzionale"),
                height=360,
            )
            st.caption(
                "Sensor e PCAP sono associazioni dichiarate dall'asset: non vengono "
                "trasformati in entità autonome senza endpoint pubblici dedicati."
            )

    with network_tab:
        st.subheader("Reti OT")
        if _capability_available(source, "networks") and networks:
            network_rows = [
                {
                    "Nome": network["name"],
                    "Tipo": network["type"] or "N/D",
                    "Range": network["ip_range"] or "N/D",
                    "VLAN": (
                        network["vlan_id"]
                        if network["vlan_id"] is not None
                        else "N/D"
                    ),
                    "Duplicata": network["duplicated"],
                }
                for network in networks
            ]
            render_filterable_table(
                st,
                network_rows,
                key="new-ui-networks",
                filename_stem="dtlab-new-ui-networks",
                filter_columns=("Tipo", "Duplicata"),
                height=330,
            )
        elif _capability_available(source, "networks"):
            empty_state("Nessuna rete", "La API New UI ha restituito zero reti.")
        else:
            empty_state("Reti N/D", "La capability reti non è disponibile.")
        st.subheader("Gerarchia operativa")
        if _capability_available(source, "org_hierarchy") and hierarchy:
            hierarchy_rows = [
                {
                    "Nome": item["name"],
                    "Percorso": item["hierarchy"] or "N/D",
                    "Descrizione": item["description"] or "N/D",
                    "Parent": item["parent_level_id"] or "—",
                }
                for item in hierarchy
            ]
            render_filterable_table(
                st,
                hierarchy_rows,
                key="new-ui-hierarchy",
                filename_stem="dtlab-new-ui-hierarchy",
                filter_columns=("Parent",),
            )
        elif _capability_available(source, "org_hierarchy"):
            empty_state(
                "Gerarchia vuota",
                "La capability è disponibile e ha restituito zero livelli.",
            )
        else:
            empty_state("Gerarchia N/D", "La capability non è disponibile.")

    with security_tab:
        st.subheader("Alert New UI")
        alert_capability_status = _capability_status(source, "alerts")
        if alert_query_statuses:
            st.caption(
                "Copertura query: "
                + " · ".join(
                    f"{query_status} {item.get('records', 0)} "
                    f"({item.get('status', 'unknown')})"
                    for query_status, item in alert_query_statuses.items()
                )
            )
        if alert_capability_status in {"partial", "truncated"}:
            st.warning(
                "Una o più query di stato alert non sono complete. Le righe visibili "
                "provengono soltanto dalle query riuscite."
            )
        if _capability_available(source, "alerts") and alerts:
            render_filterable_table(
                st,
                alerts,
                key="new-ui-alerts",
                filename_stem="dtlab-new-ui-alerts",
                filter_columns=("Stato", "Severità", "Categoria"),
            )
        elif alert_capability_status == "available":
            st.success("La capability è disponibile: zero alert New UI restituiti.")
        elif alert_capability_status in {"partial", "truncated"}:
            empty_state(
                "Alert con copertura parziale",
                "Le query riuscite hanno restituito zero righe; almeno uno stato resta N/D.",
            )
        else:
            empty_state("Alert N/D", "La capability alert non è disponibile.")
        st.subheader("Esposizione vulnerabilità New UI")
        if _capability_available(source, "vulnerability_assets") and vulnerabilities:
            render_filterable_table(
                st,
                vulnerabilities,
                key="new-ui-vulnerabilities",
                filename_stem="dtlab-new-ui-vulnerabilities",
                filter_columns=("Fonte", "Asset"),
            )
        elif _capability_available(source, "vulnerability_assets"):
            st.success(
                "La capability è disponibile: zero vulnerabilità New UI restituite."
            )
        else:
            empty_state(
                "Vulnerabilità New UI N/D",
                "La capability non è disponibile.",
            )
        st.caption(
            "Il CSRS è mostrato solo come valore restituito dalla New UI. Non viene "
            "ricalcolato, confrontato o combinato con CVSS o con il risk score Classic."
        )
