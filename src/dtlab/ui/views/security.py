"""Security pages for Cisco risk, events, vulnerabilities, and baselines."""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Mapping
from typing import Any
from urllib.parse import urlencode

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from dtlab.services.exports import build_cve_dossier_json
from dtlab.ui.components import (
    baseline_detection_banner,
    capability_notice,
    empty_state,
    format_local_time,
    metric_card,
    page_intro,
    safe,
    truth_badge,
)
from dtlab.ui.context import DashboardContext
from dtlab.ui.detection_readiness import build_detection_readiness
from dtlab.ui.table_tools import render_filterable_table

_BAND_LABEL = {"low": "Basso", "medium": "Medio", "high": "Alto"}
_BAND_COLOR = {"low": "#3f866f", "medium": "#d38600", "high": "#ba1a1a"}
_SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
    "unknown": 5,
}


def _query_parameter(name: str) -> str | None:
    try:
        value: Any = st.query_params.get(name)
    except (AttributeError, KeyError):
        return None
    if isinstance(value, list):
        value = value[-1] if value else None
    text = str(value).strip() if value is not None else ""
    return text or None


def _catalog_device_associations(
    snapshot: Mapping[str, Any],
    catalog_record: Mapping[str, Any],
) -> list[dict[str, Any]]:
    """Match only the exact source-owned external vulnerability identifier."""

    external_id = str(catalog_record.get("external_id") or "").strip().casefold()
    if not external_id:
        return []
    return [
        dict(item)
        for item in snapshot.get("vulnerabilities", [])
        if str(item.get("external_id") or "").strip().casefold() == external_id
    ]


def _safe_export_stem(value: object) -> str:
    stem = "".join(
        character if character.isalnum() or character in {"-", "_", "."} else "-"
        for character in str(value)
    )
    return (stem.strip("-._") or "dtlab-cve")[:120]


@st.cache_data(show_spinner=False, max_entries=128, ttl=3600)
def _cached_cve_dossier(
    canonical_snapshot: dict[str, Any],
    catalog_record: dict[str, Any],
) -> bytes:
    return build_cve_dossier_json(
        canonical_snapshot,
        catalog_record=catalog_record,
        mode="technical",
    )


def _dashboard_metrics(context: DashboardContext) -> dict[str, Any]:
    source = context.cybervision_source or {}
    details = source.get("details", {})
    metrics = details.get("dashboard_metrics", {}) if isinstance(details, dict) else {}
    return metrics if isinstance(metrics, dict) else {}


def _count_or_na(record: dict[str, Any], key: str) -> Any:
    value = record.get(key)
    return value if value is not None else "N/D"


def render_risk(context: DashboardContext) -> None:
    snapshot = context.snapshot
    page_intro(
        context,
        "Sicurezza",
        "Risk score Cisco",
        "Punteggi per-device letti da Cisco Cyber Vision, senza formule DTLab sostitutive.",
    )
    scores = snapshot["risk_scores"]
    capability_notice(context, "device_risk_scores", "Risk score per-device")
    assets = {asset["id"]: asset for asset in snapshot["assets"]}
    risk_distribution = _dashboard_metrics(context).get("risk_distribution", {})
    aggregate = risk_distribution.get("total") if isinstance(risk_distribution, dict) else None
    if context.cybervision_capability_available("risk_distribution") and isinstance(
        aggregate, dict
    ):
        st.subheader("Distribuzione aggregata Cisco")
        st.caption(
            "Contatori cached del dashboard Cyber Vision; restano distinti dai dettagli "
            "per-device acquisiti sotto."
        )
        aggregate_columns = st.columns(4)
        with aggregate_columns[0]:
            metric_card("Device conteggiati", _count_or_na(aggregate, "total"), "Cisco cached")
        with aggregate_columns[1]:
            metric_card("Rischio alto", _count_or_na(aggregate, "high"), "Cisco cached")
        with aggregate_columns[2]:
            metric_card("Rischio medio", _count_or_na(aggregate, "medium"), "Cisco cached")
        with aggregate_columns[3]:
            metric_card("Rischio basso", _count_or_na(aggregate, "low"), "Cisco cached")

    if not scores:
        if context.cybervision_capability_available("device_risk_scores"):
            message = (
                "La capability per-device ha risposto, ma non ha restituito score "
                "utilizzabili nell'ultima acquisizione."
            )
        else:
            message = (
                "Il portale non calcola un punteggio alternativo. Configurare il token "
                "API read-only per mostrare il valore ufficiale."
            )
        empty_state(
            "Score Cisco non disponibile",
            message,
        )
        return
    st.subheader("Dettaglio per-device acquisito")
    counts = Counter(score["band"] for score in scores)
    columns = st.columns(4)
    with columns[0]:
        metric_card("Asset con score", len(scores), "Device Cisco Cyber Vision")
    with columns[1]:
        metric_card("Rischio alto", counts["high"], "70–100")
    with columns[2]:
        metric_card("Rischio medio", counts["medium"], "40–69")
    with columns[3]:
        metric_card("Rischio basso", counts["low"], "0–39")

    ordered = sorted(scores, key=lambda item: item["score"], reverse=True)
    figure = go.Figure(
        go.Bar(
            x=[score["score"] for score in ordered],
            y=[
                assets.get(score["asset_id"], {}).get("name", score["asset_id"])
                for score in ordered
            ],
            orientation="h",
            marker_color=[_BAND_COLOR[score["band"]] for score in ordered],
            text=[f"{score['score']:g}" for score in ordered],
            textposition="auto",
        )
    )
    figure.update_layout(
        height=max(320, len(ordered) * 44),
        margin={"l": 20, "r": 20, "t": 25, "b": 30},
        xaxis={"range": [0, 100], "title": "Rischio (più alto = peggiore)"},
        yaxis={"autorange": "reversed"},
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
    )
    st.plotly_chart(figure, use_container_width=True, config={"displayModeBar": False})
    st.caption(
        "Soglie Cisco: 0–39 basso, 40–69 medio, 70–100 alto. "
        "Il timestamp di calcolo è esposto per ogni asset quando restituito."
    )
    rows = [
        {
            "Asset": assets.get(score["asset_id"], {}).get("name", score["asset_id"]),
            "Score": score["score"],
            "Fascia": _BAND_LABEL[score["band"]],
            "Ultimo calcolo engine": format_local_time(score["computed_at"]),
            "Fattori disponibili": len(score["factors"]),
            "Completezza": f"{score['evidence']['completeness'] * 100:.0f}%",
            "Verità": truth_badge(score),
        }
        for score in ordered
    ]
    render_filterable_table(
        st,
        rows,
        key="risk-device-scores",
        filename_stem="dtlab-cisco-device-risk-scores",
        filter_columns=("Fascia",),
        search_placeholder="Cerca asset o fascia…",
    )


def _event_rows(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "ID": event["id"],
            "Quando": format_local_time(event["occurred_at"]),
            "Severità": event["severity"],
            "Categoria": event["category"],
            "Center": event.get("center_label") or event.get("center_id") or "N/D",
            "Titolo": event["title"],
            "Verità": truth_badge(event),
        }
        for event in events
    ]


def render_events(context: DashboardContext) -> None:
    snapshot = context.snapshot
    page_intro(
        context,
        "Sicurezza",
        "Eventi e triage",
        "Eventi recenti aggregati dal widget Cisco cached, senza associazioni ad asset "
        "inventate dal portale.",
    )
    capability_notice(context, "event_severities", "Eventi recenti Cisco")
    readiness = build_detection_readiness(snapshot)
    st.subheader(readiness["copy"]["title"])
    st.caption(f"{readiness['copy']['scope']} {readiness['copy']['caution']}")
    summary = readiness["summary"]
    readiness_metrics = st.columns(5)
    with readiness_metrics[0]:
        metric_card(
            "Origini previste",
            summary["origins_total"],
            "Kali, HMI e PLC ufficiale",
        )
    with readiness_metrics[1]:
        metric_card(
            "Identità confermate",
            f"{summary['identity_confirmed']}/{summary['origins_total']}",
            "Link VM↔asset univoci",
        )
    with readiness_metrics[2]:
        metric_card(
            "Origini write osservate",
            summary["write_origin_observed"],
            "Solo direzione esplicita",
        )
    with readiness_metrics[3]:
        metric_card(
            "Eventi associati",
            summary["alert_events_linked"],
            "Da classificare dall'operatore",
        )
    with readiness_metrics[4]:
        metric_card(
            "Differenze baseline",
            summary["baseline_differences_linked"],
            "Associazioni asset esplicite",
        )

    baseline_detection_banner(readiness, show_unattributed_only=True)

    readiness_rows = [
        {
            "Origine": row["origin_label"],
            "Identità": row["identity"]["label"],
            "Scrittura Modbus": row["write_activity"]["label"],
            "Evento Cisco associato": row["alert_event"]["label"],
            "Evidenza baseline": row["baseline_difference"]["label"],
            "Esito": row["overall"]["label"],
            "VM": ", ".join(row["vm_ids"]) or "N/D",
            "Asset": ", ".join(row["asset_ids"]) or "N/D",
            "Nota": row["overall"]["copy"],
        }
        for row in readiness["rows"]
    ]
    render_filterable_table(
        st,
        readiness_rows,
        key="events-modbus-detection-readiness",
        filename_stem="dtlab-modbus-detection-readiness",
        filter_columns=(
            "Identità",
            "Scrittura Modbus",
            "Evidenza baseline",
            "Esito",
        ),
        search_placeholder="Cerca origine, stato, VM o asset…",
        height=300,
    )
    st.info(
        "Una scrittura con direzione non determinata prova solo il coinvolgimento degli "
        "asset. Un evento associato non è automaticamente un alert Modbus: categoria e "
        "payload devono essere classificati e conservati come evidenza. Anche una "
        "differenza baseline associata indica uno scostamento, non un attacco confermato."
    )

    metrics = _dashboard_metrics(context)
    category_metrics = metrics.get("event_categories", {})
    category_totals = category_metrics.get("total") if isinstance(category_metrics, dict) else []
    severity_metrics = metrics.get("event_severities", {})
    center_totals = severity_metrics.get("centers") if isinstance(severity_metrics, dict) else []
    if category_totals or center_totals:
        st.subheader("Contatori dashboard Cisco")
        st.caption(
            "Metriche aggregate del widget Cisco, separate dalla lista degli eventi "
            "recenti riportata sotto."
        )
        aggregate_columns = st.columns(2)
        with aggregate_columns[0]:
            if category_totals:
                category_rows = [
                    {
                        "Categoria": item["category"],
                        "Eventi": item["count"],
                    }
                    for item in category_totals
                ]
                render_filterable_table(
                    st,
                    category_rows,
                    key="events-category-metrics",
                    filename_stem="dtlab-cisco-event-category-metrics",
                    search_placeholder="Cerca categoria…",
                )
        with aggregate_columns[1]:
            if center_totals:
                center_rows = [
                    {
                        "Center": item.get("center_label")
                        or item.get("center_id")
                        or "N/D",
                        "Critici": item.get("critical"),
                        "Alti": item.get("high"),
                        "Medi": item.get("medium"),
                        "Bassi": item.get("low"),
                        "Totale": item.get("total"),
                    }
                    for item in center_totals
                ]
                render_filterable_table(
                    st,
                    center_rows,
                    key="events-center-metrics",
                    filename_stem="dtlab-cisco-event-center-metrics",
                    search_placeholder="Cerca Center…",
                )
    if not snapshot["events"]:
        if context.cybervision_capability_available("event_severities"):
            title = "Nessun evento recente restituito"
            message = (
                "La capability Cisco ha risposto correttamente, ma il widget non "
                "contiene eventi recenti nell'ultima acquisizione."
            )
        else:
            title = "Eventi non disponibili"
            message = (
                "L'assenza di righe non viene mostrata come zero se la capability "
                "eventi non è stata acquisita."
            )
        empty_state(
            title,
            message,
        )
        return
    events = snapshot["events"]
    rows = _event_rows(events)
    filtered_rows = render_filterable_table(
        st,
        rows,
        key="events-recent",
        filename_stem="dtlab-cisco-recent-events",
        filter_columns=("Severità", "Categoria", "Center"),
        search_placeholder="Cerca titolo, categoria, Center o ID…",
        hidden_columns=("ID",),
        height=430,
    )
    filtered_ids = {row["ID"] for row in filtered_rows}
    filtered = [event for event in events if event["id"] in filtered_ids]
    if filtered:
        selected_id = st.selectbox(
            "Apri evento",
            [event["id"] for event in filtered],
            format_func=lambda event_id: next(
                event["title"] for event in filtered if event["id"] == event_id
            ),
        )
        selected = next(event for event in filtered if event["id"] == selected_id)
        left, right = st.columns([1.2, 0.8])
        with left:
            st.markdown("#### Dettaglio")
            st.write(selected["description"])
            st.json(
                {
                    "categoria": selected["category"],
                    "severità": selected["severity"],
                    "center_id": selected.get("center_id"),
                    "center_label": selected.get("center_label"),
                    "timestamp": selected["occurred_at"],
                    "fonte": "Cisco cached dashboard event",
                }
            )
        with right:
            st.markdown("#### Checklist triage")
            for step in (
                "Verificare la provenienza e il timestamp dell'evento.",
                "Individuare eventuali asset o flow nello stesso intervallo temporale.",
                "Confrontare la comunicazione con la baseline.",
                "Documentare decisione ed evidenze senza alterare l'ambiente.",
            ):
                st.checkbox(step, key=f"triage-{selected_id}-{step}")


def render_vulnerabilities(context: DashboardContext) -> None:
    snapshot = context.snapshot
    page_intro(
        context,
        "Sicurezza",
        "Vulnerabilità",
        "Catalogo CVE Cisco ricercabile e associazioni device–vulnerabilità esplicite, "
        "con CVSS sempre separato dal Cisco Security Risk Score.",
    )
    source = context.cybervision_source or {}
    source_details = source.get("details")
    details_mapping = source_details if isinstance(source_details, Mapping) else {}
    raw_catalog = details_mapping.get("vulnerability_catalog", [])
    catalog = [dict(item) for item in raw_catalog if isinstance(item, Mapping)]
    capabilities = source.get("capabilities", {})
    catalog_capability = capabilities.get("vulnerabilities", {})
    device_associations_capability = capabilities.get("device_vulnerabilities", {})
    catalog_reported_count = int(catalog_capability.get("records") or 0)
    catalog_available = context.cybervision_capability_available("vulnerabilities")
    device_associations_available = context.cybervision_capability_available(
        "device_vulnerabilities"
    )

    st.subheader("Catalogo globale Cisco")
    st.caption(
        "Indice restituito dall'endpoint globale Cisco. Essere nel catalogo non significa "
        "che una CVE sia presente su un asset DTLab."
    )
    if not catalog_available:
        st.info(
            "Il catalogo globale Cisco non è disponibile. Le associazioni per-device, "
            "quando presenti, restano consultabili senza arricchimenti inventati."
        )
    elif catalog_reported_count and not catalog:
        st.warning(
            f"Cisco ha dichiarato {catalog_reported_count} record, ma questo snapshot "
            "precede l'indice CVE ricercabile. Serve una nuova raccolta verificata."
        )

    catalog_columns = st.columns(4)
    with catalog_columns[0]:
        metric_card(
            "Catalogo Cisco",
            catalog_reported_count if catalog_available else "N/D",
            "Record dichiarati dalla API",
        )
    with catalog_columns[1]:
        metric_card(
            "CVE indicizzate",
            len(catalog) if catalog_available else "N/D",
            "Ricercabili nello snapshot",
        )
    with catalog_columns[2]:
        catalog_cvss = [
            float(item["cvss_score"])
            for item in catalog
            if item.get("cvss_score") is not None
        ]
        metric_card(
            "CVSS massimo catalogo",
            max(catalog_cvss) if catalog_cvss else "N/D",
            "Valore tecnico Cisco",
        )
    with catalog_columns[3]:
        metric_card(
            "Associate agli asset",
            len(snapshot["vulnerabilities"])
            if device_associations_available
            else "N/D",
            "Relazioni esplicite, non inferite",
        )

    if catalog:
        filter_columns = st.columns([1.5, 0.7, 0.7])
        with filter_columns[0]:
            catalog_query = st.text_input(
                "Cerca CVE, titolo o ID Cisco",
                placeholder="es. CVE-2024, Schneider, vuln UUID",
                key="vulnerability-catalog-search",
            ).strip().casefold()
        with filter_columns[1]:
            minimum_cvss = st.slider(
                "CVSS minimo",
                min_value=0.0,
                max_value=10.0,
                value=0.0,
                step=0.1,
                key="vulnerability-catalog-cvss",
            )
        with filter_columns[2]:
            only_cve = st.checkbox(
                "Solo identificativi CVE",
                value=False,
                key="vulnerability-catalog-only-cve",
            )
        filtered_catalog = []
        for item in catalog:
            external_id = str(item.get("external_id") or "")
            haystack = " ".join(
                str(item.get(key) or "")
                for key in ("external_id", "title", "source_record_id", "vendor_id")
            ).casefold()
            score = item.get("cvss_score")
            if catalog_query and catalog_query not in haystack:
                continue
            if only_cve and not external_id.upper().startswith("CVE-"):
                continue
            if minimum_cvss > 0 and (score is None or float(score) < minimum_cvss):
                continue
            filtered_catalog.append(item)

        catalog_rows = [
            {
                "CVE / ID esterno": item.get("external_id") or "N/D",
                "Titolo": item.get("title") or "N/D",
                "CVSS": item.get("cvss_score"),
                "Versione CVSS": item.get("cvss_version"),
                "Pubblicata": format_local_time(item.get("published_at")),
                "ID Cisco": item.get("source_record_id"),
                "Vendor ID": item.get("vendor_id") or "N/D",
            }
            for item in filtered_catalog
        ]
        catalog_frame = pd.DataFrame(catalog_rows)
        st.caption(f"{len(filtered_catalog)} record selezionati su {len(catalog)} indicizzati.")
        st.dataframe(
            catalog_frame,
            use_container_width=True,
            hide_index=True,
            height=480,
        )
        download_columns = st.columns(2)
        with download_columns[0]:
            st.download_button(
                "Scarica selezione CVE · JSON",
                data=(
                    json.dumps(
                        filtered_catalog,
                        ensure_ascii=False,
                        sort_keys=True,
                        indent=2,
                    )
                    + "\n"
                ).encode("utf-8"),
                file_name="dtlab-cisco-cve-catalog.json",
                mime="application/json",
                icon=":material/download:",
                use_container_width=True,
            )
        with download_columns[1]:
            st.download_button(
                "Scarica selezione CVE · CSV",
                data=catalog_frame.to_csv(index=False).encode("utf-8-sig"),
                file_name="dtlab-cisco-cve-catalog.csv",
                mime="text/csv",
                icon=":material/download:",
                use_container_width=True,
            )

        if filtered_catalog:
            st.markdown("### Dossier CVE")
            st.caption(
                "Il dossier separa il catalogo globale dalle associazioni effettivamente "
                "restituite per i device. CVSS e Cisco Device Risk Score non vengono fusi."
            )
            catalog_index: dict[str, dict[str, Any]] = {}
            for item in filtered_catalog:
                option_id = str(item.get("source_record_id") or item.get("external_id"))
                catalog_index.setdefault(option_id, item)
            catalog_options = list(catalog_index)
            catalog_labels = {
                item_id: " · ".join(
                    value
                    for value in (
                        str(item.get("external_id") or "ID non CVE"),
                        str(item.get("title") or "Senza titolo"),
                    )
                    if value
                )
                for item_id, item in catalog_index.items()
            }
            requested_cve = _query_parameter("cve")
            requested_option = next(
                (
                    item_id
                    for item_id, item in catalog_index.items()
                    if requested_cve
                    in {
                        str(item.get("external_id") or ""),
                        str(item.get("source_record_id") or ""),
                    }
                ),
                None,
            )
            selected_catalog_id = st.selectbox(
                "Apri dossier",
                catalog_options,
                index=(
                    catalog_options.index(requested_option)
                    if requested_option in catalog_options
                    else 0
                ),
                format_func=catalog_labels.__getitem__,
                key="vulnerability-catalog-dossier",
            )
            selected_catalog = catalog_index[selected_catalog_id]
            associations = _catalog_device_associations(snapshot, selected_catalog)
            assets_by_id = {asset["id"]: asset for asset in snapshot["assets"]}
            scores_by_asset = {
                score["asset_id"]: score for score in snapshot["risk_scores"]
            }
            dossier_metrics = st.columns(4)
            with dossier_metrics[0]:
                metric_card(
                    "CVSS",
                    selected_catalog.get("cvss_score")
                    if selected_catalog.get("cvss_score") is not None
                    else "N/D",
                    f"Versione {selected_catalog.get('cvss_version') or 'N/D'}",
                )
            with dossier_metrics[1]:
                metric_card(
                    "Asset associati",
                    len(associations) if device_associations_available else "N/D",
                    (
                        "Relazioni esplicite Cisco"
                        if device_associations_available
                        else "Capability non disponibile"
                    ),
                )
            with dossier_metrics[2]:
                associated_scores = [
                    scores_by_asset[item["asset_id"]]["score"]
                    for item in associations
                    if item["asset_id"] in scores_by_asset
                ]
                metric_card(
                    "Risk Cisco massimo",
                    (
                        max(associated_scores)
                        if associated_scores and device_associations_available
                        else "N/D"
                    ),
                    "Score device, separato dal CVSS",
                )
            with dossier_metrics[3]:
                metric_card(
                    "Pubblicata",
                    format_local_time(selected_catalog.get("published_at")),
                    "Timestamp catalogo Cisco",
                )

            st.markdown(f"#### {selected_catalog.get('external_id') or 'ID non CVE'}")
            st.write(selected_catalog.get("title") or "Descrizione non restituita.")
            st.json(
                {
                    "id_cisco": selected_catalog.get("source_record_id"),
                    "vendor_id": selected_catalog.get("vendor_id"),
                    "cvss": selected_catalog.get("cvss_score"),
                    "cvss_version": selected_catalog.get("cvss_version"),
                    "pubblicata": selected_catalog.get("published_at"),
                    "capability_catalogo": catalog_capability,
                    "capability_associazioni_device": device_associations_capability,
                },
                expanded=False,
            )
            if not device_associations_available:
                st.warning(
                    "Le associazioni device–vulnerabilità non sono verificabili in "
                    "questo snapshot: la capability Cisco dedicata non è disponibile. "
                    "Eventuali record già presenti restano visibili, ma non ne viene "
                    "dichiarata la completezza."
                )
            if not associations and device_associations_available:
                st.info(
                    "Presente nel catalogo globale Cisco; nessuna associazione "
                    "device–vulnerabilità restituita. Questo non equivale né a presenza "
                    "né ad assenza dimostrata della CVE sui device."
                )
            elif associations:
                association_rows = []
                for association in associations:
                    asset = assets_by_id.get(association["asset_id"], {})
                    risk = scores_by_asset.get(association["asset_id"])
                    association_rows.append(
                        {
                            "Asset": asset.get("name") or association["asset_id"],
                            "Vulnerabilità": association.get("title") or "N/D",
                            "Severità": association.get("severity") or "N/D",
                            "CVSS": association.get("cvss_score"),
                            "Risk score Cisco device": risk.get("score") if risk else None,
                            "Stato": association.get("status") or "N/D",
                            "Verità": truth_badge(association),
                        }
                    )
                render_filterable_table(
                    st,
                    association_rows,
                    key=f"cve-dossier-associations-{selected_catalog_id}",
                    filename_stem="dtlab-cve-device-associations",
                    filter_columns=("Asset", "Severità", "Stato"),
                    search_placeholder="Cerca asset, stato o severità…",
                )
                associated_asset_ids = list(
                    dict.fromkeys(str(item["asset_id"]) for item in associations)
                )
                linked_asset_id = st.selectbox(
                    "Apri Asset 360 associato",
                    associated_asset_ids,
                    format_func=lambda asset_id: assets_by_id.get(asset_id, {}).get(
                        "name", asset_id
                    ),
                    key=f"cve-asset-link-{selected_catalog_id}",
                )
                asset_href = f"/assets?{urlencode({'asset': linked_asset_id})}"
                st.markdown(
                    f"<a class='dt-action-link' href='{safe(asset_href)}'>"
                    "Apri Asset 360 →</a>",
                    unsafe_allow_html=True,
                )

            dossier_json = _cached_cve_dossier(
                context.canonical_snapshot,
                selected_catalog,
            )
            dossier_stem = _safe_export_stem(
                selected_catalog.get("external_id") or selected_catalog_id
            )
            st.download_button(
                "Scarica dossier CVE verificabile · JSON",
                data=dossier_json,
                file_name=f"dtlab-cve-dossier-{dossier_stem}.json",
                mime="application/json",
                icon=":material/folder_managed:",
                key=f"cve-dossier-download-{selected_catalog_id}",
            )

    st.divider()
    st.subheader("Associazioni esplicite device–vulnerabilità")
    if not context.cybervision_capability_available("device_vulnerabilities"):
        empty_state(
            "Associazioni device–vulnerabilità non disponibili",
            "Il portale non trasforma un errore, una licenza assente o una API non letta "
            "in assenza di vulnerabilità sugli asset.",
        )
        return
    capability_notice(
        context,
        "device_vulnerabilities",
        "Associazioni device–vulnerabilità",
    )
    vulnerabilities = snapshot["vulnerabilities"]
    if not vulnerabilities:
        empty_state(
            "Nessuna associazione restituita",
            "La capability ha risposto, ma l'ultima acquisizione non contiene "
            "associazioni device–vulnerabilità. Il catalogo globale sopra resta distinto.",
        )
        return
    assets = {asset["id"]: asset["name"] for asset in snapshot["assets"]}
    columns = st.columns(4)
    with columns[0]:
        metric_card("Associazioni", len(vulnerabilities), "Device–vulnerabilità")
    with columns[1]:
        metric_card(
            "Con CVSS",
            sum(item["cvss_score"] is not None for item in vulnerabilities),
            "Valore tecnico Cisco",
        )
    with columns[2]:
        cvss_values = [
            item["cvss_score"] for item in vulnerabilities if item["cvss_score"] is not None
        ]
        metric_card("CVSS massimo", max(cvss_values) if cvss_values else "N/D", "Scala 0–10")
    with columns[3]:
        metric_card(
            "Riconosciute",
            sum(bool(item["details"].get("acknowledged_at")) for item in vulnerabilities),
            "Ack esplicito Cisco",
        )
    rows = [
        {
            "ID interno": item["id"],
            "Asset": assets.get(item["asset_id"], item["asset_id"]),
            "CVE / ID": item["external_id"] or "N/D",
            "Titolo": item["title"],
            "Severità": item["severity"] if item["severity"] != "unknown" else "N/D",
            "CVSS": item["cvss_score"],
            "Stato": item["status"],
            "Pubblicata": format_local_time(item["published_at"]),
            "Verità": truth_badge(item),
        }
        for item in sorted(
            vulnerabilities,
            key=lambda value: (
                _SEVERITY_ORDER.get(value["severity"].lower(), 9),
                -(value["cvss_score"] or 0),
            ),
        )
    ]
    filtered_rows = render_filterable_table(
        st,
        rows,
        key="vulnerabilities-device-associations",
        filename_stem="dtlab-device-vulnerability-associations",
        filter_columns=("Asset", "Severità", "Stato"),
        search_placeholder="Cerca asset, CVE, titolo o stato…",
        hidden_columns=("ID interno",),
        height=520,
    )
    st.caption(
        "CVSS valuta la severità tecnica della vulnerabilità. Non è lo score di rischio "
        "complessivo del device e non è il CSRS della vulnerabilità."
    )
    if not filtered_rows:
        st.info("Nessuna associazione corrisponde ai filtri selezionati.")
        return
    selected_vulnerability_id = st.selectbox(
        "Dettaglio vulnerabilità",
        [row["ID interno"] for row in filtered_rows],
        format_func=lambda item_id: next(
            item["title"] for item in vulnerabilities if item["id"] == item_id
        ),
    )
    selected = next(item for item in vulnerabilities if item["id"] == selected_vulnerability_id)
    details = selected["details"]
    first, second = st.columns([1.2, 0.8])
    with first:
        st.markdown("#### Descrizione e soluzione")
        st.write(details.get("full_description") or details.get("summary") or "N/D")
        st.markdown("**Soluzione Cisco**")
        st.write(details.get("solution") or "N/D")
    with second:
        st.markdown("#### Dettagli tecnici")
        st.json(
            {
                "cvss": selected["cvss_score"],
                "cvss_temporal": details.get("cvss_temporal"),
                "cvss_version": details.get("cvss_version"),
                "vector": details.get("cvss_vector"),
                "matching_at": details.get("matching_at"),
                "acknowledged_at": details.get("acknowledged_at"),
                "acknowledged_by": details.get("acknowledged_by"),
                "acknowledgement_comment": details.get("acknowledgement_comment"),
                "vendor_id": details.get("vendor_id"),
                "reasons": details.get("reasons", []),
                "links": details.get("links", []),
            },
            expanded=True,
        )


def render_baseline(context: DashboardContext) -> None:
    snapshot = context.snapshot
    page_intro(
        context,
        "Sicurezza",
        "Baseline e differenze",
        "Baseline Cisco, comunicazioni nuove e variazioni rilevate rispetto al comportamento noto.",
    )
    source = context.cybervision_source or {}
    capability = source.get("capabilities", {}).get("baselines", {})
    if capability.get("status") == "feature_unlicensed":
        empty_state(
            "Baseline non licenziata",
            "Cisco ha restituito HTTP 402: funzione disponibile con licenza Advantage. "
            "Non è un errore di sincronizzazione.",
        )
        return
    if not context.cybervision_capability_available("baselines"):
        empty_state(
            "Baseline non disponibile",
            "La capability non è stata acquisita nell'ultima sincronizzazione.",
        )
        return
    baselines = snapshot["baselines"]
    if not baselines:
        empty_state(
            "Nessuna baseline restituita",
            "La capability è disponibile ma non contiene baseline nell'ultima lettura.",
        )
        return
    differences = snapshot["baseline_differences"]
    differences_available = context.cybervision_capability_available("baseline_differences")
    capability_notice(context, "baseline_differences", "Differenze baseline")
    columns = st.columns(3)
    with columns[0]:
        metric_card("Baseline", len(baselines), "Cisco Cyber Vision")
    with columns[1]:
        metric_card(
            "Differenze",
            len(differences) if differences_available else "N/D",
            "Endpoint Cisco differences",
        )
    with columns[2]:
        metric_card(
            "Nuovi elementi",
            sum(
                (baseline["difference_counts"]["new_component"] or 0)
                + (baseline["difference_counts"]["new_activity"] or 0)
                for baseline in baselines
            ),
            "Componenti + attività",
        )
    baseline_rows = [
        {
            "Nome": baseline["name"],
            "Stato": baseline["status"],
            "Creata": format_local_time(baseline["created_at"]),
            "Periodo da": format_local_time(baseline["creation_period_start"]),
            "Periodo a": format_local_time(baseline["creation_period_end"]),
            "Ultimo scan": format_local_time(baseline["last_scan_at"]),
            "Prossimo scan": format_local_time(baseline["next_scan_at"]),
            "Nuovi componenti": baseline["difference_counts"]["new_component"],
            "Componenti cambiati": baseline["difference_counts"]["changed_component"],
            "Nuove attività": baseline["difference_counts"]["new_activity"],
            "Attività cambiate": baseline["difference_counts"]["changed_activity"],
            "Verità": truth_badge(baseline),
        }
        for baseline in baselines
    ]
    render_filterable_table(
        st,
        baseline_rows,
        key="baseline-records",
        filename_stem="dtlab-cisco-baselines",
        filter_columns=("Stato",),
        search_placeholder="Cerca baseline o stato…",
    )
    st.subheader("Differenze")
    if not differences_available:
        empty_state(
            "Differenze non disponibili",
            "Le baseline sono state lette, ma l'endpoint delle differenze non ha fornito "
            "un risultato utilizzabile nell'ultima sincronizzazione.",
        )
    elif differences:
        difference_rows = [
            {
                "Tipo": item["difference_type"],
                "Quando": format_local_time(item["detected_at"]),
                "Target Cisco": item["target_id"] or "N/D",
                "Chiave": item["key"] or "N/D",
                "Valore": item["value"] or "N/D",
                "Descrizione": item["description"],
                "Asset coinvolti": len(item["asset_ids"]),
                "Verità": truth_badge(item),
            }
            for item in differences
        ]
        render_filterable_table(
            st,
            difference_rows,
            key="baseline-differences",
            filename_stem="dtlab-cisco-baseline-differences",
            filter_columns=("Tipo",),
            search_placeholder="Cerca tipo, target, chiave o descrizione…",
        )
        st.caption(
            "I flow causali non vengono attribuiti dal solo targetId: richiedono "
            "l'endpoint Cisco dedicato della singola differenza."
        )
    else:
        empty_state(
            "Nessuna differenza restituita",
            "La baseline è disponibile e non contiene differenze nell'ultima lettura.",
        )
