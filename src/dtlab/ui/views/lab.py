"""Read-only Scenario Lab backed exclusively by the deterministic BeerFactory sandbox."""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from typing import Any

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from dtlab.sandbox import build_sandbox_snapshot
from dtlab.ui.components import empty_state, format_local_time, metric_card
from dtlab.ui.context import DashboardContext
from dtlab.ui.table_tools import render_filterable_table

_SIMULATION_BANNER = "SIMULAZIONE CONTROLLATA — NON DATI LIVE"

_DETECTION_LABELS = {True: "Rilevato", False: "GAP"}
_COMPLIANCE_STATUS_LABELS = {
    "covered": "Coperto",
    "partial": "Parziale",
    "not_covered": "Non coperto",
}
_FRAMEWORK_LABELS = {
    "iec_62443": "IEC 62443",
    "nis2": "NIS2",
    "mitre_attack_ics": "MITRE ATT&CK for ICS",
    "purdue": "Purdue",
}


def _mapping_records(snapshot: Mapping[str, Any], key: str) -> list[dict[str, Any]]:
    """Return mapping records for a sandbox domain without trusting its shape."""

    value = snapshot.get(key, [])
    if not isinstance(value, list):
        return []
    return [dict(item) for item in value if isinstance(item, Mapping)]


def _value_or_na(value: Any) -> Any:
    """Preserve meaningful zero/false values and label only missing data as unavailable."""

    return "N/D" if value is None else value


def _attack_rows(snapshot: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Join sandbox scenarios, runs and detection correlations for the replay table."""

    scenarios = {
        str(item.get("id")): item for item in _mapping_records(snapshot, "attack_scenarios")
    }
    correlations = {
        str(item.get("attack_run_id")): item
        for item in _mapping_records(snapshot, "detection_correlations")
    }
    rows: list[dict[str, Any]] = []
    for run in _mapping_records(snapshot, "attack_runs"):
        run_id = str(run.get("id") or "N/D")
        scenario = scenarios.get(str(run.get("scenario_id")), {})
        correlation = correlations.get(run_id)
        techniques = scenario.get("mitre_techniques", [])
        technique_ids = [
            str(item.get("technique_id"))
            for item in techniques
            if isinstance(item, Mapping) and item.get("technique_id")
        ]
        expected_signals = scenario.get("expected_signals", [])
        detected = correlation.get("detected") if correlation is not None else None
        rows.append(
            {
                "Run ID": run_id,
                "Scenario": scenario.get("name") or run.get("scenario_id") or "N/D",
                "Categoria": scenario.get("category") or "N/D",
                "Severità": scenario.get("severity") or "N/D",
                "Esito replay": run.get("outcome") or run.get("status") or "N/D",
                "Detection": _DETECTION_LABELS.get(detected, "N/D"),
                "Sorgente detection": (
                    correlation.get("detection_source") if correlation is not None else "N/D"
                ),
                "Latenza (s)": (
                    correlation.get("detection_latency_seconds")
                    if correlation is not None
                    else None
                ),
                "MITRE ATT&CK ICS": ", ".join(technique_ids) or "N/D",
                "Segnali attesi": (
                    "; ".join(str(value) for value in expected_signals)
                    if isinstance(expected_signals, list)
                    else "N/D"
                ),
                "Inizio replay": format_local_time(run.get("started_at")),
                "Fine replay": format_local_time(run.get("completed_at")),
                "Modalità": run.get("execution_mode") or scenario.get("execution_mode") or "N/D",
                "Nota": (
                    "; ".join(str(value) for value in correlation.get("notes", []))
                    if correlation is not None
                    else "Correlazione non disponibile"
                ),
            }
        )
    return rows


def _detection_summary(snapshot: Mapping[str, Any]) -> dict[str, int | float | None]:
    correlations = _mapping_records(snapshot, "detection_correlations")
    observed = [item for item in correlations if isinstance(item.get("detected"), bool)]
    detected = sum(item.get("detected") is True for item in observed)
    gaps = sum(item.get("detected") is False for item in observed)
    latencies = [
        float(item["detection_latency_seconds"])
        for item in observed
        if isinstance(item.get("detection_latency_seconds"), int | float)
        and not isinstance(item.get("detection_latency_seconds"), bool)
    ]
    return {
        "scenarios": len(_mapping_records(snapshot, "attack_scenarios")),
        "runs": len(_mapping_records(snapshot, "attack_runs")),
        "detected": detected,
        "gaps": gaps,
        "coverage_pct": round(detected / len(observed) * 100, 1) if observed else None,
        "mean_latency_seconds": round(sum(latencies) / len(latencies), 1) if latencies else None,
    }


def _telemetry_rows(snapshot: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Flatten replay telemetry while preserving unknown/out-of-range truth states."""

    rows: list[dict[str, Any]] = []
    for sample in _mapping_records(snapshot, "process_telemetry"):
        registers = sample.get("registers", [])
        if not isinstance(registers, list):
            continue
        for register in registers:
            if not isinstance(register, Mapping):
                continue
            in_bounds = register.get("in_bounds")
            rows.append(
                {
                    "Campione": sample.get("id") or "N/D",
                    "Timestamp replay": format_local_time(sample.get("captured_at")),
                    "Timestamp ISO": sample.get("captured_at"),
                    "Processo": sample.get("process") or "N/D",
                    "Stato nastro": sample.get("belt_state") or "N/D",
                    "Anomalia": sample.get("anomaly") or "Nessuna",
                    "Run attacco": sample.get("attack_run_id") or "Nessuno",
                    "Registro": register.get("name") or "N/D",
                    "Indirizzo": register.get("address"),
                    "Tipo": register.get("kind") or "N/D",
                    "Valore": register.get("value"),
                    "Unità": register.get("unit") or "—",
                    "Min atteso": register.get("expected_min"),
                    "Max atteso": register.get("expected_max"),
                    "In range": (
                        "Sì" if in_bounds is True else "No" if in_bounds is False else "N/D"
                    ),
                }
            )
    return rows


def _zone_rows(snapshot: Mapping[str, Any]) -> list[dict[str, Any]]:
    assets = {
        str(item.get("id")): str(item.get("name") or item.get("id"))
        for item in _mapping_records(snapshot, "assets")
    }
    rows = []
    for zone in _mapping_records(snapshot, "security_zones"):
        asset_ids = zone.get("asset_ids", [])
        asset_labels = (
            [assets.get(str(asset_id), str(asset_id)) for asset_id in asset_ids]
            if isinstance(asset_ids, list)
            else []
        )
        conduits = zone.get("conduits", [])
        rows.append(
            {
                "Zone ID": zone.get("id") or "N/D",
                "Zona": zone.get("name") or "N/D",
                "Livello Purdue": zone.get("purdue_level") or "N/D",
                "Zona IEC 62443": zone.get("iec62443_zone") or "N/D",
                "Target SL": zone.get("target_security_level") or "N/D",
                "Asset": ", ".join(asset_labels) or "Nessuno",
                "Conduit": len(conduits) if isinstance(conduits, list) else 0,
                "Descrizione": zone.get("description") or "N/D",
            }
        )
    return rows


def _conduit_rows(snapshot: Mapping[str, Any]) -> list[dict[str, Any]]:
    zones = _mapping_records(snapshot, "security_zones")
    zone_names = {str(item.get("id")): str(item.get("name") or item.get("id")) for item in zones}
    rows: list[dict[str, Any]] = []
    for zone in zones:
        conduits = zone.get("conduits", [])
        if not isinstance(conduits, list):
            continue
        for conduit in conduits:
            if not isinstance(conduit, Mapping):
                continue
            protocols = conduit.get("protocols", [])
            rows.append(
                {
                    "Da": zone.get("name") or zone.get("id") or "N/D",
                    "A": zone_names.get(
                        str(conduit.get("to_zone_id")),
                        str(conduit.get("to_zone_id") or "N/D"),
                    ),
                    "Protocolli": (
                        ", ".join(str(value) for value in protocols)
                        if isinstance(protocols, list)
                        else "N/D"
                    ),
                    "Descrizione": conduit.get("description") or "N/D",
                }
            )
    return rows


def _compliance_rows(snapshot: Mapping[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for mapping in _mapping_records(snapshot, "compliance_mappings"):
        status = str(mapping.get("status") or "unknown")
        asset_ids = mapping.get("asset_ids", [])
        zone_ids = mapping.get("zone_ids", [])
        evidence_refs = mapping.get("evidence_refs", [])
        notes = mapping.get("notes", [])
        rows.append(
            {
                "Mapping ID": mapping.get("id") or "N/D",
                "Framework": _FRAMEWORK_LABELS.get(
                    str(mapping.get("framework")), str(mapping.get("framework") or "N/D")
                ),
                "Riferimento": mapping.get("reference_id") or "N/D",
                "Controllo": mapping.get("title") or "N/D",
                "Stato": _COMPLIANCE_STATUS_LABELS.get(status, "N/D"),
                "Asset ID": (
                    ", ".join(str(value) for value in asset_ids)
                    if isinstance(asset_ids, list)
                    else "N/D"
                )
                or "—",
                "Zone ID": (
                    ", ".join(str(value) for value in zone_ids)
                    if isinstance(zone_ids, list)
                    else "N/D"
                )
                or "—",
                "Evidenze replay": (
                    ", ".join(str(value) for value in evidence_refs)
                    if isinstance(evidence_refs, list)
                    else "N/D"
                )
                or "—",
                "Note": (
                    "; ".join(str(value) for value in notes) if isinstance(notes, list) else "N/D"
                )
                or "—",
            }
        )
    return rows


def _history_rows(snapshot: Mapping[str, Any]) -> list[dict[str, Any]]:
    history = snapshot.get("history", {})
    if not isinstance(history, Mapping):
        return []
    points = history.get("points", [])
    if not isinstance(points, list):
        return []
    rows: list[dict[str, Any]] = []
    for point in points:
        if not isinstance(point, Mapping):
            continue
        metrics = point.get("metrics", {})
        if not isinstance(metrics, Mapping):
            metrics = {}
        coverage = metrics.get("attack_detection_coverage")
        rows.append(
            {
                "Snapshot replay": point.get("snapshot_id") or "N/D",
                "Timestamp replay": format_local_time(point.get("generated_at")),
                "Timestamp ISO": point.get("generated_at"),
                "Qualità": metrics.get("quality_score"),
                "Copertura detection (%)": (
                    round(float(coverage) * 100, 1)
                    if isinstance(coverage, int | float) and not isinstance(coverage, bool)
                    else None
                ),
                "Detection": metrics.get("detections"),
                "Attacchi non rilevati": metrics.get("undetected_attacks"),
                "Latenza media (s)": metrics.get("mean_detection_latency_seconds"),
                "Ticket aperti (scenario)": metrics.get("open_tickets"),
                "Asset ad alto rischio": metrics.get("high_risk_assets"),
            }
        )
    return rows


@st.cache_data(show_spinner=False)
def _load_lab_snapshot() -> dict[str, Any]:
    """Build the validated deterministic dataset without reading the operational store."""

    return build_sandbox_snapshot()


def _chart_layout(figure: go.Figure, *, height: int = 360) -> None:
    figure.update_layout(
        height=height,
        margin={"l": 20, "r": 20, "t": 40, "b": 30},
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        hovermode="x unified",
        legend={"orientation": "h", "y": 1.12, "x": 0},
    )


def _render_attacks(snapshot: Mapping[str, Any]) -> None:
    summary = _detection_summary(snapshot)
    columns = st.columns(4)
    with columns[0]:
        metric_card("Scenari", summary["scenarios"], "Replay deterministico")
    with columns[1]:
        coverage = summary["coverage_pct"]
        metric_card(
            "Copertura detection",
            f"{coverage:g}%" if isinstance(coverage, int | float) else "N/D",
            f"{summary['detected']} rilevati · {summary['gaps']} gap",
        )
    with columns[2]:
        metric_card("Gap", summary["gaps"], "Da trasformare in requisiti")
    with columns[3]:
        latency = summary["mean_latency_seconds"]
        metric_card(
            "Latenza media",
            f"{latency:g} s" if isinstance(latency, int | float) else "N/D",
            "Solo detection riuscite",
        )

    rows = _attack_rows(snapshot)
    if not rows:
        empty_state(
            "Replay attacchi non disponibile",
            "Il dataset sandbox non contiene scenari o run validi.",
        )
        return

    gaps = [row for row in rows if row["Detection"] == "GAP"]
    if gaps:
        st.warning(
            "Gap simulati da investigare: "
            + ", ".join(str(row["Scenario"]) for row in gaps)
            + ". Nessuna remediation viene eseguita da questa pagina."
        )

    detected_rows = [
        row
        for row in rows
        if row["Detection"] == "Rilevato" and isinstance(row["Latenza (s)"], int | float)
    ]
    if detected_rows:
        figure = go.Figure(
            go.Bar(
                x=[row["Scenario"] for row in detected_rows],
                y=[row["Latenza (s)"] for row in detected_rows],
                marker_color="#006b5f",
                text=[f"{row['Latenza (s)']:g} s" for row in detected_rows],
                textposition="auto",
            )
        )
        figure.update_yaxes(title="Latenza simulata (secondi)", rangemode="tozero")
        _chart_layout(figure)
        st.plotly_chart(figure, use_container_width=True, config={"displayModeBar": False})

    render_filterable_table(
        st,
        rows,
        key="scenario-lab-attacks",
        filename_stem="dtlab-sandbox-attack-detection-replay",
        filter_columns=("Detection", "Severità", "Categoria"),
        search_placeholder="Cerca scenario, tecnica MITRE, segnale o run…",
        hidden_columns=("Run ID",),
        height=430,
    )


def _render_digital_twin(snapshot: Mapping[str, Any]) -> None:
    rows = _telemetry_rows(snapshot)
    if not rows:
        empty_state(
            "Digital Twin non disponibile",
            "Il dataset sandbox non contiene campioni di telemetria Modbus.",
        )
        return

    sample_count = len({str(row["Campione"]) for row in rows})
    anomalies = len({str(row["Campione"]) for row in rows if str(row["Anomalia"]) != "Nessuna"})
    out_of_bounds = sum(row["In range"] == "No" for row in rows)
    columns = st.columns(4)
    with columns[0]:
        metric_card("Campioni", sample_count, "Telemetria sintetica")
    with columns[1]:
        metric_card("Registri", len(rows), "Valori nel replay")
    with columns[2]:
        metric_card("Campioni anomali", anomalies, "unexpected_write")
    with columns[3]:
        metric_card("Fuori range", out_of_bounds, "Valori con bound esplicito")

    frame = pd.DataFrame(rows)
    frame["_time"] = pd.to_datetime(frame["Timestamp ISO"], utc=True, errors="coerce")
    numeric = frame[
        frame["Registro"].isin(["conveyor_speed_rpm", "setpoint_speed_rpm", "temperature_c"])
    ].copy()
    numeric["_value"] = pd.to_numeric(numeric["Valore"], errors="coerce")
    numeric = numeric.dropna(subset=["_time", "_value"])
    if not numeric.empty:
        colors = {
            "conveyor_speed_rpm": "#006b5f",
            "setpoint_speed_rpm": "#735c00",
            "temperature_c": "#465d91",
        }
        figure = go.Figure()
        for register_name, series in numeric.groupby("Registro", sort=False):
            figure.add_trace(
                go.Scatter(
                    x=series["_time"],
                    y=series["_value"],
                    mode="lines+markers",
                    name=str(register_name),
                    line={"color": colors.get(str(register_name), "#626262")},
                )
            )
        anomaly_series = numeric[
            (numeric["Registro"] == "conveyor_speed_rpm") & (numeric["Anomalia"] != "Nessuna")
        ]
        if not anomaly_series.empty:
            figure.add_trace(
                go.Scatter(
                    x=anomaly_series["_time"],
                    y=anomaly_series["_value"],
                    mode="markers",
                    name="Finestra anomala",
                    marker={"color": "#ba1a1a", "size": 13, "symbol": "diamond"},
                )
            )
        figure.update_yaxes(title="Valore del registro (unità native)")
        _chart_layout(figure, height=410)
        st.plotly_chart(figure, use_container_width=True, config={"displayModeBar": False})
        st.caption(
            "RPM e °C condividono il grafico per il confronto temporale; le unità native "
            "restano dichiarate nella tabella tecnica."
        )

    render_filterable_table(
        st,
        rows,
        key="scenario-lab-digital-twin",
        filename_stem="dtlab-sandbox-modbus-telemetry",
        filter_columns=("Registro", "In range", "Anomalia"),
        search_placeholder="Cerca registro, processo, campione o run…",
        hidden_columns=("Timestamp ISO",),
        height=460,
    )


def _render_purdue_compliance(snapshot: Mapping[str, Any]) -> None:
    zone_rows = _zone_rows(snapshot)
    compliance_rows = _compliance_rows(snapshot)
    conduits = _conduit_rows(snapshot)
    status_counts = Counter(row["Stato"] for row in compliance_rows)

    columns = st.columns(4)
    with columns[0]:
        metric_card("Zone", len(zone_rows) if zone_rows else "N/D", "Purdue / IEC 62443")
    with columns[1]:
        metric_card("Conduit", len(conduits) if zone_rows else "N/D", "Relazioni simulate")
    with columns[2]:
        metric_card("Controlli coperti", status_counts["Coperto"], "Evidenze replay")
    with columns[3]:
        metric_card(
            "Gap / parziali",
            status_counts["Non coperto"] + status_counts["Parziale"],
            "Backlog di miglioramento",
        )

    if zone_rows:
        st.markdown("#### Segmentazione Purdue e zone IEC 62443")
        render_filterable_table(
            st,
            zone_rows,
            key="scenario-lab-zones",
            filename_stem="dtlab-sandbox-purdue-zones",
            filter_columns=("Livello Purdue", "Target SL"),
            search_placeholder="Cerca zona, asset, livello o descrizione…",
            hidden_columns=("Zone ID",),
        )
        if conduits:
            with st.expander(f"Conduit tra zone ({len(conduits)})"):
                render_filterable_table(
                    st,
                    conduits,
                    key="scenario-lab-conduits",
                    filename_stem="dtlab-sandbox-zone-conduits",
                    filter_columns=("Protocolli",),
                    search_placeholder="Cerca zona, protocollo o descrizione…",
                )
    else:
        empty_state(
            "Zone non disponibili",
            "Il dataset sandbox non contiene una segmentazione Purdue valida.",
        )

    st.markdown("#### Matrice di copertura")
    if not compliance_rows:
        empty_state(
            "Mapping di compliance non disponibile",
            "Il dataset sandbox non contiene controlli associati alle evidenze del replay.",
        )
        return

    framework_order = list(dict.fromkeys(row["Framework"] for row in compliance_rows))
    figure = go.Figure()
    status_colors = {
        "Coperto": "#006b5f",
        "Parziale": "#d38600",
        "Non coperto": "#ba1a1a",
    }
    for status, color in status_colors.items():
        figure.add_trace(
            go.Bar(
                name=status,
                x=framework_order,
                y=[
                    sum(
                        row["Framework"] == framework and row["Stato"] == status
                        for row in compliance_rows
                    )
                    for framework in framework_order
                ],
                marker_color=color,
            )
        )
    figure.update_layout(barmode="stack")
    figure.update_yaxes(title="Controlli mappati", dtick=1)
    _chart_layout(figure)
    st.plotly_chart(figure, use_container_width=True, config={"displayModeBar": False})
    render_filterable_table(
        st,
        compliance_rows,
        key="scenario-lab-compliance",
        filename_stem="dtlab-sandbox-compliance-matrix",
        filter_columns=("Framework", "Stato"),
        search_placeholder="Cerca controllo, riferimento, asset o evidenza…",
        hidden_columns=("Mapping ID",),
        height=430,
    )


def _render_trend(snapshot: Mapping[str, Any]) -> None:
    rows = _history_rows(snapshot)
    if not rows:
        empty_state(
            "Trend non disponibile",
            "Il dataset sandbox non contiene punti storici sintetici.",
        )
        return

    latest = rows[-1]
    columns = st.columns(4)
    with columns[0]:
        metric_card("Punti replay", len(rows), "Serie storica sintetica")
    with columns[1]:
        metric_card(
            "Qualità",
            _value_or_na(latest["Qualità"]),
            "Ultimo punto simulato",
        )
    with columns[2]:
        coverage = latest["Copertura detection (%)"]
        metric_card(
            "Copertura",
            f"{coverage:g}%" if isinstance(coverage, int | float) else "N/D",
            "Ultimo punto simulato",
        )
    with columns[3]:
        metric_card(
            "Ticket aperti",
            _value_or_na(latest["Ticket aperti (scenario)"]),
            "Scenario, non ticket operativi",
        )

    frame = pd.DataFrame(rows)
    frame["_time"] = pd.to_datetime(frame["Timestamp ISO"], utc=True, errors="coerce")
    score_figure = go.Figure()
    for column, color in (
        ("Qualità", "#006b5f"),
        ("Copertura detection (%)", "#465d91"),
    ):
        score_figure.add_trace(
            go.Scatter(
                x=frame["_time"],
                y=frame[column],
                mode="lines+markers",
                name=column,
                line={"color": color},
            )
        )
    score_figure.update_yaxes(title="Percentuale", range=[0, 100])
    _chart_layout(score_figure)
    st.plotly_chart(
        score_figure,
        use_container_width=True,
        config={"displayModeBar": False},
    )

    count_figure = go.Figure()
    for column, color in (
        ("Detection", "#006b5f"),
        ("Attacchi non rilevati", "#ba1a1a"),
        ("Ticket aperti (scenario)", "#735c00"),
    ):
        count_figure.add_trace(
            go.Scatter(
                x=frame["_time"],
                y=frame[column],
                mode="lines+markers",
                name=column,
                line={"color": color},
            )
        )
    count_figure.update_yaxes(title="Conteggio scenario", rangemode="tozero", dtick=1)
    _chart_layout(count_figure)
    st.plotly_chart(
        count_figure,
        use_container_width=True,
        config={"displayModeBar": False},
    )
    render_filterable_table(
        st,
        rows,
        key="scenario-lab-trend",
        filename_stem="dtlab-sandbox-history-trend",
        search_placeholder="Cerca snapshot o timestamp del replay…",
        hidden_columns=("Timestamp ISO",),
        height=360,
    )


def render_scenario_lab(_context: DashboardContext) -> None:
    """Render a read-only lab that never reads or mutates the operational snapshot."""

    snapshot = _load_lab_snapshot()
    environment = snapshot.get("environment", {})
    environment_name = (
        environment.get("name") if isinstance(environment, Mapping) else "BeerFactory sandbox"
    )

    st.markdown(
        "<section class='dt-hero'>"
        "<div class='dt-eyebrow'>Scenario Lab · replay isolato</div>"
        "<h1>BeerFactory Detection & Process Lab</h1>"
        "<p>Esplora detection, processo Modbus, segmentazione e controlli su un dataset "
        "deterministico. Il laboratorio è separato dallo store operativo.</p>"
        "</section>",
        unsafe_allow_html=True,
    )
    st.error(
        f"**{_SIMULATION_BANNER}**  \n"
        "Dataset BeerFactory deterministico e read-only. Non rappresenta lo stato "
        "corrente di Cisco Cyber Vision, VMware, PLC o ticket; non esegue attacchi, "
        "remediation o pubblicazioni nello store operativo."
    )
    st.caption(
        f"Dataset: {environment_name or 'BeerFactory sandbox'} · "
        f"Snapshot: {snapshot.get('snapshot_id', 'N/D')} · "
        f"Generato per il replay: {format_local_time(snapshot.get('generated_at'))}"
    )

    attacks_tab, twin_tab, compliance_tab, trend_tab = st.tabs(
        [
            "Attacchi & detection",
            "Digital Twin Modbus",
            "Purdue / compliance",
            "Trend",
        ]
    )
    with attacks_tab:
        st.caption(
            "Correlazioni già presenti nel replay: la pagina non avvia traffico e non "
            "crea ticket operativi."
        )
        _render_attacks(snapshot)
    with twin_tab:
        st.caption(
            "Telemetria Modbus sintetica del nastro BeerFactory, inclusa la finestra di "
            "scrittura inattesa."
        )
        _render_digital_twin(snapshot)
    with compliance_tab:
        st.caption(
            "Modello Purdue e mapping normativo di scenario: evidenze e gap valgono solo "
            "per il replay BeerFactory."
        )
        _render_purdue_compliance(snapshot)
    with trend_tab:
        st.caption(
            "Serie temporale sintetica per mostrare l'evoluzione futura del controllo; "
            "non è uno storico operativo."
        )
        _render_trend(snapshot)
