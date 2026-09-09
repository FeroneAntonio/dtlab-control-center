from __future__ import annotations

import html
import json
from datetime import timedelta

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from data_adapter import (
    SnapshotValidationError,
    load_snapshot,
    snapshot_from_dict,
    snapshot_schema,
)
from demo_data import build_demo_payload
from export_bundle import (
    build_evidence_bundle,
    build_technical_bundle,
    frame_records,
    normalized_payload,
)


st.set_page_config(
    page_title="DTLab OT Security",
    page_icon="DT",
    layout="wide",
    initial_sidebar_state="expanded",
)


COLORS = {
    "ink": "#172126",
    "muted": "#657178",
    "line": "#D8DEE2",
    "panel": "#FFFFFF",
    "canvas": "#F3F5F6",
    "teal": "#087F6A",
    "green": "#23885B",
    "amber": "#C47B12",
    "red": "#C7423A",
    "blue": "#2E6F9E",
}

SEVERITY_COLORS = {
    "Critica": COLORS["red"],
    "Alta": "#E17832",
    "Media": COLORS["amber"],
    "Bassa": COLORS["blue"],
}

RISK_COLORS = {
    "Critico": COLORS["red"],
    "Alto": "#E17832",
    "Medio": COLORS["amber"],
    "Basso": COLORS["green"],
}

BASELINE_COLORS = {
    "Atteso": "#A8B3B8",
    "Nuovo": COLORS["amber"],
    "Deviazione": COLORS["red"],
}

DETECTION_RULES = [
    {
        "ID": "OT-DET-001",
        "Caso d'uso": "Scrittura Modbus non autorizzata",
        "Condizione": "FC 05/06/15/16 da sorgente fuori allowlist",
        "Severità": "Critica",
        "Evidenza": "Asset, registro/coil, valore, transaction ID e PCAP",
        "MITRE ICS": "T1692.001",
    },
    {
        "ID": "OT-DET-002",
        "Caso d'uso": "Nuovo asset",
        "Condizione": "Identità non presente nella baseline di zona",
        "Severità": "Alta",
        "Evidenza": "First seen, MAC, vendor, switch/porta e zona",
        "MITRE ICS": "-",
    },
    {
        "ID": "OT-DET-003",
        "Caso d'uso": "Comunicazione inter-zona",
        "Condizione": "Flow non previsto tra zone o conduit",
        "Severità": "Alta",
        "Evidenza": "Sorgente, destinazione, protocollo e policy attesa",
        "MITRE ICS": "-",
    },
    {
        "ID": "OT-DET-004",
        "Caso d'uso": "Variazione firmware",
        "Condizione": "Versione diversa dall'inventario approvato",
        "Severità": "Media",
        "Evidenza": "Versione precedente, nuova versione e timestamp",
        "MITRE ICS": "-",
    },
    {
        "ID": "OT-DET-005",
        "Caso d'uso": "Frequenza anomala",
        "Condizione": "Tasso richieste oltre il profilo normale",
        "Severità": "Media",
        "Evidenza": "Baseline, soglia, finestra e valore osservato",
        "MITRE ICS": "-",
    },
    {
        "ID": "OT-DET-007",
        "Caso d'uso": "Servizio inatteso",
        "Condizione": "Porta o protocollo incoerenti con il ruolo asset",
        "Severità": "Alta",
        "Evidenza": "Servizio, direzione, first seen e last seen",
        "MITRE ICS": "-",
    },
]

VERIFICATION_STEPS = {
    "Scrittura non autorizzata": [
        "Confermare che la sorgente non appartenga all'allowlist operativa.",
        "Correlare function code, transaction ID, registro o coil e valore osservato.",
        "Verificare con l'operatore lo stato reale del processo prima di qualsiasi azione.",
        "Preservare PCAP e log sorgente e aprire il caso nel SIEM.",
    ],
    "Nuovo asset": [
        "Verificare MAC, vendor, switch/porta e prima osservazione.",
        "Confrontare l'asset con inventario, manutenzioni e finestre autorizzate.",
        "Classificare ruolo, zona e criticità prima di inserirlo nella baseline.",
    ],
    "Comunicazione inter-zona": [
        "Confrontare il flow con la matrice zone/conduit approvata.",
        "Verificare se sorgente, destinazione e protocollo sono ammessi.",
        "Conservare la sequenza temporale e gli eventi correlati.",
    ],
    "Variazione firmware": [
        "Confrontare la versione con l'ultimo inventario approvato.",
        "Verificare change ticket, finestra di manutenzione e firma del pacchetto.",
        "Aggiornare la baseline solo dopo conferma del referente OT.",
    ],
    "Frequenza anomala": [
        "Controllare soglia, finestra temporale e stagionalità del processo.",
        "Confrontare il volume con turni, ricette e manutenzioni pianificate.",
        "Escludere errori di sensore o problemi di rete prima dell'escalation.",
    ],
    "Servizio inatteso": [
        "Confermare che il servizio non sia previsto per il ruolo dell'asset.",
        "Verificare first seen, direzione del flow e processo che ha aperto la connessione.",
        "Correlare l'evento con accessi remoti e attività della workstation engineering.",
    ],
}


st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Montserrat:wght@400;500;600;700&display=swap');
    html, body, [class*="css"], [data-testid="stAppViewContainer"] {
        font-family: 'Montserrat', Arial, sans-serif;
        color: #172126;
        letter-spacing: 0;
    }
    [data-testid="stAppViewContainer"] { background: #F3F5F6; }
    [data-testid="stHeader"] { background: transparent; }
    [data-testid="stToolbar"] { display: none; }
    [data-testid="stSidebar"] { background: #FFFFFF; border-right: 1px solid #D8DEE2; }
    [data-testid="stSidebar"] h1, [data-testid="stSidebar"] h2, [data-testid="stSidebar"] h3 {
        font-size: 1rem !important;
    }
    .block-container { max-width: 1500px; padding-top: 1.25rem; padding-bottom: 2rem; }
    h1, h2, h3 { letter-spacing: 0 !important; }
    h1 { font-size: 1.62rem !important; font-weight: 700 !important; margin-bottom: .2rem !important; }
    h2 { font-size: 1.08rem !important; font-weight: 700 !important; margin-top: .45rem !important; }
    h3 { font-size: .98rem !important; font-weight: 700 !important; }
    p, label, .stMarkdown { font-size: .9rem; }
    [data-testid="stMetric"] {
        background: #FFFFFF;
        border: 1px solid #D8DEE2;
        border-radius: 6px;
        padding: .85rem 1rem;
        min-height: 108px;
    }
    [data-testid="stMetricLabel"] { color: #657178; font-weight: 600; }
    [data-testid="stMetricValue"] { font-size: 1.62rem; font-weight: 700; }
    .dt-kpi {
        background:#FFFFFF;
        border:1px solid #D8DEE2;
        border-radius:6px;
        padding:.85rem 1rem;
        min-height:108px;
        display:flex;
        flex-direction:column;
        justify-content:space-between;
    }
    .dt-kpi-label { color:#657178; font-size:.75rem; font-weight:600; }
    .dt-kpi-value { color:#172126; font-size:1.75rem; line-height:1.15; font-weight:700; }
    .dt-kpi-meta { font-size:.72rem; font-weight:600; }
    .dt-kpi-meta.green { color:#23885B; }
    .dt-kpi-meta.amber { color:#9B610C; }
    .dt-kpi-meta.red { color:#C7423A; }
    .dt-kpi-meta.blue { color:#2E6F9E; }
    [data-testid="stPlotlyChart"] {
        background: #FFFFFF;
        border: 1px solid #D8DEE2;
        border-radius: 6px;
        padding: .25rem;
    }
    [data-testid="stDataFrame"] { border: 1px solid #D8DEE2; border-radius: 6px; }
    .dt-topline { display:flex; align-items:center; justify-content:space-between; gap:16px; margin-bottom:4px; }
    .dt-kicker { color:#087F6A; font-size:.72rem; font-weight:700; text-transform:uppercase; }
    .dt-subtitle { color:#657178; font-size:.84rem; margin-bottom:.9rem; }
    .dt-badge-row { display:flex; align-items:center; justify-content:flex-end; flex-wrap:wrap; gap:7px; }
    .dt-badge { display:inline-flex; align-items:center; gap:7px; border:1px solid #D8DEE2; border-radius:999px; background:#FFFFFF; padding:5px 9px; font-size:.7rem; font-weight:700; }
    .dt-dot { width:7px; height:7px; border-radius:50%; background:#23885B; }
    .dt-dot.demo { background:#C47B12; }
    .dt-banner { border-left:4px solid #C47B12; background:#FFF7E8; padding:10px 13px; margin:4px 0 15px; color:#6C4A13; font-size:.79rem; font-weight:600; }
    .dt-section { display:flex; align-items:center; justify-content:space-between; gap:12px; margin:1rem 0 .45rem; }
    .dt-section-title { font-size:.94rem; font-weight:700; }
    .dt-section-meta { color:#657178; font-size:.72rem; }
    .dt-asset-head { border-left:4px solid #087F6A; background:#FFFFFF; border-top:1px solid #D8DEE2; border-right:1px solid #D8DEE2; border-bottom:1px solid #D8DEE2; border-radius:6px; padding:13px 15px; margin-bottom:12px; }
    .dt-asset-name { font-weight:700; font-size:1rem; }
    .dt-asset-meta { color:#657178; font-size:.76rem; margin-top:3px; }
    .dt-status { font-weight:700; }
    .dt-status.online { color:#23885B; }
    .dt-status.offline { color:#C7423A; }
    .stTabs [data-baseweb="tab-list"] { gap: 4px; border-bottom:1px solid #D8DEE2; overflow-x:auto; }
    .stTabs [data-baseweb="tab"] { height:42px; padding:0 12px; font-weight:600; white-space:nowrap; }
    .stButton > button, .stDownloadButton > button, .stLinkButton > a { border-radius:5px; font-weight:600; }
    footer { visibility:hidden; }
    @media (max-width: 760px) {
        .block-container { padding-left:.75rem; padding-right:.75rem; }
        .dt-topline { align-items:flex-start; flex-direction:column; }
        .dt-badge-row { justify-content:flex-start; }
        .dt-kpi { min-height:104px; }
    }
    </style>
    """,
    unsafe_allow_html=True,
)


def clean(value: object) -> str:
    if value is None or pd.isna(value):
        return "-"
    return html.escape(str(value))


def italy_time(value: object) -> str:
    if value is None or pd.isna(value):
        return "-"
    timestamp = pd.Timestamp(value)
    if timestamp.tzinfo is None:
        timestamp = timestamp.tz_localize("UTC")
    return timestamp.tz_convert("Europe/Rome").strftime("%d/%m/%Y %H:%M")


def chart_layout(fig: go.Figure, height: int = 310) -> go.Figure:
    fig.update_layout(
        height=height,
        margin=dict(l=18, r=18, t=44, b=18),
        paper_bgcolor=COLORS["panel"],
        plot_bgcolor=COLORS["panel"],
        font=dict(family="Montserrat, Arial, sans-serif", color=COLORS["ink"], size=12),
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
        hoverlabel=dict(font_family="Montserrat"),
    )
    fig.update_xaxes(showgrid=False, linecolor=COLORS["line"], tickfont=dict(size=11))
    fig.update_yaxes(gridcolor="#EDF0F2", zeroline=False, tickfont=dict(size=11))
    return fig


def kpi_card(label: str, value: str, meta: str, tone: str = "green") -> None:
    st.markdown(
        f"""
        <div class="dt-kpi">
          <div class="dt-kpi-label">{clean(label)}</div>
          <div class="dt-kpi-value">{clean(value)}</div>
          <div class="dt-kpi-meta {tone}">{clean(meta)}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def stage_for_asset(asset_type: str) -> str:
    if asset_type in {"Gateway", "Switch"}:
        return "Rete"
    if asset_type in {"Server", "Workstation", "Access Point"}:
        return "Servizi / Engineering"
    if asset_type in {"PLC", "HMI"}:
        return "Controllo"
    return "Campo"


def topology_figure(assets: pd.DataFrame, flows: pd.DataFrame) -> go.Figure:
    stages = ["Rete", "Servizi / Engineering", "Controllo", "Campo"]
    positions: dict[str, tuple[float, float]] = {}
    by_stage: dict[str, list[pd.Series]] = {stage: [] for stage in stages}
    for _, asset in assets.sort_values(["asset_type", "name"]).iterrows():
        by_stage[stage_for_asset(str(asset["asset_type"]))].append(asset)

    for x, stage in enumerate(stages):
        stage_assets = by_stage[stage]
        for index, asset in enumerate(stage_assets):
            y = (len(stage_assets) - 1) / 2 - index
            positions[str(asset["asset_id"])] = (x, y)

    figure = go.Figure()
    for baseline_status in ["Atteso", "Nuovo", "Deviazione"]:
        x_values: list[float | None] = []
        y_values: list[float | None] = []
        hover: list[str | None] = []
        status_flows = flows[flows["baseline_status"] == baseline_status]
        for _, flow in status_flows.iterrows():
            source = positions.get(str(flow["source_asset_id"]))
            destination = positions.get(str(flow["destination_asset_id"]))
            if source is None or destination is None:
                continue
            text = (
                f"{clean(flow['source_asset_id'])} → {clean(flow['destination_asset_id'])}<br>"
                f"{clean(flow['protocol'])} / {clean(flow['port'])}<br>"
                f"Messaggi: {clean(flow['messages'])}<br>Baseline: {clean(baseline_status)}"
            )
            x_values.extend([source[0], destination[0], None])
            y_values.extend([source[1], destination[1], None])
            hover.extend([text, text, None])
        figure.add_trace(
            go.Scatter(
                x=x_values,
                y=y_values,
                mode="lines",
                name=baseline_status,
                line=dict(
                    color=BASELINE_COLORS[baseline_status],
                    width=3 if baseline_status != "Atteso" else 1.4,
                ),
                hovertext=hover,
                hoverinfo="text",
            )
        )

    for risk in ["Critico", "Alto", "Medio", "Basso"]:
        risk_assets = assets[assets["risk"] == risk]
        node_x: list[float] = []
        node_y: list[float] = []
        labels: list[str] = []
        label_positions: list[str] = []
        hover: list[str] = []
        for _, asset in risk_assets.iterrows():
            position = positions.get(str(asset["asset_id"]))
            if position is None:
                continue
            node_x.append(position[0])
            node_y.append(position[1])
            labels.append(str(asset["name"]))
            label_positions.append("middle left" if position[0] >= 3 else "middle right")
            hover.append(
                f"<b>{clean(asset['name'])}</b><br>IP: {clean(asset['ip_address'])}<br>"
                f"Tipo: {clean(asset['asset_type'])}<br>Zona: {clean(asset['zone'])}<br>"
                f"Protocollo: {clean(asset['protocol'])}<br>Rischio: {clean(asset['risk'])}"
            )
        figure.add_trace(
            go.Scatter(
                x=node_x,
                y=node_y,
                mode="markers+text",
                name=f"Rischio {risk}",
                text=labels,
                textposition=label_positions,
                textfont=dict(size=10),
                marker=dict(
                    size=20,
                    color=RISK_COLORS[risk],
                    line=dict(width=2, color="#FFFFFF"),
                ),
                hovertext=hover,
                hoverinfo="text",
            )
        )

    max_stage_size = max((len(items) for items in by_stage.values()), default=1)
    for x, stage in enumerate(stages):
        figure.add_annotation(
            x=x,
            y=max_stage_size / 2 + 0.9,
            text=f"<b>{stage}</b>",
            showarrow=False,
            font=dict(size=12, color=COLORS["muted"]),
        )
        if x < len(stages) - 1:
            figure.add_vline(x=x + 0.5, line_width=1, line_dash="dot", line_color=COLORS["line"])

    figure.update_layout(
        height=620,
        margin=dict(l=25, r=170, t=55, b=25),
        paper_bgcolor=COLORS["panel"],
        plot_bgcolor=COLORS["panel"],
        font=dict(family="Montserrat, Arial, sans-serif", color=COLORS["ink"], size=11),
        legend=dict(orientation="h", yanchor="bottom", y=1.01, xanchor="right", x=1),
        hoverlabel=dict(font_family="Montserrat"),
        xaxis=dict(visible=False, range=[-0.35, 3.65], fixedrange=True),
        yaxis=dict(visible=False, range=[-max_stage_size / 2 - 0.6, max_stage_size / 2 + 1.4], fixedrange=True),
    )
    return figure


demo_payload = build_demo_payload()

with st.sidebar:
    st.markdown("### DTLab OT Security")
    st.caption("Governance e monitoraggio tecnico")
    source_mode = st.segmented_control(
        "Origine dati",
        options=["Demo", "Snapshot JSON"],
        default="Demo",
        width="stretch",
    )
    uploaded = None
    if source_mode == "Snapshot JSON":
        uploaded = st.file_uploader("Snapshot", type=["json"], label_visibility="collapsed")
    st.divider()
    st.markdown("### Ambito")
    st.caption("Filtri applicati alle viste operative")

try:
    if source_mode == "Snapshot JSON" and uploaded is not None:
        snapshot = load_snapshot(uploaded.getvalue())
    else:
        snapshot = snapshot_from_dict(demo_payload)
except SnapshotValidationError as exc:
    st.error(str(exc))
    snapshot = snapshot_from_dict(demo_payload)

all_assets = snapshot.assets.copy()
all_alerts = snapshot.alerts.copy()
all_flows = snapshot.flows.copy()
sources = snapshot.sources.copy()
metadata = snapshot.metadata

with st.sidebar:
    zone_options = sorted(value for value in all_assets["zone"].dropna().unique())
    selected_zones = st.multiselect("Zone", zone_options, placeholder="Tutte le zone")
    severity_options = [
        value
        for value in ["Critica", "Alta", "Media", "Bassa"]
        if value in set(all_alerts["severity"].dropna())
    ]
    selected_severities = st.multiselect(
        "Severità", severity_options, placeholder="Tutte le severità"
    )
    time_window = st.selectbox(
        "Finestra eventi",
        ["Ultime 6 ore", "Ultime 12 ore", "Ultime 24 ore", "Tutto"],
        index=2,
    )
    st.divider()
    st.caption(
        f"Schema {metadata.get('schema_version', '1.1')} · "
        f"Aggiornato {italy_time(metadata.get('generated_at'))}"
    )

assets = all_assets.copy()
alerts = all_alerts.copy()
flows = all_flows.copy()

window_hours = {
    "Ultime 6 ore": 6,
    "Ultime 12 ore": 12,
    "Ultime 24 ore": 24,
}
if time_window in window_hours:
    generated_at = pd.Timestamp(metadata.get("generated_at"))
    if generated_at.tzinfo is None:
        generated_at = generated_at.tz_localize("UTC")
    cutoff = generated_at - timedelta(hours=window_hours[time_window])
    alerts = alerts[alerts["timestamp"] >= cutoff]
    flows = flows[flows["last_seen"] >= cutoff]

topology_assets = all_assets.copy()
if selected_zones:
    assets = assets[assets["zone"].isin(selected_zones)]
    zone_asset_names = set(assets["name"])
    zone_asset_ids = set(assets["asset_id"])
    alerts = alerts[
        alerts["source_asset"].isin(zone_asset_names)
        | alerts["destination_asset"].isin(zone_asset_names)
    ]
    flows = flows[
        flows["source_asset_id"].isin(zone_asset_ids)
        | flows["destination_asset_id"].isin(zone_asset_ids)
    ]
    topology_ids = set(flows["source_asset_id"]) | set(flows["destination_asset_id"])
    topology_assets = all_assets[all_assets["asset_id"].isin(topology_ids)]
if selected_severities:
    alerts = alerts[alerts["severity"].isin(selected_severities)]

mode = clean(metadata.get("mode", "DEMO"))
source_status = (
    "Snapshot importato"
    if source_mode == "Snapshot JSON" and uploaded is not None
    else "Dataset sintetico"
)
st.markdown(
    f"""
    <div class="dt-topline">
      <div>
        <div class="dt-kicker">OT Security Monitoring</div>
        <h1>DTLab Control Center</h1>
        <div class="dt-subtitle">Inventario, topologia, baseline, anomalie ed evidenze tecniche</div>
      </div>
      <div class="dt-badge-row">
        <span class="dt-badge"><span class="dt-dot demo"></span>{mode}</span>
        <span class="dt-badge"><span class="dt-dot"></span>Dashboard operativa</span>
      </div>
    </div>
    """,
    unsafe_allow_html=True,
)

if mode.upper() == "DEMO":
    st.markdown(
        "<div class='dt-banner'>MODALITÀ DEMO · Dati sintetici · Nessun collegamento attivo con l'ambiente Relatech</div>",
        unsafe_allow_html=True,
    )

(
    tab_overview,
    tab_assets,
    tab_topology,
    tab_alerts,
    tab_baseline,
    tab_sources,
) = st.tabs(["Overview", "Asset", "Topologia", "Alert", "Baseline", "Sorgenti dati"])

with tab_overview:
    open_alerts = alerts[alerts["status"].isin(["Aperto", "In analisi"])]
    critical_open = int((open_alerts["severity"] == "Critica").sum())
    high_risk_assets = int(assets["risk"].isin(["Critico", "Alto"]).sum())
    online_assets = int((assets["status"] == "Online").sum())

    kpi1, kpi2, kpi3, kpi4 = st.columns(4)
    with kpi1:
        kpi_card(
            "OT Health Score",
            f"{metadata['health_score']}/100",
            "Formula spiegabile v1.1",
            "amber",
        )
    with kpi2:
        kpi_card("Asset identificati", f"{len(assets)}", f"{online_assets} online", "green")
    with kpi3:
        kpi_card("Alert aperti", f"{len(open_alerts)}", f"{critical_open} critici", "red")
    with kpi4:
        kpi_card(
            "Asset ad alto rischio",
            f"{high_risk_assets}",
            f"Qualità dati {metadata['quality_score']}%",
            "blue",
        )

    left, middle, right = st.columns([1.0, 1.2, 1.15])
    with left:
        health = int(metadata["health_score"])
        gauge = go.Figure(
            go.Indicator(
                mode="gauge+number",
                value=health,
                number={"suffix": "/100", "font": {"size": 31}},
                title={"text": "Postura del dataset", "font": {"size": 14}},
                gauge={
                    "axis": {"range": [0, 100], "tickwidth": 1},
                    "bar": {"color": COLORS["teal"], "thickness": 0.27},
                    "bgcolor": "#FFFFFF",
                    "borderwidth": 0,
                    "steps": [
                        {"range": [0, 40], "color": "#F5D7D4"},
                        {"range": [40, 70], "color": "#F8E8C8"},
                        {"range": [70, 100], "color": "#D6EBDD"},
                    ],
                    "threshold": {
                        "line": {"color": COLORS["ink"], "width": 2},
                        "thickness": 0.7,
                        "value": health,
                    },
                },
            )
        )
        st.plotly_chart(chart_layout(gauge, 315), width="stretch", config={"displayModeBar": False})

    with middle:
        breakdown = pd.DataFrame(metadata.get("health_breakdown", []))
        breakdown_fig = px.bar(
            breakdown,
            x="penalty",
            y="component",
            orientation="h",
            title="Penalità dello score",
            text="penalty",
            color="component",
            color_discrete_sequence=["#C7423A", "#E17832", "#C47B12", "#2E6F9E", "#23885B"],
            custom_data=["details", "max_penalty"],
            labels={"penalty": "Penalità", "component": "Componente"},
        )
        breakdown_fig.update_layout(showlegend=False)
        breakdown_fig.update_xaxes(range=[0, 18])
        breakdown_fig.update_yaxes(title_text="")
        breakdown_fig.update_traces(
            texttemplate="-%{text}",
            textposition="outside",
            hovertemplate="%{y}<br>Penalità: %{x}/%{customdata[1]}<br>%{customdata[0]}<extra></extra>",
            cliponaxis=False,
        )
        st.plotly_chart(
            chart_layout(breakdown_fig, 315),
            width="stretch",
            config={"displayModeBar": False},
        )

    with right:
        severity = (
            alerts["severity"]
            .value_counts()
            .reindex(["Critica", "Alta", "Media", "Bassa"])
            .fillna(0)
            .astype(int)
            .rename_axis("Severità")
            .reset_index(name="Alert")
        )
        severity_fig = px.bar(
            severity,
            x="Severità",
            y="Alert",
            color="Severità",
            color_discrete_map=SEVERITY_COLORS,
            title="Alert per severità",
            text_auto=True,
        )
        severity_fig.update_layout(showlegend=False)
        severity_fig.update_traces(textposition="outside", cliponaxis=False)
        st.plotly_chart(
            chart_layout(severity_fig, 315),
            width="stretch",
            config={"displayModeBar": False},
        )

    trend_col, protocol_col = st.columns([1.7, 1])
    with trend_col:
        trend_alerts = alerts.dropna(subset=["timestamp"]).copy()
        if not trend_alerts.empty:
            trend_alerts["Ora"] = trend_alerts["timestamp"].dt.tz_convert("Europe/Rome").dt.floor("3h")
            trend = trend_alerts.groupby(["Ora", "severity"]).size().reset_index(name="Alert")
            trend_fig = px.line(
                trend,
                x="Ora",
                y="Alert",
                color="severity",
                color_discrete_map=SEVERITY_COLORS,
                category_orders={"severity": ["Critica", "Alta", "Media", "Bassa"]},
                markers=True,
                title="Timeline degli alert",
                labels={"severity": "Severità"},
            )
            trend_fig.update_traces(line=dict(width=2), marker=dict(size=6))
            st.plotly_chart(
                chart_layout(trend_fig, 300),
                width="stretch",
                config={"displayModeBar": False},
            )
        else:
            st.info("Nessun alert nella finestra selezionata.")
    with protocol_col:
        protocols = assets["protocol"].value_counts().reset_index()
        protocols.columns = ["Protocollo", "Asset"]
        protocols = protocols.sort_values("Asset", ascending=True)
        protocol_fig = px.bar(
            protocols,
            x="Asset",
            y="Protocollo",
            orientation="h",
            title="Asset per protocollo",
            color="Protocollo",
            color_discrete_sequence=["#087F6A", "#2E6F9E", "#C47B12", "#7D5A8D", "#5D7A66", "#9B5D52"],
            text_auto=True,
        )
        protocol_fig.update_layout(showlegend=False)
        protocol_fig.update_traces(textposition="outside", cliponaxis=False)
        st.plotly_chart(
            chart_layout(protocol_fig, 300),
            width="stretch",
            config={"displayModeBar": False},
        )

    st.markdown(
        f"<div class='dt-section'><span class='dt-section-title'>Eventi recenti</span><span class='dt-section-meta'>{len(alerts)} eventi nel perimetro selezionato</span></div>",
        unsafe_allow_html=True,
    )
    recent = alerts.sort_values("timestamp", ascending=False).head(8).copy()
    recent["timestamp"] = recent["timestamp"].map(italy_time)
    recent = recent.rename(
        columns={
            "timestamp": "Data e ora",
            "severity": "Severità",
            "rule_id": "Regola",
            "category": "Categoria",
            "source_asset": "Sorgente",
            "destination_asset": "Destinazione",
            "status": "Stato",
        }
    )
    st.dataframe(
        recent[["Data e ora", "Severità", "Regola", "Categoria", "Sorgente", "Destinazione", "Stato"]],
        hide_index=True,
        width="stretch",
        height=310,
    )

with tab_assets:
    filter_col, search_col = st.columns([1, 2])
    with filter_col:
        risk_filter = st.multiselect(
            "Rischio", ["Critico", "Alto", "Medio", "Basso"], placeholder="Tutti i livelli"
        )
    with search_col:
        asset_search = st.text_input(
            "Ricerca asset", placeholder="Nome, IP, vendor o protocollo"
        )

    asset_view = assets.copy()
    if risk_filter:
        asset_view = asset_view[asset_view["risk"].isin(risk_filter)]
    if asset_search:
        query = asset_search.casefold()
        searchable = (
            asset_view[["name", "ip_address", "vendor", "protocol"]]
            .fillna("")
            .astype(str)
            .agg(" ".join, axis=1)
            .str.casefold()
        )
        asset_view = asset_view[searchable.str.contains(query, regex=False)]

    display_assets = asset_view.copy()
    display_assets["last_seen"] = display_assets["last_seen"].map(italy_time)
    display_assets = display_assets.rename(
        columns={
            "name": "Asset",
            "ip_address": "IP",
            "asset_type": "Tipologia",
            "zone": "Zona",
            "protocol": "Protocollo",
            "risk": "Rischio",
            "status": "Stato",
            "last_seen": "Ultimo avvistamento",
            "vulnerabilities": "Vulnerabilità",
        }
    )
    st.dataframe(
        display_assets[
            [
                "Asset",
                "IP",
                "Tipologia",
                "Zona",
                "Protocollo",
                "Rischio",
                "Stato",
                "Vulnerabilità",
                "Ultimo avvistamento",
            ]
        ],
        hide_index=True,
        width="stretch",
        height=390,
    )

    if not asset_view.empty:
        selected_name = st.selectbox("Dettaglio asset", asset_view["name"].tolist())
        selected = asset_view[asset_view["name"] == selected_name].iloc[0]
        status_class = "online" if selected["status"] == "Online" else "offline"
        st.markdown(
            f"""
            <div class="dt-asset-head">
              <div class="dt-asset-name">{clean(selected['name'])}</div>
              <div class="dt-asset-meta">{clean(selected['asset_id'])} · {clean(selected['ip_address'])} · <span class="dt-status {status_class}">{clean(selected['status'])}</span></div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        selected_id = str(selected["asset_id"])
        selected_flows = all_flows[
            (all_flows["source_asset_id"] == selected_id)
            | (all_flows["destination_asset_id"] == selected_id)
        ]
        selected_alerts = all_alerts[
            (all_alerts["source_asset"] == selected_name)
            | (all_alerts["destination_asset"] == selected_name)
        ]
        detail1, detail2, detail3, detail4 = st.columns(4)
        detail1.metric("Vendor", clean(selected["vendor"]))
        detail2.metric("Firmware", clean(selected["firmware"]))
        detail3.metric("Flow osservati", len(selected_flows))
        detail4.metric("Alert correlati", len(selected_alerts))

        flow_col, alert_col = st.columns(2)
        with flow_col:
            st.markdown("## Comunicazioni correlate")
            asset_flow_display = selected_flows.copy()
            asset_flow_display["last_seen"] = asset_flow_display["last_seen"].map(italy_time)
            asset_flow_display = asset_flow_display.rename(
                columns={
                    "source_asset_id": "Sorgente",
                    "destination_asset_id": "Destinazione",
                    "protocol": "Protocollo",
                    "port": "Porta",
                    "baseline_status": "Baseline",
                    "last_seen": "Ultimo flow",
                }
            )
            st.dataframe(
                asset_flow_display[
                    ["Sorgente", "Destinazione", "Protocollo", "Porta", "Baseline", "Ultimo flow"]
                ],
                hide_index=True,
                width="stretch",
                height=250,
            )
        with alert_col:
            st.markdown("## Alert correlati")
            asset_alert_display = selected_alerts.sort_values("timestamp", ascending=False).head(8).copy()
            asset_alert_display["timestamp"] = asset_alert_display["timestamp"].map(italy_time)
            asset_alert_display = asset_alert_display.rename(
                columns={
                    "timestamp": "Data e ora",
                    "severity": "Severità",
                    "category": "Categoria",
                    "rule_id": "Regola",
                    "status": "Stato",
                }
            )
            st.dataframe(
                asset_alert_display[["Data e ora", "Severità", "Regola", "Categoria", "Stato"]],
                hide_index=True,
                width="stretch",
                height=250,
            )

        asset_profile = {
            "metadata": {
                "mode": metadata.get("mode"),
                "generated_at": metadata.get("generated_at"),
            },
            "asset": frame_records(pd.DataFrame([selected]))[0],
            "flows": frame_records(selected_flows),
            "alerts": frame_records(selected_alerts),
        }
        st.download_button(
            "Scarica profilo asset JSON",
            json.dumps(asset_profile, ensure_ascii=False, indent=2),
            file_name=f"{selected_id}-asset-profile.json",
            mime="application/json",
            icon=":material/download:",
            on_click="ignore",
        )

with tab_topology:
    expected_flows = int((flows["baseline_status"] == "Atteso").sum())
    new_flows = int((flows["baseline_status"] == "Nuovo").sum())
    deviation_flows = int((flows["baseline_status"] == "Deviazione").sum())
    t1, t2, t3, t4 = st.columns(4)
    with t1:
        kpi_card("Flow nel perimetro", str(len(flows)), f"{len(topology_assets)} asset coinvolti", "blue")
    with t2:
        kpi_card("Attesi", str(expected_flows), "Presenti in baseline", "green")
    with t3:
        kpi_card("Nuovi", str(new_flows), "Da classificare", "amber")
    with t4:
        kpi_card("Deviazioni", str(deviation_flows), "Richiedono verifica", "red")

    if flows.empty:
        st.info("Lo snapshot non contiene flow per il perimetro selezionato.")
    else:
        st.plotly_chart(
            topology_figure(topology_assets, flows),
            width="stretch",
            config={"displayModeBar": False},
        )
        flow_display = flows.copy()
        flow_display["last_seen"] = flow_display["last_seen"].map(italy_time)
        flow_display = flow_display.rename(
            columns={
                "source_asset_id": "Sorgente",
                "destination_asset_id": "Destinazione",
                "source_zone": "Zona sorgente",
                "destination_zone": "Zona destinazione",
                "protocol": "Protocollo",
                "port": "Porta",
                "baseline_status": "Baseline",
                "messages": "Messaggi",
                "last_seen": "Ultimo flow",
            }
        )
        st.dataframe(
            flow_display[
                [
                    "Sorgente",
                    "Destinazione",
                    "Zona sorgente",
                    "Zona destinazione",
                    "Protocollo",
                    "Porta",
                    "Baseline",
                    "Messaggi",
                    "Ultimo flow",
                ]
            ],
            hide_index=True,
            width="stretch",
            height=340,
        )

with tab_alerts:
    status_values = sorted(value for value in alerts["status"].dropna().unique())
    status_filter = st.segmented_control(
        "Stato", ["Tutti", *status_values], default="Tutti"
    )
    alert_view = alerts.copy()
    if status_filter != "Tutti":
        alert_view = alert_view[alert_view["status"] == status_filter]

    alert_display = alert_view.sort_values("timestamp", ascending=False).copy()
    alert_display["timestamp"] = alert_display["timestamp"].map(italy_time)
    alert_display = alert_display.rename(
        columns={
            "alert_id": "ID",
            "timestamp": "Data e ora",
            "severity": "Severità",
            "rule_id": "Regola",
            "category": "Categoria",
            "source_ip": "IP sorgente",
            "destination_ip": "IP destinazione",
            "protocol": "Protocollo",
            "function_code": "Funzione",
            "confidence": "Confidenza",
            "status": "Stato",
        }
    )
    st.dataframe(
        alert_display[
            [
                "ID",
                "Data e ora",
                "Severità",
                "Regola",
                "Categoria",
                "IP sorgente",
                "IP destinazione",
                "Protocollo",
                "Funzione",
                "Confidenza",
                "Stato",
            ]
        ],
        hide_index=True,
        width="stretch",
        height=430,
    )

    if not alert_view.empty:
        selected_alert_id = st.selectbox(
            "Dettaglio alert",
            alert_view.sort_values("timestamp", ascending=False)["alert_id"].tolist(),
        )
        selected_alert = alert_view[alert_view["alert_id"] == selected_alert_id].iloc[0]
        st.markdown(
            f"""
            <div class="dt-asset-head">
              <div class="dt-asset-name">{clean(selected_alert['category'])}</div>
              <div class="dt-asset-meta">{clean(selected_alert['alert_id'])} · {italy_time(selected_alert['timestamp'])} · {clean(selected_alert['severity'])}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        st.write(selected_alert["description"])
        route1, route2, route3, route4 = st.columns(4)
        route1.metric("Sorgente", clean(selected_alert["source_ip"]))
        route2.metric("Destinazione", clean(selected_alert["destination_ip"]))
        route3.metric(
            "Protocollo / funzione",
            f"{clean(selected_alert['protocol'])} · {clean(selected_alert['function_code'])}",
        )
        route4.metric(
            "Regola / confidenza",
            f"{clean(selected_alert['rule_id'])} · {clean(selected_alert['confidence'])}",
        )

        related_names = {
            str(selected_alert["source_asset"]),
            str(selected_alert["destination_asset"]),
        }
        related_assets = all_assets[all_assets["name"].isin(related_names)]
        related_ids = set(related_assets["asset_id"].astype(str))
        related_flows = all_flows[
            all_flows["source_asset_id"].astype(str).isin(related_ids)
            | all_flows["destination_asset_id"].astype(str).isin(related_ids)
        ]

        context_col, flows_col = st.columns([1, 1.4])
        with context_col:
            st.markdown("## Contesto asset")
            context = related_assets.rename(
                columns={
                    "name": "Asset",
                    "asset_type": "Tipo",
                    "zone": "Zona",
                    "risk": "Rischio",
                    "firmware": "Firmware",
                    "vulnerabilities": "Vulnerabilità",
                }
            )
            st.dataframe(
                context[["Asset", "Tipo", "Zona", "Rischio", "Firmware", "Vulnerabilità"]],
                hide_index=True,
                width="stretch",
                height=210,
            )
        with flows_col:
            st.markdown("## Flow correlati")
            correlated = related_flows.copy()
            correlated["last_seen"] = correlated["last_seen"].map(italy_time)
            correlated = correlated.rename(
                columns={
                    "source_asset_id": "Sorgente",
                    "destination_asset_id": "Destinazione",
                    "protocol": "Protocollo",
                    "port": "Porta",
                    "baseline_status": "Baseline",
                    "last_seen": "Ultimo flow",
                }
            )
            st.dataframe(
                correlated[["Sorgente", "Destinazione", "Protocollo", "Porta", "Baseline", "Ultimo flow"]],
                hide_index=True,
                width="stretch",
                height=210,
            )

        steps = VERIFICATION_STEPS.get(str(selected_alert["category"]), [])
        if steps:
            with st.expander("Checklist di verifica", icon=":material/fact_check:"):
                for index, step in enumerate(steps, start=1):
                    st.write(f"{index}. {step}")

        action1, action2 = st.columns(2)
        with action1:
            st.download_button(
                "Scarica pacchetto evidenze ZIP",
                build_evidence_bundle(snapshot, str(selected_alert_id)),
                file_name=f"{selected_alert_id}-evidence.zip",
                mime="application/zip",
                icon=":material/folder_zip:",
                width="stretch",
                on_click="ignore",
            )
        with action2:
            technique = str(selected_alert["attack_technique"])
            if technique == "T1692.001":
                st.link_button(
                    "Apri MITRE ATT&CK ICS",
                    "https://attack.mitre.org/techniques/T1692/001/",
                    icon=":material/open_in_new:",
                    width="stretch",
                )

with tab_baseline:
    baseline_counts = (
        flows["baseline_status"]
        .value_counts()
        .reindex(["Atteso", "Nuovo", "Deviazione"])
        .fillna(0)
        .astype(int)
    )
    b1, b2, b3 = st.columns(3)
    with b1:
        kpi_card("Flow attesi", str(int(baseline_counts["Atteso"])), "Comunicazioni note", "green")
    with b2:
        kpi_card("Flow nuovi", str(int(baseline_counts["Nuovo"])), "Da classificare", "amber")
    with b3:
        kpi_card("Deviazioni", str(int(baseline_counts["Deviazione"])), "Fuori profilo", "red")

    base_left, base_right = st.columns([1, 1.45])
    with base_left:
        baseline_frame = baseline_counts.rename_axis("Stato").reset_index(name="Flow")
        baseline_fig = px.bar(
            baseline_frame,
            x="Stato",
            y="Flow",
            color="Stato",
            color_discrete_map=BASELINE_COLORS,
            title="Stato della baseline",
            text_auto=True,
        )
        baseline_fig.update_layout(showlegend=False)
        baseline_fig.update_traces(textposition="outside", cliponaxis=False)
        st.plotly_chart(
            chart_layout(baseline_fig, 330),
            width="stretch",
            config={"displayModeBar": False},
        )
    with base_right:
        if flows.empty:
            st.info("Nessun flow disponibile.")
        else:
            zone_matrix = pd.crosstab(flows["source_zone"], flows["destination_zone"])
            heatmap = px.imshow(
                zone_matrix,
                text_auto=True,
                aspect="auto",
                color_continuous_scale=[[0, "#F3F5F6"], [1, "#087F6A"]],
                title="Matrice delle comunicazioni tra zone",
                labels=dict(x="Zona destinazione", y="Zona sorgente", color="Flow"),
            )
            heatmap.update_layout(coloraxis_showscale=False)
            st.plotly_chart(
                chart_layout(heatmap, 330),
                width="stretch",
                config={"displayModeBar": False},
            )

    anomalous_flows = flows[flows["baseline_status"].isin(["Nuovo", "Deviazione"])].copy()
    anomalous_flows["last_seen"] = anomalous_flows["last_seen"].map(italy_time)
    anomalous_flows = anomalous_flows.rename(
        columns={
            "source_asset_id": "Sorgente",
            "destination_asset_id": "Destinazione",
            "source_zone": "Zona sorgente",
            "destination_zone": "Zona destinazione",
            "protocol": "Protocollo",
            "port": "Porta",
            "baseline_status": "Stato",
            "messages": "Messaggi",
            "last_seen": "Ultimo flow",
        }
    )
    st.markdown("## Nuovi flow e deviazioni")
    st.dataframe(
        anomalous_flows[
            [
                "Sorgente",
                "Destinazione",
                "Zona sorgente",
                "Zona destinazione",
                "Protocollo",
                "Porta",
                "Stato",
                "Messaggi",
                "Ultimo flow",
            ]
        ],
        hide_index=True,
        width="stretch",
        height=245,
    )

    st.markdown("## Catalogo detection")
    st.dataframe(pd.DataFrame(DETECTION_RULES), hide_index=True, width="stretch", height=275)
    st.download_button(
        "Esporta flow CSV",
        flows.to_csv(index=False),
        file_name="dtlab-flows.csv",
        mime="text/csv",
        icon=":material/download:",
        on_click="ignore",
    )

with tab_sources:
    st.markdown(
        f"<div class='dt-section'><span class='dt-section-title'>Connettori</span><span class='dt-section-meta'>{source_status}</span></div>",
        unsafe_allow_html=True,
    )
    sources_display = sources.copy()
    sources_display["last_sync"] = sources_display["last_sync"].map(italy_time)
    sources_display = sources_display.rename(
        columns={
            "source": "Sorgente",
            "type": "Tipo",
            "status": "Stato",
            "last_sync": "Ultima sincronizzazione",
            "records": "Record",
            "endpoint": "Endpoint",
        }
    )
    st.dataframe(sources_display, hide_index=True, width="stretch", height=250)

    quality_col, coverage_col = st.columns([1.15, 1])
    with quality_col:
        st.markdown("## Qualità del dataset")
        quality_checks = pd.DataFrame(metadata.get("quality_checks", []))
        quality_checks = quality_checks.rename(
            columns={
                "control": "Controllo",
                "status": "Esito",
                "details": "Dettaglio",
                "penalty": "Penalità",
            }
        )
        kpi_card(
            "Data Quality Score",
            f"{metadata.get('quality_score', 0)}%",
            f"{int((quality_checks['Esito'] == 'OK').sum())}/{len(quality_checks)} controlli OK",
            "green",
        )
        st.dataframe(
            quality_checks[["Controllo", "Esito", "Dettaglio", "Penalità"]],
            hide_index=True,
            width="stretch",
            height=330,
        )
    with coverage_col:
        st.markdown("## Completezza per entità")
        coverage = pd.DataFrame(metadata.get("coverage", []))
        coverage_fig = px.bar(
            coverage,
            x="coverage",
            y="entity",
            orientation="h",
            title="Campi chiave valorizzati",
            text="coverage",
            color="entity",
            color_discrete_sequence=[COLORS["teal"], COLORS["blue"], COLORS["amber"]],
            labels={"coverage": "Copertura %", "entity": "Entità"},
        )
        coverage_fig.update_layout(showlegend=False)
        coverage_fig.update_xaxes(range=[0, 110])
        coverage_fig.update_traces(texttemplate="%{text}%", textposition="outside", cliponaxis=False)
        st.plotly_chart(
            chart_layout(coverage_fig, 300),
            width="stretch",
            config={"displayModeBar": False},
        )

    st.markdown("## Contratto dati")
    schema_rows = [
        {
            "Entità": "Asset",
            "Campi chiave": "asset_id, name, ip_address, vendor, asset_type, zone, protocol, risk, last_seen",
        },
        {
            "Entità": "Alert",
            "Campi chiave": "alert_id, timestamp, severity, rule_id, category, source_ip, destination_ip, protocol, status",
        },
        {
            "Entità": "Flow",
            "Campi chiave": "flow_id, source_asset_id, destination_asset_id, protocol, port, baseline_status, last_seen",
        },
        {
            "Entità": "Sorgente",
            "Campi chiave": "source, type, status, last_sync, records, endpoint",
        },
    ]
    st.dataframe(pd.DataFrame(schema_rows), hide_index=True, width="stretch")

    download1, download2, download3 = st.columns(3)
    with download1:
        st.download_button(
            "Pacchetto tecnico ZIP",
            build_technical_bundle(snapshot),
            file_name="dtlab-technical-bundle.zip",
            mime="application/zip",
            icon=":material/folder_zip:",
            width="stretch",
            on_click="ignore",
        )
    with download2:
        st.download_button(
            "Snapshot normalizzato JSON",
            json.dumps(normalized_payload(snapshot), ensure_ascii=False, indent=2),
            file_name="dtlab-normalized-snapshot.json",
            mime="application/json",
            icon=":material/download:",
            width="stretch",
            on_click="ignore",
        )
    with download3:
        st.download_button(
            "JSON Schema 1.1",
            json.dumps(snapshot_schema(), ensure_ascii=False, indent=2),
            file_name="dtlab-snapshot-schema-1.1.json",
            mime="application/schema+json",
            icon=":material/schema:",
            width="stretch",
            on_click="ignore",
        )
