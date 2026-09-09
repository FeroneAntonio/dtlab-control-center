from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from data_adapter import SnapshotValidationError, load_snapshot, snapshot_from_dict, snapshot_schema
from demo_data import build_demo_payload
from environment_adapter import load_environment_payload
from export_bundle import build_evidence_bundle, build_technical_bundle, normalized_payload


APP_DIR = Path(__file__).resolve().parent
ESXI_INVENTORY = APP_DIR / "data" / "esxi_inventory.json"

st.set_page_config(
    page_title="DTLab Control Center",
    page_icon=":material/security:",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
<style>
@import url('https://fonts.googleapis.com/css2?family=Montserrat:wght@400;500;600;700&display=swap');
:root {
  --dt-primary: #006b5f;
  --dt-on-primary: #ffffff;
  --dt-primary-container: #9ef2df;
  --dt-on-primary-container: #00201b;
  --dt-secondary-container: #d5e8e2;
  --dt-surface: #f7faf9;
  --dt-surface-low: #f0f5f3;
  --dt-surface-high: #e3ebe8;
  --dt-on-surface: #17201e;
  --dt-on-surface-variant: #3f4946;
  --dt-outline: #6f7976;
  --dt-outline-variant: #bec9c5;
  --dt-error: #ba1a1a;
  --dt-warning: #8a5100;
  --dt-info: #185abc;
  --dt-radius: 20px;
}
html, body, [class*="css"] { font-family: 'Montserrat', system-ui, sans-serif; }
[data-testid="stAppViewContainer"] { background: var(--dt-surface); color: var(--dt-on-surface); }
[data-testid="stSidebar"] { background: #eef5f2; border-right: 1px solid var(--dt-outline-variant); }
[data-testid="stHeader"] { background: rgba(247,250,249,.92); }
.block-container { max-width: 1500px; padding-top: 1.4rem; padding-bottom: 3rem; }
h1, h2, h3 { color: var(--dt-on-surface); letter-spacing: -.025em; }
h1 { font-size: clamp(1.75rem, 3vw, 2.65rem); }
h2 { font-size: 1.25rem; margin-top: 1.2rem; }
h3 { font-size: 1rem; }
.dt-eyebrow { color: var(--dt-primary); font-size: .76rem; font-weight: 700; letter-spacing: .12em; text-transform: uppercase; }
.dt-hero { padding: 22px 24px; border: 1px solid var(--dt-outline-variant); border-radius: 28px; background: linear-gradient(120deg,#ffffff 0%,#e8f7f2 62%,#d8efe8 100%); margin-bottom: 18px; }
.dt-hero h1 { margin: 4px 0 6px; }
.dt-hero p { color: var(--dt-on-surface-variant); max-width: 900px; margin: 0; }
.dt-status-row { display:flex; flex-wrap:wrap; gap:8px; margin-top:14px; }
.dt-chip { display:inline-flex; align-items:center; gap:7px; min-height:32px; padding:4px 12px; border-radius:999px; background:var(--dt-secondary-container); color:#17332c; font-size:.78rem; font-weight:600; }
.dt-chip.real { background:#c5f6e8; color:#064f42; }
.dt-chip.warn { background:#ffddb8; color:#5b3100; }
.dt-chip.off { background:#e3e8e6; color:#48524f; }
.dt-dot { width:8px; height:8px; border-radius:50%; background:currentColor; }
.dt-metric { min-height:132px; padding:18px; border:1px solid var(--dt-outline-variant); border-radius:var(--dt-radius); background:#fff; box-shadow:0 1px 2px rgba(19,41,35,.04); }
.dt-metric .label { color:var(--dt-on-surface-variant); font-size:.76rem; font-weight:600; text-transform:uppercase; letter-spacing:.06em; }
.dt-metric .value { font-size:2rem; line-height:1.05; margin:9px 0 7px; font-weight:700; color:var(--dt-on-surface); }
.dt-metric .meta { color:var(--dt-on-surface-variant); font-size:.78rem; }
.dt-panel { padding:18px 20px; border:1px solid var(--dt-outline-variant); border-radius:var(--dt-radius); background:#fff; margin:8px 0 14px; }
.dt-empty { padding:28px; border:1px dashed var(--dt-outline); border-radius:var(--dt-radius); background:var(--dt-surface-low); text-align:center; color:var(--dt-on-surface-variant); }
.dt-empty strong { display:block; color:var(--dt-on-surface); margin-bottom:5px; }
.dt-finding { padding:14px 16px; border-radius:16px; background:#fff; border:1px solid var(--dt-outline-variant); margin:8px 0; }
.dt-finding.critical { border-left:5px solid var(--dt-error); }
.dt-finding.high { border-left:5px solid #d65f00; }
.dt-finding.medium { border-left:5px solid #c58a00; }
.dt-finding.info { border-left:5px solid var(--dt-info); }
.dt-finding .sev { font-size:.7rem; font-weight:700; text-transform:uppercase; letter-spacing:.08em; color:var(--dt-on-surface-variant); }
.dt-finding .title { font-weight:700; margin:3px 0; }
.dt-finding .detail { color:var(--dt-on-surface-variant); font-size:.86rem; }
.dt-step { display:grid; grid-template-columns:32px 1fr; gap:10px; align-items:start; margin:11px 0; }
.dt-step .n { width:30px; height:30px; border-radius:50%; background:var(--dt-primary-container); color:var(--dt-on-primary-container); display:flex; align-items:center; justify-content:center; font-weight:700; }
.dt-step b { display:block; }
.dt-step span { color:var(--dt-on-surface-variant); font-size:.82rem; }
div[data-testid="stButton"] button, div[data-testid="stDownloadButton"] button { border-radius:999px; min-height:42px; font-weight:600; }
div[data-baseweb="select"] > div, div[data-baseweb="input"] > div { border-radius:14px; }
[data-testid="stDataFrame"] { border:1px solid var(--dt-outline-variant); border-radius:16px; overflow:hidden; }
@media (max-width: 760px) {
  .block-container { padding: 1rem .8rem 2rem; }
  .dt-hero { padding:18px; border-radius:22px; }
  .dt-metric { min-height:112px; }
}
</style>
""",
    unsafe_allow_html=True,
)


def clean(value: object, fallback: str = "—") -> str:
    if value is None or (isinstance(value, float) and pd.isna(value)):
        return fallback
    text = str(value).strip()
    return text if text and text.lower() not in {"nan", "nat", "none"} else fallback


def local_time(value: object) -> str:
    parsed = pd.to_datetime(value, utc=True, errors="coerce")
    if pd.isna(parsed):
        return "—"
    return parsed.tz_convert("Europe/Rome").strftime("%d/%m/%Y · %H:%M:%S")


def metric_card(label: str, value: object, meta: str) -> None:
    st.markdown(
        f"<div class='dt-metric'><div class='label'>{label}</div>"
        f"<div class='value'>{clean(value)}</div><div class='meta'>{meta}</div></div>",
        unsafe_allow_html=True,
    )


def empty_state(title: str, detail: str) -> None:
    st.markdown(
        f"<div class='dt-empty'><strong>{title}</strong>{detail}</div>",
        unsafe_allow_html=True,
    )


def finding_card(item: dict) -> None:
    severity = clean(item.get("severity"), "Informativa")
    tone = {
        "Critica": "critical",
        "Alta": "high",
        "Media": "medium",
        "Informativa": "info",
    }.get(severity, "info")
    st.markdown(
        f"<div class='dt-finding {tone}'><div class='sev'>{severity} · {clean(item.get('status'))}</div>"
        f"<div class='title'>{clean(item.get('title'))}</div>"
        f"<div class='detail'>{clean(item.get('detail'))}</div></div>",
        unsafe_allow_html=True,
    )


def topology_figure(network_details: list[dict]) -> go.Figure:
    vm_names = sorted({item["vm"] for item in network_details})
    portgroups = sorted({item["portgroup"] for item in network_details if item.get("portgroup")})
    positions: dict[str, tuple[float, float]] = {}
    for index, name in enumerate(vm_names):
        positions[name] = (index - (len(vm_names) - 1) / 2, 1.0)
    for index, name in enumerate(portgroups):
        positions[name] = (index * 1.8 - (len(portgroups) - 1) * .9, 0.0)

    edge_x: list[float | None] = []
    edge_y: list[float | None] = []
    for item in network_details:
        source = item["vm"]
        target = item.get("portgroup")
        if target not in positions:
            continue
        x0, y0 = positions[source]
        x1, y1 = positions[target]
        edge_x.extend([x0, x1, None])
        edge_y.extend([y0, y1, None])

    fig = go.Figure()
    fig.add_trace(
        go.Scatter(x=edge_x, y=edge_y, mode="lines", line={"color": "#9eaaa6", "width": 2}, hoverinfo="skip")
    )
    fig.add_trace(
        go.Scatter(
            x=[positions[name][0] for name in vm_names],
            y=[positions[name][1] for name in vm_names],
            mode="markers+text",
            text=vm_names,
            textposition="top center",
            marker={"size": 34, "color": "#006b5f", "line": {"color": "#ffffff", "width": 3}},
            hovertemplate="VM: %{text}<extra></extra>",
        )
    )
    fig.add_trace(
        go.Scatter(
            x=[positions[name][0] for name in portgroups],
            y=[positions[name][1] for name in portgroups],
            mode="markers+text",
            text=portgroups,
            textposition="bottom center",
            marker={"size": 42, "symbol": "diamond", "color": "#9ef2df", "line": {"color": "#006b5f", "width": 2}},
            hovertemplate="PortGroup: %{text}<extra></extra>",
        )
    )
    fig.update_layout(
        height=510,
        margin={"l": 10, "r": 10, "t": 25, "b": 30},
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        showlegend=False,
        xaxis={"visible": False},
        yaxis={"visible": False, "range": [-.35, 1.35]},
    )
    return fig


def api_capabilities_table() -> pd.DataFrame:
    return pd.DataFrame(
        [
            ("Inventario componenti", "/components", "Da autenticare", "Asset, identità, IP/MAC, ruolo"),
            ("Eventi", "/events", "Da autenticare", "Severità, categoria, timestamp, contesto"),
            ("Versione appliance", "/scv/1.0/sbs-version", "401 verificato", "Versione/build Center"),
            ("Sensori", "/scv/3.0/admin/sensors", "Da autenticare", "Health e configurazione sensori"),
            ("Stato sensori", "/scv/3.0/sensors/status", "401 verificato", "Disponibilità e stato DPI"),
            ("Vulnerabilità", "/scv/3.0/dashboard/vulnerabilities/counts", "401 verificato", "Conteggi e priorità"),
            ("Export dump", "/scv/1.0/dump/export", "Da autorizzare", "Export tecnico/manuale"),
        ],
        columns=["Funzione", "Endpoint rilevato", "Stato", "Uso nella dashboard"],
    )


with st.sidebar:
    st.markdown("### DTLab Control Center")
    st.caption("OT visibility · evidence · governance")
    source_mode = st.radio(
        "Origine dati",
        ["Ambiente DTLab", "Demo", "Importa snapshot"],
        index=0,
    )
    uploaded = None
    if source_mode == "Importa snapshot":
        uploaded = st.file_uploader("Snapshot JSON", type=["json"])
    st.divider()
    page = st.radio(
        "Navigazione",
        [
            "Command Center",
            "Ambiente ESXi",
            "Topologia",
            "Asset",
            "Flussi",
            "Eventi",
            "Baseline",
            "Vulnerabilità",
            "Cisco Cyber Vision",
            "Sorgenti e qualità",
        ],
        index=0,
    )
    st.divider()
    st.caption("Le azioni su ESXi e Cyber Vision sono progettate come read-only. Nessun test offensivo parte dalla dashboard.")


try:
    if source_mode == "Ambiente DTLab":
        payload = load_environment_payload(ESXI_INVENTORY)
    elif source_mode == "Demo":
        payload = build_demo_payload()
    elif uploaded is not None:
        snapshot = load_snapshot(uploaded)
        payload = normalized_payload(snapshot)
    else:
        payload = load_environment_payload(ESXI_INVENTORY)
    snapshot = snapshot_from_dict(payload)
except (SnapshotValidationError, OSError, json.JSONDecodeError) as exc:
    st.error(f"Impossibile caricare il dataset: {exc}")
    st.stop()

metadata = snapshot.metadata
assets = snapshot.assets.copy()
alerts = snapshot.alerts.copy()
flows = snapshot.flows.copy()
sources = snapshot.sources.copy()
findings = metadata.get("findings", [])
vm_details = metadata.get("vm_details", [])
network_details = metadata.get("network_details", [])
mode = clean(metadata.get("mode"))
is_real = mode.startswith("REAL")
mode_class = "real" if is_real else "warn" if mode == "DEMO" else "off"

st.markdown(
    f"""
<section class="dt-hero">
  <div class="dt-eyebrow">{page}</div>
  <h1>DTLab OT Security</h1>
  <p>Un’unica vista operativa per ambiente VMware, telemetria Cisco Cyber Vision, baseline, rilevazioni ed evidenze.</p>
  <div class="dt-status-row">
    <span class="dt-chip {mode_class}"><span class="dt-dot"></span>{mode}</span>
    <span class="dt-chip">{clean(metadata.get('evidence_level'), 'Dataset normalizzato')}</span>
    <span class="dt-chip">Aggiornato {local_time(metadata.get('generated_at'))}</span>
  </div>
</section>
""",
    unsafe_allow_html=True,
)


if page == "Command Center":
    k1, k2, k3, k4, k5 = st.columns(5)
    with k1:
        metric_card("VM osservate", len(assets), "Inventario VMware")
    with k2:
        metric_card("VM online", int((assets["status"] == "Online").sum()), "Power state")
    with k3:
        metric_card("Finding aperti", len(findings), "Configurazione e copertura")
    with k4:
        metric_card("Flow osservati", len(flows), "Cyber Vision / snapshot")
    with k5:
        metric_card("Eventi", len(alerts), "Non simulati in modalità reale")

    left, right = st.columns([1.35, 1])
    with left:
        st.markdown("## Priorità operative")
        if findings:
            for finding in findings:
                finding_card(finding)
        else:
            empty_state("Nessun finding di configurazione", "Il dataset non segnala conflitti noti.")
    with right:
        st.markdown("## Catena di acquisizione")
        steps = [
            ("1", "VMware ESXi", "Inventario VM, NIC e stato alimentazione"),
            ("2", "Cisco Cyber Vision", "Asset, flow, eventi, vulnerabilità e stato sensori"),
            ("3", "Adapter DTLab", "Normalizzazione, qualità, provenienza e redazione"),
            ("4", "Control Center", "Topologia, baseline, triage ed evidence export"),
            ("5", "SIEM", "Integrazione futura senza duplicare eventi"),
        ]
        st.markdown("<div class='dt-panel'>", unsafe_allow_html=True)
        for number, title, detail in steps:
            st.markdown(
                f"<div class='dt-step'><div class='n'>{number}</div><div><b>{title}</b><span>{detail}</span></div></div>",
                unsafe_allow_html=True,
            )
        st.markdown("</div>", unsafe_allow_html=True)

elif page == "Ambiente ESXi":
    st.markdown("## Macchine virtuali reali")
    if vm_details:
        vm_frame = pd.DataFrame(vm_details).rename(
            columns={
                "name": "VM",
                "power_state": "Stato",
                "hostname": "Hostname",
                "primary_ip": "IP primario",
                "guest": "Sistema guest",
                "tools_status": "VMware Tools",
                "cpu": "vCPU",
                "memory_gb": "RAM GB",
                "disk_gb": "Disco GB",
                "snapshots": "Snapshot",
            }
        )
        st.dataframe(vm_frame, hide_index=True, use_container_width=True, height=280)
    st.markdown("## Interfacce e PortGroup")
    if network_details:
        nic_frame = pd.DataFrame(network_details).rename(
            columns={
                "vm": "VM",
                "adapter": "Interfaccia",
                "portgroup": "PortGroup",
                "mac_address": "MAC",
                "ip_addresses": "Indirizzi guest",
                "connected": "Connessa",
                "start_connected": "Connetti all'avvio",
            }
        )
        st.dataframe(nic_frame, hide_index=True, use_container_width=True, height=360)
    st.info("L’account ESXi non espone attualmente al collector le policy vSwitch/PortGroup. Promiscuous mode, MAC changes e forged transmits devono essere verificati da Relatech.")

elif page == "Topologia":
    st.markdown("## Topologia osservata da ESXi")
    if network_details:
        st.plotly_chart(topology_figure(network_details), use_container_width=True, config={"displayModeBar": False})
        st.caption("Le linee indicano collegamenti VM → PortGroup rilevati via API VMware; non rappresentano automaticamente flow di rete osservati.")
    else:
        empty_state("Topologia non disponibile", "Importare un inventario ESXi o uno snapshot con dettagli di rete.")

elif page == "Asset":
    st.markdown("## Inventario unificato")
    query = st.text_input("Cerca", placeholder="Nome, IP, tipo, zona o protocollo")
    asset_view = assets.copy()
    if query:
        mask = asset_view.fillna("").astype(str).apply(
            lambda column: column.str.contains(query, case=False, regex=False)
        ).any(axis=1)
        asset_view = asset_view[mask]
    display = asset_view.copy()
    display["last_seen"] = display["last_seen"].apply(local_time)
    st.dataframe(display, hide_index=True, use_container_width=True, height=390)
    if not asset_view.empty:
        selected = st.selectbox("Profilo asset", asset_view["name"].tolist())
        row = asset_view[asset_view["name"] == selected].iloc[0].to_dict()
        a1, a2, a3, a4 = st.columns(4)
        with a1:
            metric_card("Indirizzo", row.get("ip_address"), "IP primario")
        with a2:
            metric_card("Zona", row.get("zone"), "PortGroup")
        with a3:
            metric_card("Rischio", row.get("risk"), "Classificazione DTLab")
        with a4:
            metric_card("Stato", row.get("status"), "Ultima osservazione")

elif page == "Flussi":
    st.markdown("## Comunicazioni osservate")
    if flows.empty:
        empty_state("Nessun flow Cyber Vision importato", "L’inventario ESXi descrive le connessioni di rete, ma non prova che il traffico Modbus sia visibile al DPI.")
    else:
        view = flows.copy()
        view["first_seen"] = view["first_seen"].apply(local_time)
        view["last_seen"] = view["last_seen"].apply(local_time)
        st.dataframe(view, hide_index=True, use_container_width=True, height=430)

elif page == "Eventi":
    st.markdown("## Eventi e rilevazioni")
    if alerts.empty:
        empty_state("Nessun evento reale importato", "Gli eventi demo non vengono mescolati con l’ambiente reale. Collegare l’API Cyber Vision o importare un export autenticato.")
    else:
        status = st.multiselect("Stato", sorted(alerts["status"].dropna().unique().tolist()))
        view = alerts[alerts["status"].isin(status)] if status else alerts
        view = view.copy()
        view["timestamp"] = view["timestamp"].apply(local_time)
        st.dataframe(view, hide_index=True, use_container_width=True, height=390)
        selected_id = st.selectbox("Dettaglio evento", view["alert_id"].tolist())
        st.download_button(
            "Scarica evidence ZIP",
            build_evidence_bundle(snapshot, selected_id),
            file_name=f"dtlab-evidence-{selected_id}.zip",
            mime="application/zip",
        )

elif page == "Baseline":
    st.markdown("## Stato della baseline")
    checks = pd.DataFrame(
        [
            ("PLC e HMI distinti", True, "Le VM sono separate"),
            ("Conflitti IP assenti", not any("duplicato" in item.get("title", "").lower() for item in findings), "Due PLC riportano oggi 172.16.10.10"),
            ("DPI configurato", any(item.get("portgroup") == "PG-CV-DPI" for item in network_details), "NIC presente; mirroring da validare"),
            ("Flow Modbus osservato", not flows.empty, "Nessun flow reale importato"),
            ("Ciclo normale acquisito", False, "PCAP e finestra baseline non ancora disponibili"),
            ("Validazione referente OT", False, "Approvazione non registrata"),
        ],
        columns=["Controllo", "Completato", "Evidenza"],
    )
    st.dataframe(checks, hide_index=True, use_container_width=True)
    st.markdown("## Sequenza minima")
    st.markdown("Avvio → produzione normale → Stop/Run → Reset → HMI offline/recovery → approvazione OT.")

elif page == "Vulnerabilità":
    st.markdown("## Vulnerabilità e firmware")
    total = int(assets["vulnerabilities"].sum())
    if total == 0 and is_real:
        empty_state("Dati vulnerabilità non ancora acquisiti", "Zero indica assenza di record importati, non assenza di vulnerabilità. Cyber Vision deve fornire conteggi, CVE e asset correlati.")
    else:
        st.dataframe(
            assets[["name", "vendor", "firmware", "risk", "vulnerabilities"]].sort_values("vulnerabilities", ascending=False),
            hide_index=True,
            use_container_width=True,
        )

elif page == "Cisco Cyber Vision":
    st.markdown("## Stato integrazione")
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        metric_card("Endpoint", "Raggiungibile", "HTTPS e SSH via VPN")
    with c2:
        metric_card("API", "Rilevata", "SCV 1.0 / 3.0")
    with c3:
        metric_card("Autenticazione", "Mancante", "Serve account/API read-only")
    with c4:
        metric_card("Record", 0, "Nessuna telemetria importata")
    st.markdown("## Architettura rilevata")
    cv_nics = [item for item in network_details if item.get("vm") == "CyberVision-with-DPI"]
    if cv_nics:
        st.dataframe(pd.DataFrame(cv_nics), hide_index=True, use_container_width=True)
    st.markdown("## Funzioni disponibili per il connettore")
    st.dataframe(api_capabilities_table(), hide_index=True, use_container_width=True, height=320)
    st.warning("Il collector non deve usare credenziali amministrative permanenti. Creare un account o API key read-only, verificare la CA interna e limitare l’export ai campi necessari.")

elif page == "Sorgenti e qualità":
    st.markdown("## Sorgenti")
    source_view = sources.copy()
    source_view["last_sync"] = source_view["last_sync"].apply(local_time)
    st.dataframe(source_view, hide_index=True, use_container_width=True)
    q1, q2 = st.columns([1.1, 1])
    with q1:
        st.markdown("## Controlli qualità")
        st.dataframe(pd.DataFrame(metadata.get("quality_checks", [])), hide_index=True, use_container_width=True)
    with q2:
        st.markdown("## Completezza")
        st.dataframe(pd.DataFrame(metadata.get("coverage", [])), hide_index=True, use_container_width=True)
    st.markdown("## Export e interoperabilità")
    d1, d2, d3 = st.columns(3)
    with d1:
        st.download_button(
            "Snapshot normalizzato",
            json.dumps(normalized_payload(snapshot), ensure_ascii=False, indent=2, default=str).encode("utf-8"),
            file_name="dtlab-snapshot.json",
            mime="application/json",
            use_container_width=True,
        )
    with d2:
        st.download_button(
            "Pacchetto tecnico",
            build_technical_bundle(snapshot),
            file_name="dtlab-technical-bundle.zip",
            mime="application/zip",
            use_container_width=True,
        )
    with d3:
        st.download_button(
            "JSON Schema",
            json.dumps(snapshot_schema(), ensure_ascii=False, indent=2).encode("utf-8"),
            file_name="dtlab-schema-1.1.json",
            mime="application/json",
            use_container_width=True,
        )

st.caption(
    f"DTLab Control Center · {clean(metadata.get('environment'))} · "
    f"Generato {local_time(metadata.get('generated_at'))} · {datetime.now(timezone.utc).year}"
)
