"""Platform pages for sensors, VMware, source quality, and evidence exports."""

from __future__ import annotations

import json
import secrets
from collections.abc import Iterable, Mapping

import streamlit as st

from dtlab.services.exports import (
    build_asset_profile_json,
    build_canonical_snapshot_json,
    build_export_bundle,
    build_signal_evidence_bundle,
    build_snapshot_schema_json,
)
from dtlab.services.siem_exports import (
    SIEM_EVENT_SCHEMA_VERSION,
    build_siem_cef,
    build_siem_events,
    build_siem_export_bundle,
    build_siem_ndjson,
)
from dtlab.ui.components import (
    capability_notice,
    empty_state,
    finding_card,
    format_age,
    format_local_time,
    metric_card,
    page_intro,
    source_status,
    truth_badge,
)
from dtlab.ui.context import DashboardContext
from dtlab.ui.table_tools import render_filterable_table

_OPERATIONAL_SENSOR_STATES = frozenset({"active", "online", "operational", "running"})


def _operational_sensor_count(sensors: Iterable[Mapping[str, object]]) -> int:
    return sum(
        str(sensor.get("status") or "").strip().casefold()
        in _OPERATIONAL_SENSOR_STATES
        for sensor in sensors
    )


def _json_download_bytes(payload: Mapping[str, object]) -> bytes:
    return (
        json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def _safe_export_stem(value: object) -> str:
    stem = "".join(
        character if character.isalnum() or character in {"-", "_", "."} else "-"
        for character in str(value)
    )
    return stem.strip("-._") or "dtlab-export"


def _signal_options(
    snapshot: Mapping[str, object],
) -> list[tuple[str, str, str]]:
    options: list[tuple[str, str, str]] = []
    for signal_type, collection in (("event", "events"), ("finding", "findings")):
        records = snapshot.get(collection, [])
        if not isinstance(records, list):
            continue
        for record in records:
            if not isinstance(record, Mapping) or not isinstance(record.get("id"), str):
                continue
            label = record.get("title") or record.get("code") or record["id"]
            options.append((signal_type, record["id"], str(label)))
    return options


def _signal_option_label(option: tuple[str, str, str]) -> str:
    signal_type, signal_id, title = option
    kind = "Evento" if signal_type == "event" else "Finding"
    return f"{kind} · {title} · {signal_id}"


def render_sensors(context: DashboardContext) -> None:
    snapshot = context.snapshot
    page_intro(
        context,
        "Piattaforma",
        "Sensori e DPI",
        "Stato Cisco, capture mode e metriche tecniche dei sensori, senza health score sintetici.",
    )
    source = context.cybervision_source or {}
    capability = source.get("capabilities", {}).get("sensors", {})
    if capability.get("status") != "available":
        empty_state(
            "Sensori non disponibili",
            "La NIC PG-CV-DPI osservata in VMware non prova che il sensore stia "
            "catturando traffico. Serve la conferma della API Cisco.",
        )
        return
    sensors = snapshot["sensors"]
    if not sensors:
        empty_state(
            "Nessun sensore restituito",
            "La capability ha risposto ma non contiene sensori nell'ultima acquisizione.",
        )
        return
    stats_available = context.cybervision_capability_available("sensor_stats")
    capability_notice(context, "sensor_details", "Dettagli sensore")
    capability_notice(context, "sensor_stats", "Statistiche sensore")
    columns = st.columns(4)
    with columns[0]:
        metric_card("Sensori", len(sensors), "Cisco Cyber Vision")
    with columns[1]:
        metric_card(
            "Operativi",
            _operational_sensor_count(sensors),
            "Stato dichiarato dalla API",
        )
    with columns[2]:
        metric_card(
            "Stats disponibili",
            (
                sum(sensor["stats"] is not None for sensor in sensors)
                if stats_available
                else "N/D"
            ),
            "Endpoint Cisco /sensors/{id}/stats",
        )
    with columns[3]:
        metric_card(
            "Versioni note",
            sum(bool(sensor["version"]) for sensor in sensors),
            "Software sensore",
        )
    rows = [
        {
            "Nome": sensor["name"],
            "Tipo": sensor["sensor_type"],
            "Stato": sensor["status"],
            "IP": ", ".join(sensor["ip_addresses"]) or "N/D",
            "Capture mode": sensor["capture_mode"] or "N/D",
            "Versione": sensor["version"] or "N/D",
            "Ultimo contatto": format_local_time(sensor["last_seen_at"]),
            "CPU %": sensor["stats"].get("cpu_percent") if sensor["stats"] else None,
            "RAM %": (
                sensor["stats"].get("memory_percent") if sensor["stats"] else None
            ),
            "Disk %": sensor["stats"].get("disk_percent") if sensor["stats"] else None,
            "Packet/s": (
                sensor["stats"].get("packet_rate_pps") if sensor["stats"] else None
            ),
            "Packet drop": (
                sensor["stats"].get("drop_count") if sensor["stats"] else None
            ),
            "Uptime": (
                format_age(sensor["stats"]["uptime_seconds"])
                if sensor["stats"] and sensor["stats"].get("uptime_seconds") is not None
                else "N/D"
            ),
            "Snort": (
                sensor["stats"].get("snort_enabled") if sensor["stats"] else None
            ),
            "Discovery": (
                sensor["stats"].get("discovery_enabled") if sensor["stats"] else None
            ),
            "Verità": truth_badge(sensor),
        }
        for sensor in sensors
    ]
    render_filterable_table(
        st,
        rows,
        key="platform-sensors",
        filename_stem="dtlab-sensors",
        filter_columns=("Tipo", "Stato", "Capture mode"),
    )
    st.caption(
        "I campi N/D non diventano zero: indicano che Cisco non li ha restituiti o che "
        "la shape dell'istanza deve ancora essere verificata con l'OpenAPI installato."
    )


def render_vmware(context: DashboardContext) -> None:
    snapshot = context.snapshot
    page_intro(
        context,
        "Piattaforma",
        "Ambiente VMware",
        "Inventario ESXi read-only: VM, risorse, NIC, port group e limiti di visibilità.",
    )
    vms = snapshot["virtual_machines"]
    total_cpu = sum(vm["cpu_count"] for vm in vms)
    total_memory_gb = sum(vm["memory_mb"] for vm in vms) / 1024
    total_disk = sum(vm["disk_capacity_gb"] for vm in vms)
    powered_on = sum(vm["power_state"] == "powered_on" for vm in vms)
    columns = st.columns(5)
    for column, label, value, meta in (
        (columns[0], "VM", len(vms), f"{powered_on} powered on"),
        (columns[1], "vCPU", total_cpu, "Configurate"),
        (columns[2], "RAM", f"{total_memory_gb:g} GB", "Configurata"),
        (columns[3], "Disco", f"{total_disk:g} GB", "Capacità virtuale"),
        (
            columns[4],
            "Snapshot VMware",
            sum(vm["snapshot_count"] for vm in vms),
            "Nessuna azione eseguita",
        ),
    ):
        with column:
            metric_card(label, value, meta)

    rows = [
        {
            "VM": vm["name"].removeprefix("[Relatech] "),
            "Power": vm["power_state"],
            "Ruolo": vm["operational_context"]["purpose"],
            "Lifecycle": vm["operational_context"]["lifecycle_role"],
            "KPI": vm["operational_context"]["kpi_scope"],
            "Target ufficiale": (
                "Sì" if vm["operational_context"]["official_target"] else "No"
            ),
            "vCPU": vm["cpu_count"],
            "RAM GB": vm["memory_mb"] / 1024,
            "Disco GB": vm["disk_capacity_gb"],
            "Tools": vm["tools_status"],
            "IP primario guest": vm["primary_ip"] or "N/D",
            "Verità": truth_badge(vm),
        }
        for vm in vms
    ]
    render_filterable_table(
        st,
        rows,
        key="platform-vms",
        filename_stem="dtlab-virtual-machines",
        filter_columns=("Power", "Lifecycle", "Target ufficiale"),
        height=340,
    )

    st.subheader("NIC e port group")
    network_names = {
        network["id"]: network["name"] for network in snapshot["networks"]
    }
    interfaces = [
        {
            "VM": vm["name"].removeprefix("[Relatech] "),
            "Adapter": interface["label"],
            "Port group": network_names.get(interface["network_id"], "N/D"),
            "MAC": interface["mac_address"] or "N/D",
            "IP guest": ", ".join(interface["ip_addresses"]) or "N/D",
            "Connected": interface["connected"],
            "Start connected": interface["start_connected"],
        }
        for vm in vms
        for interface in vm["interfaces"]
    ]
    render_filterable_table(
        st,
        interfaces,
        key="platform-vm-nics",
        filename_stem="dtlab-vm-network-interfaces",
        filter_columns=("Port group", "Connected"),
        height=390,
    )
    st.subheader("Finding VMware")
    for finding in snapshot["findings"]:
        finding_card(finding)


def render_sources(context: DashboardContext) -> None:
    snapshot = context.snapshot
    page_intro(
        context,
        "Piattaforma",
        "Sorgenti e qualità",
        "Provenienza, capability, copertura e limiti espliciti dell'ultima sincronizzazione.",
    )
    columns = st.columns(4)
    with columns[0]:
        metric_card(
            "Stato snapshot",
            snapshot["sync"]["state"],
            f"Età {format_age(context.age_seconds)}",
        )
    with columns[1]:
        metric_card(
            "Qualità dati",
            f"{snapshot['quality']['score']:g}%",
            "Metrica DTLab separata",
        )
    with columns[2]:
        metric_card("Schema", snapshot["schema_version"], "Contratto canonico")
    with columns[3]:
        metric_card(
            "Pointer",
            context.pointer,
            context.manifest["sha256"][:12],
        )
    source_rows = [
        {
            "Sorgente": source["label"],
            "Tipo": source["type"],
            "Stato": source_status(source),
            "Versione": source["version"] or "N/D",
            "Ultimo tentativo": format_local_time(source["last_attempt_at"]),
            "Ultimo successo": format_local_time(source["last_success_at"]),
            "Record": sum(source["record_counts"].values()),
            "Errore": source["error"]["code"] if source["error"] else "—",
            "Verità": truth_badge(source),
        }
        for source in snapshot["sources"]
    ]
    render_filterable_table(
        st,
        source_rows,
        key="platform-sources",
        filename_stem="dtlab-sources",
        filter_columns=("Tipo", "Stato"),
    )

    st.subheader("Capability")
    capability_rows = []
    for source in snapshot["sources"]:
        for name, capability in source["capabilities"].items():
            capability_rows.append(
                {
                    "Sorgente": source["label"],
                    "Capability": name,
                    "Stato": capability["status"],
                    "Record": capability["records"],
                    "Tentativi": capability.get("attempted", "—"),
                    "Riusciti": capability.get("successful", "—"),
                    "Codice": capability["error_code"] or "—",
                }
            )
    if capability_rows:
        render_filterable_table(
            st,
            capability_rows,
            key="platform-capabilities",
            filename_stem="dtlab-source-capabilities",
            filter_columns=("Sorgente", "Stato"),
            height=390,
        )
    else:
        empty_state(
            "Capability non ancora rilevate",
            "Verranno popolate dal primo ciclo API autenticato.",
        )

    st.subheader("Controlli qualità")
    render_filterable_table(
        st,
        snapshot["quality"]["checks"],
        key="platform-quality-checks",
        filename_stem="dtlab-quality-checks",
        filter_columns=("status",),
    )
    st.subheader("Etichette di verità")
    st.markdown(
        """
- **Reale** — dato restituito dalla sorgente semantica corretta o confermato dall'operatore.
- **Osservata** — configurazione vista da un'altra sorgente, senza estenderne il significato.
- **Attesa** — configurazione o ruolo di progetto ancora da confermare.
- **Non disponibile** — capability assente, non configurata o non leggibile.
- **Obsoleta** — ultimo dato valido oltre la soglia di freschezza.
- **Demo** — sintetico; vietato nello store operativo.
"""
    )


def render_evidence(context: DashboardContext) -> None:
    snapshot = context.snapshot
    canonical_snapshot = context.canonical_snapshot
    page_intro(
        context,
        "Piattaforma",
        "Evidenze e report",
        "Bundle verificabili con manifest SHA-256, export tecnico autorizzato o versione pubblica "
        "pseudonimizzata.",
    )
    st.warning(
        "L'export tecnico contiene IP e MAC dell'ambiente. Condividerlo solo con personale "
        "autorizzato. Il token API non entra mai negli snapshot o negli export."
    )
    snapshot_stem = _safe_export_stem(canonical_snapshot["snapshot_id"])
    st.subheader("Report Cisco disponibili")
    report_capability = (context.cybervision_source or {}).get("capabilities", {}).get(
        "reports_metadata", {}
    )
    reports = snapshot.get("reports", [])
    if report_capability.get("status") != "available":
        empty_state(
            "Metadata report Cisco non disponibili",
            "La sezione resta distinta dai bundle DTLab generati dal portale.",
        )
    elif not reports:
        empty_state(
            "Nessun report configurato",
            "L'endpoint Cisco è disponibile ma non ha restituito report metadata.",
        )
    else:
        report_rows = [
            {
                "Nome": report["name"],
                "Tipo": report["report_type"] or "N/D",
                "Output": ", ".join(report["output_types"]) or "N/D",
                "Schedule": report["schedule"] or "N/D",
                "Ultimo run": format_local_time(report["last_run_at"]),
                "Stato": report["status"] or "N/D",
                "Errore": report["error"] or "—",
                "Documenti": len(report["documents"]),
                "Verità": truth_badge(report),
            }
            for report in reports
        ]
        render_filterable_table(
            st,
            report_rows,
            key="platform-cisco-reports",
            filename_stem="dtlab-cisco-reports",
            filter_columns=("Tipo", "Stato"),
        )

    st.subheader("Bundle DTLab")
    if "export-salt" not in st.session_state:
        st.session_state["export-salt"] = secrets.token_bytes(32)
    technical = build_export_bundle(canonical_snapshot, mode="technical")
    public = build_export_bundle(
        canonical_snapshot,
        mode="public",
        salt=st.session_state["export-salt"],
    )
    first, second = st.columns(2)
    with first:
        st.markdown("#### Bundle tecnico")
        st.caption("Indirizzi completi, tabelle CSV, snapshot e manifest con hash.")
        st.download_button(
            "Scarica bundle tecnico",
            data=technical,
            file_name=f"{snapshot['snapshot_id'].replace(':', '-')}-technical.zip",
            mime="application/zip",
            icon=":material/download:",
            use_container_width=True,
        )
    with second:
        st.markdown("#### Bundle pubblico redatto")
        st.caption("IP e MAC pseudonimizzati in modo coerente all'interno del bundle.")
        st.download_button(
            "Scarica bundle redatto",
            data=public,
            file_name=f"{snapshot['snapshot_id'].replace(':', '-')}-public.zip",
            mime="application/zip",
            icon=":material/shield_lock:",
            use_container_width=True,
        )

    st.subheader("Integrazione SIEM e Splunk")
    siem_events = build_siem_events(canonical_snapshot)
    st.caption(
        "Export tecnico puntuale dei segnali normalizzati DTLab. NDJSON e CEF sono "
        "pronti per ingest o collaudo; per il flusso continuo near-real-time va "
        "configurato il Syslog CEF nativo di Cyber Vision verso il receiver/SIEM."
    )
    st.info(
        "Questo download non dichiara attiva un'integrazione live e non si presenta "
        "come CEF Cisco: il vendor del file è DTLab Control Center. Contiene soltanto "
        "riferimenti espliciti presenti nello snapshot canonico."
    )
    siem_metrics = st.columns(3)
    with siem_metrics[0]:
        metric_card("Record SIEM", len(siem_events), "Eventi, finding, differenze e CVE")
    with siem_metrics[1]:
        metric_card("Schema", SIEM_EVENT_SCHEMA_VERSION, "Contratto normalizzato")
    with siem_metrics[2]:
        metric_card("Modalità", "Tecnica", "Può contenere identificativi reali")

    siem_bundle = build_siem_export_bundle(canonical_snapshot)
    siem_ndjson = build_siem_ndjson(canonical_snapshot)
    siem_cef = build_siem_cef(canonical_snapshot)
    bundle_column, ndjson_column, cef_column = st.columns(3)
    with bundle_column:
        st.markdown("#### Pacchetto verificabile")
        st.caption("NDJSON, CEF, JSON Schema, README e manifest con SHA-256.")
        st.download_button(
            "Scarica bundle SIEM",
            data=siem_bundle,
            file_name=f"{snapshot_stem}-siem-technical.zip",
            mime="application/zip",
            icon=":material/folder_zip:",
            use_container_width=True,
        )
    with ndjson_column:
        st.markdown("#### NDJSON")
        st.caption("Un record normalizzato per riga, adatto a pipeline e lookup.")
        st.download_button(
            "Scarica eventi NDJSON",
            data=siem_ndjson,
            file_name=f"{snapshot_stem}-siem.ndjson",
            mime="application/x-ndjson",
            icon=":material/data_object:",
            use_container_width=True,
        )
    with cef_column:
        st.markdown("#### CEF DTLab")
        st.caption("Linee CEF manuali per test di ingest; non è il feed Cisco nativo.")
        st.download_button(
            "Scarica eventi CEF",
            data=siem_cef,
            file_name=f"{snapshot_stem}-siem.cef",
            mime="text/plain",
            icon=":material/terminal:",
            use_container_width=True,
        )

    st.subheader("Download JSON per integrazioni")
    st.caption(
        "Snapshot e manifest provengono dallo stesso oggetto originale verificato nello "
        "store; lo schema descrive il contratto dati della release."
    )
    snapshot_json = build_canonical_snapshot_json(canonical_snapshot)
    schema_json = build_snapshot_schema_json()
    manifest_json = _json_download_bytes(context.manifest)
    snapshot_column, schema_column, manifest_column = st.columns(3)
    with snapshot_column:
        st.markdown("#### Snapshot canonico")
        st.caption("Tecnico: può contenere indirizzi IP e MAC reali.")
        st.download_button(
            "Scarica snapshot canonico JSON",
            data=snapshot_json,
            file_name=f"{snapshot_stem}.json",
            mime="application/json",
            icon=":material/data_object:",
            use_container_width=True,
        )
    with schema_column:
        st.markdown("#### JSON Schema")
        st.caption("Contratto machine-readable per validare snapshot futuri.")
        st.download_button(
            "Scarica JSON Schema",
            data=schema_json,
            file_name="dtlab-snapshot-v2.schema.json",
            mime="application/schema+json",
            icon=":material/schema:",
            use_container_width=True,
        )
    with manifest_column:
        st.markdown("#### Manifest dello store")
        st.caption("Identità, hash SHA-256 e oggetto del pointer corrente.")
        st.download_button(
            "Scarica manifest JSON",
            data=manifest_json,
            file_name=f"{snapshot_stem}-manifest.json",
            mime="application/json",
            icon=":material/fingerprint:",
            use_container_width=True,
        )

    st.subheader("Evidence bundle per asset")
    if not canonical_snapshot["assets"]:
        empty_state(
            "Asset Cyber Vision non disponibili",
            "La selezione per asset sarà attiva dopo la sincronizzazione Cisco.",
        )
    else:
        asset_id = st.selectbox(
            "Asset",
            [asset["id"] for asset in canonical_snapshot["assets"]],
            format_func=lambda value: next(
                asset["name"]
                for asset in canonical_snapshot["assets"]
                if asset["id"] == value
            ),
        )
        evidence_bundle = build_export_bundle(
            canonical_snapshot,
            mode="technical",
            asset_id=asset_id,
        )
        asset_profile = build_asset_profile_json(
            canonical_snapshot,
            asset_id=asset_id,
            mode="technical",
        )
        selected_name = next(
            asset["name"]
            for asset in canonical_snapshot["assets"]
            if asset["id"] == asset_id
        )
        asset_stem = _safe_export_stem(selected_name)
        st.caption(
            "Export tecnici: il profilo JSON raccoglie soltanto record collegati "
            "esplicitamente all'asset selezionato."
        )
        asset_bundle_column, asset_profile_column = st.columns(2)
        with asset_bundle_column:
            st.download_button(
                "Scarica evidenza asset",
                data=evidence_bundle,
                file_name=f"evidence-{asset_stem}.zip",
                mime="application/zip",
                icon=":material/folder_zip:",
                use_container_width=True,
            )
        with asset_profile_column:
            st.download_button(
                "Scarica profilo asset JSON",
                data=asset_profile,
                file_name=f"asset-profile-{asset_stem}.json",
                mime="application/json",
                icon=":material/data_object:",
                use_container_width=True,
            )

    st.subheader("Evidence bundle per evento o finding")
    signals = _signal_options(canonical_snapshot)
    if not signals:
        empty_state(
            "Eventi e finding non disponibili",
            "Il download si attiverà quando lo snapshot conterrà almeno un segnale.",
        )
    else:
        selected_signal = st.selectbox(
            "Evento o finding",
            signals,
            format_func=_signal_option_label,
        )
        signal_type, signal_id, signal_title = selected_signal
        signal_bundle = build_signal_evidence_bundle(
            canonical_snapshot,
            signal_type=signal_type,
            signal_id=signal_id,
            mode="technical",
        )
        signal_kind = "evento" if signal_type == "event" else "finding"
        st.caption(
            "Bundle tecnico verificabile: include soltanto asset referenziati "
            "direttamente e flow con endpoint su quegli asset; non crea correlazioni "
            "inferite."
        )
        st.download_button(
            f"Scarica evidence bundle {signal_kind}",
            data=signal_bundle,
            file_name=(
                f"evidence-{signal_kind}-{_safe_export_stem(signal_title)}-"
                f"{_safe_export_stem(signal_id)}.zip"
            ),
            mime="application/zip",
            icon=":material/folder_zip:",
        )

    st.subheader("Manifest corrente")
    st.json(
        {
            **context.manifest,
            "snapshot_generated_at": snapshot["generated_at"],
            "sync_state": snapshot["sync"]["state"],
            "record_counts": {
                "virtual_machines": len(snapshot["virtual_machines"]),
                "assets": len(snapshot["assets"]),
                "risk_scores": len(snapshot["risk_scores"]),
                "flows": len(snapshot["flows"]),
                "events": len(snapshot["events"]),
                "vulnerabilities": len(snapshot["vulnerabilities"]),
            },
        },
        expanded=True,
    )
