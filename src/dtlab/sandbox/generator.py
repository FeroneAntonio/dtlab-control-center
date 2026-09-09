"""Build a complete, deterministic BeerFactory sandbox snapshot (schema v3).

The output validates against ``contract_v3`` and exercises every domain the new
front-end needs: the v2 data plane (assets, flows, risk, events, vulnerabilities,
baseline) plus the v3 additions (attack scenarios/runs, detection correlations
with latency, Modbus digital-twin telemetry, Purdue/IEC 62443 zones, NIS2 and
MITRE ATT&CK for ICS compliance coverage, and history trends).

All data is synthetic. Evidence is labelled ``demo`` and the snapshot runs in
``allow_demo`` mode so it can never masquerade as real telemetry. Risk scores are
the one exception the v2 contract pins to ``real``/``stale``; there the evidence
note states explicitly that the value is a sandbox simulation.
"""

from __future__ import annotations

import argparse
import json
import math
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from dtlab import contract_v3

BASE_TIME = datetime(2026, 8, 7, 9, 0, 0, tzinfo=UTC)
SANDBOX_NOTE = "Dato simulato in ambiente sandbox DTLab; non proveniente da sistemi reali."

# --- source ids -----------------------------------------------------------
OPERATOR = "src:operator:dtlab"
ESXI = "src:vmware-esxi:dtlab-01"
CV_CLASSIC = "src:cisco-cyber-vision:dtlab-01"
CV_NEW_UI = "src:cisco-cyber-vision-new-ui:dtlab-01"
SIEM = "src:siem:dtlab-01"

# --- entity ids -----------------------------------------------------------
ENV_ID = "env:relatech-dtlab-sandbox"
NET_OT = "net:ot:172.16.10.0-24"
NET_DPI = "net:dpi:span"
NET_MGMT = "net:management:10.10.10.0-24"

VM_PLC = "vm:vmware:dtlab-01:plc-desktop"
VM_HMI = "vm:vmware:dtlab-01:hmi-ubuntu"
VM_KALI = "vm:vmware:dtlab-01:kali"
VM_CV = "vm:vmware:dtlab-01:cybervision-dpi"
VM_PLC_LEGACY = "vm:vmware:dtlab-01:plc-ubuntu-legacy"

ASSET_PLC = "asset:cybervision:plc-desktop"
ASSET_HMI = "asset:cybervision:hmi-ubuntu"
ASSET_KALI = "asset:cybervision:kali"
ASSET_PLC_LEGACY = "asset:cybervision:plc-ubuntu-legacy"

SENSOR_CV = "sensor:cybervision:dpi-01"

ZONE_PROCESS = "zone:ot-process"
ZONE_SUPERVISION = "zone:ot-supervision"
ZONE_DPI = "zone:dpi-monitoring"
ZONE_TEST = "zone:security-test"

# attack scenario / run / event ids are defined inline in the builders below.


def _t(offset_seconds: int) -> str:
    return (BASE_TIME + timedelta(seconds=offset_seconds)).isoformat().replace("+00:00", "Z")


def _evidence(
    source_id: str,
    *,
    truth: str = "demo",
    record: str | None = None,
    observed_offset: int = 0,
    completeness: float = 1.0,
    extra_notes: list[str] | None = None,
) -> dict[str, Any]:
    notes = [SANDBOX_NOTE]
    if extra_notes:
        notes = extra_notes + notes
    return {
        "source_id": source_id,
        "source_record_id": record,
        "truth": truth,
        "observed_at": _t(observed_offset),
        "fetched_at": _t(0),
        "completeness": completeness,
        "notes": notes,
    }


# ---------------------------------------------------------------------------
# v2 data plane
# ---------------------------------------------------------------------------
def _cve_catalog() -> list[dict[str, Any]]:
    """Global Cisco CVE index (sandbox), kept separate from device associations."""

    rows = [
        ("CVE-2021-22681", "Rockwell Studio 5000: chiave privata hardcoded", 10.0, "Rockwell"),
        ("CVE-2022-1161", "Rockwell Logix: iniezione di codice nel controllore", 10.0, "Rockwell"),
        ("CVE-2018-7811", "Schneider Modicon: bypass autenticazione web", 9.8, "Schneider"),
        ("CVE-2020-15782", "Siemens SIMATIC S7: lettura/scrittura memoria", 8.1, "Siemens"),
        ("ICSA-SANDBOX-001", "Modbus/TCP privo di autenticazione", 7.5, "Generic"),
        ("CVE-2015-5374", "Siemens SIPROTEC: denial of service", 7.8, "Siemens"),
        ("CVE-2019-10929", "Siemens: adversary-in-the-middle su PROFINET", 6.5, "Siemens"),
        ("ICSA-SANDBOX-002", "Sistema operativo con patch mancanti", 5.9, "Generic"),
    ]
    return [
        {
            "external_id": external_id,
            "title": title,
            "cvss_score": cvss,
            "cvss_version": "3.1",
            "published_at": _t(-2592000),
            "source_record_id": f"cv-vuln:{external_id.lower()}",
            "vendor_id": vendor,
        }
        for external_id, title, cvss, vendor in rows
    ]


def _new_ui_inventory() -> dict[str, Any]:
    """Cisco Cyber Vision New UI inventory (sandbox), separate from Device Classic."""

    profiles = [
        ("nui:plc-desktop", "plcubuntu", "PLC", "Schneider", "172.16.10.10", "OT / Livello 1"),
        ("nui:hmi", "VMware 172.16.10.20", "HMI", "VMware", "172.16.10.20", "OT / Livello 2"),
        ("nui:kali", "VMware 172.16.10.100", "Workstation", "VMware", "172.16.10.100", "Test"),
        ("nui:plc-legacy", "VMware 172.16.10.11", "PLC", "VMware", "172.16.10.11",
         "OT / Livello 1 (legacy)"),
        ("nui:cv", "CyberVision-with-DPI", "Sensor", "Cisco", "10.10.10.51",
         "Monitoraggio / Livello 3"),
    ]
    networks = [
        ("net:nui:ot-core", "OT Core", "172.16.10.0/25", "Livello 1", 3),
        ("net:nui:ot-supervision", "OT Supervisione", "172.16.10.128/26", "Livello 2", 1),
        ("net:nui:ot-test", "OT Test", "172.16.10.192/27", "Test", 1),
        ("net:nui:dpi", "DPI SPAN", "—", "Livello 3", 1),
        ("net:nui:mgmt", "Management", "10.10.10.0/24", "Livello 3", 2),
        ("net:nui:multicast", "Multicast/Discovery", "224.0.0.0/24", "Livello 1", 0),
        ("net:nui:linklocal", "Link-local", "fe80::/64", "Livello 1", 3),
    ]
    return {
        "profiles": [
            {
                "profile_id": pid, "name": name, "type": kind, "vendor": vendor,
                "interface": iface, "functional_group": group,
                "active_alerts": 0, "vulnerabilities": 0,
                "sensors": ["CENTER-ETH2"] if kind != "Sensor" else [],
                "pcaps": 0,
            }
            for pid, name, kind, vendor, iface, group in profiles
        ],
        "networks": [
            {"network_id": nid, "name": name, "cidr": cidr, "level": level, "components": comp}
            for nid, name, cidr, level, comp in networks
        ],
    }


def _sources() -> list[dict[str, Any]]:
    def src(source_id, label, source_type, status, counts, *, details=None, capabilities=None):
        return {
            "id": source_id,
            "evidence": _evidence(source_id, record=source_id),
            "label": label,
            "type": source_type,
            "endpoint_label": f"{label} · endpoint sandbox",
            "status": status,
            "version": "sandbox",
            "last_attempt_at": _t(0),
            "last_success_at": _t(0),
            "record_counts": counts,
            "capabilities": capabilities or {},
            "details": details or {},
            "error": None,
        }

    catalog = _cve_catalog()
    return [
        src(OPERATOR, "Conferme operative", "operator", "connected", {"confirmations": 3}),
        src(ESXI, "VMware ESXi", "vmware_esxi", "connected", {"virtual_machines": 5}),
        src(CV_CLASSIC, "Cisco Cyber Vision", "cisco_cyber_vision", "connected",
            {"assets": 4, "flows": 2, "events": 3, "risk_scores": 2,
             "vulnerabilities": len(catalog)},
            details={"vulnerability_catalog": catalog},
            capabilities={"vulnerabilities": {"status": "ok", "records": len(catalog),
                                              "error_code": None}}),
        src(CV_NEW_UI, "Cyber Vision New UI", "cisco_cyber_vision_new_ui", "connected",
            {"inventory": 5}, details={"new_ui_inventory": _new_ui_inventory()}),
        src(SIEM, "SIEM (Syslog/CEF)", "siem", "connected", {"forwarded": 6}),
    ]


def _environment() -> dict[str, Any]:
    return {
        "id": ENV_ID,
        "evidence": _evidence(OPERATOR, record="operator-confirmation"),
        "name": "Relatech DTLab · BeerFactory (SANDBOX)",
        "kind": "lab",
        "timezone": "Europe/Rome",
        "status": "operational",
        "description": (
            "Ambiente dimostrativo del laboratorio OT BeerFactory. Tutti i dati sono "
            "simulati e non rappresentano telemetria reale."
        ),
    }


def _networks() -> list[dict[str, Any]]:
    return [
        {
            "id": NET_OT,
            "evidence": _evidence(CV_CLASSIC, record="network:ot"),
            "name": "OT BeerFactory",
            "kind": "ot",
            "cidrs": ["172.16.10.0/24"],
            "description": "Rete di processo del nastro trasportatore PLC↔HMI.",
        },
        {
            "id": NET_DPI,
            "evidence": _evidence(CV_CLASSIC, record="network:dpi"),
            "name": "DPI SPAN",
            "kind": "dpi",
            "cidrs": [],
            "description": "Mirroring del traffico OT verso il sensore Cyber Vision.",
        },
        {
            "id": NET_MGMT,
            "evidence": _evidence(ESXI, record="network:mgmt"),
            "name": "Management",
            "kind": "management",
            "cidrs": ["10.10.10.0/24"],
            "description": "Rete di gestione ESXi e Center Cyber Vision.",
        },
    ]


def _interface(nic_id: str, network_id: str | None, mac: str, ips: list[str]) -> dict[str, Any]:
    return {
        "id": nic_id,
        "label": "Network adapter 1",
        "network_id": network_id,
        "mac_address": mac,
        "ip_addresses": ips,
        "connected": True,
        "start_connected": True,
    }


def _virtual_machines() -> list[dict[str, Any]]:
    def vm(vm_id, name, hostname, purpose, lifecycle, official, kpi, ip, mac, guest):
        return {
            "id": vm_id,
            "evidence": _evidence(ESXI, record=vm_id),
            "name": name,
            "hostname": hostname,
            "operational_context": {
                "purpose": purpose,
                "lifecycle_role": lifecycle,
                "official_target": official,
                "kpi_scope": kpi,
                "desired_power_state": "running",
                "evidence": _evidence(OPERATOR, record=f"context:{vm_id}"),
            },
            "power_state": "powered_on",
            "guest_os": guest,
            "cpu_count": 2,
            "memory_mb": 4096,
            "disk_capacity_gb": 50.0,
            "tools_status": "ok",
            "primary_ip": ip,
            "interfaces": [_interface(f"nic:{vm_id}", NET_OT, mac, [ip])],
            "snapshot_count": 0,
        }

    return [
        vm(VM_PLC, "[Relatech] PLC-Desktop", "plcdesktop", "plc", "operational",
           True, "primary", "172.16.10.10", "00:0c:29:00:10:10", "Ubuntu Linux"),
        vm(VM_HMI, "[Relatech] HMI-Ubuntu", "hmiubuntu", "hmi", "operational",
           False, "support", "172.16.10.20", "00:0c:29:00:10:20", "Ubuntu Linux"),
        vm(VM_KALI, "[Relatech] Kali", "kali", "security_testing", "test",
           False, "excluded_test", "172.16.10.100", "00:0c:29:00:10:64", "Kali Linux"),
        vm(VM_CV, "[Relatech] CyberVision-with-DPI", "cybervision", "cyber_vision",
           "support", False, "support", "10.10.10.50", "00:0c:29:00:50:50", "Cisco Cyber Vision"),
        vm(VM_PLC_LEGACY, "[Relatech] PLC-Ubuntu (legacy)", "plcubuntu", "plc", "legacy",
           False, "excluded_legacy", "172.16.10.11", "00:0c:29:00:10:11", "Ubuntu Linux"),
    ]


def _assets() -> list[dict[str, Any]]:
    def asset(asset_id, name, device_type, ip, mac, role, protocols, status="online"):
        return {
            "id": asset_id,
            "evidence": _evidence(CV_CLASSIC, record=asset_id),
            "name": name,
            "category": "Industrial automation",
            "device_type": device_type,
            "vendor": "Schneider Electric" if device_type == "PLC" else None,
            "ip_addresses": [ip],
            "mac_addresses": [mac],
            "network_ids": [NET_OT],
            "zone": "OT BeerFactory",
            "protocols": protocols,
            "status": status,
            "last_seen_at": _t(0),
            "operational_role": role,
        }

    return [
        asset(ASSET_PLC, "PLC-Desktop (BeerFactory)", "PLC", "172.16.10.10",
              "00:0c:29:00:10:10", "target", ["Modbus", "TCP"]),
        asset(ASSET_HMI, "HMI-Ubuntu", "HMI", "172.16.10.20",
              "00:0c:29:00:10:20", "support", ["Modbus", "TCP"]),
        asset(ASSET_KALI, "Kali (test offensivo)", "Workstation", "172.16.10.100",
              "00:0c:29:00:10:64", "security_test", ["TCP"]),
        asset(ASSET_PLC_LEGACY, "PLC-Ubuntu (legacy)", "PLC", "172.16.10.11",
              "00:0c:29:00:10:11", "legacy", ["Modbus", "TCP"], status="stale"),
    ]


def _identity_links() -> list[dict[str, Any]]:
    def link(link_id, vm_id, asset_id):
        return {
            "id": link_id,
            "evidence": _evidence(OPERATOR, record=link_id),
            "virtual_machine_id": vm_id,
            "asset_id": asset_id,
            "method": "operator_confirmed",
            "confidence": 1.0,
            "status": "confirmed",
        }

    return [
        link("link:plc", VM_PLC, ASSET_PLC),
        link("link:hmi", VM_HMI, ASSET_HMI),
        link("link:kali", VM_KALI, ASSET_KALI),
        link("link:plc-legacy", VM_PLC_LEGACY, ASSET_PLC_LEGACY),
    ]


def _risk_scores() -> list[dict[str, Any]]:
    def risk(risk_id, asset_id, score, factors):
        band = "low" if score < 40 else "medium" if score < 70 else "high"
        return {
            "id": risk_id,
            "evidence": _evidence(
                CV_CLASSIC,
                truth="real",
                record=f"{asset_id}:riskScore",
                extra_notes=["Risk score Cisco simulato: origine sandbox, non un sensore reale."],
            ),
            "asset_id": asset_id,
            "score": score,
            "band": band,
            "methodology": "cisco_cyber_vision",
            "computed_at": _t(0),
            "factors": factors,
        }

    return [
        risk("risk:plc", ASSET_PLC, 58, [
            {"label": "Protocollo Modbus senza autenticazione", "value": "high", "weight": 0.4},
            {"label": "Vulnerabilità note", "value": 2, "weight": 0.3},
        ]),
        risk("risk:hmi", ASSET_HMI, 34, [
            {"label": "Esposizione limitata", "value": "low", "weight": 0.5},
        ]),
    ]


def _activities() -> list[dict[str, Any]]:
    return [
        {
            "id": "activity:modbus-conveyor",
            "evidence": _evidence(CV_CLASSIC, record="activity:1"),
            "asset_ids": [ASSET_HMI, ASSET_PLC],
            "type": "Modbus polling",
            "protocol": "Modbus",
            "first_seen_at": _t(-86400),
            "last_seen_at": _t(0),
            "packet_count": 184320,
            "byte_count": 23040000,
            "flow_count": 1,
            "event_count": 3,
            "details": {"function_codes": ["read_holding_registers", "write_single_register"]},
        }
    ]


def _flows() -> list[dict[str, Any]]:
    return [
        {
            "id": "flow:hmi-plc-modbus",
            "evidence": _evidence(CV_CLASSIC, record="flow:1"),
            "left_asset_id": ASSET_HMI,
            "right_asset_id": ASSET_PLC,
            "left_component_id": None,
            "right_component_id": None,
            "left_label": "HMI-Ubuntu",
            "right_label": "PLC-Desktop",
            "left_ip": "172.16.10.20",
            "right_ip": "172.16.10.10",
            "protocol": "Modbus",
            "direction": "left_to_right",
            "direction_raw": "HMI→PLC",
            "left_port": 44012,
            "right_port": 502,
            "first_seen_at": _t(-86400),
            "last_seen_at": _t(0),
            "packet_count": 184320,
            "byte_count": 23040000,
        },
        {
            "id": "flow:kali-plc-modbus",
            "evidence": _evidence(CV_CLASSIC, record="flow:2"),
            "left_asset_id": ASSET_KALI,
            "right_asset_id": ASSET_PLC,
            "left_component_id": None,
            "right_component_id": None,
            "left_label": "Kali",
            "right_label": "PLC-Desktop",
            "left_ip": "172.16.10.100",
            "right_ip": "172.16.10.10",
            "protocol": "Modbus",
            "direction": "left_to_right",
            "direction_raw": "Kali→PLC",
            "left_port": 51222,
            "right_port": 502,
            "first_seen_at": _t(120),
            "last_seen_at": _t(900),
            "packet_count": 512,
            "byte_count": 40960,
        },
    ]


# event ids referenced by detection correlations
EVT_DISCOVERY = "event:cv:discovery"
EVT_UNAUTH_WRITE = "event:cv:unauthorized-write"
EVT_FREQUENCY = "event:cv:frequency-anomaly"


def _events() -> list[dict[str, Any]]:
    def event(event_id, offset, severity, category, title, description, source, assets):
        return {
            "id": event_id,
            "evidence": _evidence(source, record=event_id, observed_offset=offset),
            "occurred_at": _t(offset),
            "severity": severity,
            "category": category,
            "title": title,
            "description": description,
            "center_id": "center:dtlab",
            "center_label": "Cyber Vision Center",
            "status": "new",
            "asset_ids": assets,
            "acknowledged": False,
        }

    return [
        event(EVT_DISCOVERY, 188, "medium", "Anomaly Detection",
              "Scansione host sulla rete OT",
              "Rilevata attività di discovery da 172.16.10.100 verso il segmento OT.",
              CV_NEW_UI, [ASSET_KALI, ASSET_PLC]),
        event(EVT_UNAUTH_WRITE, 423, "high", "Control Systems Event",
              "Scrittura Modbus non autorizzata",
              "Write single register verso il PLC da un host non in baseline.",
              CV_CLASSIC, [ASSET_KALI, ASSET_PLC]),
        event(EVT_FREQUENCY, 642, "medium", "Anomaly Detection",
              "Frequenza di polling anomala",
              "Incremento anomalo della frequenza di richieste Modbus verso il PLC.",
              CV_CLASSIC, [ASSET_PLC]),
    ]


def _vulnerabilities() -> list[dict[str, Any]]:
    def vuln(vuln_id, asset_id, external_id, title, severity, cvss):
        return {
            "id": vuln_id,
            "evidence": _evidence(CV_NEW_UI, record=external_id),
            "asset_id": asset_id,
            "external_id": external_id,
            "title": title,
            "severity": severity,
            "cvss_score": cvss,
            "status": "open",
            "published_at": _t(-2592000),
            "details": {"catalog": "sandbox"},
        }

    return [
        vuln("vuln:plc:modbus-noauth", ASSET_PLC, "ICSA-SANDBOX-001",
             "Modbus/TCP privo di autenticazione", "high", 7.5),
        vuln("vuln:plc:legacy-os", ASSET_PLC, "ICSA-SANDBOX-002",
             "Sistema operativo con patch mancanti", "medium", 5.9),
    ]


def _baselines_and_diffs() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    baseline = {
        "id": "baseline:beerfactory",
        "evidence": _evidence(CV_CLASSIC, record="baseline:1"),
        "name": "Baseline BeerFactory",
        "description": "Traffico Modbus atteso PLC↔HMI in regime nominale.",
        "status": "active",
        "created_at": _t(-604800),
        "creation_period_start": _t(-691200),
        "creation_period_end": _t(-604800),
        "last_scan_at": _t(0),
        "next_scan_at": _t(3600),
        "difference_counts": {
            "new_component": 1,
            "changed_component": 0,
            "new_activity": 1,
            "changed_activity": 0,
        },
    }
    diffs = [
        {
            "id": "diff:new-kali-flow",
            "evidence": _evidence(CV_CLASSIC, record="diff:1", observed_offset=120),
            "baseline_id": "baseline:beerfactory",
            "difference_type": "new_activity",
            "target_id": "flow:kali-plc-modbus",
            "key": "flow",
            "value": "Kali→PLC Modbus",
            "asset_ids": [ASSET_KALI, ASSET_PLC],
            "flow_id": "flow:kali-plc-modbus",
            "detected_at": _t(120),
            "description": "Nuovo flusso Modbus non presente in baseline.",
        }
    ]
    return [baseline], diffs


def _sensors() -> list[dict[str, Any]]:
    return [
        {
            "id": SENSOR_CV,
            "evidence": _evidence(CV_CLASSIC, record=SENSOR_CV),
            "name": "Cyber Vision Sensor DPI",
            "sensor_type": "cisco_cyber_vision_sensor",
            "status": "active",
            "ip_addresses": ["10.10.10.51"],
            "last_seen_at": _t(0),
            "capture_mode": "span",
            "version": "5.5.1",
            "stats": {
                "window": "5m",
                "observed_at": _t(0),
                "cpu_percent": 34.0,
                "memory_percent": 51.0,
                "disk_percent": 40.0,
                "uptime_seconds": 864000,
                "packet_rate_pps": 320.0,
                "packet_count": 96000,
                "drop_count": 0,
                "snort_enabled": True,
                "discovery_enabled": True,
                "extension_access_valid": True,
            },
        }
    ]


def _reports() -> list[dict[str, Any]]:
    return [
        {
            "id": "report:soc-weekly",
            "evidence": _evidence(OPERATOR, record="report:1"),
            "name": "Report SOC settimanale",
            "description": "Sintesi rilevamenti, copertura compliance e trend.",
            "report_type": "soc_summary",
            "output_types": ["pdf"],
            "schedule": "weekly",
            "created_at": _t(-604800),
            "updated_at": _t(0),
            "last_run_at": _t(-86400),
            "status": "ready",
            "error": None,
            "documents": [
                {"document_id": "doc:soc-weekly:2026-08-06", "name": "SOC 2026-08-06",
                 "document_type": "pdf"}
            ],
        }
    ]


def _findings() -> list[dict[str, Any]]:
    return [
        {
            "id": "finding:plc-legacy-running",
            "evidence": _evidence(OPERATOR, record="finding:1"),
            "code": "OT-LEGACY-01",
            "severity": "medium",
            "title": "PLC-Ubuntu legacy ancora acceso",
            "description": "Il PLC legacy resta alimentato pur non essendo il target ufficiale.",
            "status": "open",
            "entity_ids": [ASSET_PLC_LEGACY, VM_PLC_LEGACY],
            "first_detected_at": _t(-604800),
            "last_detected_at": _t(0),
            "recommended_action": "Confermare con il referente se spegnere il PLC legacy.",
            "exclude_from_operational_kpis": False,
        }
    ]


def _quality() -> dict[str, Any]:
    return {
        "methodology": "dtlab_data_quality_v2",
        "score": 88,
        "checks": [
            {"code": "sandbox_dataset", "label": "Dataset sandbox",
             "status": "pass", "details": "Dati simulati coerenti col contratto v3."},
            {"code": "attack_coverage", "label": "Copertura detection",
             "status": "warn", "details": "1 scenario su 4 non rilevato (MITM)."},
        ],
        "coverage": {"vmware": 1.0, "cyber_vision": 1.0, "attack_detection": 0.75},
    }


# ---------------------------------------------------------------------------
# v3 domains
# ---------------------------------------------------------------------------
def _technique(tid: str, name: str, tactic: str) -> dict[str, str]:
    return {"technique_id": tid, "technique_name": name, "tactic": tactic}


def _attack_scenarios() -> list[dict[str, Any]]:
    def scenario(sid, name, description, category, severity, role, techniques, signals):
        return {
            "id": sid,
            "evidence": _evidence(OPERATOR, record=sid),
            "name": name,
            "description": description,
            "category": category,
            "severity": severity,
            "execution_mode": "simulated",
            "target_asset_role": role,
            "mitre_techniques": techniques,
            "expected_signals": signals,
            "roe_reference": None,
        }

    return [
        scenario(
            "scenario:discovery", "Discovery controllata",
            "Enumerazione degli host e delle porte sul segmento OT dalla Kali.",
            "discovery", "medium", "network",
            [_technique("T0846", "Remote System Discovery", "Discovery"),
             _technique("T0842", "Network Sniffing", "Collection")],
            ["Evento Cyber Vision di scansione", "Nuovo host attivo in baseline"],
        ),
        scenario(
            "scenario:unauthorized-write", "Scrittura non autorizzata",
            "Write single register verso il PLC per alterare il setpoint del nastro.",
            "unauthorized_write", "high", "plc",
            [_technique("T0855", "Unauthorized Command Message", "Execution"),
             _technique("T0836", "Modify Parameter", "Impair Process Control"),
             _technique("T0831", "Manipulation of Control", "Impact")],
            ["Evento Cyber Vision di scrittura non autorizzata",
             "Setpoint fuori range nel digital twin"],
        ),
        scenario(
            "scenario:frequency", "Frequenza anomala",
            "Flooding di richieste Modbus per degradare la reattività del PLC.",
            "anomalous_frequency", "medium", "plc",
            [_technique("T0806", "Brute Force I/O", "Impair Process Control"),
             _technique("T0814", "Denial of Service", "Inhibit Response Function")],
            ["Evento Cyber Vision di frequenza anomala"],
        ),
        scenario(
            "scenario:mitm", "MITM / Spoofing",
            "Adversary-in-the-Middle tra HMI e PLC via ARP spoofing.",
            "mitm_spoofing", "high", "network",
            [_technique("T0830", "Adversary-in-the-Middle", "Collection")],
            ["Anomalia ARP", "Alterazione dei valori letti dall'HMI"],
        ),
    ]


def _attack_step(step_id, tid, description, start, end, outcome="success"):
    return {
        "step_id": step_id,
        "technique_id": tid,
        "description": description,
        "started_at": _t(start),
        "completed_at": _t(end),
        "outcome": outcome,
    }


def _attack_runs() -> list[dict[str, Any]]:
    def run(rid, scenario_id, start, end, outcome, steps):
        return {
            "id": rid,
            "evidence": _evidence(OPERATOR, record=rid),
            "scenario_id": scenario_id,
            "status": "completed",
            "execution_mode": "simulated",
            "started_at": _t(start),
            "completed_at": _t(end),
            "source_asset_id": ASSET_KALI,
            "target_asset_ids": [ASSET_PLC],
            "outcome": outcome,
            "steps": steps,
            "roe_reference": None,
        }

    return [
        run("run:discovery", "scenario:discovery", 120, 200, "success", [
            _attack_step("s1", "T0846", "nmap -sn 172.16.10.0/24", 120, 160),
            _attack_step("s2", "T0842", "Cattura passiva del traffico Modbus", 160, 200),
        ]),
        run("run:unauthorized-write", "scenario:unauthorized-write", 400, 460, "success", [
            _attack_step("s1", "T0855", "Connessione Modbus/TCP alla 502", 400, 410),
            _attack_step("s2", "T0836", "write_single_register(0x0002, 90)", 410, 460),
        ]),
        run("run:frequency", "scenario:frequency", 600, 700, "partial", [
            _attack_step("s1", "T0806", "Loop di read_holding_registers ad alta frequenza",
                         600, 700, outcome="partial"),
        ]),
        run("run:mitm", "scenario:mitm", 800, 900, "success", [
            _attack_step("s1", "T0830", "ARP spoofing HMI↔PLC + relay Modbus", 800, 900),
        ]),
    ]


def _detection_correlations() -> list[dict[str, Any]]:
    source_of = {
        "cisco_cyber_vision": CV_CLASSIC,
        "cisco_cyber_vision_new_ui": CV_NEW_UI,
    }

    def correlation(cid, run_id, event_id, detected, source, attack_off, detect_off,
                    technique, note):
        latency = None if detect_off is None else max(0, detect_off - attack_off)
        evidence_source = source_of.get(source, SIEM) if detected else SIEM
        return {
            "id": cid,
            "evidence": _evidence(evidence_source, record=cid),
            "attack_run_id": run_id,
            "event_id": event_id,
            "detected": detected,
            "detection_source": source if detected else "none",
            "attack_at": _t(attack_off),
            "detected_at": None if detect_off is None else _t(detect_off),
            "detection_latency_seconds": latency,
            "mitre_technique_id": technique,
            "notes": [note],
        }

    return [
        correlation("corr:discovery", "run:discovery", EVT_DISCOVERY, True,
                    "cisco_cyber_vision_new_ui", 120, 188, "T0846",
                    "Discovery rilevata dalla New UI in 68s."),
        correlation("corr:unauthorized-write", "run:unauthorized-write", EVT_UNAUTH_WRITE, True,
                    "cisco_cyber_vision", 410, 423, "T0836",
                    "Scrittura non autorizzata rilevata in 13s."),
        correlation("corr:frequency", "run:frequency", EVT_FREQUENCY, True,
                    "cisco_cyber_vision", 600, 642, "T0814",
                    "Frequenza anomala rilevata in 42s."),
        correlation("corr:mitm", "run:mitm", None, False, "none", 800, None, "T0830",
                    "MITM non rilevato: gap di detection da evidenziare nella tesi."),
    ]


def _process_telemetry(samples: int = 24) -> list[dict[str, Any]]:
    """Digital-twin time series. Samples in the write-attack window show tampering."""

    telemetry: list[dict[str, Any]] = []
    attack_start, attack_end = 400, 460
    for index in range(samples):
        offset = index * 40  # one sample every 40s across ~16 minutes
        under_attack = attack_start <= offset <= attack_end
        speed = 90.0 if under_attack else round(50.0 + 6.0 * math.sin(index / 2.0), 1)
        setpoint = 90.0 if under_attack else 50.0
        temperature = round(4.0 + 1.0 * math.sin(index / 3.0), 1)
        bottles = 120 + index * 3
        belt_state = "fault" if under_attack else "running"
        registers = [
            {"address": 0, "name": "conveyor_speed_rpm", "kind": "holding_register",
             "value": speed, "unit": "rpm", "expected_min": 40.0, "expected_max": 60.0,
             "in_bounds": 40.0 <= speed <= 60.0},
            {"address": 2, "name": "setpoint_speed_rpm", "kind": "holding_register",
             "value": setpoint, "unit": "rpm", "expected_min": 40.0, "expected_max": 60.0,
             "in_bounds": 40.0 <= setpoint <= 60.0},
            {"address": 4, "name": "bottles_filled", "kind": "holding_register",
             "value": bottles, "unit": "count", "expected_min": None, "expected_max": None,
             "in_bounds": None},
            {"address": 10, "name": "temperature_c", "kind": "input_register",
             "value": temperature, "unit": "°C", "expected_min": 2.0, "expected_max": 8.0,
             "in_bounds": 2.0 <= temperature <= 8.0},
            {"address": 0, "name": "belt_motor", "kind": "coil",
             "value": not under_attack, "unit": None, "expected_min": None,
             "expected_max": None, "in_bounds": None},
            {"address": 1, "name": "emergency_stop", "kind": "coil",
             "value": under_attack, "unit": None, "expected_min": None,
             "expected_max": None, "in_bounds": None},
            {"address": 0, "name": "bottle_present", "kind": "discrete_input",
             "value": bool(index % 2), "unit": None, "expected_min": None,
             "expected_max": None, "in_bounds": None},
        ]
        telemetry.append({
            "id": f"telemetry:{index:03d}",
            "evidence": _evidence(CV_CLASSIC, record=f"telemetry:{index}",
                                  observed_offset=offset),
            "asset_id": ASSET_PLC,
            "process": "beer_factory_conveyor",
            "captured_at": _t(offset),
            "sample_index": index,
            "belt_state": belt_state,
            "registers": registers,
            "setpoints": [
                {"name": "target_speed", "value": setpoint, "unit": "rpm"},
                {"name": "target_temperature", "value": 4.0, "unit": "°C"},
            ],
            "anomaly": "unexpected_write" if under_attack else None,
            "attack_run_id": "run:unauthorized-write" if under_attack else None,
        })
    return telemetry


def _security_zones() -> list[dict[str, Any]]:
    def zone(zid, name, level, iec_zone, sl, assets, conduits, description):
        return {
            "id": zid,
            "evidence": _evidence(OPERATOR, record=zid),
            "name": name,
            "purdue_level": level,
            "iec62443_zone": iec_zone,
            "target_security_level": sl,
            "asset_ids": assets,
            "conduits": conduits,
            "description": description,
        }

    return [
        zone(ZONE_PROCESS, "Cella di processo", "1", "Zone-OT-Process", "SL-2",
             [ASSET_PLC, ASSET_PLC_LEGACY],
             [{"to_zone_id": ZONE_SUPERVISION, "protocols": ["Modbus"],
               "description": "Polling HMI→PLC sulla 502."},
              {"to_zone_id": ZONE_DPI, "protocols": ["SPAN"],
               "description": "Mirroring verso il sensore DPI."}],
             "Livello 1 Purdue: controllori del nastro."),
        zone(ZONE_SUPERVISION, "Supervisione HMI", "2", "Zone-OT-Supervision", "SL-2",
             [ASSET_HMI],
             [{"to_zone_id": ZONE_PROCESS, "protocols": ["Modbus"],
               "description": "Comandi e letture verso il PLC."}],
             "Livello 2 Purdue: stazione operatore HMI."),
        zone(ZONE_DPI, "Monitoraggio DPI", "3", "Zone-DPI", "SL-3",
             [],
             [], "Livello 3 Purdue: Cyber Vision e monitoraggio passivo."),
        zone(ZONE_TEST, "Test offensivo", "unknown", "Zone-Test", "SL-1",
             [ASSET_KALI],
             [{"to_zone_id": ZONE_PROCESS, "protocols": ["Modbus", "TCP"],
               "description": "Traffico di test autorizzato verso il PLC."}],
             "Segmento di test controllato (Kali)."),
    ]


def _compliance_mappings() -> list[dict[str, Any]]:
    def mapping(mid, framework, ref, title, status, assets, zones, evidence_refs, notes):
        return {
            "id": mid,
            "evidence": _evidence(OPERATOR, record=mid),
            "framework": framework,
            "reference_id": ref,
            "title": title,
            "status": status,
            "asset_ids": assets,
            "zone_ids": zones,
            "evidence_refs": evidence_refs,
            "notes": notes,
        }

    return [
        # IEC 62443
        mapping("cm:62443:sr1.1", "iec_62443", "SR 1.1",
                "Identificazione e autenticazione utenti umani", "not_covered",
                [ASSET_PLC], [ZONE_PROCESS], [],
                ["Modbus/TCP non prevede autenticazione."]),
        mapping("cm:62443:sr3.1", "iec_62443", "SR 3.1",
                "Integrità delle comunicazioni", "partial",
                [ASSET_PLC, ASSET_HMI], [ZONE_PROCESS],
                ["corr:mitm"], ["MITM non rilevato: integrità non garantita."]),
        mapping("cm:62443:sr7.1", "iec_62443", "SR 7.1",
                "Protezione da Denial of Service", "partial",
                [ASSET_PLC], [ZONE_PROCESS], ["corr:frequency"],
                ["Frequenza anomala rilevata ma non mitigata automaticamente."]),
        # NIS2
        mapping("cm:nis2:21.2.a", "nis2", "Art.21.2.a",
                "Analisi dei rischi e sicurezza dei sistemi informativi", "covered",
                [], [], ["risk:plc", "risk:hmi"], ["Risk scoring attivo."]),
        mapping("cm:nis2:21.2.b", "nis2", "Art.21.2.b",
                "Gestione degli incidenti", "partial",
                [], [], ["EVENT_PLACEHOLDER"], []),  # fixed below
        # MITRE ATT&CK for ICS
        mapping("cm:attack:t0846", "mitre_attack_ics", "T0846",
                "Remote System Discovery", "covered",
                [], [], ["corr:discovery"], ["Rilevato dalla New UI."]),
        mapping("cm:attack:t0836", "mitre_attack_ics", "T0836",
                "Modify Parameter", "covered",
                [ASSET_PLC], [], ["corr:unauthorized-write"], ["Rilevato dal Classic."]),
        mapping("cm:attack:t0814", "mitre_attack_ics", "T0814",
                "Denial of Service", "covered",
                [ASSET_PLC], [], ["corr:frequency"], ["Rilevato via frequenza anomala."]),
        mapping("cm:attack:t0830", "mitre_attack_ics", "T0830",
                "Adversary-in-the-Middle", "not_covered",
                [ASSET_HMI, ASSET_PLC], [], ["corr:mitm"],
                ["Gap di detection: MITM non rilevato."]),
        # Purdue
        mapping("cm:purdue:l1", "purdue", "Level 1",
                "Controllo di base (PLC)", "covered",
                [ASSET_PLC], [ZONE_PROCESS], [], []),
        mapping("cm:purdue:l2", "purdue", "Level 2",
                "Supervisione (HMI)", "covered",
                [ASSET_HMI], [ZONE_SUPERVISION], [], []),
    ]


def _history(points: int = 7) -> dict[str, Any]:
    history_points = []
    for day in range(points):
        offset = -86400 * (points - 1 - day)
        detections = 2 + (day % 3)
        history_points.append({
            "snapshot_id": f"snapshot:sandbox:hist-{day}",
            "generated_at": _t(offset),
            "metrics": {
                "open_tickets": 3 + (day % 4),
                "high_risk_assets": 1,
                "detections": detections,
                "undetected_attacks": 1,
                "mean_detection_latency_seconds": 30 + day * 2,
                "quality_score": 84 + day,
                "attack_detection_coverage": 0.75,
            },
        })
    return {
        "retention": {"max_points": 365, "max_age_days": 365, "resolution": "daily"},
        "points": history_points,
    }


def build_sandbox_snapshot() -> dict[str, Any]:
    """Assemble and validate the full BeerFactory sandbox snapshot (schema v3)."""

    baselines, baseline_differences = _baselines_and_diffs()
    compliance = _compliance_mappings()
    # Wire the NIS2 incident-handling control to a real detection evidence ref.
    for mapping in compliance:
        if mapping["id"] == "cm:nis2:21.2.b":
            mapping["evidence_refs"] = ["corr:unauthorized-write", "corr:frequency"]
            mapping["notes"] = ["Incidenti rilevati e correlati agli attacchi simulati."]

    snapshot: dict[str, Any] = {
        "schema_version": "3.0.0",
        "snapshot_id": "snapshot:sandbox:beerfactory:0001",
        "generated_at": _t(0),
        "environment": _environment(),
        "sync": {
            "state": "fresh",
            "publication_mode": "allow_demo",
            "started_at": _t(-120),
            "completed_at": _t(0),
            "max_age_seconds": 900,
            "collector_version": "2.0.0.dev0+sandbox",
            "vpn_required": False,
            "last_known_good_snapshot_id": None,
        },
        "sources": _sources(),
        "virtual_machines": _virtual_machines(),
        "networks": _networks(),
        "assets": _assets(),
        "identity_links": _identity_links(),
        "risk_scores": _risk_scores(),
        "activities": _activities(),
        "flows": _flows(),
        "events": _events(),
        "vulnerabilities": _vulnerabilities(),
        "baselines": baselines,
        "baseline_differences": baseline_differences,
        "sensors": _sensors(),
        "reports": _reports(),
        "findings": _findings(),
        "quality": _quality(),
        # v3 domains
        "attack_scenarios": _attack_scenarios(),
        "attack_runs": _attack_runs(),
        "detection_correlations": _detection_correlations(),
        "process_telemetry": _process_telemetry(),
        "security_zones": _security_zones(),
        "compliance_mappings": compliance,
        "history": _history(),
    }
    contract_v3.validate_snapshot_v3(snapshot)
    return snapshot


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Genera lo snapshot sandbox BeerFactory (v3).")
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(__file__).resolve().parents[3] / "runtime" / "sandbox" / "beerfactory-v3.json",
        help="Percorso del file JSON di output.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    snapshot = build_sandbox_snapshot()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(snapshot, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    args.output.write_text(payload, encoding="utf-8")
    print(json.dumps({
        "output": str(args.output),
        "bytes": len(payload.encode("utf-8")),
        "sha256_16": contract_v3.snapshot_sha256_v3(snapshot)[:16],
        "attack_runs": len(snapshot["attack_runs"]),
        "detections": sum(1 for c in snapshot["detection_correlations"] if c["detected"]),
        "telemetry_samples": len(snapshot["process_telemetry"]),
    }))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
