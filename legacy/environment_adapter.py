from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROLE_MAP = {
    "CyberVision-with-DPI": ("Cisco", "Cyber Vision Center + DPI", "Medio", "HTTPS / DPI"),
    "HMI-Ubuntu": ("DTLab", "HMI", "Medio", "Modbus TCP"),
    "Kali-Linux": ("OffSec", "Security test workstation", "Alto", "Test autorizzati"),
    "PLC-Desktop": ("DTLab", "PLC simulato attivo", "Alto", "Modbus TCP"),
    "PLC-Ubuntu": ("DTLab", "PLC legacy", "Critico", "Modbus TCP"),
}


def _short_name(name: str) -> str:
    return name.replace("[Relatech] ", "").strip()


def _risk_for(vm: dict[str, Any]) -> str:
    short = _short_name(vm["name"])
    return ROLE_MAP.get(short, ("Sconosciuto", "VM", "Medio", "N/D"))[2]


def build_environment_payload(inventory: dict[str, Any]) -> dict[str, Any]:
    collected_at = inventory.get("collected_at") or datetime.now(timezone.utc).isoformat()
    assets: list[dict[str, Any]] = []
    vm_details: list[dict[str, Any]] = []
    network_details: list[dict[str, Any]] = []

    for vm in inventory.get("virtual_machines", []):
        short = _short_name(vm["name"])
        vendor, asset_type, risk, protocol = ROLE_MAP.get(
            short, ("Sconosciuto", "Macchina virtuale", "Medio", "N/D")
        )
        guest_networks = vm.get("guest_networks") or []
        primary_network = guest_networks[0] if guest_networks else {}
        ipv4 = [ip for ip in primary_network.get("ip_addresses", []) if ":" not in ip]
        ip_address = vm.get("primary_ip") or (ipv4[0] if ipv4 else None)
        nics = vm.get("networks") or []
        zones = sorted({nic.get("network") for nic in nics if nic.get("network")})
        mac = nics[0].get("mac_address") if nics else None
        assets.append(
            {
                "asset_id": f"ESXI-{vm.get('moid', short)}",
                "name": short,
                "ip_address": ip_address,
                "mac_address": mac,
                "vendor": vendor,
                "asset_type": asset_type,
                "zone": " + ".join(zones) if zones else "Non rilevata",
                "protocol": protocol,
                "risk": risk,
                "status": "Online" if vm.get("power_state") == "poweredOn" else "Offline",
                "last_seen": collected_at,
                "firmware": vm.get("guest_full_name"),
                "vulnerabilities": 0,
            }
        )
        vm_details.append(
            {
                "name": short,
                "power_state": vm.get("power_state"),
                "hostname": vm.get("hostname"),
                "primary_ip": ip_address,
                "guest": vm.get("guest_full_name"),
                "tools_status": vm.get("tools_status"),
                "cpu": vm.get("cpu"),
                "memory_gb": round((vm.get("memory_mb") or 0) / 1024, 1),
                "disk_gb": sum(item.get("capacity_gb", 0) for item in vm.get("disks", [])),
                "snapshots": len(vm.get("snapshots") or []),
            }
        )
        for nic in nics:
            guest_match = next(
                (
                    item
                    for item in guest_networks
                    if item.get("mac_address") == nic.get("mac_address")
                ),
                {},
            )
            network_details.append(
                {
                    "vm": short,
                    "adapter": nic.get("label"),
                    "portgroup": nic.get("network"),
                    "mac_address": nic.get("mac_address"),
                    "ip_addresses": ", ".join(guest_match.get("ip_addresses") or []),
                    "connected": bool(nic.get("connected")),
                    "start_connected": bool(nic.get("start_connected")),
                }
            )

    findings: list[dict[str, Any]] = []
    by_ip: dict[str, list[str]] = {}
    for asset in assets:
        if asset["ip_address"]:
            by_ip.setdefault(asset["ip_address"], []).append(asset["name"])
    for ip, names in by_ip.items():
        if len(names) > 1:
            findings.append(
                {
                    "severity": "Critica",
                    "title": f"Indirizzo IP duplicato: {ip}",
                    "detail": "VM accese con lo stesso IP: " + ", ".join(names),
                    "source": "VMware ESXi",
                    "status": "Da risolvere",
                }
            )

    legacy = next((asset for asset in assets if asset["name"] == "PLC-Ubuntu"), None)
    if legacy and legacy["status"] == "Online":
        findings.append(
            {
                "severity": "Alta",
                "title": "PLC legacy ancora accesa",
                "detail": "La VM PLC-Ubuntu è poweredOn insieme alla PLC-Desktop.",
                "source": "VMware ESXi",
                "status": "Da confermare con Relatech",
            }
        )

    kali = next((vm for vm in vm_details if vm["name"] == "Kali-Linux"), None)
    if kali and kali["tools_status"] != "toolsOk":
        findings.append(
            {
                "severity": "Media",
                "title": "VMware Tools non disponibili su Kali",
                "detail": "Hostname e indirizzi guest non possono essere verificati via ESXi.",
                "source": "VMware ESXi",
                "status": "Aperto",
            }
        )

    cv_dpi = next(
        (
            nic
            for nic in network_details
            if nic["vm"] == "CyberVision-with-DPI" and nic["portgroup"] == "PG-CV-DPI"
        ),
        None,
    )
    if cv_dpi and cv_dpi["ip_addresses"]:
        findings.append(
            {
                "severity": "Informativa",
                "title": "NIC DPI con indirizzo operativo",
                "detail": f"PG-CV-DPI riporta {cv_dpi['ip_addresses']}; verificare ruolo e modalità di cattura.",
                "source": "VMware ESXi",
                "status": "Da validare in Cyber Vision",
            }
        )

    metadata = {
        "mode": "REAL_PARTIAL",
        "environment": "Relatech DTLab",
        "generated_at": collected_at,
        "schema_version": "1.2",
        "dataset_notice": "Inventario ESXi reale; telemetria Cyber Vision non ancora autenticata",
        "evidence_level": "Configurazione osservata via VMware API",
        "vm_count": len(assets),
        "findings": findings,
        "vm_details": vm_details,
        "network_details": network_details,
        "esxi_host": inventory.get("esxi_host"),
    }
    return {
        "metadata": metadata,
        "assets": assets,
        "alerts": [],
        "flows": [],
        "sources": [
            {
                "source": "VMware ESXi",
                "type": "vSphere API",
                "status": "Connesso",
                "last_sync": collected_at,
                "records": len(assets) + len(network_details),
                "endpoint": "esxi.example.invalid (esempio)",
            },
            {
                "source": "Cisco Cyber Vision",
                "type": "REST API 3.0",
                "status": "Raggiungibile · autenticazione mancante",
                "last_sync": None,
                "records": 0,
                "endpoint": "cybervision.example.invalid (esempio)",
            },
            {
                "source": "SIEM",
                "type": "Syslog / API",
                "status": "Non configurato",
                "last_sync": None,
                "records": 0,
                "endpoint": "Da definire",
            },
        ],
    }


def load_environment_payload(path: str | Path) -> dict[str, Any]:
    inventory = json.loads(Path(path).read_text(encoding="utf-8"))
    return build_environment_payload(inventory)
