"""Normalize read-only VMware ESXi inventory into the DTLab v2 contract."""

from __future__ import annotations

import ipaddress
import re
from collections import defaultdict
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

DEFAULT_SOURCE_ID = "src:vmware-esxi:dtlab-01"
DEFAULT_OPERATOR_SOURCE_ID = "src:operator:dtlab"
ID_PREFIX = "vmware:dtlab-01"

_CONTEXT_BY_NAME: dict[str, dict[str, Any]] = {
    "CyberVision-with-DPI": {
        "purpose": "cyber_vision",
        "lifecycle_role": "support",
        "official_target": False,
        "kpi_scope": "support",
        "desired_power_state": "running",
        "truth": "expected",
        "source_record_id": "project-context:cyber-vision",
    },
    "HMI-Ubuntu": {
        "purpose": "hmi",
        "lifecycle_role": "operational",
        "official_target": False,
        "kpi_scope": "support",
        "desired_power_state": "running",
        "truth": "expected",
        "source_record_id": "project-context:hmi",
    },
    "Kali-Linux": {
        "purpose": "security_testing",
        "lifecycle_role": "test",
        "official_target": False,
        "kpi_scope": "excluded_test",
        "desired_power_state": "running",
        "truth": "expected",
        "source_record_id": "project-context:kali",
    },
    "PLC-Desktop": {
        "purpose": "plc",
        "lifecycle_role": "operational",
        "official_target": True,
        "kpi_scope": "primary",
        "desired_power_state": "running",
        "truth": "real",
        "source_record_id": "operator-confirmation:plc-desktop",
    },
    "PLC-Ubuntu": {
        "purpose": "plc",
        "lifecycle_role": "legacy",
        "official_target": False,
        "kpi_scope": "excluded_legacy",
        "desired_power_state": "running",
        "truth": "real",
        "source_record_id": "operator-confirmation:plc-ubuntu-legacy-retained",
    },
}

_NETWORK_KIND_BY_NAME = {
    "CTF": "ctf",
    "PG-OT-LAB": "ot",
    "PG-CV-DPI": "dpi",
}

_POWER_STATE = {
    "poweredOn": "powered_on",
    "poweredOff": "powered_off",
    "suspended": "suspended",
}

_TOOLS_STATUS = {
    "toolsOk": "ok",
    "toolsNotRunning": "not_running",
    "toolsNotInstalled": "not_installed",
}


class EsxiNormalizationError(ValueError):
    """The ESXi response is too incomplete to normalize safely."""


def _utc_text(value: str | None) -> str | None:
    if not value:
        return None
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise EsxiNormalizationError("collected_at deve includere il fuso orario")
    return parsed.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _now_text(value: datetime | None) -> str:
    current = value or datetime.now(UTC)
    if current.tzinfo is None:
        raise EsxiNormalizationError("fetched_at deve includere il fuso orario")
    return current.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _slug(value: str) -> str:
    normalized = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return normalized or "unknown"


def _short_name(value: str) -> str:
    return value.removeprefix("[Relatech] ").strip()


def _evidence(
    source_id: str,
    source_record_id: str | None,
    truth: str,
    observed_at: str | None,
    fetched_at: str,
    *,
    completeness: float = 1.0,
    notes: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "source_id": source_id,
        "source_record_id": source_record_id,
        "truth": truth,
        "observed_at": observed_at,
        "fetched_at": fetched_at,
        "completeness": completeness,
        "notes": notes or [],
    }


def _network_id(name: str) -> str:
    return f"net:{ID_PREFIX}:{_slug(name)}"


def _vm_id(moid: str) -> str:
    return f"vm:{ID_PREFIX}:{moid}"


def _interface_id(moid: str, label: str) -> str:
    return f"nic:{ID_PREFIX}:{moid}:{_slug(label)}"


def _context(
    short_name: str,
    operator_source_id: str,
    observed_at: str | None,
    fetched_at: str,
) -> dict[str, Any]:
    configured = _CONTEXT_BY_NAME.get(
        short_name,
        {
            "purpose": "unknown",
            "lifecycle_role": "unknown",
            "official_target": False,
            "kpi_scope": "unknown",
            "desired_power_state": "unspecified",
            "truth": "expected",
            "source_record_id": f"name-inference:{_slug(short_name)}",
        },
    )
    return {
        "purpose": configured["purpose"],
        "lifecycle_role": configured["lifecycle_role"],
        "official_target": configured["official_target"],
        "kpi_scope": configured["kpi_scope"],
        "desired_power_state": configured["desired_power_state"],
        "evidence": _evidence(
            operator_source_id,
            configured["source_record_id"],
            configured["truth"],
            observed_at,
            fetched_at,
            notes=(
                []
                if configured["truth"] == "real"
                else ["Ruolo operativo derivato dal contesto di progetto, non dall'API ESXi."]
            ),
        ),
    }


def _guest_ips_by_mac(vm: Mapping[str, Any]) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for guest_network in vm.get("guest_networks") or []:
        mac = str(guest_network.get("mac_address") or "").lower()
        if mac:
            result[mac] = [
                str(address)
                for address in guest_network.get("ip_addresses") or []
                if address
            ]
    return result


def _is_ipv4(value: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(value), ipaddress.IPv4Address)
    except ValueError:
        return False


def normalize_esxi_inventory(
    inventory: Mapping[str, Any],
    *,
    fetched_at: datetime | None = None,
    source_id: str = DEFAULT_SOURCE_ID,
    operator_source_id: str = DEFAULT_OPERATOR_SOURCE_ID,
    max_age_seconds: int = 900,
) -> dict[str, Any]:
    """Return ESXi-owned v2 entities without inventing OT telemetry.

    This function never emits Cyber Vision assets, protocols, vulnerabilities, or risk
    scores. A powered-on VM is represented as a VM runtime fact, not as an online OT asset.
    """

    raw_vms = inventory.get("virtual_machines")
    if not isinstance(raw_vms, list):
        raise EsxiNormalizationError("virtual_machines deve essere una lista")

    fetched_text = _now_text(fetched_at)
    observed_text = _utc_text(inventory.get("collected_at"))
    stale = False
    if observed_text:
        observed_datetime = datetime.fromisoformat(observed_text.replace("Z", "+00:00"))
        fetched_datetime = datetime.fromisoformat(fetched_text.replace("Z", "+00:00"))
        stale = (fetched_datetime - observed_datetime).total_seconds() > max_age_seconds
    observation_truth = (
        "stale" if stale else "observed" if observed_text else "unavailable"
    )
    observation_completeness = 1.0 if observed_text else 0.75
    observation_notes = []
    if stale:
        observation_notes.append(
            f"Inventario ESXi più vecchio di {max_age_seconds} secondi."
        )
    elif not observed_text:
        observation_notes.append("Timestamp di osservazione assente nell'inventario ESXi.")

    network_names = sorted(
        {
            str(nic.get("network"))
            for vm in raw_vms
            for nic in (vm.get("networks") or [])
            if nic.get("network")
        }
    )
    networks = [
        {
            "id": _network_id(name),
            "evidence": _evidence(
                source_id,
                f"portgroup:{name}",
                observation_truth,
                observed_text,
                fetched_text,
                completeness=observation_completeness,
                notes=observation_notes,
            ),
            "name": name,
            "kind": _NETWORK_KIND_BY_NAME.get(name, "unknown"),
            "cidrs": [],
            "description": "Port group osservato; subnet, VLAN e policy non inferite.",
        }
        for name in network_names
    ]

    virtual_machines: list[dict[str, Any]] = []
    ips_to_vm_ids: dict[str, set[str]] = defaultdict(set)
    ips_to_network_ids: dict[str, set[str]] = defaultdict(set)
    vm_by_short_name: dict[str, dict[str, Any]] = {}

    for raw_vm in raw_vms:
        moid = str(raw_vm.get("moid") or "").strip()
        name = str(raw_vm.get("name") or "").strip()
        if not moid or not name:
            raise EsxiNormalizationError("Ogni VM deve avere moid e name")

        short_name = _short_name(name)
        guest_ips = _guest_ips_by_mac(raw_vm)
        interfaces: list[dict[str, Any]] = []
        for raw_interface in raw_vm.get("networks") or []:
            label = str(raw_interface.get("label") or "Network adapter")
            mac = str(raw_interface.get("mac_address") or "").lower() or None
            portgroup = str(raw_interface.get("network") or "").strip()
            ip_addresses = list(guest_ips.get(mac or "", []))
            interface = {
                "id": _interface_id(moid, label),
                "label": label,
                "network_id": _network_id(portgroup) if portgroup else None,
                "mac_address": mac,
                "ip_addresses": ip_addresses,
                "connected": bool(raw_interface.get("connected")),
                "start_connected": bool(raw_interface.get("start_connected")),
            }
            interfaces.append(interface)
            for address in ip_addresses:
                if _is_ipv4(address):
                    ips_to_vm_ids[address].add(_vm_id(moid))
                    if interface["network_id"]:
                        ips_to_network_ids[address].add(interface["network_id"])

        tools_status = _TOOLS_STATUS.get(str(raw_vm.get("tools_status")), "unknown")
        missing_guest_telemetry = tools_status == "not_installed"
        vm_evidence_notes = list(observation_notes)
        if missing_guest_telemetry:
            vm_evidence_notes.append(
                "VMware Tools non installati: hostname e indirizzi guest non disponibili."
            )
        vm = {
            "id": _vm_id(moid),
            "evidence": _evidence(
                source_id,
                f"vim.VirtualMachine:{moid}",
                observation_truth,
                observed_text,
                fetched_text,
                completeness=0.7 if missing_guest_telemetry else observation_completeness,
                notes=vm_evidence_notes,
            ),
            "name": name,
            "hostname": raw_vm.get("hostname") or None,
            "operational_context": _context(
                short_name,
                operator_source_id,
                fetched_text,
                fetched_text,
            ),
            "power_state": _POWER_STATE.get(str(raw_vm.get("power_state")), "unknown"),
            "guest_os": raw_vm.get("guest_full_name") or None,
            "cpu_count": max(0, int(raw_vm.get("cpu") or 0)),
            "memory_mb": max(0, int(raw_vm.get("memory_mb") or 0)),
            "disk_capacity_gb": round(
                sum(float(disk.get("capacity_gb") or 0) for disk in raw_vm.get("disks") or []),
                3,
            ),
            "tools_status": tools_status,
            "primary_ip": raw_vm.get("primary_ip") or None,
            "interfaces": interfaces,
            "snapshot_count": len(raw_vm.get("snapshots") or []),
        }
        virtual_machines.append(vm)
        vm_by_short_name[short_name] = vm

    findings: list[dict[str, Any]] = []
    finding_time = observed_text or fetched_text
    for address, vm_ids in sorted(ips_to_vm_ids.items()):
        powered_on_ids = {
            vm["id"]
            for vm in virtual_machines
            if vm["id"] in vm_ids and vm["power_state"] == "powered_on"
        }
        if len(powered_on_ids) < 2:
            continue
        entity_ids = sorted(powered_on_ids | ips_to_network_ids[address])
        findings.append(
            {
                "id": f"finding:vmware:duplicate-ip:{_slug(address)}",
                "evidence": _evidence(
                    source_id,
                    f"derived:duplicate-ip:{address}",
                    observation_truth,
                    observed_text,
                    fetched_text,
                    completeness=observation_completeness,
                ),
                "code": "duplicate_guest_ipv4",
                "severity": "high",
                "title": "IPv4 guest duplicato osservato",
                "description": (
                    f"L'indirizzo {address} è riportato da più VM accese. "
                    "Nessuna modifica o arresto è stato eseguito."
                ),
                "status": "open",
                "entity_ids": entity_ids,
                "first_detected_at": finding_time,
                "last_detected_at": finding_time,
                "recommended_action": (
                    "Validare ruoli e configurazione con Relatech; non correggere "
                    "automaticamente né spegnere VM."
                ),
                "exclude_from_operational_kpis": False,
            }
        )

    kali = vm_by_short_name.get("Kali-Linux")
    if kali and kali["tools_status"] == "not_installed":
        findings.append(
            {
                "id": "finding:vmware:kali-guest-telemetry",
                "evidence": _evidence(
                    source_id,
                    "derived:kali-tools-not-installed",
                    observation_truth,
                    observed_text,
                    fetched_text,
                ),
                "code": "guest_telemetry_unavailable",
                "severity": "medium",
                "title": "Telemetria guest Kali non disponibile",
                "description": (
                    "La VM è accesa; VMware Tools non è installato, quindi hostname e IP "
                    "guest non sono verificabili via ESXi."
                ),
                "status": "open",
                "entity_ids": [kali["id"]],
                "first_detected_at": finding_time,
                "last_detected_at": finding_time,
                "recommended_action": (
                    "Trattare i campi guest come non disponibili; installare Tools solo "
                    "dopo approvazione operativa."
                ),
                "exclude_from_operational_kpis": True,
            }
        )

    cyber_vision = vm_by_short_name.get("CyberVision-with-DPI")
    dpi_network_id = _network_id("PG-CV-DPI")
    if cyber_vision and any(
        interface["network_id"] == dpi_network_id and interface["ip_addresses"]
        for interface in cyber_vision["interfaces"]
    ):
        findings.append(
            {
                "id": "finding:vmware:cv-dpi-mode-unverified",
                "evidence": _evidence(
                    source_id,
                    "derived:cv-dpi-interface",
                    observation_truth,
                    observed_text,
                    fetched_text,
                ),
                "code": "dpi_capture_mode_unverified",
                "severity": "info",
                "title": "Modalità di cattura DPI non verificata",
                "description": (
                    "La NIC PG-CV-DPI e il suo indirizzo guest sono osservati da ESXi; "
                    "ESXi non prova il ruolo di cattura o lo stato del sensore."
                ),
                "status": "open",
                "entity_ids": [cyber_vision["id"], dpi_network_id],
                "first_detected_at": finding_time,
                "last_detected_at": finding_time,
                "recommended_action": "Confermare capture mode e salute tramite API Cyber Vision.",
                "exclude_from_operational_kpis": False,
            }
        )

    legacy = vm_by_short_name.get("PLC-Ubuntu")
    if legacy:
        findings.append(
            {
                "id": "finding:vmware:legacy-plc-retained",
                "evidence": _evidence(
                    operator_source_id,
                    "operator-confirmation:plc-ubuntu-legacy-retained",
                    "real",
                    fetched_text,
                    fetched_text,
                ),
                "code": "legacy_vm_intentionally_retained",
                "severity": "info",
                "title": "PLC legacy mantenuta intenzionalmente",
                "description": (
                    "PLC-Ubuntu resta accesa per scelta operativa ed è esclusa dai KPI "
                    "primari; non è un allarme di disponibilità."
                ),
                "status": "accepted",
                "entity_ids": [legacy["id"]],
                "first_detected_at": finding_time,
                "last_detected_at": finding_time,
                "recommended_action": "Mantenere accesa salvo diversa istruzione esplicita.",
                "exclude_from_operational_kpis": True,
            }
        )

    if inventory.get("hosts") == []:
        findings.append(
            {
                "id": "finding:vmware:host-scope-unavailable",
                "evidence": _evidence(
                    source_id,
                    "inventory:hosts",
                    "unavailable",
                    observed_text,
                    fetched_text,
                    completeness=0,
                    notes=["L'account read-only non espone host e vSwitch."],
                ),
                "code": "host_network_scope_unavailable",
                "severity": "info",
                "title": "Dettaglio host e vSwitch non disponibile",
                "description": (
                    "hosts=[] indica visibilità insufficiente, non assenza di host. "
                    "VLAN, promiscuous mode e policy non vengono dedotte."
                ),
                "status": "accepted",
                "entity_ids": [],
                "first_detected_at": finding_time,
                "last_detected_at": finding_time,
                "recommended_action": (
                    "Ampliare il ruolo read-only solo se il dettaglio vSwitch è necessario."
                ),
                "exclude_from_operational_kpis": True,
            }
        )

    interface_count = sum(len(vm["interfaces"]) for vm in virtual_machines)
    source = {
        "id": source_id,
        "evidence": _evidence(
            source_id,
            "inventory-root",
            observation_truth,
            observed_text,
            fetched_text,
            completeness=observation_completeness,
            notes=observation_notes,
        ),
        "label": "VMware ESXi DTLab",
        "type": "vmware_esxi",
        "endpoint_label": "ESXi DTLab · accesso VPN",
        "status": "stale" if stale else "connected" if observed_text else "degraded",
        "version": None,
        "last_attempt_at": fetched_text,
        "last_success_at": observed_text if raw_vms else None,
        "record_counts": {
            "virtual_machines": len(virtual_machines),
            "networks": len(networks),
            "interfaces": interface_count,
            "findings": len(findings),
        },
        "capabilities": {
            "vm_inventory": {
                "status": "available" if observed_text else "error",
                "records": len(virtual_machines),
                "error_code": None if observed_text else "missing_observation_timestamp",
            },
            "host_network_scope": {
                "status": (
                    "endpoint_unavailable" if inventory.get("hosts") == [] else "available"
                ),
                "records": len(inventory.get("hosts") or []),
                "error_code": (
                    "permission_scope" if inventory.get("hosts") == [] else None
                ),
            },
        },
        "error": None,
    }
    return {
        "source": source,
        "virtual_machines": virtual_machines,
        "networks": networks,
        "findings": findings,
        "quality_checks": [
            {
                "code": "esxi_vm_inventory",
                "label": "Inventario VM ESXi",
                "status": "pass" if observed_text and raw_vms else "warn",
                "details": (
                    f"{len(virtual_machines)} VM e {interface_count} NIC normalizzate."
                ),
            },
            {
                "code": "esxi_host_network_scope",
                "label": "Visibilità host e vSwitch",
                "status": "not_available" if inventory.get("hosts") == [] else "pass",
                "details": (
                    "Dettaglio host/vSwitch non esposto dall'account."
                    if inventory.get("hosts") == []
                    else "Dettaglio host disponibile."
                ),
            },
        ],
    }
