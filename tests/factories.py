from __future__ import annotations

from copy import deepcopy
from typing import Any

FETCHED_AT = "2026-08-03T10:00:02Z"


def evidence(
    source_id: str,
    truth: str,
    source_record_id: str | None,
    *,
    observed_at: str | None = FETCHED_AT,
    completeness: float = 1.0,
    notes: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "source_id": source_id,
        "source_record_id": source_record_id,
        "truth": truth,
        "observed_at": observed_at,
        "fetched_at": FETCHED_AT,
        "completeness": completeness,
        "notes": notes or [],
    }


def source(
    source_id: str,
    label: str,
    source_type: str,
    status: str,
    truth: str,
) -> dict[str, Any]:
    last_success = FETCHED_AT if status in {"connected", "stale"} else None
    return {
        "id": source_id,
        "evidence": evidence(source_id, truth, source_id, observed_at=last_success),
        "label": label,
        "type": source_type,
        "endpoint_label": f"{label} · endpoint interno",
        "status": status,
        "version": None,
        "last_attempt_at": FETCHED_AT,
        "last_success_at": last_success,
        "record_counts": {},
        "capabilities": {},
        "error": None,
    }


def valid_snapshot() -> dict[str, Any]:
    operator_id = "src:operator:dtlab"
    esxi_id = "src:vmware-esxi:dtlab-01"
    cv_id = "src:cisco-cyber-vision:dtlab-01"
    network_id = "net:vmware:dtlab-01:pg-ot-lab"
    vm_id = "vm:vmware:dtlab-01:119"
    return {
        "schema_version": "2.0.0",
        "snapshot_id": "snapshot:test:0001",
        "generated_at": FETCHED_AT,
        "environment": {
            "id": "env:relatech-dtlab",
            "evidence": evidence(operator_id, "real", "operator-confirmation"),
            "name": "Relatech DTLab",
            "kind": "lab",
            "timezone": "Europe/Rome",
            "status": "operational",
            "description": "Laboratorio OT Cisco Cyber Vision.",
        },
        "sync": {
            "state": "partial",
            "publication_mode": "real_only",
            "started_at": "2026-08-03T10:00:00Z",
            "completed_at": FETCHED_AT,
            "max_age_seconds": 900,
            "collector_version": "2.0.0.dev0",
            "vpn_required": True,
            "last_known_good_snapshot_id": None,
        },
        "sources": [
            source(operator_id, "Conferme operative", "operator", "connected", "real"),
            source(esxi_id, "VMware ESXi", "vmware_esxi", "connected", "observed"),
            source(
                cv_id,
                "Cisco Cyber Vision",
                "cisco_cyber_vision",
                "not_configured",
                "unavailable",
            ),
        ],
        "virtual_machines": [
            {
                "id": vm_id,
                "evidence": evidence(esxi_id, "observed", "vim.VirtualMachine:119"),
                "name": "[Relatech] PLC-Desktop",
                "hostname": "plcubuntu",
                "operational_context": {
                    "purpose": "plc",
                    "lifecycle_role": "operational",
                    "official_target": True,
                    "kpi_scope": "primary",
                    "desired_power_state": "running",
                    "evidence": evidence(
                        operator_id,
                        "real",
                        "operator-confirmation:plc-desktop",
                    ),
                },
                "power_state": "powered_on",
                "guest_os": "Ubuntu Linux",
                "cpu_count": 2,
                "memory_mb": 4096,
                "disk_capacity_gb": 50.0,
                "tools_status": "ok",
                "primary_ip": "172.16.10.10",
                "interfaces": [
                    {
                        "id": "nic:vmware:dtlab-01:119:network-adapter-1",
                        "label": "Network adapter 1",
                        "network_id": network_id,
                        "mac_address": "00:00:00:00:00:01",
                        "ip_addresses": ["172.16.10.10"],
                        "connected": True,
                        "start_connected": True,
                    }
                ],
                "snapshot_count": 0,
            }
        ],
        "networks": [
            {
                "id": network_id,
                "evidence": evidence(esxi_id, "observed", "PG-OT-LAB"),
                "name": "PG-OT-LAB",
                "kind": "ot",
                "cidrs": [],
                "description": "Port group osservato; VLAN e subnet non inferite.",
            }
        ],
        "assets": [],
        "identity_links": [],
        "risk_scores": [],
        "activities": [],
        "flows": [],
        "events": [],
        "vulnerabilities": [],
        "baselines": [],
        "baseline_differences": [],
        "sensors": [],
        "reports": [],
        "findings": [],
        "quality": {
            "methodology": "dtlab_data_quality_v2",
            "score": 72,
            "checks": [
                {
                    "code": "cybervision_not_configured",
                    "label": "Cyber Vision API",
                    "status": "not_available",
                    "details": "Token read-only non ancora configurato.",
                }
            ],
            "coverage": {
                "vmware": 1.0,
                "cyber_vision": 0.0,
            },
        },
    }


def snapshot_copy() -> dict[str, Any]:
    return deepcopy(valid_snapshot())


def add_cisco_asset(snapshot: dict[str, Any], *, score: float | None = None) -> str:
    cv_id = "src:cisco-cyber-vision:dtlab-01"
    asset_id = "asset:cybervision:dtlab-01:42"
    snapshot["sources"][2]["status"] = "connected"
    snapshot["sources"][2]["evidence"] = evidence(cv_id, "real", cv_id)
    snapshot["sources"][2]["last_success_at"] = FETCHED_AT
    snapshot["assets"].append(
        {
            "id": asset_id,
            "evidence": evidence(cv_id, "real", "device:42"),
            "name": "PLC BeerFactory",
            "category": "Industrial automation",
            "device_type": "PLC",
            "vendor": None,
            "ip_addresses": ["172.16.10.10"],
            "mac_addresses": [],
            "network_ids": [],
            "zone": None,
            "protocols": ["Modbus"],
            "status": "online",
            "last_seen_at": FETCHED_AT,
            "operational_role": "target",
        }
    )
    if score is not None:
        band = "low" if score < 40 else "medium" if score < 70 else "high"
        snapshot["risk_scores"].append(
            {
                "id": "risk:cybervision:dtlab-01:42",
                "evidence": evidence(cv_id, "real", "device:42:riskScore"),
                "asset_id": asset_id,
                "score": score,
                "band": band,
                "methodology": "cisco_cyber_vision",
                "computed_at": FETCHED_AT,
                "factors": [],
            }
        )
    return asset_id
