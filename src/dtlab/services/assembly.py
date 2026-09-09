"""Assemble source-owned entities into one validated DTLab v2 snapshot."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from dtlab import __version__
from dtlab.contract import validate_snapshot
from dtlab.services.identity import resolve_vm_asset_identities

OPERATOR_SOURCE_ID = "src:operator:dtlab"
COLLECTOR_SOURCE_ID = "src:collector:dtlab"
OPERATOR_CONFIRMED_VM_IPV4 = {
    "HMI-Ubuntu": "172.16.10.20",
    "Kali-Linux": "172.16.10.30",
    "PLC-Desktop": "172.16.10.10",
}


def _utc_text(value: datetime) -> str:
    if value.tzinfo is None:
        raise ValueError("I timestamp devono includere il fuso orario.")
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _evidence(
    source_id: str,
    source_record_id: str,
    truth: str,
    fetched_at: str,
    *,
    completeness: float = 1.0,
) -> dict[str, Any]:
    return {
        "source_id": source_id,
        "source_record_id": source_record_id,
        "truth": truth,
        "observed_at": fetched_at if truth != "unavailable" else None,
        "fetched_at": fetched_at,
        "completeness": completeness,
        "notes": [],
    }


def operator_source(fetched_at: str) -> dict[str, Any]:
    return {
        "id": OPERATOR_SOURCE_ID,
        "evidence": _evidence(
            OPERATOR_SOURCE_ID,
            "operator-confirmations",
            "real",
            fetched_at,
        ),
        "label": "Conferme operative DTLab",
        "type": "operator",
        "endpoint_label": "Conferme del responsabile del laboratorio",
        "status": "connected",
        "version": None,
        "last_attempt_at": fetched_at,
        "last_success_at": fetched_at,
        "record_counts": {
            "operational_context": 5,
            "identity_confirmations": len(OPERATOR_CONFIRMED_VM_IPV4),
        },
        "capabilities": {},
        "error": None,
    }


def collector_source(fetched_at: str) -> dict[str, Any]:
    return {
        "id": COLLECTOR_SOURCE_ID,
        "evidence": _evidence(
            COLLECTOR_SOURCE_ID,
            "collector-runtime",
            "real",
            fetched_at,
        ),
        "label": "DTLab Collector",
        "type": "other",
        "endpoint_label": "Collector locale su postazione VPN",
        "status": "connected",
        "version": __version__,
        "last_attempt_at": fetched_at,
        "last_success_at": fetched_at,
        "record_counts": {},
        "capabilities": {},
        "error": None,
    }


def unavailable_cybervision_source(
    fetched_at: str,
    *,
    code: str = "credential_unavailable",
    status: str = "not_configured",
) -> dict[str, Any]:
    return {
        "id": "src:cisco-cyber-vision:dtlab-01",
        "evidence": _evidence(
            "src:cisco-cyber-vision:dtlab-01",
            "classic:version",
            "unavailable",
            fetched_at,
            completeness=0,
        ),
        "label": "Cisco Cyber Vision",
        "type": "cisco_cyber_vision",
        "endpoint_label": "Cyber Vision Center · accesso VPN",
        "status": status,
        "version": None,
        "last_attempt_at": fetched_at,
        "last_success_at": None,
        "record_counts": {},
        "capabilities": {},
        "error": {
            "code": code,
            "message": "Telemetria Cisco non disponibile nell'ultima sincronizzazione.",
        },
    }


def assemble_snapshot(
    esxi: dict[str, Any],
    *,
    cybervision: dict[str, Any] | None,
    cybervision_unavailable_source: dict[str, Any] | None = None,
    started_at: datetime,
    completed_at: datetime,
    snapshot_id: str,
    last_known_good_snapshot_id: str | None = None,
) -> dict[str, Any]:
    completed_text = _utc_text(completed_at)
    started_text = _utc_text(started_at)
    cv_source = cybervision["source"] if cybervision is not None else (
        cybervision_unavailable_source
        or unavailable_cybervision_source(completed_text)
    )
    sources = [
        operator_source(completed_text),
        collector_source(completed_text),
        esxi["source"],
        cv_source,
        *(cybervision.get("additional_sources", []) if cybervision else []),
    ]
    assets = cybervision["assets"] if cybervision else []
    identities = resolve_vm_asset_identities(
        esxi["virtual_machines"],
        assets,
        fetched_at=completed_text,
        collector_source_id=COLLECTOR_SOURCE_ID,
        operator_source_id=OPERATOR_SOURCE_ID,
        operator_confirmed_vm_ipv4=OPERATOR_CONFIRMED_VM_IPV4,
    )
    sources[1]["record_counts"]["identity_links"] = len(identities)

    esxi_checks = list(esxi.get("quality_checks", []))
    esxi_coverage = {
        "esxi_vm_inventory": 1.0
        if esxi["source"]["status"] == "connected"
        else 0.5,
        "esxi_host_network_scope": 0.0
        if any(
            check.get("code") == "esxi_host_network_scope"
            and check.get("status") == "not_available"
            for check in esxi_checks
        )
        else 1.0,
    }
    cv_coverage = cybervision.get("coverage", {}) if cybervision else {
        "cybervision": 0.0
    }
    coverage = {
        **esxi_coverage,
        **{f"cybervision_{key}": value for key, value in cv_coverage.items()},
    }
    esxi_quality = sum(esxi_coverage.values()) / len(esxi_coverage) * 100
    cv_quality = float(cybervision.get("quality_score", 0)) if cybervision else 0.0
    quality_score = round(esxi_quality * 0.3 + cv_quality * 0.7)
    checks = esxi_checks + (
        list(cybervision.get("quality_checks", []))
        if cybervision
        else [
            {
                "code": "cybervision_not_available",
                "label": "Cisco Cyber Vision API",
                "status": "not_available",
                "details": "Telemetria Cisco non acquisita; nessun valore è sostituito con zero.",
            }
        ]
    )
    sync_state = (
        "fresh"
        if esxi["source"]["status"] == "connected"
        and cv_source["status"] == "connected"
        else "partial"
    )

    snapshot = {
        "schema_version": "2.0.0",
        "snapshot_id": snapshot_id,
        "generated_at": completed_text,
        "environment": {
            "id": "env:relatech-dtlab",
            "evidence": _evidence(
                OPERATOR_SOURCE_ID,
                "operator-confirmation:relatech-dtlab",
                "real",
                completed_text,
            ),
            "name": "Relatech DTLab",
            "kind": "lab",
            "timezone": "Europe/Rome",
            "status": "operational" if sync_state == "fresh" else "degraded",
            "description": "Laboratorio OT BeerFactory con Cisco Cyber Vision e VMware ESXi.",
        },
        "sync": {
            "state": sync_state,
            "publication_mode": "real_only",
            "started_at": started_text,
            "completed_at": completed_text,
            "max_age_seconds": 900,
            "collector_version": __version__,
            "vpn_required": True,
            "last_known_good_snapshot_id": last_known_good_snapshot_id,
        },
        "sources": sources,
        "virtual_machines": esxi["virtual_machines"],
        "networks": esxi["networks"],
        "assets": assets,
        "identity_links": identities,
        "risk_scores": cybervision["risk_scores"] if cybervision else [],
        "activities": cybervision["activities"] if cybervision else [],
        "flows": cybervision["flows"] if cybervision else [],
        "events": cybervision["events"] if cybervision else [],
        "vulnerabilities": cybervision["vulnerabilities"] if cybervision else [],
        "baselines": cybervision["baselines"] if cybervision else [],
        "baseline_differences": (
            cybervision["baseline_differences"] if cybervision else []
        ),
        "sensors": cybervision["sensors"] if cybervision else [],
        "reports": cybervision["reports"] if cybervision else [],
        "findings": esxi["findings"],
        "quality": {
            "methodology": "dtlab_data_quality_v2",
            "score": quality_score,
            "checks": checks,
            "coverage": coverage,
        },
    }
    validate_snapshot(snapshot)
    return snapshot
