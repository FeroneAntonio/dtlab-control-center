"""Cross-source identity proposals between ESXi VMs and Cyber Vision assets."""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Mapping
from typing import Any


def _normalized_name(value: str) -> str:
    text = value.removeprefix("[Relatech] ").lower()
    return re.sub(r"[^a-z0-9]+", "", text)


def _vm_addresses(vm: Mapping[str, Any], field: str) -> set[str]:
    values: set[str] = set()
    for interface in vm.get("interfaces", []):
        if field == "ip":
            values.update(str(item).lower() for item in interface.get("ip_addresses", []))
        else:
            mac = interface.get("mac_address")
            if mac:
                values.add(str(mac).lower())
    return values


def _evidence(
    source_id: str,
    source_record_id: str,
    truth: str,
    fetched_at: str,
    notes: list[str],
) -> dict[str, Any]:
    return {
        "source_id": source_id,
        "source_record_id": source_record_id,
        "truth": truth,
        "observed_at": fetched_at,
        "fetched_at": fetched_at,
        "completeness": 1.0,
        "notes": notes,
    }


def resolve_vm_asset_identities(
    virtual_machines: list[dict[str, Any]],
    assets: list[dict[str, Any]],
    *,
    fetched_at: str,
    collector_source_id: str,
    operator_source_id: str | None = None,
    operator_confirmed_vm_ipv4: Mapping[str, str] | None = None,
) -> list[dict[str, Any]]:
    """Return one-to-one links, confirming only explicit operator mappings."""

    confirmed_vm_ipv4 = {
        _normalized_name(name): str(address).lower()
        for name, address in (operator_confirmed_vm_ipv4 or {}).items()
    }

    eligible_vms = [
        vm
        for vm in virtual_machines
        if vm.get("operational_context", {}).get("kpi_scope") != "excluded_legacy"
    ]
    ip_occurrences = Counter(
        address
        for vm in eligible_vms
        for address in _vm_addresses(vm, "ip")
    )
    mac_occurrences = Counter(
        address
        for vm in eligible_vms
        for address in _vm_addresses(vm, "mac")
    )
    asset_ip_occurrences = Counter(
        str(address).lower()
        for asset in assets
        for address in asset.get("ip_addresses", [])
    )
    asset_mac_occurrences = Counter(
        str(address).lower()
        for asset in assets
        for address in asset.get("mac_addresses", [])
    )
    candidates: list[tuple[float, str, str, str, dict[str, Any], dict[str, Any]]] = []

    for asset in assets:
        asset_ips = {str(item).lower() for item in asset.get("ip_addresses", [])}
        asset_macs = {str(item).lower() for item in asset.get("mac_addresses", [])}
        asset_name = _normalized_name(str(asset.get("name") or ""))

        for vm in eligible_vms:
            vm_ips = _vm_addresses(vm, "ip")
            vm_macs = _vm_addresses(vm, "mac")
            shared_macs = asset_macs & vm_macs
            shared_ips = asset_ips & vm_ips
            unique_macs = {
                value
                for value in shared_macs
                if mac_occurrences[value] == 1
                and asset_mac_occurrences[value] == 1
            }
            unique_ips = {
                value
                for value in shared_ips
                if ip_occurrences[value] == 1 and asset_ip_occurrences[value] == 1
            }
            name_match = bool(
                asset_name
                and (
                    asset_name in _normalized_name(vm["name"])
                    or _normalized_name(vm["name"]) in asset_name
                )
            )
            if unique_macs and unique_ips:
                method, confidence = "ip_mac_match", 0.99
            elif unique_macs:
                method, confidence = "mac_match", 0.97
            elif unique_ips:
                method, confidence = "ip_match", 0.88
            elif name_match:
                method, confidence = "name_match", 0.65
            else:
                continue
            candidates.append(
                (confidence, vm["id"], asset["id"], method, vm, asset)
            )

    best_by_asset: dict[
        str, tuple[float, str, str, str, dict[str, Any], dict[str, Any]]
    ] = {}
    for asset_id in {candidate[2] for candidate in candidates}:
        ranked = sorted(
            (candidate for candidate in candidates if candidate[2] == asset_id),
            reverse=True,
            key=lambda candidate: candidate[0],
        )
        if len(ranked) > 1 and ranked[0][0] == ranked[1][0]:
            continue
        best_by_asset[asset_id] = ranked[0]

    best_by_vm: dict[
        str, tuple[float, str, str, str, dict[str, Any], dict[str, Any]]
    ] = {}
    for vm_id in {candidate[1] for candidate in best_by_asset.values()}:
        ranked = sorted(
            (candidate for candidate in best_by_asset.values() if candidate[1] == vm_id),
            reverse=True,
            key=lambda candidate: candidate[0],
        )
        if len(ranked) > 1 and ranked[0][0] == ranked[1][0]:
            continue
        best_by_vm[vm_id] = ranked[0]

    links: list[dict[str, Any]] = []
    for confidence, _, _, method, vm, asset in sorted(
        best_by_vm.values(), key=lambda candidate: (candidate[1], candidate[2])
    ):
        expected_ip = confirmed_vm_ipv4.get(_normalized_name(str(vm["name"])))
        asset_ips = {
            str(address).lower() for address in asset.get("ip_addresses", [])
        }
        operator_confirmed = bool(
            operator_source_id
            and expected_ip
            and expected_ip in asset_ips
            and method in {"ip_mac_match", "ip_match", "mac_match"}
        )
        if operator_confirmed:
            link_method = "operator_confirmed"
            link_confidence = 1.0
            link_status = "confirmed"
            evidence_source_id = str(operator_source_id)
            evidence_record_id = (
                f"operator-confirmation:vm-ip:{_normalized_name(str(vm['name']))}"
            )
            evidence_truth = "real"
            notes = [
                "Corrispondenza VM↔asset confermata dal responsabile DTLab sulla "
                f"base dell'indirizzo OT {expected_ip}.",
                f"Il riscontro live uno-a-uno usa anche il metodo {method}.",
            ]
        else:
            link_method = method
            link_confidence = confidence
            link_status = "proposed"
            evidence_source_id = collector_source_id
            evidence_record_id = f"identity-resolution:{method}"
            evidence_truth = "observed"
            notes = [
                "Collegamento bipartito uno-a-uno derivato; la coppia non è ancora "
                "confermata da un operatore."
            ]
            if vm.get("operational_context", {}).get("official_target") is True:
                notes.append(
                    "PLC-Desktop è il target PLC ufficiale; l'ID asset Cisco resta "
                    "proposto."
                )
        links.append(
            {
                "id": f"identity:{vm['id']}:{asset['id']}",
                "evidence": _evidence(
                    evidence_source_id,
                    evidence_record_id,
                    evidence_truth,
                    fetched_at,
                    notes,
                ),
                "virtual_machine_id": vm["id"],
                "asset_id": asset["id"],
                "method": link_method,
                "confidence": link_confidence,
                "status": link_status,
            }
        )
    return links
