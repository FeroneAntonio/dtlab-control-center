from __future__ import annotations

import json
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path

import pytest

from dtlab.adapters.esxi import EsxiNormalizationError, normalize_esxi_inventory
from dtlab.contract import validate_snapshot
from tests.factories import valid_snapshot

CURRENT_INVENTORY_PATH = Path(__file__).resolve().parents[2] / "esxi_inventory.json"
FETCHED_AT = datetime(2026, 8, 3, 12, 0, 0, tzinfo=UTC)


@pytest.fixture
def current_inventory() -> dict:
    if not CURRENT_INVENTORY_PATH.exists():
        pytest.skip("Inventario ESXi operativo non presente in questa checkout.")
    return json.loads(CURRENT_INVENTORY_PATH.read_text(encoding="utf-8"))


def test_current_inventory_normalizes_to_five_vms_and_nine_distinct_nics(
    current_inventory: dict,
) -> None:
    result = normalize_esxi_inventory(current_inventory, fetched_at=FETCHED_AT)
    vms = result["virtual_machines"]
    interfaces = [interface for vm in vms for interface in vm["interfaces"]]

    assert len(vms) == 5
    assert len({vm["id"] for vm in vms}) == 5
    assert len(interfaces) == 9
    assert len({interface["id"] for interface in interfaces}) == 9
    assert {network["name"] for network in result["networks"]} == {
        "CTF",
        "PG-OT-LAB",
        "PG-CV-DPI",
    }
    assert all(network["cidrs"] == [] for network in result["networks"])
    assert all(vm["power_state"] == "powered_on" for vm in vms)


def test_operational_target_and_legacy_roles_preserve_operator_instruction(
    current_inventory: dict,
) -> None:
    result = normalize_esxi_inventory(current_inventory, fetched_at=FETCHED_AT)
    by_name = {vm["name"]: vm for vm in result["virtual_machines"]}
    official = [
        vm
        for vm in result["virtual_machines"]
        if vm["operational_context"]["official_target"]
    ]

    assert [vm["name"] for vm in official] == ["[Relatech] PLC-Desktop"]
    assert official[0]["id"].endswith(":119")
    legacy = by_name["[Relatech] PLC-Ubuntu"]
    assert legacy["id"].endswith(":115")
    assert legacy["power_state"] == "powered_on"
    assert legacy["operational_context"]["lifecycle_role"] == "legacy"
    assert legacy["operational_context"]["kpi_scope"] == "excluded_legacy"
    assert legacy["operational_context"]["desired_power_state"] == "running"


def test_kali_is_running_while_only_guest_telemetry_is_unavailable(
    current_inventory: dict,
) -> None:
    result = normalize_esxi_inventory(current_inventory, fetched_at=FETCHED_AT)
    kali = next(
        vm for vm in result["virtual_machines"] if vm["name"] == "[Relatech] Kali-Linux"
    )

    assert kali["power_state"] == "powered_on"
    assert kali["tools_status"] == "not_installed"
    assert kali["hostname"] is None
    assert kali["primary_ip"] is None
    assert kali["evidence"]["completeness"] == 0.7
    assert any(
        finding["id"] == "finding:vmware:kali-guest-telemetry"
        for finding in result["findings"]
    )


def test_dpi_address_is_bound_only_to_the_observed_third_interface(
    current_inventory: dict,
) -> None:
    result = normalize_esxi_inventory(current_inventory, fetched_at=FETCHED_AT)
    owners = [
        (vm["id"], interface["id"], interface["network_id"])
        for vm in result["virtual_machines"]
        for interface in vm["interfaces"]
        if "172.16.10.50" in interface["ip_addresses"]
    ]

    assert owners == [
        (
            "vm:vmware:dtlab-01:118",
            "nic:vmware:dtlab-01:118:network-adapter-3",
            "net:vmware:dtlab-01:pg-cv-dpi",
        )
    ]


def test_duplicate_ip_creates_one_finding_without_requesting_an_automatic_fix(
    current_inventory: dict,
) -> None:
    result = normalize_esxi_inventory(current_inventory, fetched_at=FETCHED_AT)
    findings = [
        finding
        for finding in result["findings"]
        if finding["code"] == "duplicate_guest_ipv4"
    ]

    assert len(findings) == 1
    assert findings[0]["entity_ids"] == [
        "net:vmware:dtlab-01:pg-ot-lab",
        "vm:vmware:dtlab-01:115",
        "vm:vmware:dtlab-01:119",
    ]
    assert "Nessuna modifica o arresto" in findings[0]["description"]


def test_esxi_result_contains_no_cisco_telemetry_or_sensitive_endpoint(
    current_inventory: dict,
) -> None:
    result = normalize_esxi_inventory(current_inventory, fetched_at=FETCHED_AT)
    encoded = json.dumps(result)

    assert "assets" not in result
    assert "risk_scores" not in result
    assert "vulnerabilities" not in result
    assert current_inventory["esxi_host"] not in encoded
    assert current_inventory["certificate_sha256"] not in encoded


def test_esxi_entities_pass_the_full_v2_contract(current_inventory: dict) -> None:
    result = normalize_esxi_inventory(current_inventory, fetched_at=FETCHED_AT)
    snapshot = valid_snapshot()
    snapshot["generated_at"] = "2026-08-03T12:00:00Z"
    snapshot["sync"]["started_at"] = "2026-08-03T11:59:58Z"
    snapshot["sync"]["completed_at"] = "2026-08-03T12:00:00Z"
    snapshot["sources"][1] = result["source"]
    snapshot["virtual_machines"] = result["virtual_machines"]
    snapshot["networks"] = result["networks"]
    snapshot["findings"] = result["findings"]
    snapshot["quality"]["checks"] = result["quality_checks"]

    validate_snapshot(snapshot)


def test_missing_moid_fails_closed(current_inventory: dict) -> None:
    inventory = deepcopy(current_inventory)
    inventory["virtual_machines"][0]["moid"] = None

    with pytest.raises(EsxiNormalizationError, match="moid"):
        normalize_esxi_inventory(inventory, fetched_at=FETCHED_AT)


def test_missing_collection_timestamp_is_not_replaced_with_current_time(
    current_inventory: dict,
) -> None:
    inventory = deepcopy(current_inventory)
    inventory["collected_at"] = None

    result = normalize_esxi_inventory(inventory, fetched_at=FETCHED_AT)

    assert result["source"]["status"] == "degraded"
    assert result["virtual_machines"][0]["evidence"]["observed_at"] is None
    assert result["virtual_machines"][0]["evidence"]["truth"] == "unavailable"


def test_old_inventory_is_explicitly_stale(current_inventory: dict) -> None:
    result = normalize_esxi_inventory(current_inventory, fetched_at=FETCHED_AT)

    assert result["source"]["status"] == "stale"
    assert result["source"]["last_success_at"] == "2026-08-03T11:15:39.839953Z"
    assert all(
        vm["evidence"]["truth"] == "stale"
        for vm in result["virtual_machines"]
    )
