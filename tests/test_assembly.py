from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from dtlab.adapters.cybervision import normalize_cybervision_collection
from dtlab.adapters.esxi import normalize_esxi_inventory
from dtlab.contract import validate_snapshot
from dtlab.services.assembly import assemble_snapshot
from tests.test_cybervision_adapter import raw_collection

CURRENT_INVENTORY_PATH = Path(__file__).resolve().parents[2] / "esxi_inventory.json"
STARTED = datetime(2026, 8, 3, 13, 29, 55, tzinfo=UTC)
COMPLETED = datetime(2026, 8, 3, 13, 30, 0, tzinfo=UTC)


@pytest.fixture
def esxi_result() -> dict:
    if not CURRENT_INVENTORY_PATH.exists():
        pytest.skip("Inventario ESXi operativo non presente.")
    inventory = json.loads(CURRENT_INVENTORY_PATH.read_text(encoding="utf-8"))
    inventory["collected_at"] = COMPLETED.isoformat()
    return normalize_esxi_inventory(inventory, fetched_at=COMPLETED)


def test_partial_snapshot_keeps_real_esxi_and_explicitly_unavailable_cisco(
    esxi_result: dict,
) -> None:
    snapshot = assemble_snapshot(
        esxi_result,
        cybervision=None,
        started_at=STARTED,
        completed_at=COMPLETED,
        snapshot_id="snapshot:partial:0001",
    )

    assert snapshot["sync"]["state"] == "partial"
    assert len(snapshot["virtual_machines"]) == 5
    assert snapshot["assets"] == []
    assert snapshot["risk_scores"] == []
    cv_source = next(
        source
        for source in snapshot["sources"]
        if source["type"] == "cisco_cyber_vision"
    )
    assert cv_source["status"] == "not_configured"
    assert cv_source["evidence"]["truth"] == "unavailable"
    assert snapshot["quality"]["methodology"] == "dtlab_data_quality_v2"
    validate_snapshot(snapshot)


def test_complete_snapshot_confirms_official_plc_not_legacy(esxi_result: dict) -> None:
    cybervision = normalize_cybervision_collection(raw_collection())

    snapshot = assemble_snapshot(
        esxi_result,
        cybervision=cybervision,
        started_at=STARTED,
        completed_at=COMPLETED,
        snapshot_id="snapshot:complete:0001",
    )

    plc_link = next(
        link
        for link in snapshot["identity_links"]
        if link["asset_id"] == "asset:cybervision:dtlab-01:42"
    )
    assert plc_link["virtual_machine_id"] == "vm:vmware:dtlab-01:119"
    assert plc_link["method"] == "operator_confirmed"
    assert plc_link["status"] == "confirmed"
    assert plc_link["evidence"]["truth"] == "real"
    assert plc_link["confidence"] == 1
    assert not any(
        link["virtual_machine_id"] == "vm:vmware:dtlab-01:115"
        for link in snapshot["identity_links"]
    )
    legacy = next(
        vm for vm in snapshot["virtual_machines"] if vm["id"].endswith(":115")
    )
    assert legacy["power_state"] == "powered_on"
    assert legacy["operational_context"]["desired_power_state"] == "running"
    assert snapshot["sync"]["state"] == "fresh"
    assert [score["score"] for score in snapshot["risk_scores"]] == [68, 22]
    validate_snapshot(snapshot)


def test_hmi_operator_mapping_is_confirmed(esxi_result: dict) -> None:
    snapshot = assemble_snapshot(
        esxi_result,
        cybervision=normalize_cybervision_collection(raw_collection()),
        started_at=STARTED,
        completed_at=COMPLETED,
        snapshot_id="snapshot:complete:0002",
    )
    hmi_link = next(
        link
        for link in snapshot["identity_links"]
        if link["asset_id"] == "asset:cybervision:dtlab-01:43"
    )

    assert hmi_link["virtual_machine_id"] == "vm:vmware:dtlab-01:116"
    assert hmi_link["method"] == "operator_confirmed"
    assert hmi_link["status"] == "confirmed"
