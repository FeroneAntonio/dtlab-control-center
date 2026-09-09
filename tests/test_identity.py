from __future__ import annotations

from dtlab.services.identity import resolve_vm_asset_identities


def _vm(vm_id: str, name: str, ip: str, *, scope: str = "primary") -> dict:
    return {
        "id": vm_id,
        "name": name,
        "interfaces": [
            {
                "ip_addresses": [ip],
                "mac_address": None,
            }
        ],
        "operational_context": {
            "kpi_scope": scope,
            "official_target": scope == "primary",
        },
    }


def _asset(asset_id: str, name: str, ip: str) -> dict:
    return {
        "id": asset_id,
        "name": name,
        "device_type": "PLC",
        "ip_addresses": [ip],
        "mac_addresses": [],
    }


def test_duplicate_asset_address_does_not_create_multiple_links() -> None:
    links = resolve_vm_asset_identities(
        [_vm("vm:1", "PLC-Desktop", "172.16.10.10")],
        [
            _asset("asset:1", "PLC A", "172.16.10.10"),
            _asset("asset:2", "PLC B", "172.16.10.10"),
        ],
        fetched_at="2026-08-03T13:00:00Z",
        collector_source_id="src:collector:1",
    )

    assert links == []


def test_legacy_plc_duplicate_ip_is_excluded_but_official_pair_stays_proposed() -> None:
    links = resolve_vm_asset_identities(
        [
            _vm("vm:official", "PLC-Desktop", "172.16.10.10"),
            _vm(
                "vm:legacy",
                "PLC-Ubuntu",
                "172.16.10.10",
                scope="excluded_legacy",
            ),
        ],
        [_asset("asset:plc", "PLC", "172.16.10.10")],
        fetched_at="2026-08-03T13:00:00Z",
        collector_source_id="src:collector:1",
    )

    assert len(links) == 1
    assert links[0]["virtual_machine_id"] == "vm:official"
    assert links[0]["status"] == "proposed"
    assert links[0]["evidence"]["truth"] == "observed"
    assert links[0]["confidence"] < 1


def test_explicit_operator_mapping_confirms_the_observed_pair() -> None:
    links = resolve_vm_asset_identities(
        [_vm("vm:official", "PLC-Desktop", "172.16.10.10")],
        [_asset("asset:plc", "plcubuntu", "172.16.10.10")],
        fetched_at="2026-08-03T13:00:00Z",
        collector_source_id="src:collector:1",
        operator_source_id="src:operator:1",
        operator_confirmed_vm_ipv4={"PLC-Desktop": "172.16.10.10"},
    )

    assert len(links) == 1
    assert links[0]["status"] == "confirmed"
    assert links[0]["method"] == "operator_confirmed"
    assert links[0]["confidence"] == 1
    assert links[0]["evidence"]["source_id"] == "src:operator:1"
    assert links[0]["evidence"]["truth"] == "real"


def test_operator_mapping_does_not_override_a_different_asset_address() -> None:
    links = resolve_vm_asset_identities(
        [_vm("vm:official", "PLC-Desktop", "172.16.10.10")],
        [_asset("asset:plc", "PLC", "172.16.10.10")],
        fetched_at="2026-08-03T13:00:00Z",
        collector_source_id="src:collector:1",
        operator_source_id="src:operator:1",
        operator_confirmed_vm_ipv4={"PLC-Desktop": "172.16.10.99"},
    )

    assert links[0]["status"] == "proposed"
    assert links[0]["method"] == "ip_match"
