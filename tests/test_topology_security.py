from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime

from streamlit.testing.v1 import AppTest

from dtlab.services.snapshot_store import AtomicSnapshotStore
from dtlab.ui.context import load_dashboard_context
from dtlab.ui.topology import (
    flow_topology,
    integrated_topology,
    security_topology_summary,
    verified_identity_link_ids,
    vmware_topology,
)
from tests.factories import FETCHED_AT, add_cisco_asset, evidence, valid_snapshot


def _render_topology_for_test(context) -> None:
    from dtlab.ui.views.monitoring import render_topology

    render_topology(context)


def _render_security_summary_for_test(snapshot: dict) -> None:
    from dtlab.ui.views.monitoring import _render_security_topology_summary

    _render_security_topology_summary(snapshot)


def _security_snapshot() -> tuple[dict, str, str]:
    snapshot = valid_snapshot()
    plc_asset_id = add_cisco_asset(snapshot)
    source = next(
        source for source in snapshot["sources"] if source["type"] == "cisco_cyber_vision"
    )
    source["status"] = "degraded"
    source["capabilities"] = {"flows": {"status": "available", "records": 0, "error_code": None}}
    network_id = snapshot["networks"][0]["id"]
    kali_vm_id = "vm:vmware:dtlab-01:117"
    kali_asset_id = "asset:cybervision:dtlab-01:kali"
    snapshot["virtual_machines"].append(
        {
            "id": kali_vm_id,
            "evidence": evidence("src:vmware-esxi:dtlab-01", "observed", "vim.VirtualMachine:117"),
            "name": "[Relatech] Kali-Linux",
            "hostname": None,
            "operational_context": {
                "purpose": "security_testing",
                "lifecycle_role": "test",
                "official_target": False,
                "kpi_scope": "excluded_test",
                "desired_power_state": "running",
                "evidence": evidence(
                    "src:operator:dtlab",
                    "expected",
                    "project-context:kali",
                ),
            },
            "power_state": "powered_on",
            "guest_os": "Kali Linux",
            "cpu_count": 2,
            "memory_mb": 4096,
            "disk_capacity_gb": 50.0,
            "tools_status": "not_installed",
            "primary_ip": None,
            "interfaces": [
                {
                    "id": "nic:vmware:dtlab-01:117:network-adapter-1",
                    "label": "Network adapter 1",
                    "network_id": network_id,
                    "mac_address": "00:00:00:00:00:30",
                    "ip_addresses": [],
                    "connected": True,
                    "start_connected": True,
                }
            ],
            "snapshot_count": 0,
        }
    )
    snapshot["assets"].append(
        {
            "id": kali_asset_id,
            "evidence": evidence("src:cisco-cyber-vision:dtlab-01", "real", "device:kali"),
            "name": "172.16.10.30",
            "category": "Security testing",
            "device_type": "Device",
            "vendor": None,
            "ip_addresses": ["172.16.10.30"],
            "mac_addresses": [],
            "network_ids": [],
            "zone": None,
            "protocols": [],
            "status": "online",
            "last_seen_at": FETCHED_AT,
            "operational_role": "security_test",
        }
    )
    snapshot["identity_links"].append(
        {
            "id": "identity:kali",
            "evidence": evidence("src:operator:dtlab", "real", "operator-confirmation:vm-ip:kali"),
            "virtual_machine_id": kali_vm_id,
            "asset_id": kali_asset_id,
            "status": "confirmed",
            "method": "operator_confirmed",
            "confidence": 1.0,
        }
    )
    return snapshot, kali_asset_id, plc_asset_id


def _kali_plc_flow(kali_asset_id: str, plc_asset_id: str) -> dict:
    return {
        "id": "flow:kali-plc",
        "evidence": evidence("src:cisco-cyber-vision:dtlab-01", "real", "flow:kali-plc"),
        "left_asset_id": kali_asset_id,
        "right_asset_id": plc_asset_id,
        "left_label": "172.16.10.30",
        "right_label": "172.16.10.10",
        "left_ip": "172.16.10.30",
        "right_ip": "172.16.10.10",
        "left_port": 45000,
        "right_port": 502,
        "protocol": "TCP",
        "direction": "left_to_right",
        "direction_raw": "leftRight",
        "first_seen_at": FETCHED_AT,
        "last_seen_at": FETCHED_AT,
        "packet_count": 8,
        "byte_count": 512,
    }


def test_expected_security_role_is_qualified_and_has_no_attack_claim() -> None:
    snapshot, _, _ = _security_snapshot()

    summary = security_topology_summary(snapshot)

    assert summary["role_assertion"]["status"] == "expected"
    assert summary["identity_state"] == "confirmed"
    assert summary["telemetry_state"] == "partial"
    assert summary["activity_state"] == "no_linked_records_returned"
    assert summary["exercise_state"] == "not_evaluated"
    assert summary["observed_flow_count"] == 0
    figure = integrated_topology(snapshot)
    names = [str(trace.name) for trace in figure.data]
    assert "VM · Sorgente ostile di test" in names
    assert "Asset · Sorgente ostile di test" in names
    red_trace = next(trace for trace in figure.data if trace.name == "VM · Sorgente ostile di test")
    assert red_trace.marker.color == "#ba1a1a"
    assert red_trace.marker.symbol == "x"
    assert any("☠" in str(label) for label in red_trace.text)
    assert not any("attacc" in name.casefold() for name in names)
    assert not any(name == "Comunicazione con host di test" for name in names)


def test_excluded_test_without_security_purpose_is_not_red_team() -> None:
    snapshot, _, _ = _security_snapshot()
    kali = next(vm for vm in snapshot["virtual_machines"] if "Kali" in vm["name"])
    kali["operational_context"]["purpose"] = "qa"

    summary = security_topology_summary(snapshot)
    figure = vmware_topology(snapshot["virtual_machines"], snapshot["networks"])

    assert summary["role_assertion"]["status"] == "unknown"
    assert "VM · Sistema di test" in [str(trace.name) for trace in figure.data]


def test_proposed_identity_does_not_propagate_security_role_to_asset() -> None:
    snapshot, _, _ = _security_snapshot()
    snapshot["identity_links"][0]["status"] = "proposed"

    summary = security_topology_summary(snapshot)
    figure = integrated_topology(snapshot)

    assert summary["identity_state"] == "proposed"
    assert summary["asset_ids"] == ()
    assert "Asset · Sorgente ostile di test" not in [str(trace.name) for trace in figure.data]


def test_integrated_topology_shows_authenticated_host_ot_edr_as_separate_layer() -> None:
    snapshot, _, _ = _security_snapshot()
    figure = integrated_topology(
        snapshot,
        host_ot_sensors=[
            {
                "sensor_id": "plc-desktop",
                "coverage_state": "active",
                "received_at": FETCHED_AT,
                "event_type": "heartbeat",
            }
        ],
    )

    names = [str(trace.name) for trace in figure.data]
    assert "Host OT / EDR" in names
    assert "Copertura Host OT / EDR" in names
    edr_trace = next(trace for trace in figure.data if trace.name == "Host OT / EDR")
    assert edr_trace.marker.color == ("#00639b",)
    assert any("HOST OT / EDR" in str(label) for label in edr_trace.text)
    assert any(annotation.text == "HOST OT / EDR" for annotation in figure.layout.annotations)


def test_flow_is_communication_observed_and_never_an_attack_claim() -> None:
    snapshot, kali_asset_id, plc_asset_id = _security_snapshot()
    snapshot["flows"].append(_kali_plc_flow(kali_asset_id, plc_asset_id))
    snapshot["sources"][2]["capabilities"]["flows"]["records"] = 1

    summary = security_topology_summary(snapshot)
    integrated = integrated_topology(snapshot)
    cisco = flow_topology(
        snapshot["assets"],
        snapshot["flows"],
        virtual_machines=snapshot["virtual_machines"],
        identity_links=snapshot["identity_links"],
        cybervision_source_ids={"src:cisco-cyber-vision:dtlab-01"},
        operator_source_ids={"src:operator:dtlab"},
    )

    assert summary["activity_state"] == "communication_observed"
    assert summary["observed_flow_count"] == 1
    for figure in (integrated, cisco):
        names = [str(trace.name) for trace in figure.data]
        assert "Comunicazione con host di test" in names
        assert not any("attacc" in name.casefold() for name in names)


def test_event_record_does_not_promote_communication_to_attack() -> None:
    snapshot, kali_asset_id, _ = _security_snapshot()
    snapshot["events"].append(
        {
            "id": "event:inventory",
            "asset_ids": [kali_asset_id],
            "title": "Inventory update",
            "evidence": evidence("src:cisco-cyber-vision:dtlab-01", "real", "event:inventory"),
        }
    )

    summary = security_topology_summary(snapshot)

    assert summary["observed_event_count"] == 1
    assert summary["activity_state"] == "no_linked_records_returned"
    assert summary["exercise_state"] == "not_evaluated"


def test_real_role_from_non_operator_source_is_not_operator_confirmed() -> None:
    snapshot, _, _ = _security_snapshot()
    kali = next(vm for vm in snapshot["virtual_machines"] if "Kali" in vm["name"])
    kali["operational_context"]["evidence"] = evidence(
        "src:vmware-esxi:dtlab-01",
        "real",
        "vim.VirtualMachine:117:role",
    )

    summary = security_topology_summary(snapshot)

    assert summary["role_assertion"]["status"] == "expected"


def test_non_cisco_or_expected_flow_is_not_an_observed_communication() -> None:
    snapshot, kali_asset_id, plc_asset_id = _security_snapshot()
    flow = _kali_plc_flow(kali_asset_id, plc_asset_id)
    flow["evidence"] = evidence(
        "src:vmware-esxi:dtlab-01",
        "expected",
        "project-context:not-observed-flow",
    )
    snapshot["flows"].append(flow)

    summary = security_topology_summary(snapshot)
    figure = integrated_topology(snapshot)

    assert summary["observed_flow_count"] == 0
    assert summary["activity_state"] == "no_linked_records_returned"
    names = [str(trace.name) for trace in figure.data]
    assert "Comunicazione con host di test" not in names
    assert "Flow Cyber Vision" not in names
    assert "Dettaglio flow" not in names


def test_partial_and_truncated_flow_capabilities_remain_usable() -> None:
    snapshot, kali_asset_id, plc_asset_id = _security_snapshot()
    snapshot["flows"].append(_kali_plc_flow(kali_asset_id, plc_asset_id))

    for capability_status in ("partial", "truncated"):
        candidate = deepcopy(snapshot)
        candidate["sources"][2]["capabilities"]["flows"]["status"] = capability_status
        summary = security_topology_summary(candidate)
        assert summary["telemetry_state"] == "partial"
        assert summary["activity_state"] == "communication_observed"


def test_unverified_confirmed_link_is_not_drawn_or_highlighted() -> None:
    snapshot, _, _ = _security_snapshot()
    link = snapshot["identity_links"][0]
    link["evidence"]["truth"] = "expected"
    kali_vm_id = link["virtual_machine_id"]

    summary = security_topology_summary(snapshot)
    figure = integrated_topology(snapshot, highlight_id=kali_vm_id)
    names = [str(trace.name) for trace in figure.data]

    assert summary["identity_state"] == "ambiguous"
    assert summary["asset_ids"] == ()
    assert "Identità confermata" not in names
    asset_trace = next(
        trace for trace in figure.data if trace.name == "Asset · Asset Cisco non correlato"
    )
    assert all(float(value) < 1 for value in asset_trace.marker.opacity)


def test_plotly_customdata_escapes_asset_owned_strings() -> None:
    snapshot, _, _ = _security_snapshot()
    kali_asset = next(asset for asset in snapshot["assets"] if asset["name"] == "172.16.10.30")
    kali_asset["device_type"] = '<img src=x onerror="alert(1)">'
    kali_asset["ip_addresses"] = ["javascript:alert(1)"]

    figure = integrated_topology(snapshot)
    trace = next(trace for trace in figure.data if trace.name == "Asset · Sorgente ostile di test")
    serialized = repr(trace.customdata)

    assert "&lt;img" in serialized
    assert '<img src=x onerror="alert(1)">' not in serialized


def test_stale_confirmed_identity_is_preserved_but_activity_is_nd() -> None:
    snapshot, kali_asset_id, _ = _security_snapshot()
    snapshot["identity_links"][0]["evidence"]["truth"] = "stale"
    snapshot["sync"]["state"] = "stale"
    snapshot["activities"].append(
        {
            "id": "activity:kali:stale",
            "asset_ids": [kali_asset_id],
            "evidence": evidence(
                "src:cisco-cyber-vision:dtlab-01",
                "stale",
                "activity:kali:stale",
            ),
        }
    )

    summary = security_topology_summary(snapshot)

    assert summary["identity_state"] == "confirmed"
    assert summary["telemetry_state"] == "stale"
    assert summary["activity_state"] == "unavailable"
    assert summary["observed_activity_count"] == 1


def test_unavailable_and_stale_telemetry_remain_distinct() -> None:
    snapshot, _, _ = _security_snapshot()
    unavailable = deepcopy(snapshot)
    unavailable["sources"][2]["capabilities"]["flows"]["status"] = "error"
    stale = deepcopy(snapshot)
    stale["sync"]["state"] = "stale"

    unavailable_summary = security_topology_summary(unavailable)
    stale_summary = security_topology_summary(stale)

    assert unavailable_summary["telemetry_state"] == "unavailable"
    assert unavailable_summary["activity_state"] == "unavailable"
    assert stale_summary["telemetry_state"] == "stale"
    assert stale_summary["activity_state"] == "unavailable"


def test_cybervision_source_status_overrides_an_available_flow_capability() -> None:
    snapshot, _, _ = _security_snapshot()
    unavailable = deepcopy(snapshot)
    unavailable["sources"][2]["status"] = "unavailable"
    stale = deepcopy(snapshot)
    stale["sources"][2]["status"] = "stale"

    assert security_topology_summary(unavailable)["telemetry_state"] == "unavailable"
    assert security_topology_summary(stale)["telemetry_state"] == "stale"


def test_ip_match_or_non_operator_evidence_cannot_confirm_identity() -> None:
    snapshot, _, _ = _security_snapshot()
    link = snapshot["identity_links"][0]
    link["method"] = "ip_match"
    link["evidence"] = evidence(
        "src:vmware-esxi:dtlab-01",
        "observed",
        "vim.VirtualMachine:117:ip-match",
    )

    assert verified_identity_link_ids(snapshot) == frozenset()
    assert security_topology_summary(snapshot)["identity_state"] == "ambiguous"
    assert "Identità confermata" not in [
        str(trace.name) for trace in integrated_topology(snapshot).data
    ]


def test_one_vm_to_two_assets_is_ambiguous_on_both_sides() -> None:
    snapshot, _, plc_asset_id = _security_snapshot()
    second_link = deepcopy(snapshot["identity_links"][0])
    second_link["id"] = "identity:kali:duplicate"
    second_link["asset_id"] = plc_asset_id
    snapshot["identity_links"].append(second_link)

    assert verified_identity_link_ids(snapshot) == frozenset()
    assert security_topology_summary(snapshot)["identity_state"] == "ambiguous"


def test_two_vms_to_one_asset_is_order_independent_and_ambiguous() -> None:
    snapshot, kali_asset_id, _ = _security_snapshot()
    duplicate = deepcopy(snapshot["identity_links"][0])
    duplicate["id"] = "identity:plc-to-kali"
    duplicate["virtual_machine_id"] = snapshot["virtual_machines"][0]["id"]
    duplicate["asset_id"] = kali_asset_id
    snapshot["identity_links"].append(duplicate)

    forward = verified_identity_link_ids(snapshot)
    snapshot["identity_links"].reverse()
    reverse = verified_identity_link_ids(snapshot)

    assert forward == reverse == frozenset()


def test_equal_flow_records_share_one_technical_hover_marker() -> None:
    snapshot, kali_asset_id, plc_asset_id = _security_snapshot()
    first = _kali_plc_flow(kali_asset_id, plc_asset_id)
    second = deepcopy(first)
    second["id"] = "flow:kali-plc:second"
    second["left_port"] = 45001
    snapshot["flows"].extend([first, second])

    figure = integrated_topology(snapshot)
    hover = next(trace for trace in figure.data if trace.name == "Dettaglio flow")

    assert len(hover.x) == 1
    assert hover.customdata[0][2] == "2"


def test_reverse_and_multi_protocol_flows_share_one_complete_hover_marker() -> None:
    snapshot, kali_asset_id, plc_asset_id = _security_snapshot()
    forward = _kali_plc_flow(kali_asset_id, plc_asset_id)
    reverse = deepcopy(forward)
    reverse.update(
        {
            "id": "flow:plc-kali",
            "left_asset_id": plc_asset_id,
            "right_asset_id": kali_asset_id,
            "left_label": "172.16.10.10",
            "right_label": "172.16.10.30",
            "left_ip": "172.16.10.10",
            "right_ip": "172.16.10.30",
            "left_port": 502,
            "right_port": 45001,
        }
    )
    undetermined = deepcopy(forward)
    undetermined.update(
        {
            "id": "flow:kali-plc:udp",
            "protocol": "UDP",
            "direction": "undetermined",
        }
    )
    snapshot["flows"].extend([forward, reverse, undetermined])

    figure = integrated_topology(snapshot)
    hover = next(trace for trace in figure.data if trace.name == "Dettaglio flow")
    detail = hover.customdata[0]

    assert len(hover.x) == 1
    assert detail[2] == "3"
    assert "TCP × 2" in detail[3]
    assert "UDP × 1" in detail[3]
    assert "A → B × 1" in detail[4]
    assert "B → A × 1" in detail[4]
    assert "Non determinata × 1" in detail[4]


def test_topology_page_explains_security_role_without_false_attack_claim(
    tmp_path,
) -> None:
    snapshot, _, _ = _security_snapshot()
    store = tmp_path / "store"
    AtomicSnapshotStore(store).publish(
        snapshot,
        published_at=datetime(2026, 8, 3, 14, 30, tzinfo=UTC),
    )
    context = load_dashboard_context(
        store,
        now=datetime(2026, 8, 3, 10, 0, 2, tzinfo=UTC),
    )

    app = AppTest.from_function(
        _render_topology_for_test,
        args=(context,),
        default_timeout=30,
    ).run(timeout=30)
    rendered = "\n".join(
        str(element.value) for element in [*app.markdown, *app.caption, *app.info, *app.warning]
    )

    assert len(app.exception) == 0
    assert "Host di security testing previsto" in rendered
    assert "Nessun flow associato restituito" in rendered
    assert "Identità Cisco confermata" in rendered
    assert "Scenario Lab · SIMULAZIONE" in rendered
    assert "Apri Asset 360 e workflow" in rendered
    assert "attacco osservato" not in rendered.casefold()
    assert "non trusted" not in rendered.casefold()
    assert app.segmented_control[0].value == "Vista integrata"
    assert not any(widget.label == "Filtra protocolli nel grafico" for widget in app.multiselect)


def test_security_summary_omits_asset_workflow_cta_without_confirmed_identity() -> None:
    snapshot, _, _ = _security_snapshot()
    snapshot["identity_links"] = []

    app = AppTest.from_function(
        _render_security_summary_for_test,
        args=(snapshot,),
        default_timeout=20,
    ).run(timeout=20)
    rendered = "\n".join(str(element.value) for element in app.markdown)

    assert len(app.exception) == 0
    assert "Apri Asset 360 e workflow" not in rendered
    assert "Verifica segnalazioni" in rendered
    assert "Scenario Lab · SIMULAZIONE" in rendered


def test_security_summary_marks_kali_baseline_evidence_without_attack_claim() -> None:
    snapshot, kali_asset_id, _ = _security_snapshot()
    source = next(
        source for source in snapshot["sources"] if source["type"] == "cisco_cyber_vision"
    )
    source["capabilities"]["baseline_differences"] = {
        "status": "available",
        "records": 2,
    }
    snapshot["baseline_differences"] = [
        {
            "id": "difference:kali-component",
            "evidence": evidence(
                "src:cisco-cyber-vision:dtlab-01",
                "real",
                "difference:kali-component",
            ),
            "difference_type": "new_component",
            "asset_ids": [kali_asset_id],
        },
        {
            "id": "difference:unattributed-activity",
            "evidence": evidence(
                "src:cisco-cyber-vision:dtlab-01",
                "real",
                "difference:unattributed-activity",
            ),
            "difference_type": "new_activity",
            "asset_ids": [],
        },
    ]

    app = AppTest.from_function(
        _render_security_summary_for_test,
        args=(snapshot,),
        default_timeout=20,
    ).run(timeout=20)
    rendered = "\n".join(str(element.value) for element in app.markdown)

    assert len(app.exception) == 0
    assert "Kali · nuovo componente rilevato" in rendered
    assert "1 record globale non attribuito" in rendered
    assert "non prova un attacco" in rendered
    assert "attacco confermato" not in rendered.casefold()
