from __future__ import annotations

import json
from copy import deepcopy
from datetime import UTC, datetime

from streamlit.testing.v1 import AppTest

from dtlab.ui.context import DashboardContext
from dtlab.ui.detection_readiness import build_detection_readiness
from tests.factories import evidence, source, valid_snapshot

OPERATOR_ID = "src:operator:dtlab"
CV_ID = "src:cisco-cyber-vision:dtlab-01"


def _snapshot() -> dict:
    snapshot = valid_snapshot()
    snapshot["sources"][2] = source(
        CV_ID, "Cisco Cyber Vision", "cisco_cyber_vision", "connected", "real"
    )
    snapshot["sources"][2]["capabilities"] = {
        "activities": {"status": "available", "records": 0},
        "event_severities": {"status": "available", "records": 0},
        "baseline_differences": {"status": "available", "records": 0},
    }
    plc_vm = snapshot["virtual_machines"][0]
    plc_vm["id"] = "vm:plc"
    plc_vm["operational_context"]["purpose"] = "plc"
    plc_vm["operational_context"]["official_target"] = True
    for vm_id, purpose in (("vm:hmi", "hmi"), ("vm:kali", "security_testing")):
        vm = deepcopy(plc_vm)
        vm["id"] = vm_id
        vm["operational_context"]["purpose"] = purpose
        vm["operational_context"]["official_target"] = False
        snapshot["virtual_machines"].append(vm)
    for suffix in ("plc", "hmi", "kali"):
        snapshot["assets"].append(
            {
                "id": f"asset:{suffix}",
                "evidence": evidence(CV_ID, "real", f"device:{suffix}"),
                "name": suffix.upper(),
            }
        )
        snapshot["identity_links"].append(
            {
                "id": f"identity:{suffix}",
                "evidence": evidence(OPERATOR_ID, "real", f"confirm:{suffix}"),
                "virtual_machine_id": f"vm:{suffix}",
                "asset_id": f"asset:{suffix}",
                "method": "operator_confirmed",
                "status": "confirmed",
            }
        )
    return snapshot


def _write_activity(
    activity_id: str,
    left: str,
    right: str,
    *,
    direction: str = "undetermined",
    truth: str = "real",
) -> dict:
    return {
        "id": activity_id,
        "evidence": evidence(CV_ID, truth, activity_id),
        "asset_ids": [left, right],
        "type": "Industrial activity",
        "protocol": "Modbus",
        "details": {
            "direction": direction,
            "tags": ["Write Var"],
            "left_asset_id": left,
            "right_asset_id": right,
        },
    }


def _rows(result: dict) -> dict[str, dict]:
    return {row["origin_key"]: row for row in result["rows"]}


def _baseline_difference(
    difference_id: str, difference_type: str, asset_ids: list[str], *, truth: str = "real"
) -> dict:
    return {
        "id": difference_id,
        "evidence": evidence(CV_ID, truth, difference_id),
        "difference_type": difference_type,
        "asset_ids": asset_ids,
        "observed_at": "2026-08-03T10:00:00Z",
    }


def _render_events_for_test(context: DashboardContext) -> None:
    from dtlab.ui.views.security import render_events

    render_events(context)


def test_undetermined_write_marks_hmi_and_plc_involved_without_inventing_origin() -> None:
    snapshot = _snapshot()
    snapshot["activities"] = [
        _write_activity("activity:write-1", "asset:hmi", "asset:plc")
    ]

    result = build_detection_readiness(snapshot)
    rows = _rows(result)

    for key in ("hmi", "plc"):
        assert rows[key]["identity"]["state"] == "confirmed"
        assert rows[key]["write_activity"]["state"] == "involved_origin_unknown"
        assert rows[key]["write_activity"]["origin_attributed"] is False
        assert rows[key]["write_activity"]["origin_record_ids"] == []
        assert rows[key]["alert_event"]["state"] == "no_linked_records"
        assert rows[key]["overall"]["state"] == "involved_origin_unknown"

    assert rows["kali"]["identity"]["state"] == "confirmed"
    assert rows["kali"]["write_activity"]["state"] == "no_linked_records"
    assert rows["kali"]["alert_event"]["state"] == "no_linked_records"
    assert rows["kali"]["overall"]["state"] == "no_linked_records"
    assert rows["kali"]["overall"]["label"] == "Non verificato · nessun record"
    assert "nessuna evidenza di sicurezza è verificata" in rows["kali"]["overall"]["copy"]
    json.dumps(result)


def test_known_direction_attributes_only_the_origin_endpoint() -> None:
    snapshot = _snapshot()
    snapshot["activities"] = [
        _write_activity(
            "activity:write-1",
            "asset:hmi",
            "asset:plc",
            direction="left_to_right",
        )
    ]

    rows = _rows(build_detection_readiness(snapshot))

    assert rows["hmi"]["write_activity"]["state"] == "origin_observed"
    assert rows["hmi"]["write_activity"]["origin_attributed"] is True
    assert rows["plc"]["write_activity"]["state"] == "involved_origin_unknown"
    assert rows["plc"]["write_activity"]["origin_attributed"] is False


def test_direction_does_not_imply_origin_without_explicit_endpoint_asset_ids() -> None:
    snapshot = _snapshot()
    activity = _write_activity(
        "activity:write-1",
        "asset:hmi",
        "asset:plc",
        direction="left_to_right",
    )
    activity["details"].pop("left_asset_id")
    activity["details"].pop("right_asset_id")
    snapshot["activities"] = [activity]

    rows = _rows(build_detection_readiness(snapshot))

    assert rows["hmi"]["write_activity"]["state"] == "involved_origin_unknown"
    assert rows["plc"]["write_activity"]["state"] == "involved_origin_unknown"
    assert rows["hmi"]["write_activity"]["origin_attributed"] is False


def test_write_requires_explicit_write_var_and_modbus_not_free_text() -> None:
    snapshot = _snapshot()
    title_only = _write_activity("activity:title", "asset:kali", "asset:plc")
    title_only["details"]["tags"] = ["Industrial traffic"]
    title_only["type"] = "Kali Write Var attack over Modbus"
    non_modbus = _write_activity("activity:other", "asset:kali", "asset:plc")
    non_modbus["protocol"] = "TCP"
    snapshot["activities"] = [title_only, non_modbus]

    rows = _rows(build_detection_readiness(snapshot))

    assert rows["kali"]["write_activity"]["state"] == "no_linked_records"
    assert rows["plc"]["write_activity"]["state"] == "no_linked_records"


def test_event_title_is_ignored_and_only_explicit_asset_ids_link_evidence() -> None:
    snapshot = _snapshot()
    event = {
        "id": "event:1",
        "evidence": evidence(CV_ID, "real", "event:1"),
        "title": "Kali attack detected on PLC",
        "asset_ids": [],
    }
    snapshot["events"] = [event]

    rows = _rows(build_detection_readiness(snapshot))
    assert all(row["alert_event"]["state"] == "no_linked_records" for row in rows.values())

    event["asset_ids"] = ["asset:kali"]
    rows = _rows(build_detection_readiness(snapshot))
    assert rows["kali"]["alert_event"]["state"] == "linked_event"
    assert rows["plc"]["alert_event"]["state"] == "no_linked_records"
    assert "attacco rilevato" not in rows["kali"]["overall"]["copy"].casefold()


def test_stale_or_unavailable_capability_is_nd_even_when_records_exist() -> None:
    snapshot = _snapshot()
    snapshot["activities"] = [
        _write_activity(
            "activity:write-1",
            "asset:kali",
            "asset:plc",
            direction="left_to_right",
        )
    ]
    snapshot["events"] = [
        {
            "id": "event:1",
            "evidence": evidence(CV_ID, "real", "event:1"),
            "title": "Any title",
            "asset_ids": ["asset:kali"],
        }
    ]
    snapshot["sync"]["state"] = "stale"

    result = build_detection_readiness(snapshot)
    rows = _rows(result)

    assert result["capabilities"]["activities"]["state"] == "stale"
    assert result["capabilities"]["events"]["state"] == "stale"
    assert rows["kali"]["write_activity"]["state"] == "nd"
    assert rows["kali"]["alert_event"]["state"] == "nd"
    assert rows["kali"]["overall"]["state"] == "nd"


def test_stale_linked_record_is_nd_and_non_source_owned_record_is_not_evidence() -> None:
    snapshot = _snapshot()
    stale = _write_activity(
        "activity:stale", "asset:kali", "asset:plc", truth="stale"
    )
    foreign = _write_activity("activity:foreign", "asset:kali", "asset:plc")
    foreign["evidence"] = evidence(OPERATOR_ID, "real", "activity:foreign")
    snapshot["activities"] = [stale, foreign]

    rows = _rows(build_detection_readiness(snapshot))

    assert rows["kali"]["write_activity"]["state"] == "nd"
    assert rows["kali"]["write_activity"]["record_ids"] == []


def test_ambiguous_identity_link_is_not_used_for_attribution() -> None:
    snapshot = _snapshot()
    duplicate = deepcopy(snapshot["identity_links"][-1])
    duplicate["id"] = "identity:kali-duplicate"
    duplicate["asset_id"] = "asset:plc"
    snapshot["identity_links"].append(duplicate)
    snapshot["activities"] = [
        _write_activity(
            "activity:write-1",
            "asset:kali",
            "asset:plc",
            direction="left_to_right",
        )
    ]

    rows = _rows(build_detection_readiness(snapshot))

    assert rows["kali"]["identity"]["state"] == "not_confirmed"
    assert rows["kali"]["asset_ids"] == []
    assert rows["kali"]["write_activity"]["state"] == "nd"
    assert rows["kali"]["overall"]["state"] == "nd"


def test_non_official_plc_is_not_selected_as_the_official_origin() -> None:
    snapshot = _snapshot()
    plc = next(vm for vm in snapshot["virtual_machines"] if vm["id"] == "vm:plc")
    plc["operational_context"]["official_target"] = False

    plc_row = _rows(build_detection_readiness(snapshot))["plc"]

    assert plc_row["vm_ids"] == []
    assert plc_row["identity"]["state"] == "not_defined"
    assert plc_row["overall"]["state"] == "nd"


def test_new_component_explicitly_linked_to_kali_is_baseline_evidence() -> None:
    snapshot = _snapshot()
    snapshot["baseline_differences"] = [
        _baseline_difference("difference:kali-component", "new_component", ["asset:kali"])
    ]

    result = build_detection_readiness(snapshot)
    rows = _rows(result)
    axis = rows["kali"]["baseline_difference"]

    assert axis["state"] == "linked_difference"
    assert axis["record_ids"] == ["difference:kali-component"]
    assert axis["difference_types"] == ["new_component"]
    assert axis["attribution"] == "explicit_asset_ids_only"
    assert axis["security_interpretation"] == "unclassified"
    assert rows["kali"]["overall"]["state"] == "baseline_difference_linked"
    assert rows["hmi"]["baseline_difference"]["state"] == "no_linked_records"
    assert rows["plc"]["baseline_difference"]["state"] == "no_linked_records"
    assert result["summary"]["baseline_differences_linked"] == 1
    assert result["baseline_evidence"]["current_record_ids"] == [
        "difference:kali-component"
    ]
    rendered = json.dumps(result, ensure_ascii=False).casefold()
    assert "attacco rilevato" not in rendered


def test_global_new_activity_is_not_attributed_by_time_or_free_text() -> None:
    snapshot = _snapshot()
    difference = _baseline_difference("difference:global", "new_activity", [])
    difference["title"] = "Kali Modbus attack"
    snapshot["baseline_differences"] = [difference]
    snapshot["activities"] = [
        _write_activity(
            "activity:same-time", "asset:kali", "asset:plc", direction="left_to_right"
        )
    ]
    snapshot["activities"][0]["observed_at"] = difference["observed_at"]

    result = build_detection_readiness(snapshot)

    assert all(
        row["baseline_difference"]["state"] == "no_linked_records"
        for row in result["rows"]
    )
    assert result["baseline_evidence"]["global_unattributed_record_ids"] == [
        "difference:global"
    ]
    assert result["summary"]["baseline_differences_global_unattributed"] == 1
    assert result["summary"]["baseline_differences_linked"] == 0


def test_baseline_uses_only_current_cybervision_records_and_tracks_unmapped() -> None:
    snapshot = _snapshot()
    stale = _baseline_difference("difference:stale", "new_component", ["asset:kali"], truth="stale")
    foreign = _baseline_difference("difference:foreign", "new_component", ["asset:kali"])
    foreign["evidence"] = evidence(OPERATOR_ID, "real", "difference:foreign")
    unmapped = _baseline_difference("difference:unmapped", "new_component", ["asset:other"])
    snapshot["baseline_differences"] = [stale, foreign, unmapped]

    result = build_detection_readiness(snapshot)
    rows = _rows(result)

    assert rows["kali"]["baseline_difference"]["state"] == "no_linked_records"
    assert result["baseline_evidence"]["current_record_ids"] == ["difference:unmapped"]
    assert result["baseline_evidence"]["unmapped_explicit_record_ids"] == [
        "difference:unmapped"
    ]
    assert result["summary"]["baseline_differences_unmapped_explicit"] == 1
    json.dumps(result)


def test_baseline_is_nd_when_snapshot_source_is_stale() -> None:
    snapshot = _snapshot()
    snapshot["baseline_differences"] = [
        _baseline_difference("difference:kali", "new_component", ["asset:kali"])
    ]
    snapshot["sync"]["state"] = "stale"

    result = build_detection_readiness(snapshot)

    assert result["capabilities"]["baseline_differences"]["state"] == "stale"
    assert _rows(result)["kali"]["baseline_difference"]["state"] == "nd"
    assert result["summary"]["baseline_differences_linked"] == 0
    assert result["baseline_evidence"]["current_record_ids"] == []


def test_events_view_renders_detection_matrix_without_claiming_an_attack() -> None:
    snapshot = _snapshot()
    snapshot["activities"] = [
        _write_activity("activity:write-1", "asset:hmi", "asset:plc")
    ]
    snapshot["baseline_differences"] = [
        _baseline_difference(
            "difference:kali-component", "new_component", ["asset:kali"]
        ),
        _baseline_difference("difference:global-activity", "new_activity", []),
    ]
    context = DashboardContext(
        canonical_snapshot=snapshot,
        snapshot=snapshot,
        manifest={"sha256": "a" * 64},
        pointer="current",
        effective_state="fresh",
        age_seconds=0,
        loaded_at=datetime(2026, 8, 3, 10, 0, 2, tzinfo=UTC),
    )

    app = AppTest.from_function(
        _render_events_for_test,
        args=(context,),
        default_timeout=30,
    ).run(timeout=30)
    rendered = "\n".join(
        str(element.value)
        for element in [*app.subheader, *app.caption, *app.info, *app.markdown]
    )

    assert len(app.exception) == 0
    assert "Prontezza rilevamento scritture OT" in rendered
    assert "Kali · nuovo componente rilevato" in rendered
    assert "1 record globale non attribuito" in rendered
    assert "non è automaticamente un alert Modbus" in rendered
    assert "attacco rilevato" not in rendered.casefold()
    assert "Evidenza baseline" in app.dataframe[0].value.columns
