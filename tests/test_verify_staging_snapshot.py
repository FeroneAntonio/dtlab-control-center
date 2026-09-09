from __future__ import annotations

import json
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path

import pytest

from dtlab.services.snapshot_store import AtomicSnapshotStore
from tests.factories import FETCHED_AT, evidence, source, valid_snapshot
from tools.verify_staging_snapshot import main, verify_store

PUBLISHED_AT = datetime(2026, 8, 3, 15, 0, tzinfo=UTC)

_CLASSIC_CAPABILITIES = (
    "activities",
    "baseline_differences",
    "baselines",
    "components",
    "device_risk_scores",
    "device_vulnerabilities",
    "devices",
    "event_categories",
    "event_severities",
    "flows",
    "protocol_distribution",
    "reports_metadata",
    "risk_distribution",
    "sensor_details",
    "sensor_stats",
    "sensors",
    "version",
    "vulnerabilities",
)
_NEW_UI_CAPABILITIES = (
    "alerts",
    "assets",
    "networks",
    "org_hierarchy",
    "vulnerability_assets",
)


@pytest.fixture(autouse=True)
def _fixed_gate_clock(monkeypatch):
    monkeypatch.setattr(
        "tools.verify_staging_snapshot._utc_now",
        lambda: datetime(2026, 8, 3, 10, 0, 2, tzinfo=UTC),
    )


def _ready_snapshot() -> dict:
    snapshot = valid_snapshot()
    snapshot["sync"]["state"] = "fresh"
    snapshot["quality"]["score"] = 90

    esxi = snapshot["sources"][1]
    esxi["capabilities"] = {
        "vm_inventory": {"status": "available", "records": 5, "error_code": None},
    }

    classic = snapshot["sources"][2]
    classic["status"] = "connected"
    classic["evidence"] = evidence(classic["id"], "real", "classic:version")
    classic["last_success_at"] = FETCHED_AT
    classic["capabilities"] = {
        name: {"status": "available", "records": 1, "error_code": None}
        for name in _CLASSIC_CAPABILITIES
    }
    classic["error"] = None

    new_ui = source(
        "src:cisco-cyber-vision-new-ui:dtlab-01",
        "Cisco Cyber Vision New UI",
        "cisco_cyber_vision_new_ui",
        "connected",
        "real",
    )
    new_ui["capabilities"] = {
        name: {"status": "available", "records": 1, "error_code": None}
        for name in _NEW_UI_CAPABILITIES
    }
    snapshot["sources"].append(new_ui)
    return snapshot


def _publish(tmp_path: Path, snapshot: dict, *, allow_demo: bool = False) -> Path:
    root = tmp_path / "store"
    AtomicSnapshotStore(root, allow_demo=allow_demo).publish(
        snapshot,
        published_at=PUBLISHED_AT,
    )
    return root


def _classic(snapshot: dict) -> dict:
    return next(
        source_record
        for source_record in snapshot["sources"]
        if source_record["type"] == "cisco_cyber_vision"
    )


def test_fresh_complete_snapshot_passes_and_reports_verified_manifest(tmp_path) -> None:
    root = _publish(tmp_path, _ready_snapshot())

    result = verify_store(root)

    assert result["approved"] is True
    assert result["manifest_verified"] is True
    assert len(result["manifest_sha256"]) == 64
    assert result["source_results"] == {
        "classic": "pass",
        "esxi": "pass",
        "new_ui": "pass",
    }
    assert result["failures"] == []


def test_snapshot_that_expired_by_wall_clock_is_rejected(tmp_path) -> None:
    root = _publish(tmp_path, _ready_snapshot())

    result = verify_store(
        root,
        now=datetime(2026, 8, 3, 10, 20, 3, tzinfo=UTC),
    )

    assert result["approved"] is False
    assert result["runtime_sync_state"] == "stale"
    assert result["snapshot_age_seconds"] == 1201
    assert "snapshot_stale_by_age" in result["failures"]
    assert result["freshness_policy"] == "strict"


def test_internal_rollback_policy_accepts_only_verified_age_staleness(tmp_path) -> None:
    root = _publish(tmp_path, _ready_snapshot())

    result = verify_store(
        root,
        allow_stale_for_rollback=True,
        now=datetime(2026, 8, 3, 10, 20, 3, tzinfo=UTC),
    )

    assert result["approved"] is True
    assert result["sync_state"] == "fresh"
    assert result["runtime_sync_state"] == "stale"
    assert result["snapshot_age_seconds"] == 1201
    assert result["freshness_policy"] == "rollback_verified_stale_allowed"
    assert result["warnings"] == ["rollback_verified_stale_allowed"]


@pytest.mark.parametrize("declared_state", ["stale", "offline", "failed"])
def test_internal_rollback_policy_rejects_declared_non_fresh_states(
    tmp_path, declared_state: str
) -> None:
    snapshot = _ready_snapshot()
    snapshot["sync"]["state"] = declared_state
    root = _publish(tmp_path, snapshot)

    result = verify_store(
        root,
        allow_stale_for_rollback=True,
        now=datetime(2026, 8, 3, 10, 20, 3, tzinfo=UTC),
    )

    assert result["approved"] is False
    assert "snapshot_not_fresh" in result["failures"]
    assert result["freshness_policy"] == "strict"
    assert "rollback_verified_stale_allowed" not in result["warnings"]


def test_partial_snapshot_fails_by_default_even_if_sources_are_healthy(tmp_path) -> None:
    snapshot = _ready_snapshot()
    snapshot["sync"]["state"] = "partial"
    root = _publish(tmp_path, snapshot)

    result = verify_store(root)

    assert result["approved"] is False
    assert "snapshot_partial_not_approved" in result["failures"]


def test_exact_classic_sensor_exception_and_derived_partial_require_flag(tmp_path) -> None:
    snapshot = _ready_snapshot()
    snapshot["sync"]["state"] = "partial"
    classic = _classic(snapshot)
    classic["status"] = "degraded"
    classic["capabilities"]["sensor_stats"] = {
        "status": "error",
        "records": 0,
        "error_code": "server_error",
    }
    classic["error"] = {
        "code": "partial_capabilities",
        "message": "Capability non disponibile.",
    }
    root = _publish(tmp_path, snapshot)

    denied = verify_store(root)
    approved = verify_store(root, allow_sensor_stats_server_error=True)

    assert denied["approved"] is False
    assert "classic_sensor_stats_server_error_not_approved" in denied["failures"]
    assert "snapshot_partial_not_approved" in denied["failures"]
    assert approved["approved"] is True
    assert approved["source_results"]["classic"] == "warning"
    assert approved["approved_exceptions"] == ["classic_sensor_stats_server_error"]
    assert approved["warnings"] == ["snapshot_partial_for_approved_classic_exception"]


def test_age_stale_partial_still_requires_the_exact_approved_exception(tmp_path) -> None:
    snapshot = _ready_snapshot()
    snapshot["sync"]["state"] = "partial"
    classic = _classic(snapshot)
    classic["status"] = "degraded"
    classic["capabilities"]["sensor_stats"] = {
        "status": "error",
        "records": 0,
        "error_code": "server_error",
    }
    classic["error"] = {
        "code": "partial_capabilities",
        "message": "Capability non disponibile.",
    }
    root = _publish(tmp_path, snapshot)
    now = datetime(2026, 8, 3, 10, 20, 3, tzinfo=UTC)

    denied = verify_store(root, allow_stale_for_rollback=True, now=now)
    approved = verify_store(
        root,
        allow_sensor_stats_server_error=True,
        allow_stale_for_rollback=True,
        now=now,
    )

    assert denied["approved"] is False
    assert "snapshot_partial_not_approved" in denied["failures"]
    assert denied["freshness_policy"] == "strict"
    assert approved["approved"] is True
    assert approved["freshness_policy"] == "rollback_verified_stale_allowed"
    assert approved["warnings"] == [
        "rollback_verified_stale_allowed",
        "snapshot_partial_for_approved_classic_exception",
    ]


@pytest.mark.parametrize(
    ("status", "error_code"),
    [("error", "timeout"), ("partial", "server_error"), ("error", None)],
)
def test_sensor_exception_flag_does_not_approve_near_matches(
    tmp_path, status: str, error_code: str | None
) -> None:
    snapshot = _ready_snapshot()
    classic = _classic(snapshot)
    classic["capabilities"]["sensor_stats"] = {
        "status": status,
        "records": 0,
        "error_code": error_code,
    }
    root = _publish(tmp_path, snapshot)

    result = verify_store(root, allow_sensor_stats_server_error=True)

    assert result["approved"] is False
    assert "classic_capability_error" in result["failures"]


def test_flag_does_not_create_a_generic_partial_bypass(tmp_path) -> None:
    snapshot = _ready_snapshot()
    snapshot["sync"]["state"] = "partial"
    root = _publish(tmp_path, snapshot)

    result = verify_store(root, allow_sensor_stats_server_error=True)

    assert result["approved"] is False
    assert result["approved_exceptions"] == []
    assert "snapshot_partial_not_approved" in result["failures"]


def test_known_esxi_permission_scope_is_a_warning_not_a_failure(tmp_path) -> None:
    snapshot = _ready_snapshot()
    esxi = next(source for source in snapshot["sources"] if source["type"] == "vmware_esxi")
    esxi["capabilities"] = {
        "vm_inventory": {"status": "available", "records": 5, "error_code": None},
        "host_network_scope": {
            "status": "endpoint_unavailable",
            "records": 0,
            "error_code": "permission_scope",
        },
    }
    root = _publish(tmp_path, snapshot)

    result = verify_store(root)

    assert result["approved"] is True
    assert result["source_results"]["esxi"] == "warning"
    assert result["warnings"] == ["esxi_host_network_scope_permission_scope"]


@pytest.mark.parametrize(
    ("source_type", "failure"),
    [
        ("vmware_esxi", "esxi_capability_missing"),
        ("cisco_cyber_vision", "classic_capability_missing"),
        ("cisco_cyber_vision_new_ui", "new_ui_capability_missing"),
    ],
)
def test_empty_capability_maps_fail_closed(
    tmp_path, source_type: str, failure: str
) -> None:
    snapshot = _ready_snapshot()
    required_source = next(
        item for item in snapshot["sources"] if item["type"] == source_type
    )
    required_source["capabilities"] = {}
    root = _publish(tmp_path, snapshot)

    result = verify_store(
        root,
        allow_stale_for_rollback=True,
        now=datetime(2026, 8, 3, 10, 20, 3, tzinfo=UTC),
    )

    assert result["approved"] is False
    assert failure in result["failures"]
    assert result["freshness_policy"] == "strict"


@pytest.mark.parametrize(
    ("source_type", "capability_name", "failure"),
    [
        ("vmware_esxi", "vm_inventory", "esxi_capability_missing"),
        *(
            ("cisco_cyber_vision", name, "classic_capability_missing")
            for name in _CLASSIC_CAPABILITIES
        ),
        *(
            ("cisco_cyber_vision_new_ui", name, "new_ui_capability_missing")
            for name in _NEW_UI_CAPABILITIES
        ),
    ],
)
def test_every_required_capability_is_mandatory(
    tmp_path,
    source_type: str,
    capability_name: str,
    failure: str,
) -> None:
    snapshot = _ready_snapshot()
    required_source = next(
        item for item in snapshot["sources"] if item["type"] == source_type
    )
    required_source["capabilities"].pop(capability_name)
    root = _publish(tmp_path, snapshot)

    result = verify_store(root)

    assert result["approved"] is False
    assert failure in result["failures"]


def test_other_capability_and_source_errors_are_rejected(tmp_path) -> None:
    snapshot = _ready_snapshot()
    new_ui = next(
        source for source in snapshot["sources"] if source["type"] == "cisco_cyber_vision_new_ui"
    )
    new_ui["status"] = "degraded"
    new_ui["capabilities"]["alerts"] = {
        "status": "partial",
        "records": 1,
        "error_code": "timeout",
    }
    new_ui["error"] = {"code": "partial_capabilities", "message": "Errore parziale."}
    root = _publish(tmp_path, snapshot)

    result = verify_store(root, allow_sensor_stats_server_error=True)

    assert result["approved"] is False
    assert {
        "new_ui_capability_error",
        "new_ui_source_error",
        "new_ui_source_unhealthy",
    }.issubset(result["failures"])


@pytest.mark.parametrize(
    ("source_type", "failure"),
    [
        ("vmware_esxi", "esxi_source_missing"),
        ("cisco_cyber_vision", "classic_source_missing"),
        ("cisco_cyber_vision_new_ui", "new_ui_source_missing"),
    ],
)
def test_each_required_source_is_mandatory(tmp_path, source_type: str, failure: str) -> None:
    snapshot = _ready_snapshot()
    snapshot["sources"] = [
        source for source in snapshot["sources"] if source["type"] != source_type
    ]
    if source_type == "vmware_esxi":
        snapshot["virtual_machines"] = []
        snapshot["networks"] = []
        snapshot["findings"] = []
    root = _publish(tmp_path, snapshot)

    result = verify_store(root)

    assert result["approved"] is False
    assert failure in result["failures"]


def test_duplicate_required_source_is_rejected(tmp_path) -> None:
    snapshot = _ready_snapshot()
    duplicate = deepcopy(
        next(source for source in snapshot["sources"] if source["type"] == "vmware_esxi")
    )
    duplicate["id"] = "src:vmware-esxi:dtlab-02"
    duplicate["evidence"] = evidence(duplicate["id"], "observed", "inventory")
    snapshot["sources"].append(duplicate)
    root = _publish(tmp_path, snapshot)

    result = verify_store(root)

    assert result["approved"] is False
    assert "esxi_source_ambiguous" in result["failures"]


def test_quality_threshold_is_enforced_and_configurable(tmp_path) -> None:
    snapshot = _ready_snapshot()
    snapshot["quality"]["score"] = 79
    root = _publish(tmp_path, snapshot)

    denied = verify_store(root)
    approved = verify_store(root, min_quality=79)

    assert denied["approved"] is False
    assert "quality_below_threshold" in denied["failures"]
    assert approved["approved"] is True


def test_rollback_age_policy_never_overrides_quality(tmp_path) -> None:
    snapshot = _ready_snapshot()
    snapshot["quality"]["score"] = 79
    root = _publish(tmp_path, snapshot)

    result = verify_store(
        root,
        allow_stale_for_rollback=True,
        now=datetime(2026, 8, 3, 10, 20, 3, tzinfo=UTC),
    )

    assert result["approved"] is False
    assert "quality_below_threshold" in result["failures"]
    assert result["freshness_policy"] == "strict"


def test_allow_demo_publication_and_demo_evidence_are_rejected(tmp_path) -> None:
    snapshot = _ready_snapshot()
    snapshot["sync"]["publication_mode"] = "allow_demo"
    snapshot["environment"]["evidence"]["truth"] = "demo"
    demo = source("src:demo:dtlab", "Demo", "demo", "connected", "demo")
    snapshot["sources"].append(demo)
    root = _publish(tmp_path, snapshot, allow_demo=True)

    result = verify_store(
        root,
        allow_stale_for_rollback=True,
        now=datetime(2026, 8, 3, 10, 20, 3, tzinfo=UTC),
    )

    assert result["approved"] is False
    assert {
        "demo_evidence_present",
        "demo_source_present",
        "publication_mode_not_real_only",
    }.issubset(result["failures"])
    assert result["freshness_policy"] == "strict"


def test_gate_reads_current_only_and_rejects_a_corrupt_current(tmp_path) -> None:
    root = _publish(tmp_path, _ready_snapshot())
    current_manifest = json.loads((root / "current" / "manifest.json").read_text())
    (root / "objects" / current_manifest["object_name"]).write_text("{}")

    result = verify_store(root)

    assert result == {
        "approved": False,
        "approved_exceptions": [],
        "failures": ["snapshot_store_invalid"],
        "freshness_policy": "strict",
        "gate_version": "1.1",
        "manifest_verified": False,
        "minimum_quality": 80,
        "pointer": "current",
        "warnings": [],
    }


def test_missing_store_is_not_created(tmp_path) -> None:
    missing = tmp_path / "does-not-exist"

    result = verify_store(missing)

    assert result["approved"] is False
    assert result["failures"] == ["snapshot_store_invalid"]
    assert not missing.exists()


def test_cli_emits_only_whitelisted_safe_data_and_returns_gate_status(tmp_path, capsys) -> None:
    snapshot = _ready_snapshot()
    snapshot["sources"][0]["endpoint_label"] = "internal 192.0.2.77 secret-marker"
    root = _publish(tmp_path, snapshot)

    exit_code = main(["--store", str(root)])
    output = capsys.readouterr().out
    result = json.loads(output)

    assert exit_code == 0
    assert result["approved"] is True
    assert "192.0.2.77" not in output
    assert "secret-marker" not in output
    assert set(result) == {
        "approved",
        "approved_exceptions",
        "failures",
        "freshness_policy",
        "gate_version",
        "manifest_sha256",
        "manifest_verified",
        "minimum_quality",
        "pointer",
            "quality_score",
            "runtime_sync_state",
            "snapshot_age_seconds",
            "source_results",
        "sync_state",
        "warnings",
    }


def test_cli_returns_one_for_gate_failure(tmp_path, capsys) -> None:
    snapshot = _ready_snapshot()
    snapshot["quality"]["score"] = 10
    root = _publish(tmp_path, snapshot)

    exit_code = main(["--store", str(root)])
    result = json.loads(capsys.readouterr().out)

    assert exit_code == 1
    assert result["approved"] is False


def test_internal_rollback_cli_switch_is_hidden_and_effective(
    tmp_path, monkeypatch, capsys
) -> None:
    root = _publish(tmp_path, _ready_snapshot())
    monkeypatch.setattr(
        "tools.verify_staging_snapshot._utc_now",
        lambda: datetime(2026, 8, 3, 10, 20, 3, tzinfo=UTC),
    )

    exit_code = main(["--store", str(root), "--allow-stale-for-rollback"])
    result = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert result["freshness_policy"] == "rollback_verified_stale_allowed"
