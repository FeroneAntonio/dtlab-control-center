from __future__ import annotations

import json
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath

import pytest

from dtlab.collector.config import CollectorConfig, EsxiConfig, PublishConfig
from dtlab.collector.cybervision_client import CyberVisionConfig
from dtlab.services.snapshot_store import AtomicSnapshotStore
from tests.factories import FETCHED_AT, evidence, source, valid_snapshot
from tools import publish_verified_staging as tool

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


def test_script_can_be_started_directly() -> None:
    result = subprocess.run(
        [sys.executable, str(tool.__file__), "--help"],
        cwd=Path(tool.__file__).resolve().parents[1],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert "--expected-manifest-sha256" in result.stdout


def _snapshot(*, quality: int = 90, sensor_error: bool = False) -> dict:
    snapshot = valid_snapshot()
    snapshot["sync"]["state"] = "partial" if sensor_error else "fresh"
    snapshot["quality"]["score"] = quality
    esxi = snapshot["sources"][1]
    esxi["capabilities"] = {
        "vm_inventory": {"status": "available", "records": 5, "error_code": None},
    }
    classic = snapshot["sources"][2]
    classic["status"] = "degraded" if sensor_error else "connected"
    classic["evidence"] = evidence(classic["id"], "real", "classic:version")
    classic["last_success_at"] = FETCHED_AT
    classic["capabilities"] = {
        name: {"status": "available", "records": 1, "error_code": None}
        for name in _CLASSIC_CAPABILITIES
    }
    classic["capabilities"]["sensor_stats"] = {
        "status": "error" if sensor_error else "available",
        "records": 0 if sensor_error else 1,
        "error_code": "server_error" if sensor_error else None,
    }
    classic["error"] = (
        {"code": "partial_capabilities", "message": "Capability non disponibile."}
        if sensor_error
        else None
    )
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


def _publish(root: Path, snapshot: dict) -> str:
    manifest = AtomicSnapshotStore(root).publish(snapshot, published_at=PUBLISHED_AT)
    return manifest["sha256"]


def _publish_config(*, enabled: bool, staging: bool) -> PublishConfig:
    suffix = "-staging" if staging else ""
    return PublishConfig(
        enabled=enabled,
        ssh_alias="staging-publisher" if staging else "production-publisher",
        remote_store=PurePosixPath(
            "/var/www/clients/client1/web75/private/modbus-dashboard-data" + suffix
        ),
        remote_owner="dtlab-publish",
        remote_group="dtlab-dashboard",
        remote_account="dtlab-publish",
        manage_ownership=False,
    )


def _config(
    root: Path,
    *,
    staging_enabled: bool = True,
    include_staging: bool = True,
) -> CollectorConfig:
    return CollectorConfig(
        vpn_connection_name="DTLAB CISCO",
        esxi=EsxiConfig("esxi.internal", 443, "reader", "a" * 64),
        cybervision=CyberVisionConfig("https://cybervision.internal", "b" * 64),
        local_store=root,
        raw_directory=root.parent / "raw",
        publish=_publish_config(enabled=True, staging=False),
        publish_staging=(
            _publish_config(enabled=staging_enabled, staging=True) if include_staging else None
        ),
    )


class FakePublisher:
    initialized_with: list[PublishConfig] = []
    calls: list[dict] = []

    def __init__(self, config: PublishConfig) -> None:
        self.initialized_with.append(config)

    def publish(self, store: AtomicSnapshotStore, manifest: dict) -> None:
        assert store.load("current").manifest == manifest
        self.calls.append(manifest)


@pytest.fixture
def fake_publisher(monkeypatch):
    class IsolatedFakePublisher(FakePublisher):
        initialized_with = []
        calls = []

    monkeypatch.setattr(tool, "RemoteSnapshotPublisher", IsolatedFakePublisher)
    return IsolatedFakePublisher


def test_default_is_safe_dry_run_and_output_contains_no_connection_details(
    tmp_path,
    monkeypatch,
    fake_publisher,
    capsys,
) -> None:
    root = tmp_path / "store"
    digest = _publish(root, _snapshot())
    config = _config(root)
    monkeypatch.setattr(tool, "load_config", lambda _: config)

    assert tool.main(["--expected-manifest-sha256", digest]) == 0

    output = capsys.readouterr().out
    result = json.loads(output)
    assert result["status"] == "dry-run"
    assert result["target"] == "staging"
    assert result["minimum_quality"] == 80
    assert len(result["confirm_plan"]) == 64
    assert fake_publisher.initialized_with == []
    assert config.publish_staging is not None
    for private_value in (
        config.publish_staging.ssh_alias,
        config.publish_staging.remote_account,
        str(config.publish_staging.remote_store),
        config.cybervision.base_url,
    ):
        assert private_value not in output


def test_apply_requires_exact_plan_and_uses_only_staging(
    tmp_path,
    monkeypatch,
    fake_publisher,
    capsys,
) -> None:
    root = tmp_path / "store"
    digest = _publish(root, _snapshot())
    config = _config(root)
    monkeypatch.setattr(tool, "load_config", lambda _: config)
    base_args = ["--expected-manifest-sha256", digest]

    assert tool.main(base_args) == 0
    token = json.loads(capsys.readouterr().out)["confirm_plan"]
    assert tool.main([*base_args, "--apply"]) == 2
    assert json.loads(capsys.readouterr().err)["error"] == "apply_requires_confirm_plan"
    assert tool.main([*base_args, "--apply", "--confirm-plan", "0" * 64]) == 2
    assert json.loads(capsys.readouterr().err)["error"] == "confirm_plan_mismatch"

    assert tool.main([*base_args, "--apply", "--confirm-plan", token]) == 0

    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "published"
    assert fake_publisher.initialized_with == [config.publish_staging]
    assert len(fake_publisher.calls) == 1
    assert config.publish not in fake_publisher.initialized_with


@pytest.mark.parametrize(
    ("config_options", "error"),
    [
        ({"include_staging": False}, "staging_configuration_missing"),
        ({"staging_enabled": False}, "staging_publication_disabled"),
    ],
)
def test_missing_or_disabled_staging_never_falls_back_to_production(
    tmp_path,
    monkeypatch,
    fake_publisher,
    capsys,
    config_options,
    error,
) -> None:
    root = tmp_path / "store"
    digest = _publish(root, _snapshot())
    monkeypatch.setattr(tool, "load_config", lambda _: _config(root, **config_options))

    assert tool.main(["--expected-manifest-sha256", digest]) == 1

    assert json.loads(capsys.readouterr().err)["error"] == error
    assert fake_publisher.initialized_with == []


def test_expected_sha_is_mandatory_and_must_match_current(
    tmp_path,
    monkeypatch,
    fake_publisher,
    capsys,
) -> None:
    root = tmp_path / "store"
    _publish(root, _snapshot())
    monkeypatch.setattr(tool, "load_config", lambda _: _config(root))

    with pytest.raises(SystemExit):
        tool._parser().parse_args([])
    assert tool.main(["--expected-manifest-sha256", "0" * 64]) == 1

    assert json.loads(capsys.readouterr().err.splitlines()[-1])["error"] == (
        "current_manifest_sha256_mismatch"
    )
    assert fake_publisher.initialized_with == []


def test_quality_gate_is_fixed_at_80(tmp_path, monkeypatch, fake_publisher, capsys) -> None:
    root = tmp_path / "store"
    digest = _publish(root, _snapshot(quality=79))
    monkeypatch.setattr(tool, "load_config", lambda _: _config(root))

    assert tool.main(["--expected-manifest-sha256", digest]) == 1

    assert json.loads(capsys.readouterr().err)["error"] == "snapshot_gate_rejected"
    assert fake_publisher.initialized_with == []


def test_sensor_stats_exception_requires_its_specific_flag(
    tmp_path,
    monkeypatch,
    fake_publisher,
    capsys,
) -> None:
    root = tmp_path / "store"
    digest = _publish(root, _snapshot(sensor_error=True))
    monkeypatch.setattr(tool, "load_config", lambda _: _config(root))
    args = ["--expected-manifest-sha256", digest]

    assert tool.main(args) == 1
    assert json.loads(capsys.readouterr().err)["error"] == "snapshot_gate_rejected"
    assert tool.main([*args, "--allow-classic-sensor-stats-server-error"]) == 0

    result = json.loads(capsys.readouterr().out)
    assert result["allow_classic_sensor_stats_server_error"] is True
    assert result["approved_exceptions"] == ["classic_sensor_stats_server_error"]
    assert fake_publisher.initialized_with == []


def test_apply_fails_if_current_pointer_changes_after_verification(
    tmp_path,
    monkeypatch,
    fake_publisher,
) -> None:
    root = tmp_path / "store"
    digest = _publish(root, _snapshot())
    config = _config(root)
    monkeypatch.setattr(tool, "load_config", lambda _: config)
    dry_run = tool.publish_verified_staging(
        Path("ignored.toml"),
        expected_manifest_sha256=digest,
    )
    original_evaluate = tool.evaluate_snapshot
    evaluations = 0

    def mutate_pointer(stored, **kwargs):
        nonlocal evaluations
        evaluations += 1
        result = original_evaluate(stored, **kwargs)
        if evaluations == 1:
            pointer = root / "current" / "manifest.json"
            manifest = json.loads(pointer.read_text(encoding="utf-8"))
            manifest["published_at"] = "2026-08-03T15:01:00Z"
            pointer.write_text(json.dumps(manifest), encoding="utf-8")
        return result

    monkeypatch.setattr(tool, "evaluate_snapshot", mutate_pointer)

    with pytest.raises(tool.PublishVerifiedStagingError, match="current_pointer_changed"):
        tool.publish_verified_staging(
            Path("ignored.toml"),
            expected_manifest_sha256=digest,
            apply=True,
            confirm_plan=dry_run["confirm_plan"],
        )

    assert fake_publisher.initialized_with == []
