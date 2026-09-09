from __future__ import annotations

import hashlib
import inspect
import json
import sqlite3
import stat
from contextlib import nullcontext
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path, PurePosixPath
from types import SimpleNamespace
from typing import Any

import pytest

from deploy import production_tool
from tests.factories import evidence, source, valid_snapshot

ROOT = Path(__file__).resolve().parents[1]
DEPLOY = ROOT / "deploy"
RELEASE_ID = "0123456789abcdef"


def _target(
    *,
    ticket: bool = True,
    staging_unit_sha256: str = "",
    ingest: bool = False,
) -> production_tool.TargetInfo:
    ingest_service = (
        (DEPLOY / production_tool.INGEST_SERVICE_NAME).read_bytes() if ingest else b""
    )
    ingest_path = (
        (DEPLOY / production_tool.INGEST_PATH_NAME).read_bytes() if ingest else b""
    )
    return production_tool.TargetInfo(
        release_id=RELEASE_ID,
        release=production_tool.RELEASES_ROOT
        / f"dtlab-control-center-{RELEASE_ID}",
        venv=production_tool.VENVS_ROOT / RELEASE_ID,
        content_sha256=RELEASE_ID + "0" * 48,
        unit_bytes=b"new-unit",
        unit_sha256=hashlib.sha256(b"new-unit").hexdigest(),
        has_ticket_runtime=ticket,
        staging_unit_sha256=staging_unit_sha256,
        ingest_service_bytes=ingest_service,
        ingest_service_sha256=(
            hashlib.sha256(ingest_service).hexdigest() if ingest_service else ""
        ),
        ingest_path_bytes=ingest_path,
        ingest_path_sha256=(
            hashlib.sha256(ingest_path).hexdigest() if ingest_path else ""
        ),
    )


def _before(*, active: bool = True, enabled: bool = True) -> production_tool.DeploymentState:
    return production_tool.DeploymentState(
        release_link=production_tool.LinkState(
            True,
            str(production_tool.RELEASES_ROOT / "dtlab-control-center-fedcba9876543210"),
        ),
        venv_link=production_tool.LinkState(
            True,
            str(production_tool.VENVS_ROOT / "fedcba9876543210"),
        ),
        unit=production_tool.UnitState(True, b"old-unit", 0, 0, 0o644),
        service=production_tool.ServiceState(
            active=active,
            enabled=enabled,
            main_pid=4321 if active else 0,
            exec_main_status=0,
            result="success",
        ),
    )


def _store(
    *,
    root: Path = production_tool.PRODUCTION_STORE,
    snapshot_sha256: str = "a" * 64,
    manifest_sha256: str = "b" * 64,
    snapshot_id: str = "snapshot-1",
    manifest_archive_ready: bool = True,
    runtime_sync_state: str = "fresh",
    snapshot_age_seconds: int = 0,
    freshness_policy: str = "strict",
) -> production_tool.StoreState:
    return production_tool.StoreState(
        root=root,
        snapshot_sha256=snapshot_sha256,
        manifest_sha256=manifest_sha256,
        snapshot_id=snapshot_id,
        object_name=f"{snapshot_sha256}.json",
        byte_length=123,
        sync_state="fresh",
        quality_score=100,
        approved_exceptions=(),
        manifest_archive_ready=manifest_archive_ready,
        manifest_bytes=b'{"manifest_version":"1.0"}',
        runtime_sync_state=runtime_sync_state,
        snapshot_age_seconds=snapshot_age_seconds,
        freshness_policy=freshness_policy,
    )


def _gate_snapshot(*, declared_state: str = "fresh", quality: int = 90) -> dict:
    snapshot = valid_snapshot()
    completed_at = datetime.now(UTC) - timedelta(hours=1)
    started_at = completed_at - timedelta(seconds=2)
    snapshot["generated_at"] = completed_at.isoformat().replace("+00:00", "Z")
    snapshot["sync"].update(
        {
            "state": declared_state,
            "started_at": started_at.isoformat().replace("+00:00", "Z"),
            "completed_at": completed_at.isoformat().replace("+00:00", "Z"),
            "max_age_seconds": 900,
        }
    )
    snapshot["quality"]["score"] = quality

    esxi = next(item for item in snapshot["sources"] if item["type"] == "vmware_esxi")
    esxi["capabilities"] = {
        "vm_inventory": {"status": "available", "records": 1, "error_code": None}
    }
    classic = next(
        item for item in snapshot["sources"] if item["type"] == "cisco_cyber_vision"
    )
    classic["status"] = "connected"
    classic["error"] = None
    classic["capabilities"] = {
        name: {"status": "available", "records": 1, "error_code": None}
        for name in production_tool._REQUIRED_CAPABILITIES["cisco_cyber_vision"]
    }
    new_ui = source(
        "src:cisco-cyber-vision-new-ui:dtlab-01",
        "Cisco Cyber Vision New UI",
        "cisco_cyber_vision_new_ui",
        "connected",
        "real",
    )
    new_ui["evidence"] = evidence(new_ui["id"], "real", "new-ui:assets")
    new_ui["capabilities"] = {
        name: {"status": "available", "records": 1, "error_code": None}
        for name in production_tool._REQUIRED_CAPABILITIES[
            "cisco_cyber_vision_new_ui"
        ]
    }
    snapshot["sources"].append(new_ui)
    return snapshot


def _staging_state(
    unit_sha256: str,
    *,
    main_pid: int = 2468,
) -> production_tool.StagingState:
    return production_tool.StagingState(
        service=production_tool.ServiceState(
            active=True,
            enabled=True,
            main_pid=main_pid,
            exec_main_status=0,
            result="success",
        ),
        unit_sha256=unit_sha256,
    )


def _posixify_module_paths(
    monkeypatch: pytest.MonkeyPatch,
    *names: str,
) -> None:
    for name in names:
        path = getattr(production_tool, name)
        monkeypatch.setattr(production_tool, name, PurePosixPath(path.as_posix()))


def _current_unit() -> bytes:
    return (DEPLOY / "modbus-dashboard-v2.service").read_bytes()


def _historical_unit() -> bytes:
    text = _current_unit().decode()
    text = "\n".join(
        line
        for line in text.splitlines()
        if "DTLAB_TICKET_STORE=" not in line
        and "ReadWritePaths=" not in line
        and "DTLAB_UI_REFRESH_SECONDS=" not in line
    )
    return (text + "\n").encode()


def test_entrypoint_exposes_only_production_promote_and_rollback() -> None:
    entrypoint = (DEPLOY / "deploy_production.sh").read_text(encoding="utf-8")
    source = (DEPLOY / "production_tool.py").read_text(encoding="utf-8").casefold()

    assert "promote|rollback" in entrypoint
    assert 'production_tool.py" "${action}"' in entrypoint
    assert "ssh " not in entrypoint
    assert "scp " not in entrypoint
    assert "apache" not in source
    assert 'service_name = "modbus-dashboard-v2.service"' in source
    assert production_tool.STAGING_SERVICE_NAME.casefold() in source
    assert production_tool.STAGING_SERVICE_NAME not in inspect.getsource(
        production_tool._activate
    )


def test_parser_is_dry_run_by_default_and_confirmation_is_fail_closed() -> None:
    parsed = production_tool._parser().parse_args(
        ["promote", "--release-id", RELEASE_ID]
    )
    assert parsed.apply is False
    assert parsed.confirm_plan is None

    parsed.apply = True
    with pytest.raises(production_tool.ProductionToolError, match="confirm-plan"):
        production_tool._require_confirmation(parsed, "a" * 64)

    with pytest.raises(SystemExit):
        production_tool._parser().parse_args(
            ["rollback", "--release-id", RELEASE_ID, "--allow-stale-for-rollback"]
        )


def test_production_gate_allows_only_age_stale_for_internal_rollback() -> None:
    snapshot = _gate_snapshot()

    with pytest.raises(production_tool.ProductionToolError, match="snapshot_stale_by_age"):
        production_tool._evaluate_snapshot_gate(
            snapshot,
            allow_sensor_stats_server_error=False,
        )

    result = production_tool._evaluate_snapshot_gate(
        snapshot,
        allow_sensor_stats_server_error=False,
        allow_stale_for_rollback=True,
    )

    assert result[0:2] == ("fresh", "stale")
    assert result[2] >= 3600
    assert result[5] == ("rollback_verified_stale_allowed",)
    assert result[6] == "rollback_verified_stale_allowed"


@pytest.mark.parametrize(
    ("declared_state", "quality", "expected_failure"),
    [
        ("offline", 90, "snapshot_not_fresh"),
        ("failed", 90, "snapshot_not_fresh"),
        ("stale", 90, "snapshot_not_fresh"),
        ("fresh", 79, "quality_below_threshold"),
    ],
)
def test_production_rollback_age_policy_keeps_every_other_gate_strict(
    declared_state: str,
    quality: int,
    expected_failure: str,
) -> None:
    snapshot = _gate_snapshot(declared_state=declared_state, quality=quality)

    with pytest.raises(production_tool.ProductionToolError, match=expected_failure):
        production_tool._evaluate_snapshot_gate(
            snapshot,
            allow_sensor_stats_server_error=False,
            allow_stale_for_rollback=True,
        )


def test_production_rollback_age_policy_never_accepts_demo_truth() -> None:
    snapshot = _gate_snapshot()
    snapshot["environment"]["evidence"]["truth"] = "demo"

    with pytest.raises(production_tool.ProductionToolError, match="demo_evidence_present"):
        production_tool._evaluate_snapshot_gate(
            snapshot,
            allow_sensor_stats_server_error=False,
            allow_stale_for_rollback=True,
        )


def test_apply_requires_linux_root(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(production_tool.sys, "platform", "win32")
    with pytest.raises(production_tool.ProductionToolError, match="Linux"):
        production_tool._require_apply_host()

    monkeypatch.setattr(production_tool.sys, "platform", "linux")
    monkeypatch.setattr(production_tool.os, "geteuid", lambda: 1000, raising=False)
    with pytest.raises(production_tool.ProductionToolError, match="root"):
        production_tool._require_apply_host()


def test_production_unit_is_strict_and_historical_unit_is_rollback_compatible() -> None:
    assert production_tool._validate_production_unit(
        _current_unit(), require_ticket_runtime=True
    )
    assert not production_tool._validate_production_unit(
        _historical_unit(), require_ticket_runtime=False
    )
    with pytest.raises(production_tool.ProductionToolError, match="ticket persistente"):
        production_tool._validate_production_unit(
            _historical_unit(), require_ticket_runtime=True
        )

    malicious = _current_unit() + b"\nExecStartPost=/bin/false\n"
    with pytest.raises(production_tool.ProductionToolError, match="non ammesse"):
        production_tool._validate_production_unit(
            malicious, require_ticket_runtime=True
        )


def test_release_manifest_requires_canonical_file_hashes() -> None:
    records = {
        "app.py": {"sha256": hashlib.sha256(b"app").hexdigest(), "bytes": 3},
        "requirements-server.lock": {
            "sha256": hashlib.sha256(b"lock").hexdigest(),
            "bytes": 4,
        },
    }
    canonical = json.dumps(records, sort_keys=True, separators=(",", ":")).encode()
    manifest = {
        "manifest_version": "1.0",
        "content_sha256": hashlib.sha256(canonical).hexdigest(),
        "files": records,
    }

    assert production_tool._manifest_records(manifest) == records

    manifest["content_sha256"] = "0" * 64
    with pytest.raises(production_tool.ProductionToolError, match="content hash"):
        production_tool._manifest_records(manifest)


def test_plan_token_binds_target_store_ticket_and_service_readiness_state() -> None:
    target = _target(ingest=True)
    before = _before()
    ticket = production_tool.TicketState(True, True, 0o700, 0o600)
    production_data = _store()
    staging_data = _store(root=production_tool.STAGING_STORE)
    staging_state = _staging_state("c" * 64)
    payload, token = production_tool._plan(
        "promote",
        target,
        before,
        ticket,
        health_timeout=30.0,
        production_data=production_data,
        staging_data=staging_data,
        staging_state=staging_state,
    )
    _, changed_state_token = production_tool._plan(
        "promote",
        target,
        replace(
            before,
            service=replace(before.service, main_pid=before.service.main_pid + 1),
        ),
        ticket,
        health_timeout=30.0,
        production_data=production_data,
        staging_data=staging_data,
        staging_state=staging_state,
    )
    _, changed_ticket_token = production_tool._plan(
        "promote",
        target,
        before,
        replace(ticket, database_mode=0o640),
        health_timeout=30.0,
        production_data=production_data,
        staging_data=staging_data,
        staging_state=staging_state,
    )
    _, changed_data_token = production_tool._plan(
        "promote",
        target,
        before,
        ticket,
        health_timeout=30.0,
        production_data=replace(production_data, snapshot_sha256="d" * 64),
        staging_data=staging_data,
        staging_state=staging_state,
    )
    _, changed_staging_token = production_tool._plan(
        "promote",
        target,
        before,
        ticket,
        health_timeout=30.0,
        production_data=production_data,
        staging_data=staging_data,
        staging_state=_staging_state("c" * 64, main_pid=9999),
    )
    _, changed_age_token = production_tool._plan(
        "promote",
        target,
        before,
        ticket,
        health_timeout=30.0,
        production_data=replace(production_data, snapshot_age_seconds=1),
        staging_data=staging_data,
        staging_state=staging_state,
    )

    assert payload["service"] == production_tool.SERVICE_NAME
    assert payload["before"]["service"]["main_pid"] == 4321
    assert payload["ticket_state"] == {
        "database_exists": True,
        "database_mode": 0o600,
        "directory_exists": True,
        "directory_mode": 0o700,
    }
    assert payload["production_data"]["snapshot_sha256"] == "a" * 64
    assert payload["production_data"]["snapshot_age_seconds"] == 0
    assert payload["production_data"]["freshness_policy"] == "strict"
    assert payload["staging_readiness"]["service"]["main_pid"] == 2468
    assert payload["release"]["ticket_ingest_service_sha256"]
    assert payload["release"]["ticket_ingest_path_sha256"]
    assert len(token) == 64
    assert token != changed_state_token
    assert token != changed_ticket_token
    assert token != changed_data_token
    assert token != changed_staging_token
    assert token == changed_age_token
    plan_text = json.dumps(payload, sort_keys=True).casefold()
    assert "current staging targets" in plan_text
    assert "apache" not in plan_text
    assert "vmware" not in plan_text


def test_rollback_plan_reports_and_binds_verified_stale_policy() -> None:
    target = _target()
    before = _before()
    ticket = production_tool.TicketState(True, True, 0o700, 0o600)
    stale_data = _store(
        runtime_sync_state="stale",
        snapshot_age_seconds=3600,
        freshness_policy="rollback_verified_stale_allowed",
    )

    payload, token = production_tool._plan(
        "rollback",
        target,
        before,
        ticket,
        health_timeout=30.0,
        production_data=stale_data,
    )
    _, strict_token = production_tool._plan(
        "rollback",
        target,
        before,
        ticket,
        health_timeout=30.0,
        production_data=replace(stale_data, freshness_policy="strict"),
    )

    assert payload["production_data"]["snapshot_age_seconds"] == 3600
    assert (
        payload["production_data"]["freshness_policy"]
        == "rollback_verified_stale_allowed"
    )
    assert "verified snapshot made stale by age" in " ".join(payload["operations"])
    assert token != strict_token


def test_rollback_main_propagates_age_policy_to_initial_and_locked_recheck(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    target = _target()
    before = _before()
    identities = production_tool.Identities(0, 0, 0)
    ticket = production_tool.TicketState(True, True, 0o700, 0o600)
    observed_policies: list[bool] = []

    monkeypatch.setattr(production_tool, "_lookup_identities", lambda: identities)
    monkeypatch.setattr(
        production_tool, "_verify_release", lambda *_args, **_kwargs: target
    )
    monkeypatch.setattr(production_tool, "_capture_deployment", lambda: before)
    monkeypatch.setattr(
        production_tool,
        "_inspect_ticket_state",
        lambda *_args, **_kwargs: ticket,
    )

    def inspect_store(*_args, **kwargs):
        observed_policies.append(kwargs["allow_stale_for_rollback"])
        return _store(
            runtime_sync_state="stale",
            snapshot_age_seconds=3600,
            freshness_policy="rollback_verified_stale_allowed",
        )

    monkeypatch.setattr(production_tool, "_inspect_store", inspect_store)
    monkeypatch.setattr(production_tool, "_require_confirmation", lambda *_args: None)
    monkeypatch.setattr(production_tool, "_require_apply_host", lambda: None)
    monkeypatch.setattr(production_tool, "_production_lock", lambda: nullcontext())
    monkeypatch.setattr(
        production_tool,
        "_apply_operation",
        lambda *_args, **_kwargs: {"status": "applied"},
    )

    exit_code = production_tool.main(
        [
            "rollback",
            "--release-id",
            RELEASE_ID,
            "--apply",
            "--confirm-plan",
            "ignored-by-test",
        ]
    )

    assert exit_code == 0
    assert observed_policies == [True, True]
    assert json.loads(capsys.readouterr().out)["status"] == "applied"


def test_rollback_apply_propagates_age_policy_to_bootstrap_and_readiness(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data = _store(
        runtime_sync_state="stale",
        snapshot_age_seconds=3600,
        freshness_policy="rollback_verified_stale_allowed",
    )
    inspect_policies: list[bool] = []
    activate_policies: list[bool] = []

    monkeypatch.setattr(
        production_tool,
        "_new_backup_directory",
        lambda *_args: tmp_path,
    )
    for name in (
        "_record_before_state",
        "_write_recovery_marker",
        "_quiesce_ingest",
        "_ensure_ticket_directory",
        "_ensure_production_manifest_archive",
    ):
        monkeypatch.setattr(production_tool, name, lambda *_args, **_kwargs: None)
    monkeypatch.setattr(production_tool, "_backup_database", lambda *_args: None)

    def inspect_store(*_args, **kwargs):
        inspect_policies.append(kwargs["allow_stale_for_rollback"])
        return data

    def activate(*_args, **kwargs):
        activate_policies.append(kwargs["allow_stale_for_rollback"])

    monkeypatch.setattr(production_tool, "_inspect_store", inspect_store)
    monkeypatch.setattr(production_tool, "_activate", activate)

    result = production_tool._apply_operation(
        "rollback",
        _target(),
        _before(),
        production_tool.Identities(0, 0, 0),
        health_timeout=30.0,
        production_data=data,
        staging_data=None,
        allow_sensor_stats_server_error=False,
    )

    assert inspect_policies == [True]
    assert activate_policies == [True]
    assert result["snapshot_age_seconds"] == 3600
    assert result["freshness_policy"] == "rollback_verified_stale_allowed"


def test_promote_requires_exact_current_staging_targets(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    unit_path = tmp_path / production_tool.STAGING_SERVICE_NAME
    unit_bytes = (DEPLOY / production_tool.STAGING_SERVICE_NAME).read_bytes()
    unit_path.write_bytes(unit_bytes)
    target = _target(staging_unit_sha256=hashlib.sha256(unit_bytes).hexdigest())
    healthy = _staging_state(target.staging_unit_sha256).service
    real_is_directory = stat.S_ISDIR

    _posixify_module_paths(
        monkeypatch,
        "PRIVATE_ROOT",
        "STAGING_RELEASE_LINK",
        "STAGING_VENV_LINK",
        "STAGING_STORE",
        "INACCESSIBLE_APPLICATION_ROOT",
    )
    monkeypatch.setattr(production_tool, "STAGING_UNIT_DESTINATION", unit_path)
    monkeypatch.setattr(
        production_tool.stat,
        "S_IMODE",
        lambda mode: 0o750 if real_is_directory(mode) else 0o644,
    )

    def exact(path: Path, *, allowed_root: Path) -> production_tool.LinkState:
        del allowed_root
        if path == production_tool.STAGING_RELEASE_LINK:
            return production_tool.LinkState(True, str(target.release))
        return production_tool.LinkState(True, str(target.venv))

    monkeypatch.setattr(production_tool, "_capture_link", exact)
    monkeypatch.setattr(production_tool, "_capture_named_service", lambda _name: healthy)
    monkeypatch.setattr(production_tool, "_http_health_ok", lambda port: port == 8518)

    observed = production_tool._require_current_staging(target)
    assert observed.service.main_pid == healthy.main_pid
    assert observed.unit_sha256 == target.staging_unit_sha256

    monkeypatch.setattr(
        production_tool,
        "_capture_named_service",
        lambda _name: replace(healthy, main_pid=0),
    )
    with pytest.raises(production_tool.ProductionToolError, match="non pronto"):
        production_tool._require_current_staging(target)

    monkeypatch.setattr(production_tool, "_capture_named_service", lambda _name: healthy)
    with pytest.raises(production_tool.ProductionToolError, match="diversa dalla release"):
        production_tool._require_current_staging(
            replace(target, staging_unit_sha256="f" * 64)
        )

    monkeypatch.setattr(production_tool, "_http_health_ok", lambda _port: False)
    with pytest.raises(production_tool.ProductionToolError, match="Health staging"):
        production_tool._require_current_staging(target)

    def wrong(path: Path, *, allowed_root: Path) -> production_tool.LinkState:
        del path, allowed_root
        return production_tool.LinkState(True, "/wrong/target")

    monkeypatch.setattr(production_tool, "_capture_link", wrong)
    with pytest.raises(production_tool.ProductionToolError, match="correnti nello staging"):
        production_tool._require_current_staging(target)


def test_ticket_store_requires_0700_and_database_0600(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ticket_root = tmp_path / "tickets"
    ticket_root.mkdir()
    database = ticket_root / "tickets.sqlite3"
    with sqlite3.connect(database) as connection:
        connection.execute("CREATE TABLE ticket (id INTEGER PRIMARY KEY)")
    identities = production_tool.Identities(0, 0, 0)
    real_is_directory = stat.S_ISDIR

    monkeypatch.setattr(production_tool, "PRODUCTION_TICKET_ROOT", ticket_root)
    monkeypatch.setattr(production_tool, "PRODUCTION_TICKET_DATABASE", database)
    monkeypatch.setattr(
        production_tool.stat,
        "S_IMODE",
        lambda mode: 0o700 if real_is_directory(mode) else 0o600,
    )

    state = production_tool._inspect_ticket_state(identities)
    assert state == production_tool.TicketState(True, True, 0o700, 0o600)

    monkeypatch.setattr(
        production_tool.stat,
        "S_IMODE",
        lambda mode: 0o750 if real_is_directory(mode) else 0o640,
    )
    assert production_tool._inspect_ticket_state(
        identities, allow_legacy_modes=True
    ) == production_tool.TicketState(True, True, 0o750, 0o640)
    with pytest.raises(production_tool.ProductionToolError, match="permessi ticket store"):
        production_tool._inspect_ticket_state(identities)


@pytest.mark.parametrize("dangling", [False, True])
def test_ticket_database_rejects_symlink_and_dangling_symlink(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    dangling: bool,
) -> None:
    ticket_root = tmp_path / "tickets"
    ticket_root.mkdir()
    real_is_directory = stat.S_ISDIR

    class FakeSymlink:
        def __init__(self, path: Path, *, is_dangling: bool) -> None:
            self.path = path
            self.is_dangling = is_dangling

        def lstat(self) -> SimpleNamespace:
            return SimpleNamespace(
                st_mode=stat.S_IFLNK | 0o777,
                st_uid=0,
                st_gid=0,
            )

        def is_symlink(self) -> bool:
            return True

        def __str__(self) -> str:
            suffix = "-dangling" if self.is_dangling else ""
            return f"{self.path}{suffix}"

    database = FakeSymlink(ticket_root / "tickets.sqlite3", is_dangling=dangling)
    identities = production_tool.Identities(0, 0, 0)

    monkeypatch.setattr(production_tool, "PRODUCTION_TICKET_ROOT", ticket_root)
    monkeypatch.setattr(production_tool, "PRODUCTION_TICKET_DATABASE", database)
    monkeypatch.setattr(production_tool, "_ticket_paths", lambda: (database,))
    monkeypatch.setattr(
        production_tool,
        "_lexists",
        lambda path: path == ticket_root or path is database,
    )
    monkeypatch.setattr(
        production_tool.stat,
        "S_IMODE",
        lambda mode: 0o700 if real_is_directory(mode) else 0o777,
    )

    with pytest.raises(production_tool.ProductionToolError, match="non sicuro"):
        production_tool._inspect_ticket_state(identities)


def test_sqlite_backup_is_consistent_root_only(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ticket_root = tmp_path / "tickets"
    ticket_root.mkdir()
    database = ticket_root / "tickets.sqlite3"
    with sqlite3.connect(database) as connection:
        connection.execute("CREATE TABLE ticket (id INTEGER PRIMARY KEY, title TEXT)")
        connection.execute("INSERT INTO ticket(title) VALUES ('OT alert')")
    backup_root = tmp_path / "backup"
    backup_root.mkdir()
    replacements: list[tuple[Path, Path]] = []
    chmods: list[tuple[Path, int]] = []
    real_replace = production_tool.os.replace
    real_chmod = Path.chmod

    monkeypatch.setattr(production_tool, "PRODUCTION_TICKET_ROOT", ticket_root)
    monkeypatch.setattr(production_tool, "PRODUCTION_TICKET_DATABASE", database)
    monkeypatch.setattr(production_tool.os, "chown", lambda *_args: None, raising=False)
    monkeypatch.setattr(production_tool.os, "fsync", lambda _descriptor: None)
    monkeypatch.setattr(
        production_tool.os,
        "replace",
        lambda source, destination: (
            replacements.append((Path(source), Path(destination))),
            real_replace(source, destination),
        )[-1],
    )

    def record_chmod(path: Path, mode: int, *args: Any, **kwargs: Any) -> None:
        chmods.append((path, mode))
        real_chmod(path, mode, *args, **kwargs)

    monkeypatch.setattr(Path, "chmod", record_chmod)
    monkeypatch.setattr(
        production_tool,
        "_inspect_ticket_state",
        lambda _identities: production_tool.TicketState(True, True),
    )
    identities = production_tool.Identities(root_uid=0, dashboard_uid=0, dashboard_gid=0)

    backup = production_tool._backup_database(backup_root, identities)
    assert backup is not None
    assert backup.exists()
    assert replacements == [(replacements[0][0], backup)]
    assert replacements[0][0].name.startswith(".tickets.sqlite3.")
    assert (replacements[0][0], 0o600) in chmods
    assert not list(backup_root.glob(".tickets.sqlite3.*.tmp"))
    with sqlite3.connect(f"file:{backup.as_posix()}?mode=ro", uri=True) as connection:
        assert connection.execute("PRAGMA quick_check").fetchone() == ("ok",)
        assert connection.execute("SELECT title FROM ticket").fetchone() == ("OT alert",)


def test_sqlite_backup_cleans_temporary_file_when_atomic_replace_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = tmp_path / "tickets.sqlite3"
    with sqlite3.connect(database) as connection:
        connection.execute("CREATE TABLE ticket (id INTEGER PRIMARY KEY)")
    backup_root = tmp_path / "backup"
    backup_root.mkdir()

    monkeypatch.setattr(production_tool, "PRODUCTION_TICKET_DATABASE", database)
    monkeypatch.setattr(production_tool.os, "chown", lambda *_args: None, raising=False)
    monkeypatch.setattr(production_tool.os, "fsync", lambda _descriptor: None)
    monkeypatch.setattr(
        production_tool.os,
        "replace",
        lambda *_args: (_ for _ in ()).throw(OSError("replace failed")),
    )
    monkeypatch.setattr(
        production_tool,
        "_inspect_ticket_state",
        lambda _identities: production_tool.TicketState(True, True, 0o700, 0o600),
    )

    with pytest.raises(production_tool.ProductionToolError, match="Backup SQLite"):
        production_tool._backup_database(
            backup_root,
            production_tool.Identities(0, 0, 0),
        )

    assert not (backup_root / "tickets.sqlite3.backup").exists()
    assert not list(backup_root.glob(".tickets.sqlite3.*.tmp"))


def test_activation_catches_base_exception_rolls_back_and_marks_recovery(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = _target()
    before = _before(active=True, enabled=True)
    restored: list[production_tool.DeploymentState] = []
    markers: list[tuple[str, type[BaseException] | None]] = []

    monkeypatch.setattr(production_tool, "_run_systemctl", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(production_tool, "_quiesce_ingest", lambda: None)
    monkeypatch.setattr(production_tool, "_switch_link", lambda *_args: None)
    monkeypatch.setattr(production_tool, "_install_unit", lambda _content: None)
    monkeypatch.setattr(production_tool, "_install_ingest_units", lambda _target: None)
    monkeypatch.setattr(
        production_tool,
        "_wait_for_health",
        lambda _timeout: (_ for _ in ()).throw(KeyboardInterrupt()),
    )
    monkeypatch.setattr(
        production_tool,
        "_restore_transaction",
        lambda previous, *_args, **_kwargs: restored.append(previous),
    )
    monkeypatch.setattr(
        production_tool,
        "_write_recovery_marker",
        lambda _directory, *, status, error=None: markers.append(
            (status, type(error) if error is not None else None)
        ),
    )

    with pytest.raises(KeyboardInterrupt):
        production_tool._activate(
            target,
            before,
            1.0,
            recovery_directory=Path("/root/backup"),
        )

    assert restored == [before]
    assert markers == [
        ("mutation_starting", None),
        ("rolled_back", KeyboardInterrupt),
    ]


def test_active_readiness_rechecks_with_rollback_age_policy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = _target()
    expected_data = _store(
        runtime_sync_state="stale",
        freshness_policy="rollback_verified_stale_allowed",
    )
    identities = production_tool.Identities(0, 0, 0)
    observed_policies: list[bool] = []

    monkeypatch.setattr(
        production_tool,
        "_capture_service",
        lambda: production_tool.ServiceState(True, True, 1234, 0, "success"),
    )

    def capture_link(path: Path, *, allowed_root: Path):
        del allowed_root
        if path == production_tool.PRODUCTION_RELEASE_LINK:
            return production_tool.LinkState(True, str(target.release))
        return production_tool.LinkState(True, str(target.venv))

    monkeypatch.setattr(production_tool, "_capture_link", capture_link)
    monkeypatch.setattr(
        production_tool,
        "_capture_unit",
        lambda: production_tool.UnitState(
            True,
            target.unit_bytes,
            0,
            0,
            0o644,
        ),
    )

    def inspect_store(*_args, **kwargs):
        observed_policies.append(kwargs["allow_stale_for_rollback"])
        return expected_data

    monkeypatch.setattr(production_tool, "_inspect_store", inspect_store)
    monkeypatch.setattr(
        production_tool,
        "_inspect_ticket_state",
        lambda *_args, **_kwargs: production_tool.TicketState(True, True),
    )
    monkeypatch.setattr(production_tool, "_http_health_ok", lambda _port: True)

    production_tool._wait_for_active_readiness(
        target,
        expected_data,
        identities,
        allow_sensor_stats_server_error=False,
        allow_stale_for_rollback=True,
        timeout=1.0,
    )

    assert observed_policies == [True]


def test_recovery_always_allows_verified_age_stale_even_after_promote(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    before = _before()
    expected_data = _store()
    identities = production_tool.Identities(0, 0, 0)
    observed_policies: list[bool] = []

    for name in (
        "_quiesce_ingest",
        "_restore_link",
        "_restore_unit",
        "_restore_raw_unit",
        "_restore_service_state",
        "_set_ingest_path_state",
        "_wait_for_ingest_idle",
    ):
        monkeypatch.setattr(production_tool, name, lambda *_args, **_kwargs: None)
    monkeypatch.setattr(production_tool, "_capture_deployment", lambda: before)

    def inspect_store(*_args, **kwargs):
        observed_policies.append(kwargs["allow_stale_for_rollback"])
        return replace(
            expected_data,
            runtime_sync_state="stale",
            snapshot_age_seconds=901,
            freshness_policy="rollback_verified_stale_allowed",
        )

    monkeypatch.setattr(production_tool, "_inspect_store", inspect_store)
    monkeypatch.setattr(
        production_tool,
        "_inspect_ticket_state",
        lambda *_args, **_kwargs: production_tool.TicketState(True, True),
    )

    production_tool._restore_transaction(
        before,
        30.0,
        expected_data=expected_data,
        identities=identities,
        allow_sensor_stats_server_error=False,
        gate_python=Path("/verified/venv/bin/python"),
    )

    assert observed_policies == [True]


def test_ticket_ingest_units_are_validated_and_production_isolated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = (DEPLOY / production_tool.INGEST_SERVICE_NAME).read_bytes()
    path = (DEPLOY / production_tool.INGEST_PATH_NAME).read_bytes()
    _posixify_module_paths(
        monkeypatch,
        "PRODUCTION_STORE",
        "PRODUCTION_RELEASE_LINK",
        "PRODUCTION_VENV_LINK",
        "PRODUCTION_TICKET_ROOT",
        "PRODUCTION_TICKET_DATABASE",
        "INACCESSIBLE_APPLICATION_ROOT",
    )

    production_tool._validate_ingest_units(service, path)

    with pytest.raises(production_tool.ProductionToolError, match="incomplete"):
        production_tool._validate_ingest_units(
            service.replace(b"UMask=0077", b"UMask=0027"),
            path,
        )
    with pytest.raises(production_tool.ProductionToolError, match="non isolate"):
        production_tool._validate_ingest_units(
            service,
            path + b"\n# modbus-dashboard-data-staging\n",
        )


def test_ticket_ingest_activation_waits_for_app_and_initial_worker_before_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = _target(ingest=True)
    before = _before()
    expected_data = _store()
    identities = production_tool.Identities(0, 0, 0)
    events: list[str] = []

    monkeypatch.setattr(
        production_tool,
        "_write_recovery_marker",
        lambda _directory, *, status, error=None: events.append(f"marker:{status}"),
    )
    monkeypatch.setattr(
        production_tool,
        "_run_systemctl",
        lambda *arguments, **_kwargs: events.append("systemctl:" + ":".join(arguments)),
    )
    monkeypatch.setattr(
        production_tool,
        "_quiesce_ingest",
        lambda: events.append("ingest-quiescent"),
    )
    monkeypatch.setattr(
        production_tool,
        "_switch_link",
        lambda path, _target: events.append(f"link:{path.name}"),
    )
    monkeypatch.setattr(
        production_tool, "_install_unit", lambda _content: events.append("app-unit")
    )
    monkeypatch.setattr(
        production_tool,
        "_install_ingest_units",
        lambda _target: events.append("ingest-units"),
    )
    monkeypatch.setattr(
        production_tool,
        "_wait_for_active_readiness",
        lambda *_args, **_kwargs: events.append("app-ready"),
    )
    monkeypatch.setattr(
        production_tool,
        "_run_initial_ingest",
        lambda *_args: events.append("initial-ingest-ready"),
    )
    monkeypatch.setattr(
        production_tool,
        "_set_ingest_path_state",
        lambda *, enabled, active: events.append(f"path:{enabled}:{active}"),
    )
    monkeypatch.setattr(
        production_tool,
        "_verify_ingest_readiness",
        lambda *_args: events.append("ingest-ready"),
    )

    production_tool._activate(
        target,
        before,
        5.0,
        expected_data=expected_data,
        identities=identities,
    )

    assert events.index("ingest-quiescent") < events.index("ingest-units")
    assert events.index("app-ready") < events.index("initial-ingest-ready")
    assert events.index("initial-ingest-ready") < events.index("path:True:True")
    assert events.index("path:True:True") < events.index("ingest-ready")
    assert events[-1] == "marker:complete"


def test_ticket_ingest_failure_restores_complete_prior_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    old_service = production_tool.UnitState(True, b"old-ingest-service", 0, 0, 0o644)
    old_path = production_tool.UnitState(True, b"old-ingest-path", 0, 0, 0o644)
    before = replace(
        _before(),
        ingest_service_unit=old_service,
        ingest_path_unit=old_path,
        ingest_path_state=production_tool.ServiceState(
            active=True,
            enabled=True,
            main_pid=0,
            exec_main_status=0,
            result="success",
        ),
    )
    target = _target(ingest=True)
    expected_data = _store()
    restored: list[production_tool.DeploymentState] = []
    enabled_path: list[tuple[bool, bool]] = []
    markers: list[str] = []

    monkeypatch.setattr(production_tool, "_run_systemctl", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(production_tool, "_quiesce_ingest", lambda: None)
    monkeypatch.setattr(production_tool, "_switch_link", lambda *_args: None)
    monkeypatch.setattr(production_tool, "_install_unit", lambda _content: None)
    monkeypatch.setattr(production_tool, "_install_ingest_units", lambda _target: None)
    monkeypatch.setattr(
        production_tool, "_wait_for_active_readiness", lambda *_args, **_kwargs: None
    )
    monkeypatch.setattr(
        production_tool,
        "_run_initial_ingest",
        lambda *_args: (_ for _ in ()).throw(
            production_tool.ProductionToolError("worker failed")
        ),
    )
    monkeypatch.setattr(
        production_tool,
        "_set_ingest_path_state",
        lambda *, enabled, active: enabled_path.append((enabled, active)),
    )
    monkeypatch.setattr(
        production_tool,
        "_restore_transaction",
        lambda previous, *_args, **_kwargs: restored.append(previous),
    )
    monkeypatch.setattr(
        production_tool,
        "_write_recovery_marker",
        lambda _directory, *, status, error=None: markers.append(status),
    )

    with pytest.raises(production_tool.ProductionToolError, match="worker failed"):
        production_tool._activate(
            target,
            before,
            5.0,
            expected_data=expected_data,
            identities=production_tool.Identities(0, 0, 0),
            recovery_directory=Path("/root/backup"),
        )

    assert enabled_path == []
    assert restored == [before]
    assert markers == ["mutation_starting", "rolled_back"]


def test_restore_unit_accepts_historical_release_unit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    unit_path = tmp_path / production_tool.SERVICE_NAME
    monkeypatch.setattr(production_tool, "UNIT_DESTINATION", unit_path)
    monkeypatch.setattr(production_tool.os, "chown", lambda *_args: None, raising=False)
    previous = production_tool.UnitState(True, _historical_unit(), 0, 0, 0o644)

    production_tool._restore_unit(previous)

    assert unit_path.read_bytes() == _historical_unit()
    assert "database" not in inspect.getsource(production_tool._restore_transaction)


def test_main_dry_run_never_calls_apply(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    target = _target()
    before = _before()
    identities = production_tool.Identities(0, 0, 0)
    ticket = production_tool.TicketState(True, False, 0o700, None)
    unit_sha256 = "c" * 64
    applied = False
    freshness_policies: list[bool] = []

    monkeypatch.setattr(production_tool, "_lookup_identities", lambda: identities)
    monkeypatch.setattr(production_tool, "_verify_release", lambda *_args, **_kwargs: target)
    monkeypatch.setattr(
        production_tool,
        "_require_current_staging",
        lambda _target: _staging_state(unit_sha256),
    )
    monkeypatch.setattr(production_tool, "_capture_deployment", lambda: before)
    monkeypatch.setattr(
        production_tool,
        "_inspect_ticket_state",
        lambda _ids, **_kwargs: ticket,
    )

    def inspect_store(root, *_args, **kwargs):
        freshness_policies.append(kwargs.get("allow_stale_for_rollback", False))
        return _store(root=root)

    monkeypatch.setattr(production_tool, "_inspect_store", inspect_store)

    def unexpected_apply(*_args, **_kwargs):
        nonlocal applied
        applied = True
        raise AssertionError("dry-run mutated production")

    monkeypatch.setattr(production_tool, "_apply_operation", unexpected_apply)

    assert production_tool.main(["promote", "--release-id", RELEASE_ID]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["status"] == "dry-run"
    assert len(output["confirm_plan"]) == 64
    assert freshness_policies == [False, False]
    assert applied is False


def test_system_actions_are_scoped_to_the_single_production_service() -> None:
    source = inspect.getsource(production_tool)

    assert "subprocess.run" in source
    assert '["systemctl", *arguments]' in source
    activation_source = inspect.getsource(production_tool._activate)
    assert "SERVICE_NAME" in activation_source
    assert "_quiesce_ingest" in activation_source
    assert "INGEST_PATH_NAME" in inspect.getsource(production_tool._quiesce_ingest)
    assert "STAGING_SERVICE_NAME" not in activation_source
    assert "SERVICE_NAME" in inspect.getsource(production_tool._restore_service_state)
    assert "with _production_lock():" in inspect.getsource(production_tool.main)
    assert "LOCK_EX | fcntl.LOCK_NB" in inspect.getsource(production_tool._production_lock)
    assert "PRODUCTION_TICKET_DATABASE.unlink" not in source
    assert "shutil.rmtree" not in source
    assert "os.remove" not in source
