from __future__ import annotations

import hashlib
import io
import json
import stat
import tarfile
from pathlib import Path, PurePosixPath
from types import SimpleNamespace

import pytest

from deploy import staging_tool
from tools.build_release import build_release

ROOT = Path(__file__).resolve().parents[1]
DEPLOY = ROOT / "deploy"


def _bundle_for_plan() -> staging_tool.BundleInfo:
    release_id = "0123456789abcdef"
    ingest_service = (DEPLOY / staging_tool.INGEST_SERVICE_NAME).read_bytes()
    ingest_path = (DEPLOY / staging_tool.INGEST_PATH_NAME).read_bytes()
    return staging_tool.BundleInfo(
        archive=Path("release.tar.gz"),
        archive_sha256="a" * 64,
        prefix=f"dtlab-control-center-{release_id}",
        release_id=release_id,
        manifest={},
        unit_bytes=b"",
        requirements_path=PurePosixPath("requirements-server.lock"),
        requirements_sha256="b" * 64,
        ingest_service_bytes=ingest_service,
        ingest_service_sha256=hashlib.sha256(ingest_service).hexdigest(),
        ingest_path_bytes=ingest_path,
        ingest_path_sha256=hashlib.sha256(ingest_path).hexdigest(),
    )


def test_entrypoints_are_dry_run_by_default_and_apply_requires_plan_token(capsys) -> None:
    parsed = staging_tool._parser().parse_args(["bootstrap"])
    assert parsed.apply is False
    assert parsed.confirm_plan is None

    assert staging_tool.main(["bootstrap"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "dry-run"
    assert len(result["confirm_plan"]) == 64

    assert staging_tool.main(["bootstrap", "--apply"]) == 2
    error = json.loads(capsys.readouterr().err)
    assert "--confirm-plan" in error["error"]


def test_shell_entrypoints_only_dispatch_local_staging_actions() -> None:
    bootstrap = (DEPLOY / "bootstrap_staging.sh").read_text(encoding="utf-8")
    deploy = (DEPLOY / "deploy_staging.sh").read_text(encoding="utf-8")

    assert 'staging_tool.py" bootstrap' in bootstrap
    assert "install|rollback" in deploy
    assert "ssh " not in bootstrap + deploy
    assert "modbus-dashboard.service" not in bootstrap + deploy
    assert "modbus-dashboard-v2.service" not in bootstrap + deploy


def test_publisher_account_keeps_ssh_shell_but_locks_password() -> None:
    source = (DEPLOY / "staging_tool.py").read_text(encoding="utf-8")

    assert 'PUBLISH_SHELL = "/bin/bash"' in source
    assert '"--password",\n                "!"' in source
    assert '["passwd", "--lock", PUBLISH_USER]' in source
    assert "publisher.pw_shell != PUBLISH_SHELL" in source
    assert "nologin" not in source
    assert 'f"u:{PUBLISH_USER}:---", str(LEGACY_ROOT)' in source
    assert 'f"user:{PUBLISH_USER}:---"' in source


def test_publisher_home_is_dedicated_and_key_material_is_not_created() -> None:
    source = (DEPLOY / "staging_tool.py").read_text(encoding="utf-8")

    assert staging_tool.PUBLISH_HOME.as_posix() == "/var/lib/dtlab-publish"
    assert 'PUBLISH_HOME / ".ssh"' in source
    assert "mode=0o700" in source
    assert "publisher.pw_dir != _path_text(PUBLISH_HOME)" in source
    assert '["usermod", "--home", str(PUBLISH_HOME), PUBLISH_USER]' in source
    assert "authorized_keys" not in source
    assert "/nonexistent" not in source


def test_staging_bootstrap_prepares_immutable_manifest_archive_directory() -> None:
    source = (DEPLOY / "staging_tool.py").read_text(encoding="utf-8")

    # The same path must be both bootstrapped and verified before deployment.
    assert source.count('STAGING_STORE / "manifests"') == 2


def test_staging_unit_is_loopback_isolated_and_cannot_read_legacy() -> None:
    unit = (DEPLOY / "modbus-dashboard-v2-staging.service").read_text(encoding="utf-8")

    assert "User=web75" in unit
    assert "Group=dtlab-dashboard" in unit
    assert "modbus-dashboard-staging-current" in unit
    assert "modbus-dashboard-staging-venv-current/bin/python" in unit
    assert "modbus-dashboard-data-staging" in unit
    assert "--server.address=127.0.0.1" in unit
    assert "--server.port=8518" in unit
    assert "--server.port=8517" not in unit
    assert "UMask=0077" in unit
    assert "InaccessiblePaths=/var/www/clients/client1/web75/private/modbus-dashboard" in unit
    staging_tool._validate_staging_unit(unit.encode())


def test_historical_safe_unit_remains_a_valid_rollback_target() -> None:
    unit = (DEPLOY / "modbus-dashboard-v2-staging.service").read_text(encoding="utf-8")
    historical = "\n".join(
        line
        for line in unit.splitlines()
        if "DTLAB_TICKET_STORE" not in line
        and "modbus-dashboard-ticket-data-staging" not in line
    ).encode()

    with pytest.raises(staging_tool.StagingToolError, match="Unità staging incompleta"):
        staging_tool._validate_staging_unit(historical)
    staging_tool._validate_staging_unit(historical, require_ticket_store=False)


def test_future_production_unit_uses_isolated_group_and_versioned_venv() -> None:
    unit = (DEPLOY / "modbus-dashboard-v2.service").read_text(encoding="utf-8")

    assert "User=web75" in unit
    assert "Group=dtlab-dashboard" in unit
    assert "modbus-dashboard-venv-current/bin/python" in unit
    assert "modbus-dashboard-venvs" in unit
    assert "--server.address=127.0.0.1" in unit
    assert "--server.port=8517" in unit
    assert "InaccessiblePaths=/var/www/clients/client1/web75/private/modbus-dashboard" in unit


def test_release_bundle_is_fully_verified_and_prefers_server_lock(tmp_path) -> None:
    archive, checksum = build_release(tmp_path / "dist", root=ROOT)

    bundle = staging_tool.inspect_bundle(archive, checksum)

    assert bundle.requirements_path.as_posix() == "requirements-server.lock"
    assert bundle.release_directory.parent == staging_tool.RELEASES_ROOT
    assert bundle.venv_directory.parent == staging_tool.VENVS_ROOT
    assert len(bundle.archive_sha256) == 64
    assert bundle.ingest_service_sha256 == hashlib.sha256(
        (DEPLOY / staging_tool.INGEST_SERVICE_NAME).read_bytes()
    ).hexdigest()
    assert bundle.ingest_path_sha256 == hashlib.sha256(
        (DEPLOY / staging_tool.INGEST_PATH_NAME).read_bytes()
    ).hexdigest()


def test_staging_ticket_ingest_units_are_canonical_and_isolated() -> None:
    service = (DEPLOY / staging_tool.INGEST_SERVICE_NAME).read_bytes()
    path = (DEPLOY / staging_tool.INGEST_PATH_NAME).read_bytes()

    staging_tool._validate_staging_ingest_units(service, path)
    with pytest.raises(staging_tool.StagingToolError, match="non canonica"):
        staging_tool._validate_staging_ingest_units(
            service + b"\nExecStartPost=/bin/false\n",
            path,
        )

    text = (service + path).decode()
    assert "modbus-dashboard-data-staging" in text
    assert "modbus-dashboard-ticket-data-staging" in text
    assert "modbus-dashboard-data/manifests" not in text
    assert "UMask=0077" in text


def test_bundle_rejects_a_bad_checksum_before_extracting(tmp_path) -> None:
    archive, checksum = build_release(tmp_path / "dist", root=ROOT)
    checksum.write_text(f"{'0' * 64}  {archive.name}\n", encoding="ascii")

    with pytest.raises(staging_tool.StagingToolError, match="Checksum"):
        staging_tool.inspect_bundle(archive, checksum)


def test_bundle_rejects_traversal_and_links(tmp_path) -> None:
    for kind in ("traversal", "symlink"):
        archive = tmp_path / f"{kind}.tar.gz"
        with tarfile.open(archive, mode="w:gz") as output:
            if kind == "traversal":
                info = tarfile.TarInfo("../escape")
                info.size = 1
                output.addfile(info, io.BytesIO(b"x"))
            else:
                info = tarfile.TarInfo("dtlab-control-center-0000000000000000/link")
                info.type = tarfile.SYMTYPE
                info.linkname = "/etc/passwd"
                output.addfile(info)
        checksum = archive.with_suffix(archive.suffix + ".sha256")
        checksum.write_text(
            f"{hashlib.sha256(archive.read_bytes()).hexdigest()}  {archive.name}\n",
            encoding="ascii",
        )

        with pytest.raises(staging_tool.StagingToolError):
            staging_tool.inspect_bundle(archive, checksum)


def test_trusted_python_accepts_a_safe_system_symlink_target(monkeypatch) -> None:
    alias = Path("/usr/bin/python3")
    canonical = Path("/usr/bin/python3.12")

    def fake_resolve(path: Path, *, strict: bool = False) -> Path:
        assert path == alias
        assert strict is True
        return canonical

    def fake_lstat(path: Path) -> SimpleNamespace:
        if path == canonical:
            return SimpleNamespace(st_mode=stat.S_IFREG | 0o755, st_uid=0)
        assert path in canonical.parents
        return SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0)

    monkeypatch.setattr(Path, "resolve", fake_resolve)
    monkeypatch.setattr(Path, "lstat", fake_lstat)

    assert staging_tool._resolve_trusted_python(alias) == canonical


@pytest.mark.parametrize(
    ("mode", "uid", "error"),
    [
        (stat.S_IFDIR | 0o755, 0, "non regolare"),
        (stat.S_IFREG | 0o755, 1000, "non posseduto da root"),
        (stat.S_IFREG | 0o775, 0, "scrivibile da gruppo/altri"),
        (stat.S_IFREG | 0o644, 0, "non eseguibile"),
    ],
)
def test_trusted_python_rejects_an_unsafe_target(
    monkeypatch,
    mode: int,
    uid: int,
    error: str,
) -> None:
    alias = Path("/usr/bin/python3")
    canonical = Path("/usr/bin/python3.12")
    monkeypatch.setattr(Path, "resolve", lambda _path, *, strict=False: canonical)
    monkeypatch.setattr(
        Path,
        "lstat",
        lambda _path: SimpleNamespace(st_mode=mode, st_uid=uid),
    )

    with pytest.raises(staging_tool.StagingToolError, match=error):
        staging_tool._resolve_trusted_python(alias)


def test_trusted_python_rejects_an_unsafe_ancestor(monkeypatch) -> None:
    alias = Path("/usr/bin/python3")
    canonical = Path("/usr/bin/python3.12")

    def fake_lstat(path: Path) -> SimpleNamespace:
        if path == canonical:
            return SimpleNamespace(st_mode=stat.S_IFREG | 0o755, st_uid=0)
        mode = 0o775 if path == canonical.parent else 0o755
        return SimpleNamespace(st_mode=stat.S_IFDIR | mode, st_uid=0)

    monkeypatch.setattr(Path, "resolve", lambda _path, *, strict=False: canonical)
    monkeypatch.setattr(Path, "lstat", fake_lstat)

    with pytest.raises(staging_tool.StagingToolError, match="Directory.*non sicura"):
        staging_tool._resolve_trusted_python(alias)


def test_install_plan_token_binds_canonical_python_and_health_timeout() -> None:
    bundle = _bundle_for_plan()
    python = Path("/usr/bin/python3.12")
    payload, token = staging_tool._plan(
        "install",
        bundle=bundle,
        python_executable=python,
        health_timeout=30.0,
    )
    _, different_python_token = staging_tool._plan(
        "install",
        bundle=bundle,
        python_executable=Path("/usr/bin/python3.13"),
        health_timeout=30.0,
    )
    _, different_timeout_token = staging_tool._plan(
        "install",
        bundle=bundle,
        python_executable=python,
        health_timeout=45.0,
    )

    assert payload["python_executable"] == "/usr/bin/python3.12"
    assert payload["health_timeout_seconds"] == 30.0
    assert payload["ticket_ingest_service_sha256"] == bundle.ingest_service_sha256
    assert payload["ticket_ingest_path_sha256"] == bundle.ingest_path_sha256
    assert token != different_python_token
    assert token != different_timeout_token


def test_rollback_plan_mutates_only_staging_links_and_staging_service() -> None:
    release_id = "0123456789abcdef"
    payload, _ = staging_tool._plan("rollback", release_id=release_id)
    plan = json.dumps(payload, sort_keys=True)

    assert staging_tool.SERVICE_NAME in plan
    assert staging_tool.STAGING_RELEASE_LINK.as_posix() in plan
    assert staging_tool.STAGING_VENV_LINK.as_posix() in plan
    assert "modbus-dashboard-data-staging" not in plan
    assert "modbus-dashboard-current" not in plan
    assert "modbus-dashboard-v2.service" not in plan
    assert "delete" not in plan.lower()


def test_failed_activation_restores_unit_before_restarting_previous_release(
    monkeypatch,
) -> None:
    events: list[tuple[str, object]] = []
    monkeypatch.setattr(
        staging_tool,
        "_restore_link",
        lambda path, _state: events.append(("link", path)),
    )
    monkeypatch.setattr(
        staging_tool,
        "_restore_unit",
        lambda state: events.append(("unit", state)),
    )
    monkeypatch.setattr(
        staging_tool,
        "_restore_ingest_units",
        lambda service, path: events.append(("ingest_units", (service, path))),
    )
    monkeypatch.setattr(
        staging_tool,
        "_systemctl",
        lambda *arguments, **_kwargs: events.append(("systemctl", arguments)),
    )
    previous_link = staging_tool.LinkState(True, "/previous")
    previous_unit = staging_tool.UnitState(True, b"safe historical unit")
    previous_ingest = staging_tool.UnitState(False, None)
    previous_service = staging_tool.ServiceState(
        active=True,
        enabled=False,
        main_pid=123,
    )
    previous_path = staging_tool.ServiceState(active=False, enabled=False)
    monkeypatch.setattr(staging_tool, "_wait_for_health", lambda _timeout: None)
    monkeypatch.setattr(
        staging_tool,
        "_set_ingest_path_state",
        lambda **state: events.append(("path_state", state)),
    )
    monkeypatch.setattr(staging_tool, "_capture_service", lambda: previous_service)
    monkeypatch.setattr(
        staging_tool,
        "_capture_ingest_units",
        lambda: (previous_ingest, previous_ingest),
    )
    monkeypatch.setattr(
        staging_tool,
        "_capture_named_service",
        lambda _name: previous_path,
    )
    monkeypatch.setattr(staging_tool, "_capture_link", lambda _path: previous_link)
    monkeypatch.setattr(staging_tool, "_capture_unit", lambda: previous_unit)
    monkeypatch.setattr(staging_tool, "_verify_ticket_store", lambda _ids: None)
    identities = staging_tool.Identities(0, 0, 0, 0, 0)

    staging_tool._rollback_failed_switch(
        previous_link,
        previous_link,
        service_before=previous_service,
        unit_before=previous_unit,
        ingest_service_before=previous_ingest,
        ingest_path_before=previous_ingest,
        ingest_path_state_before=previous_path,
        identities=identities,
        health_timeout=1.0,
    )

    unit_index = events.index(("unit", previous_unit))
    restart_index = events.index(
        ("systemctl", ("restart", staging_tool.SERVICE_NAME))
    )
    assert unit_index < restart_index
    assert ("systemctl", ("daemon-reload",)) in events
    assert ("systemctl", ("disable", staging_tool.SERVICE_NAME)) in events


def test_activation_enables_ingest_path_only_after_app_and_worker_readiness(
    monkeypatch,
) -> None:
    events: list[tuple[str, object]] = []
    absent_link = staging_tool.LinkState(False, None)
    absent_unit = staging_tool.UnitState(False, None)
    inactive = staging_tool.ServiceState(active=False, enabled=False)
    identities = staging_tool.Identities(0, 0, 0, 0, 0)
    service = (DEPLOY / staging_tool.INGEST_SERVICE_NAME).read_bytes()
    path = (DEPLOY / staging_tool.INGEST_PATH_NAME).read_bytes()

    monkeypatch.setattr(staging_tool, "_capture_link", lambda _path: absent_link)
    monkeypatch.setattr(staging_tool, "_capture_unit", lambda: absent_unit)
    monkeypatch.setattr(
        staging_tool,
        "_capture_ingest_units",
        lambda: (absent_unit, absent_unit),
    )
    monkeypatch.setattr(staging_tool, "_capture_service", lambda: inactive)
    monkeypatch.setattr(
        staging_tool,
        "_capture_named_service",
        lambda _name: inactive,
    )
    monkeypatch.setattr(
        staging_tool,
        "_systemctl",
        lambda *args, **_kwargs: events.append(("systemctl", args)),
    )
    monkeypatch.setattr(
        staging_tool,
        "_switch_link",
        lambda link, target: events.append(("link", (link, target))) or True,
    )
    monkeypatch.setattr(
        staging_tool,
        "_install_unit",
        lambda _content: events.append(("unit", "app")) or True,
    )
    monkeypatch.setattr(
        staging_tool,
        "_install_ingest_units",
        lambda _service, _path: events.append(("unit", "ingest")) or True,
    )
    monkeypatch.setattr(
        staging_tool,
        "_wait_for_app_readiness",
        lambda *_args: events.append(("ready", "app")),
    )
    monkeypatch.setattr(
        staging_tool,
        "_run_initial_ingest",
        lambda *_args: events.append(("ready", "worker")),
    )
    monkeypatch.setattr(
        staging_tool,
        "_set_ingest_path_state",
        lambda **state: events.append(("path", state)),
    )
    monkeypatch.setattr(staging_tool, "_verify_ingest_readiness", lambda *_args: None)

    staging_tool._activate(
        Path("/release"),
        Path("/venv"),
        unit_bytes=b"app-unit",
        expected_unit_sha256="a" * 64,
        ingest_service_bytes=service,
        ingest_path_bytes=path,
        snapshot_sha256="b" * 64,
        identities=identities,
        health_timeout=1.0,
    )

    assert events.index(("ready", "app")) < events.index(("ready", "worker"))
    assert events.index(("ready", "worker")) < events.index(
        ("path", {"enabled": True, "active": True})
    )


def test_ticket_store_bootstrap_narrows_legacy_modes_and_rejects_symlinks(
    tmp_path: Path,
    monkeypatch,
) -> None:
    if staging_tool.os.name == "nt":
        pytest.skip("semantica chmod/chown POSIX non disponibile su Windows")
    root = tmp_path / "tickets"
    root.mkdir()
    root.chmod(0o750)
    database = root / "tickets.sqlite3"
    database.write_bytes(b"not-opened-by-permission-check")
    database.chmod(0o640)
    details = root.stat()
    identities = staging_tool.Identities(
        root_uid=details.st_uid,
        dashboard_uid=details.st_uid,
        publisher_uid=details.st_uid,
        dashboard_gid=details.st_gid,
        private_gid=details.st_gid,
    )
    monkeypatch.setattr(staging_tool, "STAGING_TICKET_STORE", root)
    monkeypatch.setattr(staging_tool.os, "chown", lambda *_args: None, raising=False)

    staging_tool._bootstrap_ticket_store(identities)
    assert stat.S_IMODE(root.stat().st_mode) == 0o700
    assert stat.S_IMODE(database.stat().st_mode) == 0o600

    database.unlink()
    try:
        database.symlink_to(root / "missing")
    except OSError:
        pytest.skip("symlink non disponibile su questa piattaforma")
    with pytest.raises(staging_tool.StagingToolError):
        staging_tool._verify_ticket_store(identities)


def test_backend_contains_no_remote_transport_or_production_service_actions() -> None:
    source = (DEPLOY / "staging_tool.py").read_text(encoding="utf-8")

    assert "subprocess.run" in source
    assert '["ssh"' not in source
    assert '["scp"' not in source
    assert 'SERVICE_NAME = "modbus-dashboard-v2-staging.service"' in source
    assert '"modbus-dashboard-v2.service"' not in source
    assert '"modbus-dashboard.service"' not in source
