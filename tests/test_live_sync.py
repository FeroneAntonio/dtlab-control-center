from __future__ import annotations

import subprocess
import sys
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

from dtlab.collector.config import load_config
from dtlab.collector.remote_publish import RemotePublishSummary
from dtlab.collector.sync import SyncResult
from dtlab.services.snapshot_store import AtomicSnapshotStore
from tests.factories import valid_snapshot
from tools import live_sync

PUBLISHED_AT = datetime(2026, 8, 3, 16, 0, tzinfo=UTC)

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


class FakePublisher:
    published: list[str] = []
    archived: list[list[str]] = []

    def __init__(self, config) -> None:
        self.config = config

    def publish(self, store, manifest) -> None:
        del store
        self.published.append(manifest["sha256"])

    def publish_batch(self, store, archives, current) -> RemotePublishSummary:
        del store
        self.published.append(current.manifest["sha256"])
        self.archived.append([stored.manifest["sha256"] for stored in archives])
        return RemotePublishSummary(
            archives_requested=len(archives),
            archives_published=len(archives),
            archives_already_present=0,
            objects_uploaded=len(archives) + 1,
            current_archive_published=1,
            current_archive_already_present=0,
            current_updated=1,
        )


def test_script_can_be_started_directly() -> None:
    result = subprocess.run(
        [sys.executable, str(live_sync.__file__), "--help"],
        cwd=Path(live_sync.__file__).resolve().parents[1],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert "--publish-current" in result.stdout


def _config(tmp_path):
    config_path = tmp_path / "collector.toml"
    config_path.write_text(
        f'''[vpn]
connection_name = "DTLAB CISCO"

[esxi]
host = "esxi.example.test"
port = 443
username = "user"
tls_sha256 = "{'a' * 64}"

[cybervision]
base_url = "https://cybervision.example.test"
tls_sha256 = "{'b' * 64}"

[storage]
local_store = "{(tmp_path / 'store').as_posix()}"
raw_directory = "{(tmp_path / 'raw').as_posix()}"

[publish.production]
enabled = false
ssh_alias = "publisher"
remote_account = "dtlab-publish"
remote_store = "/var/www/clients/client1/web75/private/modbus-dashboard-data"
remote_owner = "dtlab-publish"
remote_group = "dtlab-dashboard"
manage_ownership = false

[publish.staging]
enabled = true
ssh_alias = "publisher"
remote_account = "dtlab-publish"
remote_store = "/var/www/clients/client1/web75/private/modbus-dashboard-data-staging"
remote_owner = "dtlab-publish"
remote_group = "dtlab-dashboard"
manage_ownership = false
''',
        encoding="utf-8",
    )
    return load_config(config_path)


def _gate_ready_snapshot() -> dict:
    snapshot = valid_snapshot()
    snapshot["sync"]["state"] = "fresh"
    snapshot["quality"]["score"] = 90
    esxi = next(
        source for source in snapshot["sources"] if source["type"] == "vmware_esxi"
    )
    esxi["capabilities"] = {
        "vm_inventory": {"status": "available", "records": 5, "error_code": None},
    }
    classic = next(
        source
        for source in snapshot["sources"]
        if source["type"] == "cisco_cyber_vision"
    )
    classic["status"] = "connected"
    classic["last_success_at"] = classic["last_attempt_at"]
    classic["capabilities"] = {
        name: {"status": "available", "records": 1, "error_code": None}
        for name in _CLASSIC_CAPABILITIES
    }
    new_ui = deepcopy(classic)
    new_ui["id"] = "src:cisco-cyber-vision-new-ui:test"
    new_ui["label"] = "Cisco Cyber Vision · New UI"
    new_ui["type"] = "cisco_cyber_vision_new_ui"
    new_ui["evidence"]["source_id"] = new_ui["id"]
    new_ui["capabilities"] = {
        name: {"status": "available", "records": 1, "error_code": None}
        for name in _NEW_UI_CAPABILITIES
    }
    snapshot["sources"].append(new_ui)
    return snapshot


def test_cycle_publishes_only_after_gate_approval(tmp_path, monkeypatch) -> None:
    config = _config(tmp_path)
    snapshot = _gate_ready_snapshot()
    manifest = AtomicSnapshotStore(config.local_store).publish(snapshot, published_at=PUBLISHED_AT)

    monkeypatch.setattr(
        live_sync,
        "run_sync",
        lambda *args, **kwargs: SyncResult(
            snapshot_id=snapshot["snapshot_id"],
            state="fresh",
            manifest_sha256=manifest["sha256"],
            virtual_machines=0,
            assets=0,
            risk_scores=0,
            remote_published=False,
            publish_target=None,
        ),
    )
    FakePublisher.published = []
    FakePublisher.archived = []
    monkeypatch.setattr(live_sync, "RemoteSnapshotPublisher", FakePublisher)

    output = live_sync.run_cycle(config, targets=("staging",))

    assert output["published_targets"] == ["staging"]
    assert FakePublisher.published == [manifest["sha256"]]
    assert output["publication_counts"]["staging"]["manifests_deleted"] == 0
    assert output["publication_counts"]["staging"]["objects_deleted"] == 0


def test_cycle_validates_every_target_before_collecting_or_publishing(
    tmp_path, monkeypatch
) -> None:
    config = _config(tmp_path)
    FakePublisher.published = []
    FakePublisher.archived = []
    monkeypatch.setattr(live_sync, "RemoteSnapshotPublisher", FakePublisher)
    monkeypatch.setattr(
        live_sync,
        "run_sync",
        lambda *_args, **_kwargs: pytest.fail("collection must not start"),
    )

    with pytest.raises(live_sync.LiveSyncError, match="publish_production_disabled"):
        live_sync.run_cycle(config, targets=("staging", "production"))

    assert FakePublisher.published == []


def test_cycle_rejects_unapproved_partial_snapshot(tmp_path, monkeypatch) -> None:
    config = _config(tmp_path)
    snapshot = valid_snapshot()
    manifest = AtomicSnapshotStore(config.local_store).publish(snapshot, published_at=PUBLISHED_AT)
    monkeypatch.setattr(
        live_sync,
        "run_sync",
        lambda *args, **kwargs: SyncResult(
            snapshot_id=snapshot["snapshot_id"],
            state="partial",
            manifest_sha256=manifest["sha256"],
            virtual_machines=0,
            assets=0,
            risk_scores=0,
            remote_published=False,
            publish_target=None,
        ),
    )

    with pytest.raises(live_sync.LiveSyncError, match="snapshot_gate_rejected"):
        live_sync.run_cycle(config, targets=("staging",))


def test_cycle_rejects_a_pointer_changed_by_another_collector(tmp_path, monkeypatch) -> None:
    config = _config(tmp_path)
    snapshot = valid_snapshot()
    manifest = AtomicSnapshotStore(config.local_store).publish(snapshot, published_at=PUBLISHED_AT)
    monkeypatch.setattr(
        live_sync,
        "run_sync",
        lambda *args, **kwargs: SyncResult(
            snapshot_id="snapshot:other-cycle",
            state="fresh",
            manifest_sha256=manifest["sha256"],
            virtual_machines=0,
            assets=0,
            risk_scores=0,
            remote_published=False,
            publish_target=None,
        ),
    )

    with pytest.raises(live_sync.LiveSyncError, match="local_store_changed_during_cycle"):
        live_sync.run_cycle(config, targets=("staging",))


def test_once_reports_transient_remote_publish_failure(
    tmp_path, monkeypatch, capsys
) -> None:
    monkeypatch.setattr(
        live_sync,
        "load_config",
        lambda _path: SimpleNamespace(local_store=tmp_path / "store"),
    )

    def fail_publish(*_args, **_kwargs):
        raise live_sync.RemotePublishError("Comando SSH/SCP non riuscito.")

    monkeypatch.setattr(live_sync, "publish_current", fail_publish)

    assert live_sync.main(["--once", "--publish-current", "--target", "staging"]) == 2
    output = capsys.readouterr().out
    assert '"status": "not_published"' in output
    assert "Comando SSH/SCP non riuscito." in output


def test_once_reports_targets_committed_before_a_later_failure(
    tmp_path, monkeypatch, capsys
) -> None:
    monkeypatch.setattr(
        live_sync,
        "load_config",
        lambda _path: SimpleNamespace(local_store=tmp_path / "store"),
    )

    def fail_second_target(*_args, **_kwargs):
        raise live_sync.TargetPublishError(
            "production",
            ("staging",),
            live_sync.RemotePublishError("Comando SSH/SCP non riuscito."),
        )

    monkeypatch.setattr(live_sync, "publish_current", fail_second_target)

    assert live_sync.main(["--once", "--publish-current", "--target", "staging"]) == 2
    output = capsys.readouterr().out
    assert '"status": "partially_published"' in output
    assert '"published_targets": ["staging"]' in output
    assert '"failed_target": "production"' in output


def test_default_cli_is_collect_only_and_never_selects_staging(
    tmp_path, monkeypatch, capsys
) -> None:
    config = SimpleNamespace(local_store=tmp_path / "store")
    received: dict[str, object] = {}
    monkeypatch.setattr(live_sync, "load_config", lambda _path: config)

    def collect_only(_config, **kwargs):
        received.update(kwargs)
        return {"mode": "collect_only", "published_targets": []}

    monkeypatch.setattr(live_sync, "run_cycle", collect_only)
    monkeypatch.setattr(
        live_sync,
        "publish_current",
        lambda *_args, **_kwargs: pytest.fail("publish must not run"),
    )

    assert live_sync.main(["--once"]) == 0
    output = capsys.readouterr().out

    assert received["targets"] == ()
    assert received["snapshot_retention"] == 240
    assert '"mode": "collect_only"' in output
    assert '"published_targets": []' in output


def test_cli_requires_explicit_publish_mode_and_target(monkeypatch) -> None:
    monkeypatch.setattr(
        live_sync,
        "load_config",
        lambda _path: pytest.fail("invalid CLI must fail before config is loaded"),
    )

    with pytest.raises(SystemExit, match="--target richiede --publish-current"):
        live_sync.main(["--once", "--target", "staging"])
    with pytest.raises(SystemExit, match="richiede almeno un --target esplicito"):
        live_sync.main(["--once", "--publish-current"])
    with pytest.raises(SystemExit, match="una sola volta"):
        live_sync.main(
            [
                "--once",
                "--publish-current",
                "--target",
                "staging",
                "--target",
                "staging",
            ]
        )


def test_publish_current_never_runs_collection(tmp_path, monkeypatch) -> None:
    config = _config(tmp_path)
    snapshot = _gate_ready_snapshot()
    manifest = AtomicSnapshotStore(config.local_store).publish(snapshot, published_at=PUBLISHED_AT)
    monkeypatch.setattr(
        live_sync,
        "run_sync",
        lambda *_args, **_kwargs: pytest.fail("existing-snapshot publication must not collect"),
    )
    FakePublisher.published = []
    FakePublisher.archived = []
    monkeypatch.setattr(live_sync, "RemoteSnapshotPublisher", FakePublisher)

    output = live_sync.publish_current(config, targets=("staging",))

    assert output["mode"] == "publish_current"
    assert output["published_targets"] == ["staging"]
    assert FakePublisher.published == [manifest["sha256"]]


def test_publish_current_backfills_only_gate_approved_archives(tmp_path, monkeypatch) -> None:
    config = _config(tmp_path)
    store = AtomicSnapshotStore(config.local_store)

    approved = _gate_ready_snapshot()
    approved["snapshot_id"] = "snapshot:test:approved-backlog"
    approved_manifest = store.publish(
        approved,
        published_at=datetime(2026, 8, 3, 10, 0, 3, tzinfo=UTC),
    )

    rejected = _gate_ready_snapshot()
    rejected["snapshot_id"] = "snapshot:test:rejected-backlog"
    rejected["quality"]["score"] = 10
    store.publish(
        rejected,
        published_at=datetime(2026, 8, 3, 10, 0, 4, tzinfo=UTC),
    )

    current = _gate_ready_snapshot()
    current["snapshot_id"] = "snapshot:test:current-after-outage"
    store.publish(
        current,
        published_at=datetime(2026, 8, 3, 10, 0, 5, tzinfo=UTC),
    )
    FakePublisher.published = []
    FakePublisher.archived = []
    monkeypatch.setattr(live_sync, "RemoteSnapshotPublisher", FakePublisher)

    output = live_sync.publish_current(config, targets=("staging",))

    assert output["archives_scanned"] == 2
    assert output["archives_approved"] == 1
    assert output["archives_rejected"] == 1
    assert output["archives_invalid"] == 0
    assert FakePublisher.archived == [[approved_manifest["sha256"]]]
    assert "snapshot_id" not in output
    assert "manifest_sha256" not in output


def test_historical_gate_uses_published_at_but_current_uses_wall_clock(
    tmp_path,
    monkeypatch,
) -> None:
    config = _config(tmp_path)
    store = AtomicSnapshotStore(config.local_store)
    historical = _gate_ready_snapshot()
    historical["snapshot_id"] = "snapshot:test:historical-gate-clock"
    published_at = datetime(2026, 8, 3, 10, 0, 3, tzinfo=UTC)
    store.publish(historical, published_at=published_at)
    current = _gate_ready_snapshot()
    current["snapshot_id"] = "snapshot:test:current-gate-clock"
    store.publish(
        current,
        published_at=datetime(2026, 8, 3, 10, 0, 4, tzinfo=UTC),
    )

    observed_now: list[datetime | None] = []
    real_evaluate = live_sync.evaluate_snapshot

    def recording_evaluate(stored, **kwargs):
        observed_now.append(kwargs.get("now"))
        return real_evaluate(stored, **kwargs)

    FakePublisher.published = []
    FakePublisher.archived = []
    monkeypatch.setattr(live_sync, "evaluate_snapshot", recording_evaluate)
    monkeypatch.setattr(live_sync, "RemoteSnapshotPublisher", FakePublisher)

    live_sync.publish_current(config, targets=("staging",))

    assert observed_now[0] is None
    assert published_at in observed_now[1:]


def test_stale_current_is_rejected_before_any_backlog_remote_access(
    tmp_path,
    monkeypatch,
) -> None:
    config = _config(tmp_path)
    snapshot = _gate_ready_snapshot()
    AtomicSnapshotStore(config.local_store).publish(snapshot, published_at=PUBLISHED_AT)
    monkeypatch.setattr(
        "tools.verify_staging_snapshot._utc_now",
        lambda: datetime(2026, 8, 3, 11, 0, tzinfo=UTC),
    )
    FakePublisher.published = []
    FakePublisher.archived = []
    monkeypatch.setattr(live_sync, "RemoteSnapshotPublisher", FakePublisher)

    with pytest.raises(live_sync.LiveSyncError, match="snapshot_stale_by_age"):
        live_sync.publish_current(config, targets=("staging",))

    assert FakePublisher.published == []
    assert FakePublisher.archived == []


def test_process_lock_rejects_a_second_holder_and_is_reusable(tmp_path) -> None:
    lock_path = tmp_path / ".store.live-sync.lock"

    with (
        live_sync.LiveSyncProcessLock(lock_path),
        pytest.raises(live_sync.LiveSyncAlreadyRunning),
        live_sync.LiveSyncProcessLock(lock_path),
    ):
        pytest.fail("second process lock must never be acquired")

    with live_sync.LiveSyncProcessLock(lock_path):
        assert lock_path.is_file()
