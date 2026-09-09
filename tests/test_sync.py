from __future__ import annotations

import json
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from pathlib import Path, PurePosixPath
from typing import Any

import pytest

from dtlab.collector.config import CollectorConfig, EsxiConfig, PublishConfig
from dtlab.collector.cybervision_client import CyberVisionConfig
from dtlab.collector.sync import (
    DEFAULT_SNAPSHOT_RETENTION,
    SyncError,
    SyncResult,
    _parser,
    main,
    run_sync,
)
from dtlab.services.snapshot_store import AtomicSnapshotStore
from tests.test_cybervision_adapter import raw_collection

CURRENT_INVENTORY_PATH = Path(__file__).resolve().parents[2] / "esxi_inventory.json"
BASE_TIME = datetime(2026, 8, 3, 14, 0, tzinfo=UTC)


def collector_config(
    tmp_path: Path,
    *,
    production_enabled: bool = False,
    staging_enabled: bool = False,
    include_staging: bool = True,
) -> CollectorConfig:
    production = PublishConfig(
        enabled=production_enabled,
        ssh_alias="web75-publisher",
        remote_store=PurePosixPath("/var/www/clients/client1/web75/private/modbus-dashboard-data"),
        remote_owner="dtlab-publish",
        remote_group="dtlab-dashboard",
        remote_account="dtlab-publish",
        manage_ownership=False,
    )
    staging = PublishConfig(
        enabled=staging_enabled,
        ssh_alias="web75-publisher",
        remote_store=PurePosixPath(
            "/var/www/clients/client1/web75/private/modbus-dashboard-data-staging"
        ),
        remote_owner="dtlab-publish",
        remote_group="dtlab-dashboard",
        remote_account="dtlab-publish",
        manage_ownership=False,
    )
    return CollectorConfig(
        vpn_connection_name="DTLAB CISCO",
        esxi=EsxiConfig(
            host="esxi.internal",
            port=443,
            username="read-only",
            tls_sha256="a" * 64,
        ),
        cybervision=CyberVisionConfig(
            base_url="https://cybervision.internal",
            tls_sha256="b" * 64,
        ),
        local_store=tmp_path / "store",
        raw_directory=tmp_path / "raw",
        publish=production,
        publish_staging=staging if include_staging else None,
    )


def inventory_at(timestamp: datetime) -> dict[str, Any]:
    if not CURRENT_INVENTORY_PATH.exists():
        pytest.skip("Inventario ESXi operativo non presente.")
    payload = json.loads(CURRENT_INVENTORY_PATH.read_text(encoding="utf-8"))
    payload["collected_at"] = timestamp.isoformat()
    return payload


def clock_from(start: datetime):
    current = start

    def clock() -> datetime:
        nonlocal current
        value = current
        current += timedelta(seconds=1)
        return value

    return clock


def test_local_sync_without_cisco_token_publishes_honest_partial_snapshot(
    tmp_path,
    monkeypatch,
) -> None:
    monkeypatch.setattr("dtlab.collector.sync.token_is_configured", lambda: False)
    config = collector_config(tmp_path)

    result = run_sync(
        config,
        esxi_inventory_override=inventory_at(BASE_TIME),
        require_vpn=False,
        clock=clock_from(BASE_TIME),
    )

    stored = AtomicSnapshotStore(config.local_store).load("current").snapshot
    assert result.state == "partial"
    assert result.virtual_machines == 5
    assert result.assets == 0
    assert stored["risk_scores"] == []
    assert stored["sources"][3]["status"] == "not_configured"
    assert result.remote_published is False
    assert result.publish_target is None


def test_local_sync_with_cisco_fixture_publishes_real_scores(tmp_path) -> None:
    config = collector_config(tmp_path)

    result = run_sync(
        config,
        esxi_inventory_override=inventory_at(BASE_TIME),
        cybervision_raw_override=raw_collection(),
        require_vpn=False,
        clock=clock_from(BASE_TIME),
    )

    stored = AtomicSnapshotStore(config.local_store).load("current").snapshot
    assert result.state == "fresh"
    assert result.assets == 2
    assert result.risk_scores == 2
    assert [score["score"] for score in stored["risk_scores"]] == [68, 22]


def test_snapshot_retention_defaults_to_240_cycles_and_is_configurable(
    tmp_path,
    monkeypatch,
) -> None:
    config = collector_config(tmp_path)
    observed: list[int] = []
    original_prune = AtomicSnapshotStore.prune_objects

    def recording_prune(self, *, retain=30):
        observed.append(retain)
        return original_prune(self, retain=retain)

    monkeypatch.setattr(AtomicSnapshotStore, "prune_objects", recording_prune)
    run_sync(
        config,
        esxi_inventory_override=inventory_at(BASE_TIME),
        cybervision_raw_override=raw_collection(),
        require_vpn=False,
        clock=clock_from(BASE_TIME),
    )
    run_sync(
        config,
        esxi_inventory_override=inventory_at(BASE_TIME + timedelta(minutes=1)),
        cybervision_raw_override=raw_collection(),
        require_vpn=False,
        snapshot_retention=360,
        clock=clock_from(BASE_TIME + timedelta(minutes=1)),
    )

    assert observed == [DEFAULT_SNAPSHOT_RETENTION, 360]


def test_invalid_snapshot_retention_fails_before_collection(tmp_path) -> None:
    config = collector_config(tmp_path)

    with pytest.raises(SyncError, match="retention snapshot"):
        run_sync(
            config,
            esxi_inventory_override=inventory_at(BASE_TIME),
            require_vpn=False,
            snapshot_retention=2,
        )

    assert not config.local_store.exists()
    assert not config.raw_directory.exists()


def test_invalid_esxi_inventory_does_not_replace_last_known_good(
    tmp_path,
    monkeypatch,
) -> None:
    monkeypatch.setattr("dtlab.collector.sync.token_is_configured", lambda: False)
    config = collector_config(tmp_path)
    valid = inventory_at(BASE_TIME)
    run_sync(
        config,
        esxi_inventory_override=valid,
        require_vpn=False,
        clock=clock_from(BASE_TIME),
    )
    first_id = AtomicSnapshotStore(config.local_store).load("current").snapshot["snapshot_id"]
    invalid = deepcopy(valid)
    invalid["virtual_machines"][0]["moid"] = None

    with pytest.raises(SyncError):
        run_sync(
            config,
            esxi_inventory_override=invalid,
            require_vpn=False,
            clock=clock_from(BASE_TIME + timedelta(minutes=1)),
        )

    current_id = AtomicSnapshotStore(config.local_store).load("current").snapshot["snapshot_id"]
    assert current_id == first_id


def test_vpn_failure_stops_before_any_publication(tmp_path, monkeypatch) -> None:
    config = collector_config(tmp_path)
    monkeypatch.setattr("dtlab.collector.sync.vpn_is_connected", lambda *_: False)

    with pytest.raises(SyncError, match="VPN"):
        run_sync(
            config,
            esxi_inventory_override=inventory_at(BASE_TIME),
            clock=clock_from(BASE_TIME),
        )

    assert not config.local_store.exists()


class FakeRemotePublisher:
    initialized_with: list[PublishConfig] = []
    publish_calls: list[tuple[AtomicSnapshotStore, dict[str, Any]]] = []

    def __init__(self, config: PublishConfig) -> None:
        self.initialized_with.append(config)

    def publish(
        self,
        store: AtomicSnapshotStore,
        manifest: dict[str, Any],
    ) -> None:
        self.publish_calls.append((store, manifest))


def _install_fake_remote_publisher(monkeypatch) -> type[FakeRemotePublisher]:
    class IsolatedFakeRemotePublisher(FakeRemotePublisher):
        initialized_with = []
        publish_calls = []

    monkeypatch.setattr(
        "dtlab.collector.sync.RemoteSnapshotPublisher",
        IsolatedFakeRemotePublisher,
    )
    return IsolatedFakeRemotePublisher


def test_remote_publish_is_never_implicit_even_when_targets_are_enabled(
    tmp_path,
    monkeypatch,
) -> None:
    fake_remote = _install_fake_remote_publisher(monkeypatch)
    config = collector_config(
        tmp_path,
        production_enabled=True,
        staging_enabled=True,
    )

    result = run_sync(
        config,
        esxi_inventory_override=inventory_at(BASE_TIME),
        cybervision_raw_override=raw_collection(),
        require_vpn=False,
        clock=clock_from(BASE_TIME),
    )

    assert result.remote_published is False
    assert result.publish_target is None
    assert fake_remote.initialized_with == []
    assert fake_remote.publish_calls == []


@pytest.mark.parametrize("publish_target", ["staging", "production"])
def test_explicit_publish_target_selects_only_requested_configuration(
    tmp_path,
    monkeypatch,
    publish_target,
) -> None:
    fake_remote = _install_fake_remote_publisher(monkeypatch)
    config = collector_config(
        tmp_path,
        production_enabled=True,
        staging_enabled=True,
    )

    result = run_sync(
        config,
        esxi_inventory_override=inventory_at(BASE_TIME),
        cybervision_raw_override=raw_collection(),
        publish_target=publish_target,
        require_vpn=False,
        clock=clock_from(BASE_TIME),
    )

    expected = config.publish_staging if publish_target == "staging" else config.publish
    assert fake_remote.initialized_with == [expected]
    assert len(fake_remote.publish_calls) == 1
    assert result.remote_published is True
    assert result.publish_target == publish_target


@pytest.mark.parametrize(
    ("publish_target", "config_kwargs", "message"),
    [
        ("production", {}, "production disabilitata"),
        ("staging", {}, "staging disabilitata"),
        (
            "staging",
            {"include_staging": False},
            "staging assente",
        ),
    ],
)
def test_unavailable_requested_target_fails_before_any_local_or_remote_publication(
    tmp_path,
    monkeypatch,
    publish_target,
    config_kwargs,
    message,
) -> None:
    fake_remote = _install_fake_remote_publisher(monkeypatch)
    config = collector_config(tmp_path, **config_kwargs)

    with pytest.raises(SyncError, match=message):
        run_sync(
            config,
            esxi_inventory_override=inventory_at(BASE_TIME),
            publish_target=publish_target,
            require_vpn=False,
            clock=clock_from(BASE_TIME),
        )

    assert not config.local_store.exists()
    assert not config.raw_directory.exists()
    assert fake_remote.initialized_with == []


def test_local_only_conflicts_with_explicit_publish_target_before_collection(
    tmp_path,
) -> None:
    config = collector_config(tmp_path, staging_enabled=True)

    with pytest.raises(SyncError, match="non è compatibile"):
        run_sync(
            config,
            esxi_inventory_override=inventory_at(BASE_TIME),
            local_only=True,
            publish_target="staging",
            require_vpn=False,
        )

    assert not config.local_store.exists()
    assert not config.raw_directory.exists()


def test_invalid_programmatic_publish_target_fails_closed(tmp_path) -> None:
    config = collector_config(tmp_path, staging_enabled=True)

    with pytest.raises(SyncError, match="non valido"):
        run_sync(
            config,
            esxi_inventory_override=inventory_at(BASE_TIME),
            publish_target="preview",
            require_vpn=False,
        )

    assert not config.local_store.exists()
    assert not config.raw_directory.exists()


def test_cli_rejects_local_only_with_publish_target(capsys) -> None:
    with pytest.raises(SystemExit):
        _parser().parse_args(["--local-only", "--publish-target", "staging"])

    assert "not allowed with argument" in capsys.readouterr().err


def test_cli_json_reports_requested_target_without_publish_configuration(
    tmp_path,
    monkeypatch,
    capsys,
) -> None:
    config = collector_config(tmp_path, staging_enabled=True)
    received: dict[str, Any] = {}

    def fake_run_sync(_config, **kwargs):
        received.update(kwargs)
        return SyncResult(
            snapshot_id="snapshot:test",
            state="fresh",
            manifest_sha256="f" * 64,
            virtual_machines=5,
            assets=2,
            risk_scores=2,
            remote_published=True,
            publish_target="staging",
        )

    monkeypatch.setattr("dtlab.collector.sync.load_config", lambda _: config)
    monkeypatch.setattr("dtlab.collector.sync.run_sync", fake_run_sync)

    assert main(["--config", "ignored.toml", "--publish-target", "staging"]) == 0

    output = capsys.readouterr().out
    payload = json.loads(output)
    assert received["publish_target"] == "staging"
    assert received["snapshot_retention"] == DEFAULT_SNAPSHOT_RETENTION
    assert payload["publish_target"] == "staging"
    assert payload["remote_published"] is True
    assert config.publish_staging is not None
    for sensitive in (
        config.publish_staging.ssh_alias,
        config.publish_staging.remote_account,
        str(config.publish_staging.remote_store),
    ):
        assert sensitive not in output
