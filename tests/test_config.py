from __future__ import annotations

import tomllib
from pathlib import Path, PurePosixPath

import pytest

from dtlab.collector.config import PublishConfig, load_config


def _config_text(publish_sections: str) -> str:
    return f"""
[vpn]
connection_name = "DTLAB CISCO"

[esxi]
host = "esxi.internal"
port = 443
username = "read-only"
tls_sha256 = "{"a" * 64}"

[cybervision]
base_url = "https://cybervision.internal"
tls_sha256 = "{"b" * 64}"

[storage]
local_store = "store"
raw_directory = "raw"

{publish_sections}
"""


def _load_text(tmp_path: Path, publish_sections: str):
    path = tmp_path / "dtlab.toml"
    path.write_text(_config_text(publish_sections), encoding="utf-8")
    return load_config(path)


def test_local_config_contains_no_credentials_and_resolves_private_paths() -> None:
    local_config = Path("config/dtlab.local.toml")
    if not local_config.exists():
        pytest.skip("private local deployment config is intentionally not versioned")
    config = load_config(local_config)
    text = local_config.read_text(encoding="utf-8").lower()

    assert "password" not in text
    assert "api_token" not in text
    assert config.local_store.is_absolute()
    assert config.raw_directory.is_absolute()
    assert config.publish.remote_store == PurePosixPath(
        "/var/www/clients/client1/web75/private/modbus-dashboard-data"
    )
    assert config.publish.enabled is True
    assert config.publish_staging is not None
    assert config.publish_staging.enabled is True
    assert config.publish_staging.remote_store == PurePosixPath(
        "/var/www/clients/client1/web75/private/modbus-dashboard-data-staging"
    )
    assert config.publish_staging.remote_account == "dtlab-publish"
    assert config.publish_staging.remote_group == "dtlab-dashboard"
    assert config.publish.remote_retention == 240
    assert config.publish_staging.remote_retention == 240
    assert config.publish_production is config.publish


def test_example_has_disabled_separate_non_root_publish_targets() -> None:
    payload = tomllib.loads(Path("config/dtlab.example.toml").read_text(encoding="utf-8"))
    production = payload["publish"]["production"]
    staging = payload["publish"]["staging"]

    assert production["enabled"] is False
    assert staging["enabled"] is False
    assert production["remote_store"] != staging["remote_store"]
    assert not staging["remote_store"].startswith(production["remote_store"] + "/")
    for target in (production, staging):
        assert target["ssh_alias"].casefold() != "root"
        assert target["remote_account"] == "dtlab-publish"
        assert target["remote_owner"] == "dtlab-publish"
        assert target["remote_group"] == "dtlab-dashboard"
        assert target["manage_ownership"] is False
        assert target["remote_retention"] == 240


def test_nested_publish_targets_default_to_disabled(tmp_path: Path) -> None:
    config = _load_text(
        tmp_path,
        """
[publish.production]
ssh_alias = "web75-publisher"
remote_store = "/var/www/clients/client1/web75/private/modbus-dashboard-data"
remote_owner = "dtlab-publish"
remote_group = "dtlab-dashboard"

[publish.staging]
ssh_alias = "web75-publisher"
remote_store = "/var/www/clients/client1/web75/private/modbus-dashboard-data-staging"
remote_owner = "dtlab-publish"
remote_group = "dtlab-dashboard"
""",
    )

    assert config.publish.enabled is False
    assert config.publish_staging is not None
    assert config.publish_staging.enabled is False
    assert config.publish.remote_store != config.publish_staging.remote_store
    assert config.publish.remote_account == "dtlab-publish"
    assert config.publish_staging.remote_account == "dtlab-publish"
    assert config.publish.remote_retention == 240
    assert config.publish_staging.remote_retention == 240


@pytest.mark.parametrize("retention", [True, 2, 10_001, "240"])
def test_remote_retention_rejects_invalid_values(retention) -> None:
    with pytest.raises(ValueError, match="remote_retention"):
        PublishConfig(
            enabled=False,
            ssh_alias="web75-publisher",
            remote_account="dtlab-publish",
            remote_store=PurePosixPath(
                "/var/www/clients/client1/web75/private/modbus-dashboard-data"
            ),
            remote_owner="dtlab-publish",
            remote_group="dtlab-dashboard",
            remote_retention=retention,
        )


@pytest.mark.parametrize(
    "staging_store",
    [
        "/var/www/clients/client1/web75/private/modbus-dashboard-data",
        "/var/www/clients/client1/web75/private/modbus-dashboard-data/staging",
    ],
)
def test_staging_and_production_remote_stores_cannot_overlap(
    tmp_path: Path,
    staging_store: str,
) -> None:
    with pytest.raises(ValueError, match="separati e non sovrapposti"):
        _load_text(
            tmp_path,
            f"""
[publish.production]
ssh_alias = "web75-publisher"
remote_store = "/var/www/clients/client1/web75/private/modbus-dashboard-data"
remote_owner = "dtlab-publish"
remote_group = "dtlab-dashboard"

[publish.staging]
ssh_alias = "web75-publisher"
remote_store = "{staging_store}"
remote_owner = "dtlab-publish"
remote_group = "dtlab-dashboard"
""",
        )


@pytest.mark.parametrize(
    ("ssh_alias", "remote_owner"),
    [
        ("root", "web75"),
        ("web75-publisher", "root"),
    ],
)
def test_enabled_publish_rejects_root_account_or_owner(
    ssh_alias: str,
    remote_owner: str,
) -> None:
    with pytest.raises(ValueError, match="non-root"):
        PublishConfig(
            enabled=True,
            ssh_alias=ssh_alias,
            remote_store=PurePosixPath(
                "/var/www/clients/client1/web75/private/modbus-dashboard-data"
            ),
            remote_owner=remote_owner,
            remote_group="client1",
        )


def test_enabled_publish_requires_dedicated_account_owner_and_group() -> None:
    with pytest.raises(ValueError, match="coerenti"):
        PublishConfig(
            enabled=True,
            ssh_alias="publisher",
            remote_store=PurePosixPath(
                "/var/www/clients/client1/web75/private/modbus-dashboard-data"
            ),
            remote_owner="another-owner",
            remote_group="another-group",
        )


def test_enabled_non_root_publish_disables_ownership_management() -> None:
    with pytest.raises(ValueError, match="manage_ownership = false"):
        PublishConfig(
            enabled=True,
            ssh_alias="web75-publisher",
            remote_account="dtlab-publish",
            remote_store=PurePosixPath(
                "/var/www/clients/client1/web75/private/modbus-dashboard-data"
            ),
            remote_owner="dtlab-publish",
            remote_group="dtlab-dashboard",
            manage_ownership=True,
        )


def test_disabled_legacy_root_publish_remains_loadable() -> None:
    config = PublishConfig(
        enabled=False,
        ssh_alias="root",
        remote_store=PurePosixPath("/var/www/clients/client1/web75/private/modbus-dashboard-data"),
        remote_owner="root",
        remote_group="client1",
    )

    assert config.enabled is False


@pytest.mark.parametrize(
    "remote_store",
    [
        "/",
        "/var/lib/dtlab",
        "/var/www/clients/client2/private/data",
        "/var/www/clients/client1/web75/private",
        "/var/www/clients/client1/web75/private/../escape",
        "/var/www/clients/client1/web75/private/data;touch-owned",
        "/var/www/clients/client1/web75/private/data with spaces",
    ],
)
def test_publish_scope_rejects_broad_or_unrelated_remote_paths(
    remote_store: str,
) -> None:
    with pytest.raises(ValueError, match="perimetro|percorso figlio sicuro"):
        PublishConfig(
            enabled=True,
            ssh_alias="root",
            remote_store=PurePosixPath(remote_store),
            remote_owner="web75",
            remote_group="client1",
        )
