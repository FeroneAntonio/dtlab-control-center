"""Typed collector configuration without credential fields."""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from dtlab.collector.cybervision_client import CyberVisionConfig

_SHA256 = re.compile(r"^[a-fA-F0-9]{64}$")
_SSH_ALIAS = re.compile(r"^[a-zA-Z0-9_.-]+$")
_SAFE_REMOTE_COMPONENT = re.compile(r"^[a-zA-Z0-9._-]+$")
_SAFE_REMOTE_PREFIX = PurePosixPath("/var/www/clients/client1/web75/private")
_PUBLISH_ACCOUNT = "dtlab-publish"
_PUBLISH_OWNER = "dtlab-publish"
_PUBLISH_GROUP = "dtlab-dashboard"
DEFAULT_REMOTE_RETENTION = 240
_PUBLISH_FIELDS = {
    "enabled",
    "ssh_alias",
    "remote_account",
    "remote_store",
    "remote_owner",
    "remote_group",
    "manage_ownership",
    "remote_retention",
}


@dataclass(frozen=True)
class EsxiConfig:
    host: str
    port: int
    username: str
    tls_sha256: str

    def __post_init__(self) -> None:
        if not self.host or any(character.isspace() for character in self.host):
            raise ValueError("Host ESXi non valido.")
        if not 1 <= self.port <= 65535:
            raise ValueError("Porta ESXi non valida.")
        if not self.username:
            raise ValueError("Username ESXi assente.")
        normalized = self.tls_sha256.replace(":", "").lower()
        if not _SHA256.fullmatch(normalized):
            raise ValueError("Fingerprint ESXi non valido.")
        object.__setattr__(self, "tls_sha256", normalized)


@dataclass(frozen=True)
class PublishConfig:
    enabled: bool
    ssh_alias: str
    remote_store: PurePosixPath
    remote_owner: str
    remote_group: str
    remote_account: str | None = None
    manage_ownership: bool = False
    remote_retention: int = DEFAULT_REMOTE_RETENTION

    def __post_init__(self) -> None:
        if not isinstance(self.enabled, bool):
            raise ValueError("publish.enabled deve essere booleano.")
        if not isinstance(self.manage_ownership, bool):
            raise ValueError("publish.manage_ownership deve essere booleano.")
        if (
            isinstance(self.remote_retention, bool)
            or not isinstance(self.remote_retention, int)
            or not 3 <= self.remote_retention <= 10_000
        ):
            raise ValueError(
                "publish.remote_retention deve essere compreso tra 3 e 10000."
            )
        if not _SSH_ALIAS.fullmatch(self.ssh_alias):
            raise ValueError("Alias SSH non valido.")
        if not self.remote_store.is_absolute():
            raise ValueError("remote_store deve essere assoluto.")
        try:
            relative = self.remote_store.relative_to(_SAFE_REMOTE_PREFIX)
        except ValueError as exc:
            raise ValueError("remote_store fuori dal perimetro web75 autorizzato.") from exc
        if not relative.parts or any(
            part in {".", ".."} or not _SAFE_REMOTE_COMPONENT.fullmatch(part)
            for part in relative.parts
        ):
            raise ValueError(
                "remote_store deve essere un percorso figlio sicuro del perimetro web75."
            )
        account = self.remote_account or self.remote_owner
        object.__setattr__(self, "remote_account", account)
        for label, value in (
            ("remote_account", account),
            ("remote_owner", self.remote_owner),
            ("remote_group", self.remote_group),
        ):
            if not isinstance(value, str) or not re.fullmatch(r"[a-zA-Z0-9_-]+", value):
                raise ValueError(f"{label} non valido.")
        if self.enabled:
            if self.ssh_alias.casefold() == "root" or account.casefold() == "root":
                raise ValueError("La pubblicazione abilitata richiede account e owner non-root.")
            if (
                account != _PUBLISH_ACCOUNT
                or self.remote_owner != _PUBLISH_OWNER
                or self.remote_group != _PUBLISH_GROUP
            ):
                raise ValueError(
                    "Account, owner e gruppo remoti non sono coerenti con il publisher DTLab."
                )
            if self.manage_ownership:
                raise ValueError("Il publisher non-root deve usare manage_ownership = false.")


@dataclass(frozen=True)
class CollectorConfig:
    vpn_connection_name: str
    esxi: EsxiConfig
    cybervision: CyberVisionConfig
    local_store: Path
    raw_directory: Path
    publish: PublishConfig
    publish_staging: PublishConfig | None = None

    def __post_init__(self) -> None:
        if self.publish_staging is None:
            return
        production_store = self.publish.remote_store
        staging_store = self.publish_staging.remote_store
        if _paths_overlap(production_store, staging_store):
            raise ValueError(
                "Production e staging devono usare remote_store separati e non sovrapposti."
            )

    @property
    def publish_production(self) -> PublishConfig:
        """Explicit production alias while keeping config.publish backward compatible."""

        return self.publish


def _mapping(payload: dict[str, Any], key: str) -> dict[str, Any]:
    value = payload.get(key)
    if not isinstance(value, dict):
        raise ValueError(f"Sezione [{key}] assente o non valida.")
    return value


def _resolve(base: Path, value: Any) -> Path:
    path = Path(str(value)).expanduser()
    return path if path.is_absolute() else (base / path).resolve()


def _paths_overlap(first: PurePosixPath, second: PurePosixPath) -> bool:
    for child, parent in ((first, second), (second, first)):
        try:
            child.relative_to(parent)
        except ValueError:
            continue
        return True
    return False


def _publish_config(payload: dict[str, Any], *, section: str) -> PublishConfig:
    enabled = payload.get("enabled", False)
    if not isinstance(enabled, bool):
        raise ValueError(f"{section}.enabled deve essere booleano.")
    manage_ownership = payload.get("manage_ownership", False)
    if not isinstance(manage_ownership, bool):
        raise ValueError(f"{section}.manage_ownership deve essere booleano.")
    try:
        ssh_alias = payload["ssh_alias"]
        remote_store = payload["remote_store"]
        remote_owner = payload["remote_owner"]
        remote_group = payload["remote_group"]
    except KeyError as exc:
        raise ValueError(f"Campo {section}.{exc.args[0]} assente.") from exc
    return PublishConfig(
        enabled=enabled,
        ssh_alias=str(ssh_alias),
        remote_store=PurePosixPath(str(remote_store)),
        remote_owner=str(remote_owner),
        remote_group=str(remote_group),
        remote_account=(
            str(payload["remote_account"]) if payload.get("remote_account") is not None else None
        ),
        manage_ownership=manage_ownership,
        remote_retention=payload.get(
            "remote_retention",
            DEFAULT_REMOTE_RETENTION,
        ),
    )


def _publish_sections(
    payload: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    publish = _mapping(payload, "publish")
    nested = "production" in publish or "staging" in publish
    if nested:
        if _PUBLISH_FIELDS.intersection(publish):
            raise ValueError("La sezione [publish] non può mescolare campi legacy e ambienti.")
        if "publish_staging" in payload:
            raise ValueError("Configurazione staging ambigua: usare solo [publish.staging].")
        production = publish.get("production")
        staging = publish.get("staging")
        if not isinstance(production, dict):
            raise ValueError("Sezione [publish.production] assente o non valida.")
        if not isinstance(staging, dict):
            raise ValueError("Sezione [publish.staging] assente o non valida.")
        return production, staging

    staging = payload.get("publish_staging")
    if staging is not None and not isinstance(staging, dict):
        raise ValueError("Sezione [publish_staging] non valida.")
    return publish, staging


def load_config(path: str | Path) -> CollectorConfig:
    config_path = Path(path).resolve()
    payload = tomllib.loads(config_path.read_text(encoding="utf-8"))
    vpn = _mapping(payload, "vpn")
    esxi = _mapping(payload, "esxi")
    cybervision = _mapping(payload, "cybervision")
    storage = _mapping(payload, "storage")
    publish, publish_staging = _publish_sections(payload)
    connection_name = str(vpn.get("connection_name") or "").strip()
    if not connection_name:
        raise ValueError("vpn.connection_name assente.")
    return CollectorConfig(
        vpn_connection_name=connection_name,
        esxi=EsxiConfig(
            host=str(esxi["host"]),
            port=int(esxi.get("port", 443)),
            username=str(esxi["username"]),
            tls_sha256=str(esxi["tls_sha256"]),
        ),
        cybervision=CyberVisionConfig(
            base_url=str(cybervision["base_url"]),
            tls_sha256=str(cybervision["tls_sha256"]),
            page_size=int(cybervision.get("page_size", 200)),
            max_pages=int(cybervision.get("max_pages", 500)),
        ),
        local_store=_resolve(config_path.parent, storage["local_store"]),
        raw_directory=_resolve(config_path.parent, storage["raw_directory"]),
        publish=_publish_config(publish, section="publish.production"),
        publish_staging=(
            _publish_config(publish_staging, section="publish.staging")
            if publish_staging is not None
            else None
        ),
    )
