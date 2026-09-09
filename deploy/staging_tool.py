"""Root-side, fail-closed lifecycle helper for the isolated v2 staging service.

The public entry points are ``bootstrap_staging.sh`` and ``deploy_staging.sh``.
Every action is a dry run unless both ``--apply`` and the exact plan token printed by
the dry run are supplied.  This module never connects to another host and never
addresses the legacy or production services.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sqlite3
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

PRIVATE_ROOT = Path("/var/www/clients/client1/web75/private")
LEGACY_ROOT = PRIVATE_ROOT / "modbus-dashboard"
RELEASES_ROOT = PRIVATE_ROOT / "modbus-dashboard-releases"
VENVS_ROOT = PRIVATE_ROOT / "modbus-dashboard-venvs"
STAGING_RELEASE_LINK = PRIVATE_ROOT / "modbus-dashboard-staging-current"
STAGING_VENV_LINK = PRIVATE_ROOT / "modbus-dashboard-staging-venv-current"
STAGING_STORE = PRIVATE_ROOT / "modbus-dashboard-data-staging"
STAGING_TICKET_STORE = PRIVATE_ROOT / "modbus-dashboard-ticket-data-staging"

SERVICE_NAME = "modbus-dashboard-v2-staging.service"
UNIT_DESTINATION = Path("/etc/systemd/system") / SERVICE_NAME
UNIT_ARCHIVE_PATH = PurePosixPath("deploy") / SERVICE_NAME
INGEST_SERVICE_NAME = "modbus-dashboard-ticket-ingest-staging.service"
INGEST_PATH_NAME = "modbus-dashboard-ticket-ingest-staging.path"
INGEST_SERVICE_DESTINATION = Path("/etc/systemd/system") / INGEST_SERVICE_NAME
INGEST_PATH_DESTINATION = Path("/etc/systemd/system") / INGEST_PATH_NAME
INGEST_SERVICE_ARCHIVE_PATH = PurePosixPath("deploy") / INGEST_SERVICE_NAME
INGEST_PATH_ARCHIVE_PATH = PurePosixPath("deploy") / INGEST_PATH_NAME
HEALTH_URL = "http://127.0.0.1:8518/_stcore/health"

DASHBOARD_USER = "web75"
PUBLISH_USER = "dtlab-publish"
DASHBOARD_GROUP = "dtlab-dashboard"
PRIVATE_GROUP = "client1"
PUBLISH_SHELL = "/bin/bash"
PUBLISH_HOME = Path("/var/lib/dtlab-publish")

_RELEASE_ID = re.compile(r"^[a-f0-9]{16}$")
_SHA256 = re.compile(r"^[a-f0-9]{64}$")
_OBJECT_NAME = re.compile(r"^[a-f0-9]{64}\.json$")
_RELEASE_PREFIX = "dtlab-control-center-"
_VENV_MARKER = ".dtlab-venv.json"
_SNAPSHOT_POINTERS = ("current", "previous", "last_known_good")


class StagingToolError(RuntimeError):
    """A preflight, safety, or staging operation failed."""


@dataclass(frozen=True)
class BundleInfo:
    archive: Path
    archive_sha256: str
    prefix: str
    release_id: str
    manifest: dict[str, Any]
    unit_bytes: bytes
    requirements_path: PurePosixPath
    requirements_sha256: str
    ingest_service_bytes: bytes
    ingest_service_sha256: str
    ingest_path_bytes: bytes
    ingest_path_sha256: str

    @property
    def release_directory(self) -> Path:
        return RELEASES_ROOT / self.prefix

    @property
    def venv_directory(self) -> Path:
        return VENVS_ROOT / self.release_id


@dataclass(frozen=True)
class Identities:
    root_uid: int
    dashboard_uid: int
    publisher_uid: int
    dashboard_gid: int
    private_gid: int


@dataclass(frozen=True)
class LinkState:
    exists: bool
    target: str | None


@dataclass(frozen=True)
class UnitState:
    exists: bool
    content: bytes | None

    @property
    def sha256(self) -> str | None:
        return _sha256_bytes(self.content) if self.content is not None else None


@dataclass(frozen=True)
class ServiceState:
    active: bool
    enabled: bool
    main_pid: int = 0
    exec_main_status: int = 0
    result: str = "success"


def _sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _path_text(path: Path) -> str:
    """Render target paths consistently while static tests run on Windows."""

    return path.as_posix()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _json_object(content: bytes, *, label: str) -> dict[str, Any]:
    try:
        value = json.loads(content.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise StagingToolError(f"{label}: JSON non valido.") from exc
    if not isinstance(value, dict):
        raise StagingToolError(f"{label}: è richiesto un oggetto JSON.")
    return value


def _manifest_records(manifest: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    if manifest.get("manifest_version") != "1.0":
        raise StagingToolError("release-manifest.json: versione non supportata.")
    content_sha256 = manifest.get("content_sha256")
    if not isinstance(content_sha256, str) or not _SHA256.fullmatch(content_sha256):
        raise StagingToolError("release-manifest.json: content_sha256 non valido.")
    raw_files = manifest.get("files")
    if not isinstance(raw_files, dict) or not raw_files:
        raise StagingToolError("release-manifest.json: elenco file assente.")

    records: dict[str, dict[str, Any]] = {}
    for raw_name, raw_record in raw_files.items():
        if not isinstance(raw_name, str):
            raise StagingToolError("release-manifest.json: nome file non valido.")
        name = PurePosixPath(raw_name)
        if name.is_absolute() or ".." in name.parts or not name.parts:
            raise StagingToolError("release-manifest.json: percorso file non sicuro.")
        if str(name) != raw_name or raw_name == "release-manifest.json":
            raise StagingToolError("release-manifest.json: percorso file non canonico.")
        if not isinstance(raw_record, dict):
            raise StagingToolError(f"Manifest non valido per {raw_name}.")
        digest = raw_record.get("sha256")
        byte_length = raw_record.get("bytes")
        if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
            raise StagingToolError(f"SHA-256 non valido per {raw_name}.")
        if type(byte_length) is not int or byte_length < 0:
            raise StagingToolError(f"Dimensione non valida per {raw_name}.")
        records[raw_name] = {"sha256": digest, "bytes": byte_length}

    canonical = json.dumps(records, sort_keys=True, separators=(",", ":")).encode()
    if _sha256_bytes(canonical) != content_sha256:
        raise StagingToolError("release-manifest.json: content hash incoerente.")
    return records


def _verify_checksum_file(archive: Path, checksum: Path) -> str:
    if not archive.is_file() or archive.is_symlink():
        raise StagingToolError("Archivio release assente o non regolare.")
    if not checksum.is_file() or checksum.is_symlink():
        raise StagingToolError("File checksum assente o non regolare.")
    try:
        lines = [line.strip() for line in checksum.read_text(encoding="ascii").splitlines()]
    except UnicodeDecodeError as exc:
        raise StagingToolError("File checksum non ASCII.") from exc
    lines = [line for line in lines if line]
    if len(lines) != 1:
        raise StagingToolError("File checksum: è richiesta una sola riga.")
    match = re.fullmatch(r"([0-9a-fA-F]{64})(?:\s+\*?([^\s]+))?", lines[0])
    if not match:
        raise StagingToolError("Formato checksum SHA-256 non valido.")
    expected = match.group(1).lower()
    named_file = match.group(2)
    if named_file is not None and Path(named_file).name != archive.name:
        raise StagingToolError("Il checksum appartiene a un archivio diverso.")
    actual = _sha256_file(archive)
    if actual != expected:
        raise StagingToolError("Checksum archivio non valido.")
    return actual


def _safe_tar_name(raw_name: str) -> PurePosixPath:
    name = PurePosixPath(raw_name)
    if name.is_absolute() or ".." in name.parts or not name.parts:
        raise StagingToolError("Archivio con percorso non sicuro.")
    if str(name) != raw_name.rstrip("/"):
        raise StagingToolError("Archivio con percorso non canonico.")
    return name


def _member_bytes(archive: tarfile.TarFile, member: tarfile.TarInfo) -> bytes:
    extracted = archive.extractfile(member)
    if extracted is None:
        raise StagingToolError(f"Impossibile leggere {member.name}.")
    content = extracted.read()
    if len(content) != member.size:
        raise StagingToolError(f"Dimensione TAR incoerente per {member.name}.")
    return content


def _validate_staging_unit(content: bytes, *, require_ticket_store: bool = True) -> None:
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise StagingToolError("Unità staging non UTF-8.") from exc
    required = [
        f"User={DASHBOARD_USER}",
        f"Group={DASHBOARD_GROUP}",
        f"WorkingDirectory={_path_text(STAGING_RELEASE_LINK)}",
        f"Environment=PYTHONPATH={_path_text(STAGING_RELEASE_LINK)}/src",
        f"Environment=DTLAB_SNAPSHOT_STORE={_path_text(STAGING_STORE)}",
        f"ExecStart={_path_text(STAGING_VENV_LINK)}/bin/python -m streamlit run app.py",
        "--server.address=127.0.0.1",
        "--server.port=8518",
        "ProtectSystem=strict",
        f"ReadOnlyPaths={_path_text(RELEASES_ROOT)}",
        f"ReadOnlyPaths={_path_text(VENVS_ROOT)}",
        f"ReadOnlyPaths={_path_text(STAGING_STORE)}",
        f"InaccessiblePaths={_path_text(LEGACY_ROOT)}",
    ]
    if require_ticket_store:
        host_ot_store = PRIVATE_ROOT / "modbus-dashboard-host-ot-data-staging"
        required.extend(
            (
                f"Environment=DTLAB_TICKET_STORE={_path_text(STAGING_TICKET_STORE)}"
                "/tickets.sqlite3",
                f"Environment=DTLAB_HOST_OT_EVENT_STORE={_path_text(host_ot_store)}",
                f"ReadWritePaths={_path_text(STAGING_TICKET_STORE)}",
                f"ReadOnlyPaths=-{_path_text(host_ot_store)}",
                "UMask=0077",
            )
        )
    elif "UMask=0027" not in text and "UMask=0077" not in text:
        required.append("UMask=0027|0077")
    missing = [item for item in required if item not in text]
    if missing:
        raise StagingToolError("Unità staging incompleta: " + ", ".join(missing))
    forbidden = (
        "--server.address=0.0.0.0",
        "--server.port=8517",
        "modbus-dashboard-current",
        "modbus-dashboard-data\n",
        "modbus-dashboard-venv-v2",
    )
    if any(item in text for item in forbidden):
        raise StagingToolError("Unità staging riferita a endpoint o percorsi non isolati.")


def _unit_directives(content: bytes, *, label: str) -> set[tuple[str, str, str]]:
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise StagingToolError(f"{label}: unità non UTF-8.") from exc
    section: str | None = None
    directives: list[tuple[str, str, str]] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1]
            if section not in {"Unit", "Service", "Path", "Install"}:
                raise StagingToolError(f"{label}: sezione non ammessa: {section}")
            continue
        if section is None or "=" not in line or raw_line.rstrip().endswith("\\"):
            raise StagingToolError(f"{label}: sintassi unità non ammessa.")
        key, value = line.split("=", 1)
        if not key or not value:
            raise StagingToolError(f"{label}: direttiva vuota non ammessa.")
        directives.append((section, key, value))
    if len(directives) != len(set(directives)):
        raise StagingToolError(f"{label}: direttiva duplicata non ammessa.")
    return set(directives)


def _validate_staging_ingest_units(service: bytes, path: bytes) -> None:
    expected_service = {
        ("Unit", "Description", "DTLab staging snapshot ticket ingest"),
        ("Unit", "After", "network-online.target"),
        (
            "Unit",
            "ConditionPathIsDirectory",
            f"{_path_text(STAGING_STORE)}/manifests",
        ),
        ("Service", "Type", "oneshot"),
        ("Service", "User", DASHBOARD_USER),
        ("Service", "Group", DASHBOARD_GROUP),
        ("Service", "WorkingDirectory", _path_text(STAGING_RELEASE_LINK)),
        (
            "Service",
            "Environment",
            f"PYTHONPATH={_path_text(STAGING_RELEASE_LINK)}/src",
        ),
        (
            "Service",
            "Environment",
            f"DTLAB_SNAPSHOT_STORE={_path_text(STAGING_STORE)}",
        ),
        (
            "Service",
            "Environment",
            f"DTLAB_TICKET_STORE={_path_text(STAGING_TICKET_STORE)}/tickets.sqlite3",
        ),
        (
            "Service",
            "ExecStart",
            f"{_path_text(STAGING_VENV_LINK)}/bin/python "
            "-m dtlab.services.ticket_ingest_worker",
        ),
        ("Service", "UMask", "0077"),
        ("Service", "NoNewPrivileges", "true"),
        ("Service", "PrivateTmp", "true"),
        ("Service", "PrivateDevices", "true"),
        ("Service", "ProtectHome", "true"),
        ("Service", "ProtectSystem", "strict"),
        ("Service", "ProtectKernelTunables", "true"),
        ("Service", "ProtectKernelModules", "true"),
        ("Service", "ProtectControlGroups", "true"),
        ("Service", "RestrictSUIDSGID", "true"),
        ("Service", "LockPersonality", "true"),
        ("Service", "RestrictAddressFamilies", "AF_UNIX"),
        ("Service", "ReadOnlyPaths", _path_text(RELEASES_ROOT)),
        ("Service", "ReadOnlyPaths", _path_text(VENVS_ROOT)),
        ("Service", "ReadOnlyPaths", _path_text(STAGING_STORE)),
        ("Service", "ReadWritePaths", _path_text(STAGING_TICKET_STORE)),
        ("Service", "InaccessiblePaths", _path_text(LEGACY_ROOT)),
    }
    expected_path = {
        ("Unit", "Description", "Watch DTLab staging immutable snapshot manifests"),
        ("Path", "PathChanged", f"{_path_text(STAGING_STORE)}/manifests"),
        ("Path", "Unit", INGEST_SERVICE_NAME),
        ("Install", "WantedBy", "multi-user.target"),
    }
    if _unit_directives(service, label="ticket ingest staging service") != expected_service:
        raise StagingToolError("Unità service ticket ingest staging non canonica.")
    if _unit_directives(path, label="ticket ingest staging path") != expected_path:
        raise StagingToolError("Unità path ticket ingest staging non canonica.")


def inspect_bundle(archive_path: Path, checksum_path: Path) -> BundleInfo:
    archive_path = archive_path.resolve()
    checksum_path = checksum_path.resolve()
    archive_digest = _verify_checksum_file(archive_path, checksum_path)
    try:
        archive = tarfile.open(archive_path, mode="r:gz")  # noqa: SIM115
    except (OSError, tarfile.TarError) as exc:
        raise StagingToolError("Archivio release non leggibile.") from exc

    with archive:
        members: dict[str, tarfile.TarInfo] = {}
        prefixes: set[str] = set()
        for member in archive.getmembers():
            name = _safe_tar_name(member.name)
            prefixes.add(name.parts[0])
            if member.isdir():
                continue
            if not member.isfile():
                raise StagingToolError("Archivio con link o file speciale non ammesso.")
            canonical = str(name)
            if canonical in members:
                raise StagingToolError("Archivio con nomi duplicati.")
            members[canonical] = member
        if len(prefixes) != 1:
            raise StagingToolError("Archivio: è richiesta una singola directory release.")
        prefix = prefixes.pop()
        manifest_name = f"{prefix}/release-manifest.json"
        manifest_member = members.get(manifest_name)
        if manifest_member is None:
            raise StagingToolError("release-manifest.json assente dall'archivio.")
        manifest = _json_object(
            _member_bytes(archive, manifest_member), label="release-manifest.json"
        )
        records = _manifest_records(manifest)
        content_digest = str(manifest["content_sha256"])
        release_id = content_digest[:16]
        expected_prefix = f"{_RELEASE_PREFIX}{release_id}"
        if prefix != expected_prefix:
            raise StagingToolError("Nome directory release incoerente con il manifest.")

        expected_names = {f"{prefix}/{name}" for name in records}
        expected_names.add(manifest_name)
        if set(members) != expected_names:
            raise StagingToolError("Archivio e manifest non contengono lo stesso file set.")
        for relative, record in records.items():
            member = members[f"{prefix}/{relative}"]
            content = _member_bytes(archive, member)
            if len(content) != record["bytes"]:
                raise StagingToolError(f"Dimensione non valida per {relative}.")
            if _sha256_bytes(content) != record["sha256"]:
                raise StagingToolError(f"Hash non valido per {relative}.")

        unit_key = str(UNIT_ARCHIVE_PATH)
        if unit_key not in records:
            raise StagingToolError("Unità staging assente dal manifest.")
        unit_bytes = _member_bytes(archive, members[f"{prefix}/{unit_key}"])
        _validate_staging_unit(unit_bytes)

        ingest_service_key = str(INGEST_SERVICE_ARCHIVE_PATH)
        ingest_path_key = str(INGEST_PATH_ARCHIVE_PATH)
        if ingest_service_key not in records or ingest_path_key not in records:
            raise StagingToolError("Unità ticket ingest staging assenti dal manifest.")
        ingest_service_bytes = _member_bytes(
            archive,
            members[f"{prefix}/{ingest_service_key}"],
        )
        ingest_path_bytes = _member_bytes(
            archive,
            members[f"{prefix}/{ingest_path_key}"],
        )
        _validate_staging_ingest_units(ingest_service_bytes, ingest_path_bytes)

        if "requirements-server.lock" in records:
            requirements_path = PurePosixPath("requirements-server.lock")
        elif "requirements.lock" in records:
            requirements_path = PurePosixPath("requirements.lock")
        else:
            raise StagingToolError("Nessun lockfile server disponibile.")
        requirements_sha256 = records[str(requirements_path)]["sha256"]

    return BundleInfo(
        archive=archive_path,
        archive_sha256=archive_digest,
        prefix=prefix,
        release_id=release_id,
        manifest=manifest,
        unit_bytes=unit_bytes,
        requirements_path=requirements_path,
        requirements_sha256=requirements_sha256,
        ingest_service_bytes=ingest_service_bytes,
        ingest_service_sha256=_sha256_bytes(ingest_service_bytes),
        ingest_path_bytes=ingest_path_bytes,
        ingest_path_sha256=_sha256_bytes(ingest_path_bytes),
    )


def _plan(
    action: str,
    *,
    bundle: BundleInfo | None = None,
    release_id: str | None = None,
    python_executable: Path | None = None,
    health_timeout: float | None = None,
):
    if action == "bootstrap":
        operations = [
            f"create/verify group {DASHBOARD_GROUP}",
            f"create/verify password-locked key-only account {PUBLISH_USER} "
            f"with shell {PUBLISH_SHELL} (not in {PRIVATE_GROUP})",
            f"prepare {_path_text(PUBLISH_HOME)}/.ssh without installing a key",
            f"add {DASHBOARD_USER} to {DASHBOARD_GROUP}",
            f"grant only u:{PUBLISH_USER}:--x ACL on {_path_text(PRIVATE_ROOT)}",
            f"deny {PUBLISH_USER} access to legacy {_path_text(LEGACY_ROOT)}",
            f"prepare immutable roots {_path_text(RELEASES_ROOT)} and {_path_text(VENVS_ROOT)}",
            f"prepare publisher-owned staging store {_path_text(STAGING_STORE)} "
            "with objects, immutable manifests and pointer directories",
            f"prepare dashboard-owned ticket store {_path_text(STAGING_TICKET_STORE)}",
        ]
        identity = "bootstrap-v2"
    elif action == "install":
        if bundle is None:
            raise StagingToolError("Bundle richiesto dal piano install.")
        if python_executable is None:
            raise StagingToolError("Interprete Python canonico richiesto dal piano install.")
        if type(health_timeout) not in (int, float) or not 1 <= health_timeout <= 60:
            raise StagingToolError("Timeout health non valido nel piano install.")
        health_timeout = float(health_timeout)
        release_id = bundle.release_id
        operations = [
            f"verify target identities, ACL, ownership and {_path_text(STAGING_STORE)}/current",
            f"install immutable release {_path_text(bundle.release_directory)} without overwrite",
            f"build/reuse immutable venv {_path_text(bundle.venv_directory)} "
            f"with {_path_text(python_executable)}",
            f"install generic unit {_path_text(UNIT_DESTINATION)}",
            f"atomically install verified {INGEST_SERVICE_NAME} and {INGEST_PATH_NAME}",
            f"atomically switch {_path_text(STAGING_RELEASE_LINK)} and "
            f"{_path_text(STAGING_VENV_LINK)}",
            f"restart only {SERVICE_NAME} and verify {HEALTH_URL} "
            f"within {health_timeout:g} seconds",
            "run the ticket ingest oneshot for the verified current snapshot, then "
            f"enable and start {INGEST_PATH_NAME}",
        ]
        identity = bundle.archive_sha256
    elif action == "rollback":
        if release_id is None or not _RELEASE_ID.fullmatch(release_id):
            raise StagingToolError("Release ID rollback non valido.")
        operations = [
            f"verify immutable release {_path_text(_release_directory(release_id))}",
            f"verify immutable venv {_path_text(VENVS_ROOT / release_id)}",
            f"atomically switch only {_path_text(STAGING_RELEASE_LINK)} and "
            f"{_path_text(STAGING_VENV_LINK)}",
            f"restart only {SERVICE_NAME} and verify {HEALTH_URL}",
            "install or remove release-matched ticket ingest units and enable the "
            "path only after successful application and worker readiness",
        ]
        identity = release_id
    else:
        raise StagingToolError("Azione non supportata.")

    payload = {
        "action": action,
        "identity": identity,
        "operations": operations,
        "service": SERVICE_NAME if action != "bootstrap" else None,
    }
    if action == "install":
        payload["python_executable"] = _path_text(python_executable)
        payload["health_timeout_seconds"] = health_timeout
        payload["ticket_ingest_service_sha256"] = bundle.ingest_service_sha256
        payload["ticket_ingest_path_sha256"] = bundle.ingest_path_sha256
    token = _sha256_bytes(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode())
    return payload, token


def _emit_plan(payload: Mapping[str, Any], token: str) -> None:
    print(
        json.dumps(
            {
                "apply": False,
                "confirm_plan": token,
                "plan": payload,
                "status": "dry-run",
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )


def _require_confirmation(args: argparse.Namespace, expected: str) -> None:
    if not args.apply:
        return
    if args.confirm_plan != expected:
        raise StagingToolError(
            "--apply richiede --confirm-plan uguale al token del dry-run corrente."
        )


def _require_apply_host() -> None:
    if not sys.platform.startswith("linux"):
        raise StagingToolError("--apply è consentito solo sull'host Linux di staging.")
    if os.geteuid() != 0:
        raise StagingToolError("--apply richiede root.")


def _run(
    command: Sequence[str],
    *,
    check: bool = True,
    capture_output: bool = False,
) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            list(command),
            check=check,
            capture_output=capture_output,
            text=True,
            timeout=300,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise StagingToolError(f"Comando locale non riuscito: {command[0]}") from exc


def _linux_accounts():
    try:
        import grp
        import pwd
    except ImportError as exc:  # pragma: no cover - guarded by _require_apply_host
        raise StagingToolError("Database account POSIX non disponibile.") from exc
    return pwd, grp


def _password_is_locked(username: str) -> bool:
    result = _run(["passwd", "--status", username], check=False, capture_output=True)
    fields = result.stdout.split()
    return result.returncode == 0 and len(fields) >= 2 and fields[1] in {"L", "LK"}


def _lookup_identities() -> Identities:
    pwd, grp = _linux_accounts()
    try:
        root = pwd.getpwnam("root")
        dashboard = pwd.getpwnam(DASHBOARD_USER)
        publisher = pwd.getpwnam(PUBLISH_USER)
        dashboard_group = grp.getgrnam(DASHBOARD_GROUP)
        private_group = grp.getgrnam(PRIVATE_GROUP)
    except KeyError as exc:
        raise StagingToolError("Account o gruppo bootstrap mancante.") from exc
    if publisher.pw_gid != dashboard_group.gr_gid:
        raise StagingToolError(f"{PUBLISH_USER} non ha gruppo primario {DASHBOARD_GROUP}.")
    if publisher.pw_shell != PUBLISH_SHELL:
        raise StagingToolError(
            f"{PUBLISH_USER} deve usare {PUBLISH_SHELL} per il publisher SSH/SCP."
        )
    if publisher.pw_dir != _path_text(PUBLISH_HOME):
        raise StagingToolError(f"{PUBLISH_USER} deve usare la home {_path_text(PUBLISH_HOME)}.")
    if not _password_is_locked(PUBLISH_USER):
        raise StagingToolError(f"La password di {PUBLISH_USER} deve essere bloccata.")
    if publisher.pw_gid == private_group.gr_gid or PUBLISH_USER in private_group.gr_mem:
        raise StagingToolError(f"{PUBLISH_USER} non deve appartenere a {PRIVATE_GROUP}.")
    if dashboard.pw_gid != dashboard_group.gr_gid and DASHBOARD_USER not in dashboard_group.gr_mem:
        raise StagingToolError(f"{DASHBOARD_USER} non appartiene a {DASHBOARD_GROUP}.")
    return Identities(
        root_uid=root.pw_uid,
        dashboard_uid=dashboard.pw_uid,
        publisher_uid=publisher.pw_uid,
        dashboard_gid=dashboard_group.gr_gid,
        private_gid=private_group.gr_gid,
    )


def _ensure_real_directory(
    path: Path,
    *,
    uid: int,
    gid: int,
    mode: int,
    create: bool,
) -> None:
    if not path.exists():
        if not create:
            raise StagingToolError(f"Directory bootstrap mancante: {path}")
        path.mkdir(mode=mode)
        os.chown(path, uid, gid)
        path.chmod(mode)
    details = path.lstat()
    if not stat.S_ISDIR(details.st_mode) or path.is_symlink():
        raise StagingToolError(f"Percorso non-directory o symlink non ammesso: {path}")
    if details.st_uid != uid or details.st_gid != gid:
        raise StagingToolError(f"Ownership inattesa: {path}")
    if stat.S_IMODE(details.st_mode) != mode:
        raise StagingToolError(f"Permessi inattesi: {path}")


def _verify_private_root(identities: Identities) -> None:
    _ensure_real_directory(
        PRIVATE_ROOT,
        uid=identities.dashboard_uid,
        gid=identities.private_gid,
        mode=0o710,
        create=False,
    )
    if not LEGACY_ROOT.is_dir() or LEGACY_ROOT.is_symlink():
        raise StagingToolError("Directory legacy non regolare.")
    getfacl = shutil.which("getfacl")
    if getfacl is None:
        raise StagingToolError("getfacl mancante: installare il pacchetto acl.")
    for path, expected in (
        (PRIVATE_ROOT, f"user:{PUBLISH_USER}:--x"),
        (LEGACY_ROOT, f"user:{PUBLISH_USER}:---"),
    ):
        result = _run([getfacl, "-cp", str(path)], capture_output=True)
        if expected not in result.stdout.splitlines():
            raise StagingToolError(f"ACL staging mancante: {path}")


def _verify_layout(identities: Identities) -> None:
    for path in (PUBLISH_HOME, PUBLISH_HOME / ".ssh"):
        _ensure_real_directory(
            path,
            uid=identities.publisher_uid,
            gid=identities.dashboard_gid,
            mode=0o700,
            create=False,
        )
    for path in (RELEASES_ROOT, VENVS_ROOT):
        _ensure_real_directory(
            path,
            uid=identities.root_uid,
            gid=identities.dashboard_gid,
            mode=0o750,
            create=False,
        )
    for path in (
        STAGING_STORE,
        STAGING_STORE / "objects",
        STAGING_STORE / "manifests",
        *(STAGING_STORE / pointer for pointer in _SNAPSHOT_POINTERS),
    ):
        _ensure_real_directory(
            path,
            uid=identities.publisher_uid,
            gid=identities.dashboard_gid,
            mode=0o750,
            create=False,
        )
    _verify_ticket_store(identities)


def _ticket_paths() -> tuple[Path, ...]:
    database = STAGING_TICKET_STORE / "tickets.sqlite3"
    return database, Path(f"{database}-wal"), Path(f"{database}-shm")


def _verify_ticket_store(identities: Identities) -> None:
    _ensure_real_directory(
        STAGING_TICKET_STORE,
        uid=identities.dashboard_uid,
        gid=identities.dashboard_gid,
        mode=0o700,
        create=False,
    )
    for path in _ticket_paths():
        if not os.path.lexists(path):
            continue
        details = path.lstat()
        if (
            not stat.S_ISREG(details.st_mode)
            or path.is_symlink()
            or details.st_uid != identities.dashboard_uid
            or details.st_gid != identities.dashboard_gid
            or stat.S_IMODE(details.st_mode) != 0o600
            or not details.st_mode & stat.S_IWUSR
        ):
            raise StagingToolError(f"File ticket staging non sicuro: {path}")


def _narrow_ticket_path(
    path: Path,
    identities: Identities,
    *,
    directory: bool,
    allow_root_owner: bool = False,
) -> None:
    flags = os.O_RDONLY | os.O_NOFOLLOW
    if directory:
        flags |= os.O_DIRECTORY
    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags)
        before = os.fstat(descriptor)
        expected_type = stat.S_ISDIR if directory else stat.S_ISREG
        allowed_modes = {0o700, 0o750} if directory else {0o600, 0o640}
        owner_ok = before.st_uid == identities.dashboard_uid or (
            allow_root_owner and before.st_uid == identities.root_uid
        )
        group_ok = before.st_gid == identities.dashboard_gid or (
            allow_root_owner and before.st_uid == identities.root_uid
        )
        if (
            not expected_type(before.st_mode)
            or not owner_ok
            or not group_ok
            or stat.S_IMODE(before.st_mode) not in allowed_modes
        ):
            raise StagingToolError(f"Percorso ticket staging non migrabile: {path}")
        os.fchown(descriptor, identities.dashboard_uid, identities.dashboard_gid)
        target_mode = 0o700 if directory else 0o600
        os.fchmod(descriptor, target_mode)
        after = os.fstat(descriptor)
        current = path.lstat()
        if (
            (current.st_dev, current.st_ino) != (after.st_dev, after.st_ino)
            or path.is_symlink()
            or after.st_uid != identities.dashboard_uid
            or after.st_gid != identities.dashboard_gid
            or stat.S_IMODE(after.st_mode) != target_mode
        ):
            raise StagingToolError(
                f"Percorso ticket staging cambiato durante la migrazione: {path}"
            )
    except OSError as exc:
        raise StagingToolError(f"Migrazione sicura ticket staging fallita: {path}") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _bootstrap_ticket_store(identities: Identities) -> None:
    created = False
    if not os.path.lexists(STAGING_TICKET_STORE):
        try:
            STAGING_TICKET_STORE.mkdir(mode=0o700)
            created = True
        except FileExistsError:
            created = False
        except OSError as exc:
            raise StagingToolError("Creazione ticket store staging fallita.") from exc
    else:
        details = STAGING_TICKET_STORE.lstat()
        if (
            not stat.S_ISDIR(details.st_mode)
            or STAGING_TICKET_STORE.is_symlink()
            or details.st_uid != identities.dashboard_uid
            or details.st_gid != identities.dashboard_gid
            or stat.S_IMODE(details.st_mode) not in {0o700, 0o750}
        ):
            raise StagingToolError("Ticket store staging esistente non sicuro.")
    _narrow_ticket_path(
        STAGING_TICKET_STORE,
        identities,
        directory=True,
        allow_root_owner=created,
    )
    for path in _ticket_paths():
        if not os.path.lexists(path):
            continue
        details = path.lstat()
        if (
            not stat.S_ISREG(details.st_mode)
            or path.is_symlink()
            or details.st_uid != identities.dashboard_uid
            or details.st_gid != identities.dashboard_gid
            or stat.S_IMODE(details.st_mode) not in {0o600, 0o640}
        ):
            raise StagingToolError(f"File ticket staging non migrabile: {path}")
        _narrow_ticket_path(path, identities, directory=False)
    _verify_ticket_store(identities)


def _bootstrap() -> None:
    pwd, grp = _linux_accounts()
    try:
        grp.getgrnam(PRIVATE_GROUP)
        dashboard = pwd.getpwnam(DASHBOARD_USER)
    except KeyError as exc:
        raise StagingToolError("Account web75 o gruppo client1 mancante.") from exc
    private_group = grp.getgrnam(PRIVATE_GROUP)
    _ensure_real_directory(
        PRIVATE_ROOT,
        uid=dashboard.pw_uid,
        gid=private_group.gr_gid,
        mode=0o710,
        create=False,
    )

    try:
        dashboard_group = grp.getgrnam(DASHBOARD_GROUP)
    except KeyError:
        _run(["groupadd", "--system", DASHBOARD_GROUP])
        dashboard_group = grp.getgrnam(DASHBOARD_GROUP)

    try:
        publisher = pwd.getpwnam(PUBLISH_USER)
    except KeyError:
        _run(
            [
                "useradd",
                "--system",
                "--gid",
                DASHBOARD_GROUP,
                "--home-dir",
                str(PUBLISH_HOME),
                "--no-create-home",
                "--shell",
                PUBLISH_SHELL,
                "--password",
                "!",
                PUBLISH_USER,
            ]
        )
        publisher = pwd.getpwnam(PUBLISH_USER)
    if publisher.pw_gid != dashboard_group.gr_gid:
        raise StagingToolError(f"Account esistente {PUBLISH_USER} con gruppo primario errato.")
    if publisher.pw_shell != PUBLISH_SHELL:
        _run(["usermod", "--shell", PUBLISH_SHELL, PUBLISH_USER])
        publisher = pwd.getpwnam(PUBLISH_USER)
    if publisher.pw_dir != _path_text(PUBLISH_HOME):
        _run(["usermod", "--home", str(PUBLISH_HOME), PUBLISH_USER])
        publisher = pwd.getpwnam(PUBLISH_USER)
    if not _password_is_locked(PUBLISH_USER):
        _run(["passwd", "--lock", PUBLISH_USER])
    if publisher.pw_shell != PUBLISH_SHELL or not _password_is_locked(PUBLISH_USER):
        raise StagingToolError(
            f"Account {PUBLISH_USER} non configurato come key-only con shell {PUBLISH_SHELL}."
        )

    private_group = grp.getgrnam(PRIVATE_GROUP)
    if publisher.pw_gid == private_group.gr_gid or PUBLISH_USER in private_group.gr_mem:
        raise StagingToolError(f"Rimuovere {PUBLISH_USER} da {PRIVATE_GROUP} prima di continuare.")

    dashboard_group = grp.getgrnam(DASHBOARD_GROUP)
    if dashboard.pw_gid != dashboard_group.gr_gid and DASHBOARD_USER not in dashboard_group.gr_mem:
        _run(["usermod", "--append", "--groups", DASHBOARD_GROUP, DASHBOARD_USER])

    setfacl = shutil.which("setfacl")
    if setfacl is None:
        raise StagingToolError("setfacl mancante: installare il pacchetto acl.")
    _run([setfacl, "-m", f"u:{PUBLISH_USER}:--x", str(PRIVATE_ROOT)])
    if not LEGACY_ROOT.is_dir() or LEGACY_ROOT.is_symlink():
        raise StagingToolError("Directory legacy non regolare.")
    _run([setfacl, "-m", f"u:{PUBLISH_USER}:---", str(LEGACY_ROOT)])

    identities = _lookup_identities()
    for path in (PUBLISH_HOME, PUBLISH_HOME / ".ssh"):
        _ensure_real_directory(
            path,
            uid=identities.publisher_uid,
            gid=identities.dashboard_gid,
            mode=0o700,
            create=True,
        )
    for path in (RELEASES_ROOT, VENVS_ROOT):
        _ensure_real_directory(
            path,
            uid=identities.root_uid,
            gid=identities.dashboard_gid,
            mode=0o750,
            create=True,
        )
    for path in (
        STAGING_STORE,
        STAGING_STORE / "objects",
        STAGING_STORE / "manifests",
        *(STAGING_STORE / pointer for pointer in _SNAPSHOT_POINTERS),
    ):
        _ensure_real_directory(
            path,
            uid=identities.publisher_uid,
            gid=identities.dashboard_gid,
            mode=0o750,
            create=True,
        )
    _bootstrap_ticket_store(identities)
    _verify_private_root(identities)
    _verify_layout(identities)


def _validate_store(identities: Identities) -> dict[str, Any]:
    _verify_layout(identities)
    manifest_path = STAGING_STORE / "current" / "manifest.json"
    if not manifest_path.is_file() or manifest_path.is_symlink():
        raise StagingToolError("Snapshot staging current mancante.")
    details = manifest_path.stat()
    if details.st_uid != identities.publisher_uid or details.st_gid != identities.dashboard_gid:
        raise StagingToolError("Ownership manifest snapshot non valida.")
    if stat.S_IMODE(details.st_mode) & 0o022:
        raise StagingToolError("Manifest snapshot scrivibile da gruppo/altri.")
    content = manifest_path.read_bytes()
    manifest = _json_object(content, label="snapshot current manifest")
    required = {
        "manifest_version",
        "snapshot_id",
        "sha256",
        "object_name",
        "byte_length",
        "trusted_origin",
    }
    if required - set(manifest):
        raise StagingToolError("Snapshot current manifest incompleto.")
    digest = manifest.get("sha256")
    object_name = manifest.get("object_name")
    byte_length = manifest.get("byte_length")
    if manifest.get("manifest_version") != "1.0":
        raise StagingToolError("Versione manifest snapshot non supportata.")
    if manifest.get("trusted_origin") != "dtlab_collector":
        raise StagingToolError("Origine snapshot staging non attendibile.")
    if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
        raise StagingToolError("Hash snapshot staging non valido.")
    if not isinstance(object_name, str) or not _OBJECT_NAME.fullmatch(object_name):
        raise StagingToolError("Nome oggetto snapshot staging non valido.")
    if object_name != f"{digest}.json":
        raise StagingToolError("Puntatore snapshot staging incoerente.")
    if type(byte_length) is not int or byte_length < 0:
        raise StagingToolError("Dimensione snapshot staging non valida.")
    object_path = STAGING_STORE / "objects" / object_name
    if not object_path.is_file() or object_path.is_symlink():
        raise StagingToolError("Oggetto snapshot staging mancante.")
    object_details = object_path.stat()
    if (
        object_details.st_uid != identities.publisher_uid
        or object_details.st_gid != identities.dashboard_gid
    ):
        raise StagingToolError("Ownership oggetto snapshot non valida.")
    if stat.S_IMODE(object_details.st_mode) & 0o022:
        raise StagingToolError("Oggetto snapshot scrivibile da gruppo/altri.")
    object_bytes = object_path.read_bytes()
    if len(object_bytes) != byte_length or _sha256_bytes(object_bytes) != digest:
        raise StagingToolError("Integrità oggetto snapshot staging non valida.")
    snapshot = _json_object(object_bytes, label="snapshot current object")
    if snapshot.get("snapshot_id") != manifest.get("snapshot_id"):
        raise StagingToolError("Snapshot ID non coerente con il manifest.")
    sync = snapshot.get("sync")
    if not isinstance(sync, dict) or sync.get("publication_mode") != "real_only":
        raise StagingToolError("Lo staging accetta soltanto snapshot real_only.")
    return manifest


def _ownership_ok(path: Path, identities: Identities, *, executable: bool = False) -> None:
    details = path.lstat()
    if details.st_uid != identities.root_uid or details.st_gid != identities.dashboard_gid:
        raise StagingToolError(f"Ownership release/venv inattesa: {path}")
    mode = stat.S_IMODE(details.st_mode)
    if mode & 0o022:
        raise StagingToolError(f"Percorso release/venv scrivibile da gruppo/altri: {path}")
    if executable and not mode & stat.S_IXUSR:
        raise StagingToolError(f"Eseguibile venv non eseguibile: {path}")


def _release_directory(release_id: str) -> Path:
    return RELEASES_ROOT / f"{_RELEASE_PREFIX}{release_id}"


def _verify_release_directory(
    path: Path,
    manifest: Mapping[str, Any],
    identities: Identities,
) -> None:
    if not path.is_dir() or path.is_symlink():
        raise StagingToolError(f"Release assente o non regolare: {path}")
    _ownership_ok(path, identities)
    records = _manifest_records(manifest)
    expected = set(records) | {"release-manifest.json"}
    actual = {
        item.relative_to(path).as_posix()
        for item in path.rglob("*")
        if item.is_file() and not item.is_symlink()
    }
    if actual != expected:
        raise StagingToolError("Release esistente diversa dal manifest; non verrà sovrascritta.")
    for relative, record in records.items():
        candidate = path.joinpath(*PurePosixPath(relative).parts)
        if not candidate.is_file() or candidate.is_symlink():
            raise StagingToolError(f"File release non regolare: {relative}")
        _ownership_ok(candidate, identities)
        if (
            candidate.stat().st_size != record["bytes"]
            or _sha256_file(candidate) != record["sha256"]
        ):
            raise StagingToolError(f"File release esistente non valido: {relative}")
    manifest_path = path / "release-manifest.json"
    _ownership_ok(manifest_path, identities)
    deployed = _json_object(manifest_path.read_bytes(), label="manifest release installata")
    if deployed != manifest:
        raise StagingToolError("Manifest release installata non corrispondente.")


def _freeze_tree(path: Path, identities: Identities) -> None:
    for candidate in [path, *path.rglob("*")]:
        if candidate.is_symlink():
            os.chown(
                candidate,
                identities.root_uid,
                identities.dashboard_gid,
                follow_symlinks=False,
            )
            continue
        os.chown(candidate, identities.root_uid, identities.dashboard_gid)
        details = candidate.stat()
        if candidate.is_dir() or details.st_mode & 0o111:
            candidate.chmod(0o750)
        else:
            candidate.chmod(0o640)


def _extract_release(bundle: BundleInfo, identities: Identities) -> tuple[Path, bool]:
    destination = bundle.release_directory
    if destination.exists() or destination.is_symlink():
        _verify_release_directory(destination, bundle.manifest, identities)
        return destination, False

    temporary = Path(tempfile.mkdtemp(prefix=f".{bundle.release_id}.", dir=RELEASES_ROOT))
    try:
        with tarfile.open(bundle.archive, mode="r:gz") as archive:
            for member in archive.getmembers():
                name = _safe_tar_name(member.name)
                if member.isdir():
                    continue
                if not member.isfile() or name.parts[0] != bundle.prefix:
                    raise StagingToolError("Archivio mutato dopo il preflight.")
                relative = PurePosixPath(*name.parts[1:])
                target = temporary.joinpath(*relative.parts)
                target.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
                content = _member_bytes(archive, member)
                with target.open("xb") as handle:
                    handle.write(content)
        _freeze_tree(temporary, identities)
        try:
            temporary.rename(destination)
        except FileExistsError:
            _verify_release_directory(destination, bundle.manifest, identities)
        _verify_release_directory(destination, bundle.manifest, identities)
        return destination, True
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)


def _venv_marker(bundle: BundleInfo) -> dict[str, Any]:
    return {
        "marker_version": "1.0",
        "release_id": bundle.release_id,
        "requirements_path": str(bundle.requirements_path),
        "requirements_sha256": bundle.requirements_sha256,
    }


def _verify_venv(path: Path, marker: Mapping[str, Any], identities: Identities) -> None:
    if not path.is_dir() or path.is_symlink():
        raise StagingToolError(f"Venv assente o non regolare: {path}")
    _ownership_ok(path, identities)
    marker_path = path / _VENV_MARKER
    python_path = path / "bin" / "python"
    if not marker_path.is_file() or marker_path.is_symlink():
        raise StagingToolError("Marker venv mancante.")
    _ownership_ok(marker_path, identities)
    existing = _json_object(marker_path.read_bytes(), label="marker venv")
    if existing != marker:
        raise StagingToolError(
            "Venv versionato esistente non corrispondente; non verrà modificato."
        )
    if not python_path.exists() or not (python_path.is_file() or python_path.is_symlink()):
        raise StagingToolError("Python del venv mancante.")
    if python_path.is_file() and not python_path.is_symlink():
        _ownership_ok(python_path, identities, executable=True)


def _resolve_trusted_python(path: Path, *, root_uid: int = 0) -> Path:
    """Resolve a Python alias to an immutable, root-controlled executable."""

    try:
        canonical = path.resolve(strict=True)
        details = canonical.lstat()
    except (OSError, RuntimeError) as exc:
        raise StagingToolError(f"Interprete Python non risolvibile: {path}") from exc

    mode = stat.S_IMODE(details.st_mode)
    if not stat.S_ISREG(details.st_mode):
        raise StagingToolError(f"Interprete Python non regolare: {canonical}")
    if details.st_uid != root_uid:
        raise StagingToolError(f"Interprete Python non posseduto da root: {canonical}")
    if mode & 0o022:
        raise StagingToolError(
            f"Interprete Python scrivibile da gruppo/altri: {canonical}"
        )
    if not mode & stat.S_IXUSR:
        raise StagingToolError(f"Interprete Python non eseguibile: {canonical}")

    for ancestor in canonical.parents:
        try:
            ancestor_details = ancestor.lstat()
        except OSError as exc:
            raise StagingToolError(
                f"Directory interprete Python non verificabile: {ancestor}"
            ) from exc
        ancestor_mode = stat.S_IMODE(ancestor_details.st_mode)
        if (
            not stat.S_ISDIR(ancestor_details.st_mode)
            or ancestor_details.st_uid != root_uid
            or ancestor_mode & 0o022
        ):
            raise StagingToolError(
                f"Directory interprete Python non sicura: {ancestor}"
            )
    return canonical


def _build_venv(
    bundle: BundleInfo,
    release: Path,
    identities: Identities,
    python_executable: Path,
) -> tuple[Path, bool]:
    python_executable = _resolve_trusted_python(
        python_executable,
        root_uid=identities.root_uid,
    )
    destination = bundle.venv_directory
    marker = _venv_marker(bundle)
    if destination.exists() or destination.is_symlink():
        _verify_venv(destination, marker, identities)
        return destination, False

    temporary = Path(tempfile.mkdtemp(prefix=f".{bundle.release_id}.", dir=VENVS_ROOT))
    temporary.rmdir()
    try:
        _run([str(python_executable), "-m", "venv", str(temporary)])
        venv_python = temporary / "bin" / "python"
        lockfile = release.joinpath(*bundle.requirements_path.parts)
        command = [
            str(venv_python),
            "-m",
            "pip",
            "install",
            "--disable-pip-version-check",
            "--no-input",
        ]
        if bundle.requirements_path.name == "requirements-server.lock":
            command.append("--require-hashes")
        command.extend(["-r", str(lockfile)])
        _run(command)
        (temporary / _VENV_MARKER).write_text(
            json.dumps(marker, sort_keys=True) + "\n", encoding="utf-8"
        )
        _freeze_tree(temporary, identities)
        try:
            temporary.rename(destination)
        except FileExistsError:
            _verify_venv(destination, marker, identities)
        _verify_venv(destination, marker, identities)
        return destination, True
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)


def _install_unit(content: bytes, *, require_ticket_store: bool = True) -> bool:
    _validate_staging_unit(content, require_ticket_store=require_ticket_store)
    return _install_raw_unit(UNIT_DESTINATION, content)


def _install_raw_unit(destination: Path, content: bytes) -> bool:
    try:
        details = destination.lstat()
    except FileNotFoundError:
        details = None
    if details is not None:
        if (
            not stat.S_ISREG(details.st_mode)
            or destination.is_symlink()
            or details.st_uid != 0
            or details.st_gid != 0
            or stat.S_IMODE(details.st_mode) != 0o644
        ):
            raise StagingToolError(f"Destinazione unità systemd non sicura: {destination}")
        if destination.read_bytes() == content:
            return False
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=destination.parent,
            prefix=f".{destination.name}.",
            delete=False,
        ) as handle:
            temporary = Path(handle.name)
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chown(temporary, 0, 0)
        temporary.chmod(0o644)
        os.replace(temporary, destination)
        return True
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()


def _capture_unit() -> UnitState:
    state = _capture_raw_unit(UNIT_DESTINATION)
    if state.content is not None:
        _validate_staging_unit(state.content, require_ticket_store=False)
    return state


def _capture_raw_unit(destination: Path) -> UnitState:
    try:
        details = destination.lstat()
    except FileNotFoundError:
        return UnitState(False, None)
    if (
        not stat.S_ISREG(details.st_mode)
        or destination.is_symlink()
        or details.st_uid != 0
        or details.st_gid != 0
        or stat.S_IMODE(details.st_mode) != 0o644
    ):
        raise StagingToolError(f"Unità systemd installata non sicura: {destination}")
    return UnitState(True, destination.read_bytes())


def _remove_raw_unit(destination: Path) -> bool:
    try:
        details = destination.lstat()
    except FileNotFoundError:
        return False
    if (
        not stat.S_ISREG(details.st_mode)
        or destination.is_symlink()
        or details.st_uid != 0
        or details.st_gid != 0
        or stat.S_IMODE(details.st_mode) != 0o644
    ):
        raise StagingToolError(f"Unità systemd da rimuovere non regolare: {destination}")
    destination.unlink()
    return True


def _capture_ingest_units() -> tuple[UnitState, UnitState]:
    service = _capture_raw_unit(INGEST_SERVICE_DESTINATION)
    path = _capture_raw_unit(INGEST_PATH_DESTINATION)
    if service.exists != path.exists:
        raise StagingToolError("Installazione ticket ingest staging parziale.")
    if service.content is not None and path.content is not None:
        _validate_staging_ingest_units(service.content, path.content)
    return service, path


def _install_ingest_units(service: bytes, path: bytes) -> bool:
    if bool(service) != bool(path):
        raise StagingToolError("Coppia unità ticket ingest staging incompleta.")
    if not service:
        changed = _remove_raw_unit(INGEST_SERVICE_DESTINATION)
        changed |= _remove_raw_unit(INGEST_PATH_DESTINATION)
        return changed
    _validate_staging_ingest_units(service, path)
    changed = _install_raw_unit(INGEST_SERVICE_DESTINATION, service)
    changed |= _install_raw_unit(INGEST_PATH_DESTINATION, path)
    return changed


def _restore_unit(previous: UnitState) -> None:
    if not previous.exists:
        _remove_raw_unit(UNIT_DESTINATION)
        return
    if previous.content is None:
        raise StagingToolError("Stato unità staging precedente incompleto.")
    _install_unit(previous.content, require_ticket_store=False)


def _restore_ingest_units(service: UnitState, path: UnitState) -> None:
    if service.exists != path.exists:
        raise StagingToolError("Stato precedente ticket ingest staging parziale.")
    if not service.exists:
        _install_ingest_units(b"", b"")
        return
    if service.content is None or path.content is None:
        raise StagingToolError("Stato precedente ticket ingest staging incompleto.")
    _install_ingest_units(service.content, path.content)


def _capture_link(path: Path) -> LinkState:
    try:
        details = path.lstat()
    except FileNotFoundError:
        return LinkState(False, None)
    if not stat.S_ISLNK(details.st_mode):
        raise StagingToolError(f"Il puntatore staging non è un symlink: {path}")
    target = os.readlink(path)
    target_path = Path(target)
    allowed_root = RELEASES_ROOT if path == STAGING_RELEASE_LINK else VENVS_ROOT
    expected_name = (
        re.compile(rf"^{re.escape(_RELEASE_PREFIX)}[a-f0-9]{{16}}$")
        if allowed_root == RELEASES_ROOT
        else _RELEASE_ID
    )
    if (
        not target_path.is_absolute()
        or target_path.parent != allowed_root
        or not expected_name.fullmatch(target_path.name)
        or not target_path.is_dir()
        or target_path.is_symlink()
    ):
        raise StagingToolError(f"Target symlink staging non sicuro: {path}")
    return LinkState(True, target)


def _switch_link(path: Path, target: Path) -> bool:
    previous = _capture_link(path)
    expected = str(target)
    if previous.exists and previous.target == expected:
        return False
    temporary = path.parent / f".{path.name}.{uuid.uuid4().hex}.tmp"
    try:
        os.symlink(expected, temporary)
        os.replace(temporary, path)
    finally:
        if temporary.is_symlink():
            temporary.unlink()
    return True


def _restore_link(path: Path, previous: LinkState) -> None:
    if previous.exists:
        _switch_link(path, Path(str(previous.target)))
        return
    current = _capture_link(path)
    if current.exists:
        path.unlink()


def _systemctl(*arguments: str, check: bool = True):
    return _run(["systemctl", *arguments], check=check, capture_output=True)


def _service_active() -> bool:
    return _capture_service().active


def _service_enabled() -> bool:
    return _capture_service().enabled


def _capture_named_service(service_name: str) -> ServiceState:
    active_result = _systemctl("is-active", "--quiet", service_name, check=False)
    enabled_result = _systemctl("is-enabled", "--quiet", service_name, check=False)
    show = _systemctl(
        "show",
        service_name,
        "--property=LoadState",
        "--property=MainPID",
        "--property=ExecMainStatus",
        "--property=Result",
        "--no-pager",
        check=False,
    )
    if show.returncode != 0:
        raise StagingToolError("Impossibile verificare lo stato systemd staging.")
    values: dict[str, str] = {}
    for line in show.stdout.splitlines():
        key, separator, value = line.partition("=")
        if separator:
            values[key] = value
    required = {"LoadState", "Result"}
    if service_name.endswith(".service"):
        required.update({"MainPID", "ExecMainStatus"})
    if required - set(values):
        raise StagingToolError("Stato systemd staging incompleto.")
    load_state = values["LoadState"]
    if load_state == "not-found":
        if active_result.returncode == 0 or enabled_result.returncode == 0:
            raise StagingToolError("Stato systemd staging incoerente per unità assente.")
        return ServiceState(active=False, enabled=False)
    if load_state != "loaded":
        raise StagingToolError(f"Unità systemd staging non caricabile: {load_state}")
    if active_result.returncode not in {0, 3} or enabled_result.returncode not in {0, 1}:
        raise StagingToolError("Comando stato systemd staging non concluso correttamente.")
    try:
        main_pid = int(values.get("MainPID", "0"))
        exec_main_status = int(values.get("ExecMainStatus", "0"))
    except ValueError as exc:
        raise StagingToolError("Stato numerico systemd staging non valido.") from exc
    return ServiceState(
        active=active_result.returncode == 0,
        enabled=enabled_result.returncode == 0,
        main_pid=main_pid,
        exec_main_status=exec_main_status,
        result=values.get("Result", "success"),
    )


def _capture_service() -> ServiceState:
    return _capture_named_service(SERVICE_NAME)


def _service_ready(
    state: ServiceState,
    *,
    expected_active: bool,
    expected_enabled: bool,
) -> bool:
    if state.active != expected_active or state.enabled != expected_enabled:
        return False
    if state.exec_main_status != 0 or state.result not in {"success", ""}:
        return False
    return state.main_pid > 0 if expected_active else state.main_pid == 0


def _wait_for_health(timeout: float) -> None:
    deadline = time.monotonic() + timeout
    last_error = "nessuna risposta"
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(HEALTH_URL, timeout=2) as response:  # noqa: S310
                body = response.read(128).strip().lower()
                if response.status == 200 and body == b"ok":
                    return
                last_error = f"HTTP {response.status} body={body!r}"
        except (OSError, urllib.error.URLError) as exc:
            last_error = type(exc).__name__
        time.sleep(0.5)
    raise StagingToolError(f"Health staging fallita: {last_error}")


def _health_ok() -> bool:
    try:
        with urllib.request.urlopen(HEALTH_URL, timeout=2) as response:  # noqa: S310
            return response.status == 200 and response.read(128).strip().lower() == b"ok"
    except (OSError, urllib.error.URLError):
        return False


def _wait_for_app_readiness(
    release: Path,
    venv: Path,
    unit_sha256: str,
    identities: Identities,
    timeout: float,
) -> None:
    deadline = time.monotonic() + timeout
    last_error = "readiness non eseguita"
    while time.monotonic() < deadline:
        try:
            service = _capture_service()
            if not _service_ready(service, expected_active=True, expected_enabled=True):
                raise StagingToolError("MainPID/ExecMainStatus staging non pronti.")
            if _capture_link(STAGING_RELEASE_LINK).target != str(release):
                raise StagingToolError("Link release staging non coerente.")
            if _capture_link(STAGING_VENV_LINK).target != str(venv):
                raise StagingToolError("Link venv staging non coerente.")
            if _capture_unit().sha256 != unit_sha256:
                raise StagingToolError("Unità applicativa staging non coerente.")
            _verify_ticket_store(identities)
            if not _health_ok():
                raise StagingToolError("Health Streamlit staging non pronta.")
            return
        except StagingToolError as exc:
            last_error = str(exc)
        time.sleep(0.5)
    raise StagingToolError(f"Readiness staging fallita: {last_error}")


def _ticket_snapshot_ingested(snapshot_sha256: str) -> bool:
    database = STAGING_TICKET_STORE / "tickets.sqlite3"
    if not os.path.lexists(database) or database.is_symlink():
        return False
    try:
        uri = database.resolve(strict=True).as_uri() + "?mode=ro"
        with sqlite3.connect(uri, uri=True, timeout=5) as connection:
            row = connection.execute(
                "SELECT 1 FROM snapshot_ingests WHERE snapshot_sha256 = ?",
                (snapshot_sha256,),
            ).fetchone()
    except (OSError, RuntimeError, sqlite3.Error):
        return False
    return row == (1,)


def _run_initial_ingest(snapshot_sha256: str, identities: Identities) -> None:
    _systemctl("start", INGEST_SERVICE_NAME)
    state = _capture_named_service(INGEST_SERVICE_NAME)
    if state.exec_main_status != 0 or state.result not in {"success", ""}:
        raise StagingToolError("Esecuzione iniziale ticket ingest staging fallita.")
    _verify_ticket_store(identities)
    if not _ticket_snapshot_ingested(snapshot_sha256):
        raise StagingToolError("Snapshot staging corrente non registrato dal ticket ingest.")


def _set_ingest_path_state(*, enabled: bool, active: bool) -> None:
    if enabled:
        _systemctl("enable", INGEST_PATH_NAME)
    else:
        _systemctl("disable", INGEST_PATH_NAME, check=False)
    if active:
        _systemctl("start", INGEST_PATH_NAME)
    else:
        _systemctl("stop", INGEST_PATH_NAME, check=False)
    final = _capture_named_service(INGEST_PATH_NAME)
    if (
        final.enabled != enabled
        or final.active != active
        or final.exec_main_status != 0
        or final.result not in {"success", ""}
    ):
        raise StagingToolError("Stato ticket ingest path staging non applicato.")


def _verify_ingest_readiness(
    service_sha256: str,
    path_sha256: str,
    snapshot_sha256: str,
) -> None:
    service, path = _capture_ingest_units()
    path_state = _capture_named_service(INGEST_PATH_NAME)
    if service_sha256:
        if (
            service.sha256 != service_sha256
            or path.sha256 != path_sha256
            or not path_state.active
            or not path_state.enabled
            or path_state.exec_main_status != 0
            or path_state.result not in {"success", ""}
            or not _ticket_snapshot_ingested(snapshot_sha256)
        ):
            raise StagingToolError("Ticket ingest staging non pronto.")
    elif service.exists or path.exists or path_state.active or path_state.enabled:
        raise StagingToolError("Ticket ingest staging storico non disattivato.")


def _rollback_failed_switch(
    release_before: LinkState,
    venv_before: LinkState,
    *,
    service_before: ServiceState,
    unit_before: UnitState,
    ingest_service_before: UnitState,
    ingest_path_before: UnitState,
    ingest_path_state_before: ServiceState,
    identities: Identities,
    health_timeout: float,
) -> None:
    _systemctl("stop", INGEST_PATH_NAME, check=False)
    _restore_link(STAGING_RELEASE_LINK, release_before)
    _restore_link(STAGING_VENV_LINK, venv_before)
    _restore_unit(unit_before)
    _restore_ingest_units(ingest_service_before, ingest_path_before)
    _systemctl("daemon-reload")
    if service_before.enabled:
        _systemctl("enable", SERVICE_NAME)
    else:
        _systemctl("disable", SERVICE_NAME, check=False)
    if service_before.active:
        if not release_before.exists or not venv_before.exists:
            raise StagingToolError("Servizio staging attivo senza link precedenti.")
        _systemctl("restart", SERVICE_NAME)
        _wait_for_health(health_timeout)
    else:
        _systemctl("stop", SERVICE_NAME, check=False)
    _set_ingest_path_state(
        enabled=ingest_path_state_before.enabled,
        active=ingest_path_state_before.active,
    )
    restored_service = _capture_service()
    restored_ingest_service, restored_ingest_path = _capture_ingest_units()
    restored_path_state = _capture_named_service(INGEST_PATH_NAME)
    if (
        _capture_link(STAGING_RELEASE_LINK) != release_before
        or _capture_link(STAGING_VENV_LINK) != venv_before
        or _capture_unit() != unit_before
        or restored_ingest_service != ingest_service_before
        or restored_ingest_path != ingest_path_before
        or restored_path_state.active != ingest_path_state_before.active
        or restored_path_state.enabled != ingest_path_state_before.enabled
        or not _service_ready(
            restored_service,
            expected_active=service_before.active,
            expected_enabled=service_before.enabled,
        )
    ):
        raise StagingToolError("Stato staging precedente non ripristinato.")
    _verify_ticket_store(identities)


def _activate(
    release: Path,
    venv: Path,
    *,
    unit_bytes: bytes | None,
    expected_unit_sha256: str,
    ingest_service_bytes: bytes,
    ingest_path_bytes: bytes,
    snapshot_sha256: str,
    identities: Identities,
    health_timeout: float,
) -> None:
    release_before = _capture_link(STAGING_RELEASE_LINK)
    venv_before = _capture_link(STAGING_VENV_LINK)
    unit_before = _capture_unit()
    ingest_service_before, ingest_path_before = _capture_ingest_units()
    service_before = _capture_service()
    ingest_path_state_before = _capture_named_service(INGEST_PATH_NAME)
    if not ingest_path_before.exists and (
        ingest_path_state_before.active or ingest_path_state_before.enabled
    ):
        raise StagingToolError("Path ticket ingest staging attivo senza unità verificata.")
    try:
        _systemctl("stop", INGEST_PATH_NAME, check=False)
        _switch_link(STAGING_RELEASE_LINK, release)
        _switch_link(STAGING_VENV_LINK, venv)
        if unit_bytes is not None:
            _install_unit(unit_bytes)
        _install_ingest_units(ingest_service_bytes, ingest_path_bytes)
        _systemctl("daemon-reload")
        if not service_before.enabled:
            _systemctl("enable", SERVICE_NAME)
        _systemctl("restart", SERVICE_NAME)
        _wait_for_app_readiness(
            release,
            venv,
            expected_unit_sha256,
            identities,
            health_timeout,
        )
        if ingest_service_bytes:
            _run_initial_ingest(snapshot_sha256, identities)
            _set_ingest_path_state(enabled=True, active=True)
        else:
            _set_ingest_path_state(enabled=False, active=False)
        _verify_ingest_readiness(
            _sha256_bytes(ingest_service_bytes) if ingest_service_bytes else "",
            _sha256_bytes(ingest_path_bytes) if ingest_path_bytes else "",
            snapshot_sha256,
        )
        _wait_for_app_readiness(
            release,
            venv,
            expected_unit_sha256,
            identities,
            health_timeout,
        )
    except BaseException as original:
        try:
            _rollback_failed_switch(
                release_before,
                venv_before,
                service_before=service_before,
                unit_before=unit_before,
                ingest_service_before=ingest_service_before,
                ingest_path_before=ingest_path_before,
                ingest_path_state_before=ingest_path_state_before,
                identities=identities,
                health_timeout=health_timeout,
            )
        except BaseException as restoration:
            raise StagingToolError(
                "Attivazione staging fallita e ripristino non completato: "
                f"{type(restoration).__name__}"
            ) from original
        raise


def _apply_install(bundle: BundleInfo, python_executable: Path, health_timeout: float) -> None:
    identities = _lookup_identities()
    _verify_private_root(identities)
    snapshot = _validate_store(identities)
    release, _ = _extract_release(bundle, identities)
    venv, _ = _build_venv(bundle, release, identities, python_executable)
    _activate(
        release,
        venv,
        unit_bytes=bundle.unit_bytes,
        expected_unit_sha256=_sha256_bytes(bundle.unit_bytes),
        ingest_service_bytes=bundle.ingest_service_bytes,
        ingest_path_bytes=bundle.ingest_path_bytes,
        snapshot_sha256=str(snapshot["sha256"]),
        identities=identities,
        health_timeout=health_timeout,
    )


def _load_installed_release(release_id: str, identities: Identities):
    path = _release_directory(release_id)
    manifest_path = path / "release-manifest.json"
    if not manifest_path.is_file() or manifest_path.is_symlink():
        raise StagingToolError("Manifest release rollback assente.")
    manifest = _json_object(manifest_path.read_bytes(), label="manifest release rollback")
    if str(manifest.get("content_sha256", ""))[:16] != release_id:
        raise StagingToolError("Release rollback incoerente con il suo ID.")
    _verify_release_directory(path, manifest, identities)
    unit_path = path.joinpath(*UNIT_ARCHIVE_PATH.parts)
    # Historical releases predate the mutable ticket store.  They remain valid rollback
    # targets when their unit still satisfies every original isolation guarantee; the
    # currently installed, stricter unit stays active during this link-only rollback.
    _validate_staging_unit(unit_path.read_bytes(), require_ticket_store=False)
    records = _manifest_records(manifest)
    if "requirements-server.lock" in records:
        requirements_path = PurePosixPath("requirements-server.lock")
    elif "requirements.lock" in records:
        requirements_path = PurePosixPath("requirements.lock")
    else:
        raise StagingToolError("Lockfile release rollback assente.")
    marker = {
        "marker_version": "1.0",
        "release_id": release_id,
        "requirements_path": str(requirements_path),
        "requirements_sha256": records[str(requirements_path)]["sha256"],
    }
    venv = VENVS_ROOT / release_id
    _verify_venv(venv, marker, identities)
    ingest_service_key = str(INGEST_SERVICE_ARCHIVE_PATH)
    ingest_path_key = str(INGEST_PATH_ARCHIVE_PATH)
    if (ingest_service_key in records) != (ingest_path_key in records):
        raise StagingToolError("Release rollback con unità ticket ingest parziali.")
    if ingest_service_key in records:
        ingest_service = path.joinpath(*INGEST_SERVICE_ARCHIVE_PATH.parts).read_bytes()
        ingest_path = path.joinpath(*INGEST_PATH_ARCHIVE_PATH.parts).read_bytes()
        _validate_staging_ingest_units(ingest_service, ingest_path)
    else:
        ingest_service = b""
        ingest_path = b""
    return path, venv, ingest_service, ingest_path


def _apply_rollback(release_id: str, health_timeout: float) -> None:
    identities = _lookup_identities()
    _verify_private_root(identities)
    snapshot = _validate_store(identities)
    release, venv, ingest_service, ingest_path = _load_installed_release(
        release_id,
        identities,
    )
    installed_unit = _capture_unit()
    if installed_unit.content is None:
        raise StagingToolError("Unità staging installata assente o non regolare.")
    _validate_staging_unit(
        installed_unit.content,
        require_ticket_store=False,
    )
    _activate(
        release,
        venv,
        unit_bytes=None,
        expected_unit_sha256=str(installed_unit.sha256),
        ingest_service_bytes=ingest_service,
        ingest_path_bytes=ingest_path,
        snapshot_sha256=str(snapshot["sha256"]),
        identities=identities,
        health_timeout=health_timeout,
    )


def _positive_timeout(value: str) -> float:
    try:
        timeout = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("timeout non numerico") from exc
    if not 1 <= timeout <= 60:
        raise argparse.ArgumentTypeError("timeout richiesto tra 1 e 60 secondi")
    return timeout


def _add_apply_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Applica il piano locale (default: dry-run senza mutazioni).",
    )
    parser.add_argument(
        "--confirm-plan",
        help="Token esatto stampato dal dry-run; obbligatorio con --apply.",
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Lifecycle sicuro DTLab v2 staging.")
    commands = parser.add_subparsers(dest="action", required=True)

    bootstrap = commands.add_parser("bootstrap", help="Prepara account, ACL e directory v2.")
    _add_apply_arguments(bootstrap)

    install = commands.add_parser("install", help="Installa una release nello staging isolato.")
    install.add_argument("--archive", type=Path, required=True)
    install.add_argument("--checksum", type=Path, required=True)
    install.add_argument("--python", type=Path, default=Path("/usr/bin/python3"))
    install.add_argument("--health-timeout", type=_positive_timeout, default=30.0)
    _add_apply_arguments(install)

    rollback = commands.add_parser("rollback", help="Ripunta solo lo staging a una release nota.")
    rollback.add_argument("--release-id", required=True)
    rollback.add_argument("--health-timeout", type=_positive_timeout, default=30.0)
    _add_apply_arguments(rollback)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.action == "bootstrap":
            payload, token = _plan("bootstrap")
            _require_confirmation(args, token)
            if not args.apply:
                _emit_plan(payload, token)
                return 0
            _require_apply_host()
            _bootstrap()
        elif args.action == "install":
            bundle = inspect_bundle(args.archive, args.checksum)
            python_executable = _resolve_trusted_python(args.python)
            payload, token = _plan(
                "install",
                bundle=bundle,
                python_executable=python_executable,
                health_timeout=args.health_timeout,
            )
            _require_confirmation(args, token)
            if not args.apply:
                _emit_plan(payload, token)
                return 0
            _require_apply_host()
            _apply_install(bundle, python_executable, args.health_timeout)
        else:
            release_id = args.release_id.lower()
            if not _RELEASE_ID.fullmatch(release_id):
                raise StagingToolError("--release-id deve contenere 16 cifre esadecimali.")
            payload, token = _plan("rollback", release_id=release_id)
            _require_confirmation(args, token)
            if not args.apply:
                _emit_plan(payload, token)
                return 0
            _require_apply_host()
            _apply_rollback(release_id, args.health_timeout)
        print(json.dumps({"action": args.action, "status": "applied"}, sort_keys=True))
        return 0
    except StagingToolError as exc:
        print(json.dumps({"error": str(exc), "status": "failed"}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
