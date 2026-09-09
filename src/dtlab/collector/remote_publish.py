"""Atomic SSH publication of content-addressed snapshots to the dashboard host."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import tempfile
import uuid
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

from dtlab.collector.config import PublishConfig
from dtlab.services.snapshot_store import (
    AtomicSnapshotStore,
    SnapshotStoreError,
    StoredSnapshot,
)


class RemotePublishError(RuntimeError):
    """The remote snapshot pointer was not safely committed."""

    def __init__(self, message: str, *, committed: bool | None = False) -> None:
        self.committed = committed
        super().__init__(message)


Runner = Callable[..., subprocess.CompletedProcess[str]]
_SSH_COMMON_OPTIONS = (
    "-4",
    "-o",
    "ConnectTimeout=10",
    "-o",
    "BatchMode=yes",
    "-o",
    "StrictHostKeyChecking=yes",
)
_SSH_OPTIONS = (*_SSH_COMMON_OPTIONS, "-o", "StdinNull=yes")
_SCP_OPTIONS = _SSH_COMMON_OPTIONS
_SHA256 = re.compile(r"^[a-f0-9]{64}$")
_CONTENT_NAME = re.compile(r"^[a-f0-9]{64}\.json$")
_POINTER_NAMES = ("current", "previous", "last_known_good")
_REMOTE_READ_BATCH = 96


@dataclass(frozen=True)
class RemotePublishSummary:
    """Non-sensitive counters for one atomic remote batch."""

    archives_requested: int
    archives_published: int
    archives_already_present: int
    objects_uploaded: int
    current_archive_published: int
    current_archive_already_present: int
    current_updated: int
    manifests_deleted: int = 0
    objects_deleted: int = 0


@dataclass(frozen=True)
class _PreparedSnapshot:
    stored: StoredSnapshot
    manifest_content: bytes
    manifest_digest: str


@dataclass(frozen=True)
class _RemoteManifest:
    digest: str
    object_name: str
    published_at: datetime


@dataclass
class _RemoteSnapshotPresence:
    objects: set[str]
    archives: set[str]


class RemoteSnapshotPublisher:
    def __init__(self, config: PublishConfig, *, runner: Runner = subprocess.run):
        self.config = config
        self._runner = runner

    @property
    def _ssh_target(self) -> str:
        return f"{self.config.remote_account}@{self.config.ssh_alias}"

    def _run(
        self,
        command: Sequence[str],
        *,
        check: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        try:
            return self._runner(
                list(command),
                check=check,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="strict",
                timeout=60,
            )
        except subprocess.TimeoutExpired as exc:
            executable = Path(command[0]).name.lower()
            raise RemotePublishError(f"Timeout comando {executable}.") from exc
        except subprocess.CalledProcessError as exc:
            executable = Path(command[0]).name.lower()
            raise RemotePublishError(
                f"Comando {executable} terminato con codice {exc.returncode}."
            ) from exc
        except (OSError, UnicodeError) as exc:
            executable = Path(command[0]).name.lower()
            raise RemotePublishError(f"Avvio comando {executable} non riuscito.") from exc

    def _ssh(self, *arguments: str, check: bool = True):
        try:
            return self._run(
                ["ssh", *_SSH_OPTIONS, self._ssh_target, *arguments],
                check=check,
            )
        except RemotePublishError as exc:
            operation = arguments[0] if arguments else "none"
            if operation == "test" and len(arguments) >= 3:
                remote_path = PurePosixPath(arguments[-1])
                path_tail = "/".join(remote_path.parts[-2:])
                operation = f"test_{arguments[1].lstrip('-')}_{path_tail}"
            raise RemotePublishError(
                f"{exc} Operazione remota {operation}.",
                committed=exc.committed,
            ) from exc

    def _scp(self, local: Path, remote: PurePosixPath) -> None:
        try:
            self._run(
                [
                    "scp",
                    "-q",
                    *_SCP_OPTIONS,
                    str(local),
                    f"{self._ssh_target}:{remote}",
                ]
            )
        except RemotePublishError as exc:
            raise RemotePublishError(
                f"{exc} Operazione remota upload.",
                committed=exc.committed,
            ) from exc

    def _chown(self, *paths: PurePosixPath) -> None:
        if not self.config.manage_ownership:
            return
        self._ssh(
            "chown",
            f"{self.config.remote_owner}:{self.config.remote_group}",
            *(str(path) for path in paths),
        )

    def _remote_file_exists(self, path: PurePosixPath) -> bool:
        result = self._ssh("test", "-f", str(path), check=False)
        if result.returncode == 0:
            return True
        if result.returncode == 1:
            return False
        raise RemotePublishError("Verifica presenza file remoto non riuscita.")

    def _remote_sha256_required(self, path: PurePosixPath) -> str:
        result = self._ssh("sha256sum", "--", str(path))
        lines = result.stdout.splitlines()
        if len(lines) != 1 or result.stderr:
            raise RemotePublishError("Risposta hash remota non valida.")
        separator = f"  {path}"
        if not lines[0].endswith(separator):
            raise RemotePublishError("Risposta hash remota non valida.")
        digest = lines[0][: -len(separator)].lower()
        if not _SHA256.fullmatch(digest):
            raise RemotePublishError("Risposta hash remota non valida.")
        return digest

    @staticmethod
    def _chunks(
        values: Sequence[PurePosixPath],
    ) -> tuple[tuple[PurePosixPath, ...], ...]:
        return tuple(
            tuple(values[index : index + _REMOTE_READ_BATCH])
            for index in range(0, len(values), _REMOTE_READ_BATCH)
        )

    def _remote_hashes_required(
        self,
        paths: Sequence[PurePosixPath],
    ) -> dict[PurePosixPath, str]:
        """Hash exact validated paths in bounded batches and reject ambiguous output."""

        expected = set(paths)
        if len(expected) != len(paths):
            raise RemotePublishError("Elenco file remoto ambiguo.")
        observed: dict[PurePosixPath, str] = {}
        for batch in self._chunks(paths):
            result = self._ssh("sha256sum", "--", *(str(path) for path in batch))
            if result.stderr:
                raise RemotePublishError("Risposta hash remota non valida.")
            lines = result.stdout.splitlines()
            if len(lines) != len(batch):
                raise RemotePublishError("Risposta hash remota non valida.")
            batch_expected = set(batch)
            for line in lines:
                try:
                    digest, remote_name = line.split("  ", maxsplit=1)
                except ValueError as exc:
                    raise RemotePublishError(
                        "Risposta hash remota non valida."
                    ) from exc
                path = PurePosixPath(remote_name)
                normalized = digest.lower()
                if (
                    path not in batch_expected
                    or path in observed
                    or not _SHA256.fullmatch(normalized)
                ):
                    raise RemotePublishError("Risposta hash remota non valida.")
                observed[path] = normalized
        if set(observed) != expected:
            raise RemotePublishError("Risposta hash remota non valida.")
        return observed

    def _remote_contents_required(
        self,
        paths: Sequence[PurePosixPath],
    ) -> dict[PurePosixPath, bytes]:
        """Read small JSON files in bounded batches without shell interpolation."""

        expected = set(paths)
        if len(expected) != len(paths):
            raise RemotePublishError("Elenco file remoto ambiguo.")
        observed: dict[PurePosixPath, bytes] = {}
        for batch in self._chunks(paths):
            result = self._ssh(
                "grep",
                "-H",
                "-z",
                "--binary-files=text",
                "-e",
                "^",
                "--",
                *(str(path) for path in batch),
            )
            if result.stderr or not result.stdout.endswith("\0"):
                raise RemotePublishError("Lettura manifest remoti ambigua.")
            records = result.stdout[:-1].split("\0")
            if len(records) != len(batch):
                raise RemotePublishError("Lettura manifest remoti ambigua.")
            batch_expected = set(batch)
            for record in records:
                try:
                    remote_name, content = record.split(":", maxsplit=1)
                except ValueError as exc:
                    raise RemotePublishError(
                        "Lettura manifest remoti ambigua."
                    ) from exc
                path = PurePosixPath(remote_name)
                if path not in batch_expected or path in observed:
                    raise RemotePublishError("Lettura manifest remoti ambigua.")
                observed[path] = content.encode("utf-8")
        if set(observed) != expected:
            raise RemotePublishError("Lettura manifest remoti ambigua.")
        return observed

    def _remote_entries(self, directory: PurePosixPath) -> dict[str, str]:
        """Return exact entry types/names; NUL framing makes names unambiguous."""

        result = self._ssh(
            "find",
            str(directory),
            "-mindepth",
            "1",
            "-maxdepth",
            "1",
            "-printf",
            # OpenSSH joins remote argv into a shell command.  Each doubled
            # backslash survives that shell as one backslash for GNU find,
            # which then emits the intended NUL delimiter.
            "%y\\\\000%f\\\\000",
        )
        if result.stderr:
            raise RemotePublishError("Inventario directory remota ambiguo.")
        if not result.stdout:
            return {}
        if not result.stdout.endswith("\0"):
            raise RemotePublishError("Inventario directory remota ambiguo.")
        fields = result.stdout[:-1].split("\0")
        if len(fields) % 2:
            raise RemotePublishError("Inventario directory remota ambiguo.")
        entries: dict[str, str] = {}
        for entry_type, name in zip(fields[::2], fields[1::2], strict=True):
            if len(entry_type) != 1 or not name or name in entries:
                raise RemotePublishError("Inventario directory remota ambiguo.")
            entries[name] = entry_type
        return entries

    def _verified_snapshot_presence(
        self,
        prepared_snapshots: Sequence[_PreparedSnapshot],
    ) -> _RemoteSnapshotPresence:
        """Verify relevant immutable files with bounded remote inventory/hash calls."""

        remote = self.config.remote_store
        object_directory = remote / "objects"
        manifest_directory = remote / "manifests"
        object_entries = self._remote_entries(object_directory)
        manifest_entries = self._remote_entries(manifest_directory)

        expected_objects: dict[str, str] = {}
        expected_archives: dict[str, str] = {}
        for prepared in prepared_snapshots:
            manifest = prepared.stored.manifest
            object_name = str(manifest["object_name"])
            object_digest = str(manifest["sha256"])
            archive_name = f"{prepared.manifest_digest}.json"
            if (
                not _CONTENT_NAME.fullmatch(object_name)
                or object_name != f"{object_digest}.json"
                or not _CONTENT_NAME.fullmatch(archive_name)
            ):
                raise RemotePublishError("Snapshot locale con nomi contenuto non validi.")
            prior_object = expected_objects.setdefault(object_name, object_digest)
            if prior_object != object_digest:
                raise RemotePublishError("Snapshot locali con oggetto remoto ambiguo.")
            expected_archives[archive_name] = prepared.manifest_digest

        relevant_object_paths: list[PurePosixPath] = []
        for name in expected_objects:
            entry_type = object_entries.get(name)
            if entry_type is None:
                continue
            if entry_type != "f":
                raise RemotePublishError("Oggetto remoto rilevante non regolare.")
            relevant_object_paths.append(object_directory / name)

        relevant_archive_paths: list[PurePosixPath] = []
        for name in expected_archives:
            entry_type = manifest_entries.get(name)
            if entry_type is None:
                continue
            if entry_type != "f":
                raise RemotePublishError("Manifest remoto rilevante non regolare.")
            relevant_archive_paths.append(manifest_directory / name)

        observed_hashes = self._remote_hashes_required(
            [*relevant_object_paths, *relevant_archive_paths]
        )
        for path in relevant_object_paths:
            if observed_hashes[path] != expected_objects[path.name]:
                raise RemotePublishError(
                    "Oggetto remoto esistente con hash non valido."
                )
        for path in relevant_archive_paths:
            if observed_hashes[path] != expected_archives[path.name]:
                raise RemotePublishError(
                    "Manifest remoto immutabile con hash non valido."
                )
        return _RemoteSnapshotPresence(
            objects={path.name for path in relevant_object_paths},
            archives={path.name for path in relevant_archive_paths},
        )

    @staticmethod
    def _decode_remote_manifest(
        content: bytes,
        *,
        digest: str,
    ) -> _RemoteManifest:
        if hashlib.sha256(content).hexdigest() != digest:
            raise RemotePublishError("Hash manifest remoto non valido.")
        try:
            payload = json.loads(content.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RemotePublishError("JSON manifest remoto non valido.") from exc
        if not isinstance(payload, dict):
            raise RemotePublishError("JSON manifest remoto non valido.")
        required = {
            "manifest_version",
            "contract_version",
            "snapshot_id",
            "sha256",
            "object_name",
            "byte_length",
            "published_at",
            "trusted_origin",
            "collector_version",
        }
        if not required.issubset(payload) or payload.get("trusted_origin") != "dtlab_collector":
            raise RemotePublishError("JSON manifest remoto non valido.")
        sha256 = payload.get("sha256")
        object_name = payload.get("object_name")
        byte_length = payload.get("byte_length")
        if (
            not isinstance(sha256, str)
            or not _SHA256.fullmatch(sha256)
            or object_name != f"{sha256}.json"
            or isinstance(byte_length, bool)
            or not isinstance(byte_length, int)
            or byte_length < 0
            or not isinstance(payload.get("snapshot_id"), str)
            or not payload["snapshot_id"]
        ):
            raise RemotePublishError("JSON manifest remoto non valido.")
        try:
            published_at = datetime.fromisoformat(
                str(payload["published_at"]).replace("Z", "+00:00")
            )
        except ValueError as exc:
            raise RemotePublishError("Timestamp manifest remoto non valido.") from exc
        if published_at.tzinfo is None:
            raise RemotePublishError("Timestamp manifest remoto privo di fuso orario.")
        return _RemoteManifest(
            digest=digest,
            object_name=object_name,
            published_at=published_at.astimezone(UTC),
        )

    def _remove_exact_verified(
        self,
        path: PurePosixPath,
        *,
        expected_sha256: str,
    ) -> None:
        symlink = self._ssh("test", "-L", str(path), check=False)
        if symlink.returncode == 0:
            raise RemotePublishError("Rimozione remota rifiutata per symlink.")
        if symlink.returncode != 1:
            raise RemotePublishError("Verifica symlink remota non riuscita.")
        if self._remote_sha256_required(path) != expected_sha256:
            raise RemotePublishError("File remoto cambiato durante la retention.")
        self._ssh("rm", "--", str(path))

    def _commit_file(
        self,
        local: Path,
        destination: PurePosixPath,
        *,
        expected_sha256: str,
    ) -> None:
        token = uuid.uuid4().hex
        temporary = destination.parent / f".{destination.name}.{token}.tmp"
        try:
            self._scp(local, temporary)
            if self._remote_sha256_required(temporary) != expected_sha256:
                raise RemotePublishError("Hash upload remoto non valido.")
            self._chown(temporary)
            self._ssh("chmod", "0640", str(temporary))
            self._ssh("mv", str(temporary), str(destination))
        finally:
            self._ssh("rm", "-f", str(temporary), check=False)

    def _commit_bytes(
        self,
        content: bytes,
        destination: PurePosixPath,
        *,
        expected_sha256: str,
    ) -> None:
        temporary: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(mode="wb", delete=False) as handle:
                temporary = Path(handle.name)
                handle.write(content)
                handle.flush()
            self._commit_file(
                temporary,
                destination,
                expected_sha256=expected_sha256,
            )
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)

    @staticmethod
    def _manifest_content(manifest: dict[str, Any]) -> bytes:
        return (
            json.dumps(
                manifest,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")

    def _prepare_stored(
        self,
        store: AtomicSnapshotStore,
        stored: StoredSnapshot,
    ) -> _PreparedSnapshot:
        manifest_content = self._manifest_content(stored.manifest)
        manifest_digest = hashlib.sha256(manifest_content).hexdigest()
        try:
            verified = store.load_archive(f"{manifest_digest}.json")
        except SnapshotStoreError as exc:
            raise RemotePublishError("Archivio snapshot locale non valido.") from exc
        if verified.manifest != stored.manifest or verified.snapshot != stored.snapshot:
            raise RemotePublishError("Snapshot locale e archivio immutabile non coerenti.")
        return _PreparedSnapshot(
            stored=verified,
            manifest_content=manifest_content,
            manifest_digest=manifest_digest,
        )

    @staticmethod
    def _publication_order_key(
        prepared: _PreparedSnapshot,
    ) -> tuple[datetime, str]:
        value = str(prepared.stored.manifest.get("published_at") or "")
        try:
            published_at = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise RemotePublishError("Timestamp manifest locale non valido.") from exc
        if published_at.tzinfo is None:
            raise RemotePublishError("Timestamp manifest locale privo di fuso orario.")
        return published_at.astimezone(UTC), prepared.manifest_digest

    def _ensure_immutable_locked(
        self,
        store: AtomicSnapshotStore,
        prepared: _PreparedSnapshot,
        presence: _RemoteSnapshotPresence,
    ) -> tuple[bool, bool]:
        remote = self.config.remote_store
        manifest = prepared.stored.manifest
        object_name = manifest["object_name"]
        object_path = store.objects / object_name
        remote_object = remote / "objects" / object_name
        object_present = object_name in presence.objects
        if not object_present:
            self._commit_file(
                object_path,
                remote_object,
                expected_sha256=manifest["sha256"],
            )
            presence.objects.add(object_name)

        archive_name = f"{prepared.manifest_digest}.json"
        remote_archive = remote / "manifests" / archive_name
        archive_present = archive_name in presence.archives
        if not archive_present:
            self._commit_bytes(
                prepared.manifest_content,
                remote_archive,
                expected_sha256=prepared.manifest_digest,
            )
            presence.archives.add(archive_name)
        return not archive_present, not object_present

    def _commit_current_locked(self, prepared: _PreparedSnapshot) -> int:
        remote = self.config.remote_store
        remote_current = remote / "current" / "manifest.json"
        remote_previous = remote / "previous" / "manifest.json"
        remote_lkg = remote / "last_known_good" / "manifest.json"

        if self._remote_file_exists(remote_current):
            current_digest = self._remote_sha256_required(remote_current)
            if current_digest == prepared.manifest_digest:
                return 0
            previous_temp = remote_previous.parent / f".manifest.previous.{uuid.uuid4().hex}.tmp"
            try:
                self._ssh("cp", str(remote_current), str(previous_temp))
                self._chown(previous_temp)
                self._ssh("chmod", "0640", str(previous_temp))
                self._ssh("mv", str(previous_temp), str(remote_previous))
            finally:
                self._ssh("rm", "-f", str(previous_temp), check=False)

        lkg_exists = self._remote_file_exists(remote_lkg)
        if prepared.stored.snapshot["sync"]["state"] == "fresh" or not lkg_exists:
            self._commit_bytes(
                prepared.manifest_content,
                remote_lkg,
                expected_sha256=prepared.manifest_digest,
            )

        # ``current`` is the authoritative commit point and is deliberately written last.
        # A transport failure during its atomic rename is commit-unknown to the caller.
        try:
            self._commit_bytes(
                prepared.manifest_content,
                remote_current,
                expected_sha256=prepared.manifest_digest,
            )
        except RemotePublishError as exc:
            raise RemotePublishError(
                "Commit del manifest current non determinabile.",
                committed=None,
            ) from exc
        if self._remote_sha256_required(remote_current) != prepared.manifest_digest:
            raise RemotePublishError(
                "Manifest current committato ma verifica finale non riuscita.",
                committed=True,
            )
        return 1

    def _ensure_remote_layout(self) -> None:
        remote = self.config.remote_store
        directories = [
            remote,
            remote / "objects",
            remote / "manifests",
            remote / "current",
            remote / "previous",
            remote / "last_known_good",
        ]
        if self.config.manage_ownership:
            self._ssh(
                "install",
                "-d",
                "-m",
                "0750",
                *(str(directory) for directory in directories),
            )
            self._chown(*directories)
            return
        for directory in directories:
            exists = self._ssh("test", "-d", str(directory), check=False)
            if exists.returncode != 0:
                raise RemotePublishError(
                    "Directory remota non predisposta per il publisher non-root."
                )

    def _prune_remote_locked(self) -> tuple[int, int]:
        """Apply fail-closed remote retention while the publication lock is held."""

        remote = self.config.remote_store
        manifests_directory = remote / "manifests"
        objects_directory = remote / "objects"

        manifest_entries = self._remote_entries(manifests_directory)
        object_entries = self._remote_entries(objects_directory)
        for entries, label in (
            (manifest_entries, "manifest"),
            (object_entries, "oggetto"),
        ):
            if any(entry_type != "f" for entry_type in entries.values()):
                raise RemotePublishError(
                    f"Retention rifiutata: {label} remoto non regolare."
                )
            if any(not _CONTENT_NAME.fullmatch(name) for name in entries):
                raise RemotePublishError(
                    f"Retention rifiutata: nome {label} remoto non valido."
                )

        pointer_paths: list[PurePosixPath] = []
        pointer_entries: dict[str, dict[str, str]] = {}
        for pointer in _POINTER_NAMES:
            pointer_directory = remote / pointer
            entries = self._remote_entries(pointer_directory)
            pointer_entries[pointer] = entries
            if any(
                name != "manifest.json" or entry_type != "f"
                for name, entry_type in entries.items()
            ):
                raise RemotePublishError(
                    f"Retention rifiutata: pointer {pointer} non regolare."
                )
            if "manifest.json" in entries:
                pointer_paths.append(pointer_directory / "manifest.json")
            elif pointer == "current":
                raise RemotePublishError("Pointer current remoto assente dopo il commit.")

        archive_paths = [
            manifests_directory / name for name in sorted(manifest_entries)
        ]
        manifest_paths = [*archive_paths, *pointer_paths]
        manifest_hashes = self._remote_hashes_required(manifest_paths)
        manifest_contents = self._remote_contents_required(manifest_paths)

        archives: dict[str, _RemoteManifest] = {}
        for path in archive_paths:
            digest = path.name.removesuffix(".json")
            if manifest_hashes[path] != digest:
                raise RemotePublishError("Hash archivio manifest remoto non valido.")
            archives[digest] = self._decode_remote_manifest(
                manifest_contents[path],
                digest=digest,
            )

        pointers: list[_RemoteManifest] = []
        for path in pointer_paths:
            digest = manifest_hashes[path]
            pointer = self._decode_remote_manifest(
                manifest_contents[path],
                digest=digest,
            )
            pointers.append(pointer)

        object_paths = [objects_directory / name for name in sorted(object_entries)]
        object_hashes = self._remote_hashes_required(object_paths)
        for path, digest in object_hashes.items():
            if digest != path.name.removesuffix(".json"):
                raise RemotePublishError("Hash oggetto remoto non valido.")

        available_objects = set(object_entries)
        all_manifests = [*archives.values(), *pointers]
        if any(record.object_name not in available_objects for record in all_manifests):
            raise RemotePublishError("Manifest remoto riferisce un oggetto assente.")

        recent = sorted(
            archives.values(),
            key=lambda record: (record.published_at, record.digest),
            reverse=True,
        )[: self.config.remote_retention]
        kept_digests = {record.digest for record in recent}
        kept_digests.update(record.digest for record in pointers)
        kept_objects = {
            record.object_name
            for digest, record in archives.items()
            if digest in kept_digests
        }
        kept_objects.update(record.object_name for record in pointers)

        manifest_deletions = [
            path
            for path in archive_paths
            if path.name.removesuffix(".json") not in kept_digests
        ]
        object_deletions = [
            path for path in object_paths if path.name not in kept_objects
        ]

        # Manifests are always removed before objects.  A failure can therefore
        # leave an extra unreferenced object, never a newly dangling manifest.
        for path in manifest_deletions:
            self._remove_exact_verified(
                path,
                expected_sha256=path.name.removesuffix(".json"),
            )
        if object_deletions:
            expected_archives = {
                path.name: "f"
                for path in archive_paths
                if path not in manifest_deletions
            }
            if self._remote_entries(manifests_directory) != expected_archives:
                raise RemotePublishError(
                    "Manifest remoti cambiati durante la retention."
                )
            for pointer in _POINTER_NAMES:
                if self._remote_entries(remote / pointer) != pointer_entries[pointer]:
                    raise RemotePublishError(
                        "Pointer remoto cambiato durante la retention."
                    )
            protected_paths = [
                path
                for path in manifest_paths
                if path not in manifest_deletions
            ]
            protected_hashes = self._remote_hashes_required(protected_paths)
            if any(
                protected_hashes[path] != manifest_hashes[path]
                for path in protected_paths
            ):
                raise RemotePublishError(
                    "Manifest remoto cambiato durante la retention."
                )
        for path in object_deletions:
            self._remove_exact_verified(
                path,
                expected_sha256=path.name.removesuffix(".json"),
            )
        return len(manifest_deletions), len(object_deletions)

    def _publish_prepared(
        self,
        store: AtomicSnapshotStore,
        archives: Sequence[_PreparedSnapshot],
        current: _PreparedSnapshot | None,
    ) -> RemotePublishSummary:
        if not self.config.enabled:
            raise RemotePublishError("Pubblicazione remota disabilitata.")
        self._ensure_remote_layout()

        remote = self.config.remote_store
        lock_directory = remote / ".publish.lock"
        acquired = self._ssh("mkdir", str(lock_directory), check=False)
        if acquired.returncode != 0:
            raise RemotePublishError(
                "Un'altra pubblicazione DTLab è già in corso o il lock è bloccato."
            )

        archives_published = 0
        archives_already_present = 0
        objects_uploaded = 0
        current_archive_published = 0
        current_archive_already_present = 0
        current_updated = 0
        manifests_deleted = 0
        objects_deleted = 0
        publish_error: RemotePublishError | None = None
        try:
            presence = self._verified_snapshot_presence(
                [*archives, *([current] if current is not None else [])]
            )
            for prepared in archives:
                archive_added, object_added = self._ensure_immutable_locked(
                    store,
                    prepared,
                    presence,
                )
                archives_published += int(archive_added)
                archives_already_present += int(not archive_added)
                objects_uploaded += int(object_added)
            if current is not None:
                archive_added, object_added = self._ensure_immutable_locked(
                    store,
                    current,
                    presence,
                )
                current_archive_published = int(archive_added)
                current_archive_already_present = int(not archive_added)
                objects_uploaded += int(object_added)
                current_updated = self._commit_current_locked(current)
                try:
                    manifests_deleted, objects_deleted = self._prune_remote_locked()
                except RemotePublishError as exc:
                    raise RemotePublishError(
                        "Snapshot committato ma retention remota non riuscita.",
                        committed=True,
                    ) from exc
        except RemotePublishError as exc:
            publish_error = exc

        cleanup_error: RemotePublishError | None = None
        try:
            cleanup = self._ssh("rmdir", str(lock_directory), check=False)
            if cleanup.returncode != 0:
                cleanup_error = RemotePublishError(
                    "Snapshot committato ma lock remoto non rimosso.",
                    committed=True,
                )
        except RemotePublishError as exc:
            cleanup_error = exc
        if publish_error is not None:
            raise publish_error
        if cleanup_error is not None:
            raise RemotePublishError(
                "Snapshot committato ma lock remoto non rimosso.",
                committed=True,
            ) from cleanup_error
        return RemotePublishSummary(
            archives_requested=len(archives),
            archives_published=archives_published,
            archives_already_present=archives_already_present,
            objects_uploaded=objects_uploaded,
            current_archive_published=current_archive_published,
            current_archive_already_present=current_archive_already_present,
            current_updated=current_updated,
            manifests_deleted=manifests_deleted,
            objects_deleted=objects_deleted,
        )

    def publish_batch(
        self,
        store: AtomicSnapshotStore,
        archives: Sequence[StoredSnapshot],
        current: StoredSnapshot,
    ) -> RemotePublishSummary:
        """Backfill immutable archives in order and commit ``current`` last."""

        try:
            local_current = store.load("current")
        except SnapshotStoreError as exc:
            raise RemotePublishError("Snapshot locale corrente non valido.") from exc
        if local_current.manifest != current.manifest:
            raise RemotePublishError("Manifest locale non corrisponde al pointer current.")

        current_prepared = self._prepare_stored(store, current)
        unique: dict[str, _PreparedSnapshot] = {}
        for stored in archives:
            prepared = self._prepare_stored(store, stored)
            if prepared.manifest_digest != current_prepared.manifest_digest:
                unique.setdefault(prepared.manifest_digest, prepared)
        ordered = sorted(
            unique.values(),
            key=self._publication_order_key,
        )
        return self._publish_prepared(store, ordered, current_prepared)

    def publish_stored(
        self,
        store: AtomicSnapshotStore,
        stored: StoredSnapshot,
        *,
        commit_current: bool,
    ) -> RemotePublishSummary:
        """Publish a verified archive, optionally using it as the final current commit."""

        prepared = self._prepare_stored(store, stored)
        if commit_current:
            try:
                local_current = store.load("current")
            except SnapshotStoreError as exc:
                raise RemotePublishError("Snapshot locale corrente non valido.") from exc
            if local_current.manifest != stored.manifest:
                raise RemotePublishError("Manifest locale non corrisponde al pointer current.")
            return self._publish_prepared(store, (), prepared)
        return self._publish_prepared(store, (prepared,), None)

    def publish(
        self,
        store: AtomicSnapshotStore,
        manifest: dict[str, Any],
    ) -> None:
        try:
            stored = store.load("current")
        except SnapshotStoreError as exc:
            raise RemotePublishError("Snapshot locale corrente non valido.") from exc
        if stored.manifest != manifest:
            raise RemotePublishError("Manifest locale non corrisponde al pointer current.")
        self.publish_stored(store, stored, commit_current=True)
