"""Content-addressed, atomic snapshot storage for collector and dashboard."""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from dtlab.contract import (
    ContractValidationError,
    canonical_bytes,
    snapshot_sha256,
    validate_snapshot,
)

_OBJECT_NAME = re.compile(r"^[a-f0-9]{64}\.json$")
_MANIFEST_NAME = re.compile(r"^[a-f0-9]{64}\.json$")
_POINTER_NAMES = ("current", "last_known_good", "previous")


class SnapshotStoreError(RuntimeError):
    """The trusted snapshot store is missing, inconsistent, or corrupt."""


def _decode_manifest(content: bytes, *, label: str) -> dict[str, Any]:
    try:
        manifest = json.loads(content.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SnapshotStoreError(f"Manifest '{label}' non valido") from exc
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
    missing = sorted(required - set(manifest))
    if missing:
        raise SnapshotStoreError(f"Manifest '{label}' incompleto: {', '.join(missing)}")
    if manifest["trusted_origin"] != "dtlab_collector":
        raise SnapshotStoreError(f"Manifest '{label}' non proviene dal collector")
    if not _OBJECT_NAME.fullmatch(str(manifest["object_name"])):
        raise SnapshotStoreError(f"Manifest '{label}' contiene un object_name non valido")
    if manifest["object_name"] != f"{manifest['sha256']}.json":
        raise SnapshotStoreError(f"Manifest '{label}' ha puntatore/hash incoerenti")
    return manifest


@dataclass(frozen=True)
class StoredSnapshot:
    snapshot: dict[str, Any]
    manifest: dict[str, Any]
    pointer: str


def _utc_now_text(now: datetime | None = None) -> str:
    value = now or datetime.now(UTC)
    if value.tzinfo is None:
        raise SnapshotStoreError("published_at deve includere il fuso orario")
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _atomic_write(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary_path = Path(handle.name)
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        with suppress(OSError):
            temporary_path.chmod(0o600)
        os.replace(temporary_path, path)
    finally:
        if temporary_path and temporary_path.exists():
            temporary_path.unlink()


def _manifest_bytes(manifest: dict[str, Any]) -> bytes:
    return (
        json.dumps(manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


class AtomicSnapshotStore:
    """Publish immutable objects and atomically switch small trusted pointers."""

    def __init__(
        self,
        root: str | Path,
        *,
        allow_demo: bool = False,
        create_layout: bool = True,
    ):
        self.root = Path(root)
        self.allow_demo = allow_demo
        self.objects = self.root / "objects"
        self.manifests = self.root / "manifests"
        if create_layout:
            self.initialize_layout()

    def initialize_layout(self) -> None:
        """Create and harden the writable collector layout explicitly.

        Readers pass ``create_layout=False`` so merely opening a dashboard or
        verification tool can never create directories or change permissions.
        """

        self.objects.mkdir(parents=True, exist_ok=True)
        self.manifests.mkdir(parents=True, exist_ok=True)
        try:
            self.root.chmod(0o700)
            self.objects.chmod(0o700)
            self.manifests.chmod(0o700)
        except OSError:
            pass

    def _pointer_path(self, pointer: str) -> Path:
        if pointer not in _POINTER_NAMES:
            raise SnapshotStoreError(f"Pointer non supportato: {pointer}")
        return self.root / pointer / "manifest.json"

    def _read_manifest(self, pointer: str) -> dict[str, Any]:
        path = self._pointer_path(pointer)
        try:
            content = path.read_bytes()
        except FileNotFoundError as exc:
            raise SnapshotStoreError(f"Pointer '{pointer}' non disponibile") from exc
        return _decode_manifest(content, label=pointer)

    def _write_pointer(self, pointer: str, manifest: dict[str, Any]) -> None:
        _atomic_write(self._pointer_path(pointer), _manifest_bytes(manifest))

    def publish(
        self, snapshot: dict[str, Any], *, published_at: datetime | None = None
    ) -> dict[str, Any]:
        validate_snapshot(snapshot)
        if not self.allow_demo and snapshot["sync"]["publication_mode"] != "real_only":
            raise SnapshotStoreError("Lo store operativo accetta solo publication_mode=real_only")

        content = canonical_bytes(snapshot)
        digest = snapshot_sha256(snapshot)
        object_name = f"{digest}.json"
        object_path = self.objects / object_name
        if object_path.exists():
            existing = object_path.read_bytes()
            if existing != content:
                raise SnapshotStoreError("Collisione hash o oggetto esistente corrotto")
        else:
            _atomic_write(object_path, content)

        manifest = {
            "manifest_version": "1.0",
            "contract_version": snapshot["schema_version"],
            "snapshot_id": snapshot["snapshot_id"],
            "sha256": digest,
            "object_name": object_name,
            "byte_length": len(content),
            "published_at": _utc_now_text(published_at),
            "trusted_origin": "dtlab_collector",
            "collector_version": snapshot["sync"]["collector_version"],
        }
        manifest_content = _manifest_bytes(manifest)
        manifest_digest = hashlib.sha256(manifest_content).hexdigest()
        archive_path = self.manifests / f"{manifest_digest}.json"
        if archive_path.exists():
            if archive_path.read_bytes() != manifest_content:
                raise SnapshotStoreError("Manifest immutabile esistente con contenuto diverso")
        else:
            _atomic_write(archive_path, manifest_content)

        try:
            previous_manifest = self._read_manifest("current")
        except SnapshotStoreError:
            previous_manifest = None
        if previous_manifest and previous_manifest["sha256"] != digest:
            self._write_pointer("previous", previous_manifest)

        self._write_pointer("current", manifest)
        try:
            last_known_good = self.load("last_known_good").manifest
        except SnapshotStoreError:
            last_known_good = None
        if snapshot["sync"]["state"] == "fresh" or last_known_good is None:
            self._write_pointer("last_known_good", manifest)
        return manifest

    def _load_manifest(self, manifest: dict[str, Any], *, pointer: str) -> StoredSnapshot:
        object_path = self.objects / manifest["object_name"]
        try:
            content = object_path.read_bytes()
        except FileNotFoundError as exc:
            raise SnapshotStoreError(f"Oggetto del pointer '{pointer}' non disponibile") from exc
        if len(content) != manifest["byte_length"]:
            raise SnapshotStoreError(f"Dimensione oggetto '{pointer}' non valida")
        digest = hashlib.sha256(content).hexdigest()
        if digest != manifest["sha256"]:
            raise SnapshotStoreError(f"Hash oggetto '{pointer}' non valido")
        try:
            snapshot = json.loads(content)
            validate_snapshot(snapshot)
        except (UnicodeDecodeError, json.JSONDecodeError, ContractValidationError) as exc:
            raise SnapshotStoreError(f"Snapshot '{pointer}' non valido") from exc
        if snapshot["snapshot_id"] != manifest["snapshot_id"]:
            raise SnapshotStoreError(f"Snapshot ID del pointer '{pointer}' non coerente")
        return StoredSnapshot(snapshot=snapshot, manifest=manifest, pointer=pointer)

    def load(self, pointer: str = "current") -> StoredSnapshot:
        return self._load_manifest(self._read_manifest(pointer), pointer=pointer)

    def probe_manifest(self, pointer: str = "current") -> dict[str, Any]:
        """Validate pointer metadata and object presence without reading the object body."""

        manifest = self._read_manifest(pointer)
        object_path = self.objects / manifest["object_name"]
        try:
            byte_length = object_path.stat().st_size
        except OSError as exc:
            raise SnapshotStoreError(f"Oggetto del pointer '{pointer}' non disponibile") from exc
        if byte_length != manifest["byte_length"]:
            raise SnapshotStoreError(f"Dimensione oggetto '{pointer}' non valida")
        return dict(manifest)

    def archived_manifest_names(self) -> tuple[str, ...]:
        return tuple(
            path.name
            for path in sorted(self.manifests.glob("*.json"))
            if _MANIFEST_NAME.fullmatch(path.name)
        )

    def load_archive(self, manifest_name: str) -> StoredSnapshot:
        if not _MANIFEST_NAME.fullmatch(manifest_name):
            raise SnapshotStoreError("Nome manifest archiviato non valido")
        path = self.manifests / manifest_name
        manifest = self._read_archived_manifest(path)
        return self._load_manifest(manifest, pointer=f"archive:{manifest_name}")

    def probe_archive_manifest(self, manifest_name: str) -> dict[str, Any]:
        """Validate immutable archive metadata without decoding its snapshot body.

        Consumers that have already transactionally ingested a snapshot can use
        this inexpensive probe to preserve manifest/hash/object-size checks without
        repeatedly loading and validating a multi-megabyte JSON object.
        """

        if not _MANIFEST_NAME.fullmatch(manifest_name):
            raise SnapshotStoreError("Nome manifest archiviato non valido")
        manifest = self._read_archived_manifest(self.manifests / manifest_name)
        object_path = self.objects / manifest["object_name"]
        try:
            byte_length = object_path.stat().st_size
        except OSError as exc:
            raise SnapshotStoreError("Oggetto del manifest archiviato non disponibile") from exc
        if byte_length != manifest["byte_length"]:
            raise SnapshotStoreError("Dimensione oggetto del manifest archiviato non valida")
        return dict(manifest)

    def _read_archived_manifest(self, path: Path) -> dict[str, Any]:
        try:
            content = path.read_bytes()
        except FileNotFoundError as exc:
            raise SnapshotStoreError("Manifest archiviato non disponibile") from exc
        if hashlib.sha256(content).hexdigest() != path.name.removesuffix(".json"):
            raise SnapshotStoreError("Hash manifest archiviato non valido")
        return _decode_manifest(content, label=path.name)

    def load_best_available(self) -> StoredSnapshot:
        errors: list[str] = []
        for pointer in ("current", "last_known_good", "previous"):
            try:
                return self.load(pointer)
            except SnapshotStoreError as exc:
                errors.append(str(exc))
        raise SnapshotStoreError("Nessuno snapshot valido disponibile: " + "; ".join(errors))

    def prune_objects(self, *, retain: int = 30) -> list[Path]:
        """Prune old objects and their archives without breaking any pointer.

        Every archived manifest whose object is retained is preserved.  An archive
        whose object is absent or selected for pruning is removed before the object,
        so an interrupted cleanup can leave an extra object but never a new dangling
        archive.  The returned paths include both manifest and object removals.
        """

        if retain < 3:
            raise SnapshotStoreError("retain deve essere almeno 3")
        protected: set[str] = set()
        for pointer in _POINTER_NAMES:
            try:
                protected.add(self._read_manifest(pointer)["object_name"])
            except SnapshotStoreError:
                continue
        objects = sorted(
            (path for path in self.objects.glob("*.json") if _OBJECT_NAME.fullmatch(path.name)),
            key=lambda path: path.stat().st_mtime,
            reverse=True,
        )
        keep = protected | {path.name for path in objects[:retain]}
        removed: list[Path] = []

        # Delete archive references first.  Should a later object unlink fail, the
        # remaining state is conservative (an unreferenced object), not inconsistent.
        for path in sorted(self.manifests.glob("*.json")):
            if not _MANIFEST_NAME.fullmatch(path.name):
                continue
            manifest = self._read_archived_manifest(path)
            object_name = manifest["object_name"]
            if object_name not in keep or not (self.objects / object_name).is_file():
                path.unlink()
                removed.append(path)

        for path in objects:
            if path.name not in keep and _OBJECT_NAME.fullmatch(path.name):
                path.unlink()
                removed.append(path)
        return removed
