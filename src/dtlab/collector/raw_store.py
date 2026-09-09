"""Private local retention for raw source responses."""

from __future__ import annotations

import gzip
import json
import os
import re
import tempfile
from contextlib import suppress
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

_SOURCE_NAME = re.compile(r"^[a-z0-9_-]+$")


class RawStoreError(RuntimeError):
    """Raw evidence could not be stored within the configured private directory."""


class RawStore:
    def __init__(self, root: str | Path):
        self.root = Path(root).resolve()
        if self.root == Path(self.root.anchor) or len(self.root.parts) < 3:
            raise RawStoreError("Directory raw troppo ampia.")
        self.root.mkdir(parents=True, exist_ok=True)
        with suppress(OSError):
            self.root.chmod(0o700)

    def write(
        self,
        source: str,
        payload: Any,
        *,
        collected_at: datetime | None = None,
    ) -> Path:
        if not _SOURCE_NAME.fullmatch(source):
            raise RawStoreError("Nome sorgente raw non valido.")
        timestamp = collected_at or datetime.now(UTC)
        if timestamp.tzinfo is None:
            raise RawStoreError("collected_at deve includere il fuso orario.")
        source_directory = self.root / source
        source_directory.mkdir(parents=True, exist_ok=True)
        with suppress(OSError):
            source_directory.chmod(0o700)
        name = timestamp.astimezone(UTC).strftime("%Y%m%dT%H%M%S.%fZ.json.gz")
        destination = source_directory / name
        content = json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        temporary: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="wb",
                dir=source_directory,
                prefix=f".{name}.",
                suffix=".tmp",
                delete=False,
            ) as handle:
                temporary = Path(handle.name)
                with gzip.GzipFile(fileobj=handle, mode="wb", mtime=0) as compressed:
                    compressed.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            with suppress(OSError):
                temporary.chmod(0o600)
            os.replace(temporary, destination)
        finally:
            if temporary and temporary.exists():
                temporary.unlink()
        return destination

    def prune(
        self,
        *,
        older_than: timedelta = timedelta(days=7),
        retain_per_source: int = 100,
        now: datetime | None = None,
    ) -> list[Path]:
        if older_than < timedelta(hours=1) or retain_per_source < 1:
            raise RawStoreError("Policy di retention non valida.")
        reference = now or datetime.now(UTC)
        if reference.tzinfo is None:
            raise RawStoreError("now deve includere il fuso orario.")
        cutoff = reference.timestamp() - older_than.total_seconds()
        removed: list[Path] = []
        for source_directory in self.root.iterdir():
            if not source_directory.is_dir() or not _SOURCE_NAME.fullmatch(
                source_directory.name
            ):
                continue
            files = sorted(
                source_directory.glob("*.json.gz"),
                key=lambda path: path.stat().st_mtime,
                reverse=True,
            )
            for path in files[retain_per_source:]:
                if path.stat().st_mtime < cutoff:
                    path.unlink()
                    removed.append(path)
        return removed
