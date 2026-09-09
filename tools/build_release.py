"""Build a deterministic, secret-free DTLab dashboard release archive."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import tarfile
from collections.abc import Iterable, Sequence
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
INCLUDE_ROOTS = (
    Path("app.py"),
    Path("pyproject.toml"),
    Path("requirements.txt"),
    Path("requirements.lock"),
    Path("requirements-server.in"),
    Path("requirements-server.lock"),
    Path("README.md"),
    Path(".streamlit"),
    Path("assets"),
    Path("integrations"),
    Path("config/cybervision-dtlab-modbus.rules"),
    Path("schemas"),
    Path("src"),
    Path("tools/verify_staging_snapshot.py"),
    Path("tools/cybervision_admin_audit.py"),
    Path("tools/configure_cybervision_modbus_detection.py"),
    Path("tools/prune_raw_snapshots.py"),
    Path("deploy"),
    Path("docs"),
)
EXCLUDED_PARTS = {"__pycache__", ".pytest_cache", ".ruff_cache"}
EXCLUDED_SUFFIXES = {".pyc", ".pyo"}


def release_files(root: Path = ROOT) -> list[Path]:
    files: list[Path] = []
    for relative in INCLUDE_ROOTS:
        source = root / relative
        candidates: Iterable[Path] = source.rglob("*") if source.is_dir() else (source,)
        for candidate in candidates:
            if not candidate.is_file() or candidate.is_symlink():
                continue
            project_relative = candidate.relative_to(root)
            if any(part in EXCLUDED_PARTS for part in project_relative.parts):
                continue
            if candidate.suffix.lower() in EXCLUDED_SUFFIXES:
                continue
            files.append(project_relative)
    return sorted(set(files), key=lambda path: path.as_posix())


def _file_manifest(root: Path, files: list[Path]) -> dict[str, object]:
    records = {
        path.as_posix(): {
            "sha256": hashlib.sha256((root / path).read_bytes()).hexdigest(),
            "bytes": (root / path).stat().st_size,
        }
        for path in files
    }
    digest_input = json.dumps(records, sort_keys=True, separators=(",", ":")).encode()
    return {
        "manifest_version": "1.0",
        "content_sha256": hashlib.sha256(digest_input).hexdigest(),
        "files": records,
    }


def _tar_info(name: str, size: int) -> tarfile.TarInfo:
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError("Percorso archivio non sicuro.")
    info = tarfile.TarInfo(name)
    info.size = size
    info.mtime = 0
    info.uid = 0
    info.gid = 0
    info.uname = "root"
    info.gname = "client1"
    info.mode = 0o640
    return info


def build_release(output_directory: Path, *, root: Path = ROOT) -> tuple[Path, Path]:
    files = release_files(root)
    manifest = _file_manifest(root, files)
    release_id = str(manifest["content_sha256"])[:16]
    prefix = f"dtlab-control-center-{release_id}"
    manifest_bytes = (
        json.dumps(manifest, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    ).encode()

    output_directory.mkdir(parents=True, exist_ok=True)
    archive_path = output_directory / f"{prefix}.tar.gz"
    with (
        archive_path.open("wb") as raw,
        gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed,
        tarfile.open(fileobj=compressed, mode="w") as archive,
    ):
        for relative in files:
            content = (root / relative).read_bytes()
            name = f"{prefix}/{relative.as_posix()}"
            archive.addfile(_tar_info(name, len(content)), io.BytesIO(content))
        manifest_name = f"{prefix}/release-manifest.json"
        archive.addfile(
            _tar_info(manifest_name, len(manifest_bytes)),
            io.BytesIO(manifest_bytes),
        )

    digest = hashlib.sha256(archive_path.read_bytes()).hexdigest()
    checksum_path = archive_path.with_suffix(archive_path.suffix + ".sha256")
    checksum_path.write_text(f"{digest}  {archive_path.name}\n", encoding="ascii")
    return archive_path, checksum_path


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Crea una release DTLab verificabile.")
    parser.add_argument("--output-dir", type=Path, default=ROOT / "dist")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    archive, checksum = build_release(args.output_dir.resolve())
    print(json.dumps({"archive": str(archive), "checksum": str(checksum)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
