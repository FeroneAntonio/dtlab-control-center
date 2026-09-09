from __future__ import annotations

import hashlib
import json
import tarfile

from tools.build_release import build_release


def test_release_archive_is_deterministic_and_excludes_local_state(tmp_path) -> None:
    first, _ = build_release(tmp_path / "first")
    second, _ = build_release(tmp_path / "second")

    assert first.read_bytes() == second.read_bytes()
    with tarfile.open(first, mode="r:gz") as archive:
        names = archive.getnames()
        assert any(name.endswith("/app.py") for name in names)
        assert any(name.endswith("/README.md") for name in names)
        assert any(name.endswith("/docs/RUNBOOK.md") for name in names)
        assert any(name.endswith("/src/dtlab/ui/operational_index.py") for name in names)
        assert any(name.endswith("/src/dtlab/ui/views/lab.py") for name in names)
        assert any(name.endswith("/schemas/dtlab-snapshot-v2.schema.json") for name in names)
        assert any(
            name.endswith("/integrations/plc_endpoint_audit/README.md") for name in names
        )
        server_lock_member = next(
            member
            for member in archive.getmembers()
            if member.name.endswith("/requirements-server.lock")
        )
        assert any(name.endswith("/release-manifest.json") for name in names)
        assert not any("/runtime/" in name for name in names)
        assert not any("/legacy/" in name for name in names)
        assert not any("/.venv/" in name for name in names)
        assert not any(name.endswith("config/dtlab.local.toml") for name in names)
        assert not any("/apps/api/" in name or "/apps/web/" in name for name in names)
        server_lock_file = archive.extractfile(server_lock_member)
        assert server_lock_file is not None
        server_lock = server_lock_file.read().decode("utf-8").lower()
        assert "--hash=sha256:" in server_lock
        for excluded in ("pytest==", "ruff==", "coverage==", "pyvmomi==", "keyring=="):
            assert excluded not in server_lock


def test_release_manifest_hashes_every_packaged_source_file(tmp_path) -> None:
    archive_path, checksum_path = build_release(tmp_path)
    checksum = checksum_path.read_text(encoding="ascii").split()[0]

    assert checksum == hashlib.sha256(archive_path.read_bytes()).hexdigest()
    with tarfile.open(archive_path, mode="r:gz") as archive:
        manifest_member = next(
            member
            for member in archive.getmembers()
            if member.name.endswith("release-manifest.json")
        )
        manifest_file = archive.extractfile(manifest_member)
        assert manifest_file is not None
        manifest = json.loads(manifest_file.read())
        prefix = manifest_member.name.rsplit("/", maxsplit=1)[0]
        for relative, metadata in manifest["files"].items():
            packaged = archive.extractfile(f"{prefix}/{relative}")
            assert packaged is not None
            content = packaged.read()
            assert hashlib.sha256(content).hexdigest() == metadata["sha256"]
            assert len(content) == metadata["bytes"]
