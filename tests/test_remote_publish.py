from __future__ import annotations

import hashlib
import json
import re
import subprocess
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath

import pytest

from dtlab.collector.config import PublishConfig
from dtlab.collector.remote_publish import RemotePublishError, RemoteSnapshotPublisher
from dtlab.services.snapshot_store import AtomicSnapshotStore, StoredSnapshot
from tests.factories import valid_snapshot

PUBLISHED_AT = datetime(2026, 8, 3, 14, 45, tzinfo=UTC)
REMOTE_ROOT = PurePosixPath("/var/www/clients/client1/web75/private/modbus-dashboard-data")
SSH_ALIAS = "web75-publisher"
SSH_TARGET = f"dtlab-publish@{SSH_ALIAS}"


class FakeRemote:
    def __init__(self) -> None:
        self.files: dict[str, bytes] = {}
        self.calls: list[list[str]] = []
        self.directories = {
            str(REMOTE_ROOT),
            str(REMOTE_ROOT / "objects"),
            str(REMOTE_ROOT / "manifests"),
            str(REMOTE_ROOT / "current"),
            str(REMOTE_ROOT / "previous"),
            str(REMOTE_ROOT / "last_known_good"),
        }
        self.locked = False
        self.corrupt_temporary_hash = False
        self.fail_lock_cleanup = False
        self.fail_exact_remove = False
        self.symlinks: set[str] = set()
        self.extra_entry_types: dict[str, str] = {}

    @staticmethod
    def _result(command: list[str], returncode: int = 0, stdout: str = ""):
        return subprocess.CompletedProcess(command, returncode, stdout=stdout, stderr="")

    def __call__(
        self,
        command,
        *,
        check: bool,
        capture_output: bool,
        text: bool,
        encoding: str,
        errors: str,
        timeout: int,
    ):
        del capture_output, text, encoding, errors, timeout
        call = list(command)
        self.calls.append(call)
        returncode = 0
        stdout = ""

        if call[0] == "scp":
            local = Path(call[-2])
            remote_path = call[-1].split(":", maxsplit=1)[1]
            self.files[remote_path] = local.read_bytes()
        else:
            alias_index = call.index(SSH_TARGET)
            arguments = call[alias_index + 1 :]
            operation = arguments[0]
            if operation == "sha256sum":
                paths = arguments[2:] if arguments[1] == "--" else arguments[1:]
                lines: list[str] = []
                for remote_path in paths:
                    content = self.files.get(remote_path)
                    if content is None or remote_path in self.symlinks:
                        returncode = 1
                        break
                    digest = hashlib.sha256(content).hexdigest()
                    if self.corrupt_temporary_hash and remote_path.endswith(".tmp"):
                        digest = "0" * 64
                    lines.append(f"{digest}  {remote_path}\n")
                stdout = "".join(lines)
            elif operation == "test":
                if arguments[1] == "-d":
                    returncode = 0 if arguments[2] in self.directories else 1
                elif arguments[1] == "-L":
                    returncode = 0 if arguments[2] in self.symlinks else 1
                else:
                    returncode = (
                        0
                        if arguments[2] in self.files
                        and arguments[2] not in self.symlinks
                        else 1
                    )
            elif operation == "find":
                directory = arguments[1]
                # OpenSSH constructs a remote command string rather than
                # preserving argv.  Simulate the remote shell consuming one
                # escaping layer before GNU find parses its -printf format.
                remote_format = re.sub(r"\\(.)", r"\1", arguments[-1])
                nul_framed = remote_format == r"%y\000%f\000"
                prefix = directory.rstrip("/") + "/"
                entries: dict[str, str] = {}
                for remote_path in self.files:
                    if remote_path.startswith(prefix) and "/" not in remote_path[len(prefix) :]:
                        entries[remote_path[len(prefix) :]] = (
                            "l" if remote_path in self.symlinks else "f"
                        )
                for remote_path in self.symlinks:
                    if remote_path.startswith(prefix) and "/" not in remote_path[len(prefix) :]:
                        entries[remote_path[len(prefix) :]] = "l"
                for remote_path, entry_type in self.extra_entry_types.items():
                    if remote_path.startswith(prefix) and "/" not in remote_path[len(prefix) :]:
                        entries[remote_path[len(prefix) :]] = entry_type
                if nul_framed:
                    stdout = "".join(
                        f"{entry_type}\0{name}\0"
                        for name, entry_type in sorted(entries.items())
                    )
                else:
                    stdout = "".join(
                        f"{entry_type}000{name}000"
                        for name, entry_type in sorted(entries.items())
                    )
            elif operation == "grep":
                separator = arguments.index("--")
                paths = arguments[separator + 1 :]
                records: list[str] = []
                for remote_path in paths:
                    content = self.files.get(remote_path)
                    if content is None or remote_path in self.symlinks:
                        returncode = 2
                        break
                    records.append(f"{remote_path}:{content.decode('utf-8')}\0")
                stdout = "".join(records)
            elif operation == "cp":
                source, destination = arguments[1:3]
                if source not in self.files:
                    returncode = 1
                else:
                    self.files[destination] = self.files[source]
            elif operation == "mv":
                source, destination = arguments[1:3]
                if source not in self.files:
                    returncode = 1
                else:
                    self.files[destination] = self.files.pop(source)
            elif operation == "rm":
                if self.fail_exact_remove and "--" in arguments:
                    returncode = 1
                else:
                    self.files.pop(arguments[-1], None)
                    self.symlinks.discard(arguments[-1])
            elif operation == "mkdir" and arguments[1].endswith(".publish.lock"):
                if self.locked:
                    returncode = 1
                else:
                    self.locked = True
                    self.directories.add(arguments[1])
            elif operation == "rmdir" and arguments[1].endswith(".publish.lock"):
                if self.fail_lock_cleanup:
                    returncode = 1
                else:
                    self.locked = False
                    self.directories.discard(arguments[1])

        result = self._result(call, returncode, stdout)
        if check and returncode != 0:
            raise subprocess.CalledProcessError(returncode, call, stdout, "")
        return result


def _config(*, remote_retention: int = 240) -> PublishConfig:
    return PublishConfig(
        enabled=True,
        ssh_alias=SSH_ALIAS,
        remote_store=REMOTE_ROOT,
        remote_owner="dtlab-publish",
        remote_group="dtlab-dashboard",
        remote_account="dtlab-publish",
        manage_ownership=False,
        remote_retention=remote_retention,
    )


def _published_store(tmp_path, *, state: str = "fresh"):
    store = AtomicSnapshotStore(tmp_path / "store")
    snapshot = valid_snapshot()
    snapshot["sync"]["state"] = state
    manifest = store.publish(snapshot, published_at=PUBLISHED_AT)
    return store, manifest


def _archived(store: AtomicSnapshotStore, manifest: dict) -> StoredSnapshot:
    content = (
        json.dumps(manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode()
    return store.load_archive(f"{hashlib.sha256(content).hexdigest()}.json")


def test_remote_publish_is_locked_atomic_and_uses_strict_ssh_options(tmp_path) -> None:
    store, manifest = _published_store(tmp_path)
    remote = FakeRemote()

    RemoteSnapshotPublisher(_config(), runner=remote).publish(store, manifest)

    remote_current = str(REMOTE_ROOT / "current" / "manifest.json")
    remote_lkg = str(REMOTE_ROOT / "last_known_good" / "manifest.json")
    manifest_digest = hashlib.sha256(
        (store.root / "current" / "manifest.json").read_bytes()
    ).hexdigest()
    remote_archive = str(REMOTE_ROOT / "manifests" / f"{manifest_digest}.json")
    assert remote.files[remote_current] == (store.root / "current" / "manifest.json").read_bytes()
    assert remote.files[remote_lkg] == remote.files[remote_current]
    assert remote.files[remote_archive] == remote.files[remote_current]
    assert remote.locked is False
    assert any(call[-2:] == ["mkdir", str(REMOTE_ROOT / ".publish.lock")] for call in remote.calls)
    for call in remote.calls:
        if call[0] in {"ssh", "scp"}:
            assert "BatchMode=yes" in call
            assert "StrictHostKeyChecking=yes" in call
            if call[0] == "ssh":
                assert "StdinNull=yes" in call
            else:
                assert "StdinNull=yes" not in call
            assert any(
                argument == SSH_TARGET or argument.startswith(f"{SSH_TARGET}:") for argument in call
            )
            assert "root" not in call
    assert not any("chown" in call for call in remote.calls)
    assert not any("install" in call for call in remote.calls)


def test_remote_publish_uses_captured_manifest_bytes_if_local_current_changes(
    tmp_path,
) -> None:
    store, first_manifest = _published_store(tmp_path)
    first_bytes = (store.root / "current" / "manifest.json").read_bytes()
    remote = FakeRemote()
    changed = False

    def racing_runner(command, **kwargs):
        nonlocal changed
        if not changed:
            changed = True
            next_snapshot = deepcopy(store.load("current").snapshot)
            next_snapshot["snapshot_id"] = "snapshot:test:concurrent-publish"
            store.publish(next_snapshot, published_at=PUBLISHED_AT)
        return remote(command, **kwargs)

    RemoteSnapshotPublisher(_config(), runner=racing_runner).publish(store, first_manifest)

    remote_current = str(REMOTE_ROOT / "current" / "manifest.json")
    assert remote.files[remote_current] == first_bytes
    assert (store.root / "current" / "manifest.json").read_bytes() != first_bytes


def test_non_root_publish_requires_precreated_remote_directories(tmp_path) -> None:
    store, manifest = _published_store(tmp_path)
    remote = FakeRemote()
    remote.directories.remove(str(REMOTE_ROOT / "objects"))

    with pytest.raises(RemotePublishError, match="non predisposta"):
        RemoteSnapshotPublisher(_config(), runner=remote).publish(store, manifest)

    assert not any(call[0] == "scp" for call in remote.calls)
    assert not any("chown" in call for call in remote.calls)


def test_remote_publish_releases_lock_when_upload_hash_is_invalid(tmp_path) -> None:
    store, manifest = _published_store(tmp_path)
    remote = FakeRemote()
    remote.corrupt_temporary_hash = True

    with pytest.raises(RemotePublishError, match="Hash upload"):
        RemoteSnapshotPublisher(_config(), runner=remote).publish(store, manifest)

    assert remote.locked is False


def test_current_transport_failure_is_reported_as_commit_unknown(tmp_path) -> None:
    store, manifest = _published_store(tmp_path)
    remote = FakeRemote()
    failed = False

    def uncertain_runner(command, **kwargs):
        nonlocal failed
        result = remote(command, **kwargs)
        call = list(command)
        if call[0] == "ssh":
            arguments = call[call.index(SSH_TARGET) + 1 :]
            if (
                not failed
                and arguments[0] == "mv"
                and arguments[-1] == str(REMOTE_ROOT / "current" / "manifest.json")
            ):
                failed = True
                raise subprocess.TimeoutExpired(call, 60)
        return result

    with pytest.raises(RemotePublishError) as caught:
        RemoteSnapshotPublisher(_config(), runner=uncertain_runner).publish(store, manifest)

    assert caught.value.committed is None
    assert str(REMOTE_ROOT / "current" / "manifest.json") in remote.files


def test_partial_publish_preserves_existing_remote_fresh_lkg(tmp_path) -> None:
    store, first_manifest = _published_store(tmp_path)
    remote = FakeRemote()
    publisher = RemoteSnapshotPublisher(_config(), runner=remote)
    publisher.publish(store, first_manifest)
    lkg_path = str(REMOTE_ROOT / "last_known_good" / "manifest.json")
    fresh_lkg = remote.files[lkg_path]

    partial = deepcopy(store.load("current").snapshot)
    partial["snapshot_id"] = "snapshot:test:remote-partial"
    partial["sync"]["state"] = "partial"
    partial_manifest = store.publish(partial, published_at=PUBLISHED_AT)
    publisher.publish(store, partial_manifest)

    assert remote.files[lkg_path] == fresh_lkg
    assert remote.locked is False


def test_remote_publish_refuses_an_existing_lock(tmp_path) -> None:
    store, manifest = _published_store(tmp_path)
    remote = FakeRemote()
    remote.locked = True

    with pytest.raises(RemotePublishError, match="già in corso"):
        RemoteSnapshotPublisher(_config(), runner=remote).publish(store, manifest)

    assert remote.locked is True


def test_remote_publish_reports_committed_when_lock_cleanup_fails(tmp_path) -> None:
    store, manifest = _published_store(tmp_path)
    remote = FakeRemote()
    remote.fail_lock_cleanup = True

    with pytest.raises(RemotePublishError, match="lock remoto non rimosso") as caught:
        RemoteSnapshotPublisher(_config(), runner=remote).publish(store, manifest)

    assert caught.value.committed is True
    assert remote.locked is True
    assert str(REMOTE_ROOT / "current" / "manifest.json") in remote.files


def test_batch_backfills_archives_in_publication_order_and_commits_current_last(
    tmp_path,
) -> None:
    store = AtomicSnapshotStore(tmp_path / "store")
    first = valid_snapshot()
    first["snapshot_id"] = "snapshot:test:backlog-1"
    first_manifest = store.publish(
        first,
        published_at=datetime(2026, 8, 3, 14, 40, tzinfo=UTC),
    )
    first_stored = _archived(store, first_manifest)

    second = deepcopy(first)
    second["snapshot_id"] = "snapshot:test:backlog-2"
    second_manifest = store.publish(
        second,
        published_at=datetime(2026, 8, 3, 14, 41, tzinfo=UTC),
    )
    second_stored = _archived(store, second_manifest)

    current = deepcopy(first)
    current["snapshot_id"] = "snapshot:test:backlog-current"
    current_manifest = store.publish(
        current,
        published_at=datetime(2026, 8, 3, 14, 42, tzinfo=UTC),
    )
    current_stored = _archived(store, current_manifest)

    remote = FakeRemote()
    publisher = RemoteSnapshotPublisher(_config(), runner=remote)
    summary = publisher.publish_batch(
        store,
        [second_stored, first_stored],
        current_stored,
    )

    assert summary.archives_requested == 2
    assert summary.archives_published == 2
    assert summary.archives_already_present == 0
    assert summary.current_archive_published == 1
    assert summary.current_updated == 1

    expected_archives = [
        str(REMOTE_ROOT / "manifests" / f"{_archived_digest(manifest)}.json")
        for manifest in (first_manifest, second_manifest, current_manifest)
    ]
    archive_commits = [
        call[-1]
        for call in remote.calls
        if call[0] == "ssh"
        and "mv" in call
        and call[-1].startswith(str(REMOTE_ROOT / "manifests"))
    ]
    assert archive_commits == expected_archives
    mutating_destinations = [
        call[-1]
        for call in remote.calls
        if call[0] == "ssh" and "mv" in call
    ]
    assert mutating_destinations[-1] == str(REMOTE_ROOT / "current" / "manifest.json")

    scp_calls = sum(call[0] == "scp" for call in remote.calls)
    second_call_start = len(remote.calls)
    second_summary = publisher.publish_batch(
        store,
        [first_stored, second_stored],
        current_stored,
    )
    second_calls = remote.calls[second_call_start:]
    assert second_summary.archives_published == 0
    assert second_summary.archives_already_present == 2
    assert second_summary.current_archive_already_present == 1
    assert second_summary.current_updated == 0
    assert sum(call[0] == "scp" for call in remote.calls) == scp_calls
    immutable_test_probes = []
    immutable_hash_batches = []
    for call in second_calls:
        if call[0] != "ssh":
            continue
        arguments = call[call.index(SSH_TARGET) + 1 :]
        if arguments[:2] == ["test", "-f"] and any(
            str(REMOTE_ROOT / directory) in arguments[-1]
            for directory in ("objects", "manifests")
        ):
            immutable_test_probes.append(arguments)
        if arguments[:2] == ["sha256sum", "--"]:
            relevant_paths = [
                value
                for value in arguments[2:]
                if str(REMOTE_ROOT / "objects") in value
                or str(REMOTE_ROOT / "manifests") in value
            ]
            if relevant_paths:
                immutable_hash_batches.append(relevant_paths)
    assert immutable_test_probes == []
    assert max(map(len, immutable_hash_batches)) >= 3


def _archived_digest(manifest: dict) -> str:
    content = (
        json.dumps(manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode()
    return hashlib.sha256(content).hexdigest()


def test_publish_stored_can_upload_an_archive_without_moving_current(tmp_path) -> None:
    store, manifest = _published_store(tmp_path)
    archived = _archived(store, manifest)
    remote = FakeRemote()

    summary = RemoteSnapshotPublisher(_config(), runner=remote).publish_stored(
        store,
        archived,
        commit_current=False,
    )

    assert summary.archives_published == 1
    assert summary.current_updated == 0
    assert str(REMOTE_ROOT / "current" / "manifest.json") not in remote.files
    assert (
        str(REMOTE_ROOT / "manifests" / f"{_archived_digest(manifest)}.json")
        in remote.files
    )


def test_remote_inventory_failure_is_not_treated_as_an_empty_directory(tmp_path) -> None:
    store, manifest = _published_store(tmp_path)
    remote = FakeRemote()

    def failing_probe(command, **kwargs):
        call = list(command)
        if call[0] == "ssh":
            arguments = call[call.index(SSH_TARGET) + 1 :]
            if arguments[0] == "find":
                raise subprocess.CalledProcessError(255, call, "", "")
        return remote(command, **kwargs)

    with pytest.raises(RemotePublishError, match="Comando ssh"):
        RemoteSnapshotPublisher(_config(), runner=failing_probe).publish(store, manifest)

    assert not any(call[0] == "scp" for call in remote.calls)


def _publish_snapshot(
    store: AtomicSnapshotStore,
    publisher: RemoteSnapshotPublisher,
    *,
    sequence: int,
    state: str = "partial",
):
    snapshot = valid_snapshot()
    snapshot["snapshot_id"] = f"snapshot:test:retention-{sequence}"
    snapshot["sync"]["state"] = state
    manifest = store.publish(
        snapshot,
        published_at=PUBLISHED_AT.replace(minute=sequence),
    )
    return manifest, publisher.publish_stored(
        store,
        _archived(store, manifest),
        commit_current=True,
    )


def test_retention_preserves_old_last_known_good_beyond_recent_window_and_orders_deletes(
    tmp_path,
) -> None:
    store = AtomicSnapshotStore(tmp_path / "store")
    remote = FakeRemote()
    publisher = RemoteSnapshotPublisher(_config(remote_retention=3), runner=remote)

    first, _ = _publish_snapshot(store, publisher, sequence=1, state="fresh")
    manifests = [first]
    for sequence in range(2, 6):
        manifest, summary = _publish_snapshot(store, publisher, sequence=sequence)
        manifests.append(manifest)

    first_digest = _archived_digest(first)
    second_digest = _archived_digest(manifests[1])
    assert (
        str(REMOTE_ROOT / "manifests" / f"{first_digest}.json")
        in remote.files
    )
    assert (
        str(REMOTE_ROOT / "manifests" / f"{second_digest}.json")
        not in remote.files
    )
    assert str(REMOTE_ROOT / "objects" / first["object_name"]) in remote.files
    assert str(REMOTE_ROOT / "objects" / manifests[1]["object_name"]) not in remote.files
    assert summary.manifests_deleted == 1
    assert summary.objects_deleted == 1

    exact_removals = [
        call
        for call in remote.calls
        if call[0] == "ssh" and "rm" in call and "--" in call
    ]
    assert exact_removals[-2][-1].startswith(str(REMOTE_ROOT / "manifests"))
    assert exact_removals[-1][-1].startswith(str(REMOTE_ROOT / "objects"))


def test_retention_with_no_extra_files_reports_zero_and_issues_no_exact_delete(
    tmp_path,
) -> None:
    store = AtomicSnapshotStore(tmp_path / "store")
    remote = FakeRemote()
    publisher = RemoteSnapshotPublisher(_config(remote_retention=3), runner=remote)

    _, summary = _publish_snapshot(store, publisher, sequence=1, state="fresh")

    assert summary.manifests_deleted == 0
    assert summary.objects_deleted == 0
    assert not any(
        call[0] == "ssh" and "rm" in call and "--" in call
        for call in remote.calls
    )


@pytest.mark.parametrize("corruption", ["hash", "object_hash", "json", "symlink"])
def test_retention_fails_closed_before_delete_and_releases_lock_after_commit(
    tmp_path,
    corruption: str,
) -> None:
    store = AtomicSnapshotStore(tmp_path / "store")
    remote = FakeRemote()
    publisher = RemoteSnapshotPublisher(_config(remote_retention=3), runner=remote)
    first, _ = _publish_snapshot(store, publisher, sequence=1, state="fresh")
    archive_path = str(
        REMOTE_ROOT / "manifests" / f"{_archived_digest(first)}.json"
    )
    if corruption == "hash":
        remote.files[archive_path] += b"corrupt"
    elif corruption == "object_hash":
        remote.files[str(REMOTE_ROOT / "objects" / first["object_name"])] += b"corrupt"
    elif corruption == "json":
        invalid = b"not-json\n"
        digest = hashlib.sha256(invalid).hexdigest()
        remote.files[str(REMOTE_ROOT / "manifests" / f"{digest}.json")] = invalid
    else:
        remote.symlinks.add(archive_path)

    calls_before = len(remote.calls)
    snapshot = valid_snapshot()
    snapshot["snapshot_id"] = f"snapshot:test:retention-corrupt-{corruption}"
    snapshot["sync"]["state"] = "partial"
    manifest = store.publish(
        snapshot,
        published_at=PUBLISHED_AT.replace(minute=2),
    )
    with pytest.raises(RemotePublishError, match="retention remota") as caught:
        publisher.publish_stored(
            store,
            _archived(store, manifest),
            commit_current=True,
        )

    assert caught.value.committed is True
    assert remote.locked is False
    assert str(REMOTE_ROOT / "current" / "manifest.json") in remote.files
    assert not any(
        call[0] == "ssh" and "rm" in call and "--" in call
        for call in remote.calls[calls_before:]
    )


def test_retention_delete_failure_is_committed_and_lock_is_still_released(
    tmp_path,
) -> None:
    store = AtomicSnapshotStore(tmp_path / "store")
    remote = FakeRemote()
    publisher = RemoteSnapshotPublisher(_config(remote_retention=3), runner=remote)
    _publish_snapshot(store, publisher, sequence=1, state="fresh")
    for sequence in range(2, 5):
        _publish_snapshot(store, publisher, sequence=sequence)
    remote.fail_exact_remove = True

    snapshot = valid_snapshot()
    snapshot["snapshot_id"] = "snapshot:test:retention-delete-failure"
    snapshot["sync"]["state"] = "partial"
    manifest = store.publish(
        snapshot,
        published_at=PUBLISHED_AT.replace(minute=5),
    )
    with pytest.raises(RemotePublishError, match="retention remota") as caught:
        publisher.publish_stored(
            store,
            _archived(store, manifest),
            commit_current=True,
        )

    assert caught.value.committed is True
    assert remote.locked is False
    assert remote.fail_exact_remove is True


def test_retention_never_deletes_object_still_referenced_by_kept_manifest(
    tmp_path,
) -> None:
    store = AtomicSnapshotStore(tmp_path / "store")
    remote = FakeRemote()
    publisher = RemoteSnapshotPublisher(_config(remote_retention=3), runner=remote)
    shared = valid_snapshot()
    shared["snapshot_id"] = "snapshot:test:shared-object"
    first = store.publish(shared, published_at=PUBLISHED_AT.replace(minute=1))
    publisher.publish(store, first)
    shared_object = str(REMOTE_ROOT / "objects" / first["object_name"])

    for sequence in range(2, 5):
        if sequence == 4:
            snapshot = deepcopy(shared)
            published_at = PUBLISHED_AT.replace(minute=4)
        else:
            snapshot = valid_snapshot()
            snapshot["snapshot_id"] = f"snapshot:test:unique-{sequence}"
            snapshot["sync"]["state"] = "partial"
            published_at = PUBLISHED_AT.replace(minute=sequence)
        manifest = store.publish(snapshot, published_at=published_at)
        publisher.publish(store, manifest)

    # The oldest archive is outside the recent window, but the newest current
    # archive references the exact same content-addressed object.
    assert shared_object in remote.files


def test_pointer_without_archive_still_protects_legacy_object(tmp_path) -> None:
    store = AtomicSnapshotStore(tmp_path / "store")
    remote = FakeRemote()
    publisher = RemoteSnapshotPublisher(_config(remote_retention=3), runner=remote)
    first, _ = _publish_snapshot(store, publisher, sequence=1, state="fresh")
    first_archive = str(
        REMOTE_ROOT / "manifests" / f"{_archived_digest(first)}.json"
    )
    first_object = str(REMOTE_ROOT / "objects" / first["object_name"])
    remote.files.pop(first_archive)

    _, summary = _publish_snapshot(store, publisher, sequence=2, state="partial")

    assert summary.manifests_deleted == 0
    assert summary.objects_deleted == 0
    assert first_object in remote.files
