from __future__ import annotations

import hashlib
import json
import os
from copy import deepcopy
from datetime import UTC, datetime

import pytest

from dtlab.contract import ContractValidationError
from dtlab.services.snapshot_store import AtomicSnapshotStore, SnapshotStoreError
from tests.factories import valid_snapshot

PUBLISHED_AT = datetime(2026, 8, 3, 12, 30, tzinfo=UTC)


def test_publish_creates_verified_current_and_last_known_good(tmp_path) -> None:
    store = AtomicSnapshotStore(tmp_path)
    snapshot = valid_snapshot()

    manifest = store.publish(snapshot, published_at=PUBLISHED_AT)

    assert manifest["trusted_origin"] == "dtlab_collector"
    assert store.load("current").snapshot == snapshot
    assert store.load("last_known_good").snapshot == snapshot
    assert (tmp_path / "objects" / manifest["object_name"]).is_file()


def test_second_publish_preserves_previous_snapshot(tmp_path) -> None:
    store = AtomicSnapshotStore(tmp_path)
    first = valid_snapshot()
    second = deepcopy(first)
    second["snapshot_id"] = "snapshot:test:0002"
    second["quality"]["score"] = 73

    store.publish(first, published_at=PUBLISHED_AT)
    store.publish(second, published_at=PUBLISHED_AT)

    assert store.load("current").snapshot["snapshot_id"] == "snapshot:test:0002"
    assert store.load("previous").snapshot["snapshot_id"] == "snapshot:test:0001"


def test_partial_publish_does_not_replace_an_existing_fresh_lkg(tmp_path) -> None:
    store = AtomicSnapshotStore(tmp_path)
    initial = valid_snapshot()
    fresh = deepcopy(initial)
    fresh["snapshot_id"] = "snapshot:test:fresh"
    fresh["sync"]["state"] = "fresh"
    later_partial = deepcopy(initial)
    later_partial["snapshot_id"] = "snapshot:test:partial-later"

    store.publish(initial, published_at=PUBLISHED_AT)
    store.publish(fresh, published_at=PUBLISHED_AT)
    store.publish(later_partial, published_at=PUBLISHED_AT)

    assert store.load("current").snapshot["snapshot_id"] == later_partial["snapshot_id"]
    assert store.load("last_known_good").snapshot["snapshot_id"] == fresh["snapshot_id"]


def test_invalid_snapshot_does_not_replace_current(tmp_path) -> None:
    store = AtomicSnapshotStore(tmp_path)
    valid = valid_snapshot()
    store.publish(valid, published_at=PUBLISHED_AT)
    invalid = deepcopy(valid)
    invalid["risk_scores"] = [
        {
            "id": "risk:fake",
            "evidence": invalid["virtual_machines"][0]["evidence"],
            "asset_id": "asset:missing",
            "score": 68,
            "band": "medium",
            "methodology": "cisco_cyber_vision",
            "computed_at": None,
            "factors": [],
        }
    ]

    with pytest.raises(ContractValidationError):
        store.publish(invalid, published_at=PUBLISHED_AT)

    assert store.load("current").snapshot == valid


def test_corrupt_current_falls_back_to_previous_and_never_to_demo(tmp_path) -> None:
    store = AtomicSnapshotStore(tmp_path)
    first = valid_snapshot()
    second = deepcopy(first)
    second["snapshot_id"] = "snapshot:test:0002"
    second["quality"]["score"] = 73
    store.publish(first, published_at=PUBLISHED_AT)
    second_manifest = store.publish(second, published_at=PUBLISHED_AT)
    object_path = tmp_path / "objects" / second_manifest["object_name"]
    object_path.write_text("{}", encoding="utf-8")

    loaded = store.load_best_available()

    assert loaded.pointer == "last_known_good"
    assert loaded.snapshot["snapshot_id"] == "snapshot:test:0001"


def test_operational_store_rejects_demo_publication_mode(tmp_path) -> None:
    store = AtomicSnapshotStore(tmp_path)
    snapshot = valid_snapshot()
    snapshot["sync"]["publication_mode"] = "allow_demo"

    with pytest.raises(SnapshotStoreError, match="real_only"):
        store.publish(snapshot, published_at=PUBLISHED_AT)


def test_manifest_cannot_redirect_outside_object_store(tmp_path) -> None:
    store = AtomicSnapshotStore(tmp_path)
    snapshot = valid_snapshot()
    store.publish(snapshot, published_at=PUBLISHED_AT)
    manifest_path = tmp_path / "current" / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["object_name"] = "../../outside.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(SnapshotStoreError, match="object_name"):
        store.load("current")


def test_read_only_store_open_does_not_create_or_chmod_layout(tmp_path) -> None:
    missing = tmp_path / "missing"

    store = AtomicSnapshotStore(missing, create_layout=False)

    assert not missing.exists()
    with pytest.raises(SnapshotStoreError, match="non disponibile"):
        store.load_best_available()
    assert not missing.exists()


def test_load_archive_and_prune_keep_archives_in_lockstep_with_objects(tmp_path) -> None:
    store = AtomicSnapshotStore(tmp_path)
    published: list[tuple[str, str]] = []
    for index in range(1, 7):
        snapshot = valid_snapshot()
        snapshot["snapshot_id"] = f"snapshot:test:prune-{index}"
        manifest = store.publish(snapshot, published_at=PUBLISHED_AT)
        object_path = store.objects / manifest["object_name"]
        os.utime(object_path, (index, index))
        manifest_content = (store.root / "current" / "manifest.json").read_bytes()
        archive_name = f"{hashlib.sha256(manifest_content).hexdigest()}.json"
        assert store.load_archive(archive_name).snapshot["snapshot_id"] == snapshot["snapshot_id"]
        published.append((manifest["object_name"], archive_name))

    orphan_manifest = dict(store.load("current").manifest)
    orphan_manifest["sha256"] = "f" * 64
    orphan_manifest["object_name"] = f"{'f' * 64}.json"
    orphan_content = (
        json.dumps(
            orphan_manifest,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode()
    orphan_name = f"{hashlib.sha256(orphan_content).hexdigest()}.json"
    (store.manifests / orphan_name).write_bytes(orphan_content)

    removed = store.prune_objects(retain=3)

    removed_names = {path.name for path in removed}
    # Current, previous, LKG, and the newest retained objects all remain loadable.
    assert store.load("current").snapshot["snapshot_id"] == "snapshot:test:prune-6"
    assert store.load("previous").snapshot["snapshot_id"] == "snapshot:test:prune-5"
    assert store.load("last_known_good").snapshot["snapshot_id"] == "snapshot:test:prune-1"
    for object_name, archive_name in published:
        object_kept = (store.objects / object_name).exists()
        assert (store.manifests / archive_name).exists() is object_kept
        if object_kept:
            assert store.load_archive(archive_name).manifest["object_name"] == object_name
        else:
            assert object_name in removed_names
            assert archive_name in removed_names
    assert orphan_name in removed_names
    assert not (store.manifests / orphan_name).exists()
