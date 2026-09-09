"""Tests for the trend history store and its retention policy."""

from __future__ import annotations

from datetime import UTC, datetime

from dtlab.sandbox import build_sandbox_snapshot
from dtlab.services.history_store import (
    HistoryStore,
    derive_metrics,
    prune_points,
)


def _point(generated_at: str, snapshot_id: str = "s") -> dict:
    return {"snapshot_id": snapshot_id, "generated_at": generated_at, "metrics": {}}


def _daily(max_points: int = 365, max_age_days: int = 365) -> dict:
    return {"resolution": "daily", "max_points": max_points, "max_age_days": max_age_days}


def test_derive_metrics_from_sandbox() -> None:
    metrics = derive_metrics(build_sandbox_snapshot())
    assert metrics["attack_runs"] == 4
    assert metrics["detections"] == 3
    assert metrics["undetected_attacks"] == 1
    assert metrics["attack_detection_coverage"] == 0.75
    assert metrics["mean_detection_latency_seconds"] is not None
    assert metrics["quality_score"] == 88


def test_derive_metrics_handles_empty_v2_snapshot() -> None:
    metrics = derive_metrics({"quality": {"score": 50}})
    assert metrics["attack_runs"] == 0
    assert metrics["attack_detection_coverage"] is None
    assert metrics["mean_detection_latency_seconds"] is None
    assert metrics["quality_score"] == 50


def test_prune_collapses_daily_buckets() -> None:
    now = datetime(2026, 8, 7, 12, 0, tzinfo=UTC)
    points = [
        _point("2026-08-07T08:00:00Z", "a"),
        _point("2026-08-07T09:00:00Z", "b"),  # same day -> keeps latest (b)
        _point("2026-08-06T09:00:00Z", "c"),
    ]
    kept = prune_points(points, _daily(), now=now)
    ids = [p["snapshot_id"] for p in kept]
    assert ids == ["c", "b"]


def test_prune_drops_points_older_than_max_age() -> None:
    now = datetime(2026, 8, 7, 12, 0, tzinfo=UTC)
    points = [
        _point("2026-08-01T09:00:00Z", "old"),
        _point("2026-08-07T09:00:00Z", "fresh"),
    ]
    kept = prune_points(points, _daily(max_age_days=3), now=now)
    assert [p["snapshot_id"] for p in kept] == ["fresh"]


def test_prune_caps_max_points() -> None:
    now = datetime(2026, 8, 10, tzinfo=UTC)
    points = [_point(f"2026-08-0{d}T09:00:00Z", f"d{d}") for d in range(1, 8)]
    kept = prune_points(points, _daily(max_points=3), now=now)
    assert [p["snapshot_id"] for p in kept] == ["d5", "d6", "d7"]


def test_record_persists_and_is_idempotent_per_snapshot(tmp_path) -> None:
    store = HistoryStore(tmp_path / "history.json")
    snapshot = build_sandbox_snapshot()
    store.record(snapshot)
    history = store.record(snapshot)  # same snapshot_id twice
    assert len(history["points"]) == 1
    assert (tmp_path / "history.json").exists()
    reloaded = store.load()
    assert reloaded["points"][0]["snapshot_id"] == snapshot["snapshot_id"]
    assert reloaded["points"][0]["metrics"]["detections"] == 3


def test_recorded_history_validates_against_v3_schema(tmp_path) -> None:
    """A recorded history must fit the v3 ``history`` sub-schema when embedded."""

    from dtlab import contract_v3 as c3

    store = HistoryStore(tmp_path / "history.json")
    history = store.record(build_sandbox_snapshot())
    snap = build_sandbox_snapshot()
    snap["history"] = history
    c3.validate_snapshot_v3(snap)
