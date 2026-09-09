"""Persistent trend history with retention for the DTLab v3 snapshots.

The history store distils each snapshot into a small set of scalar KPIs and keeps
them over time so the front-end can draw trends without re-reading every archived
snapshot. Retention is explicit and bounded: a resolution bucket (raw/hourly/
daily), a maximum number of points, and a maximum age in days. Metrics from
incompatible scales are never combined into a single number — each KPI stays in
its own named series, mirroring the v2 discipline.
"""

from __future__ import annotations

import json
import os
import tempfile
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

DEFAULT_RETENTION: dict[str, Any] = {
    "max_points": 365,
    "max_age_days": 365,
    "resolution": "daily",
}


class HistoryStoreError(RuntimeError):
    """The history store could not be read or written safely."""


def _parse(ts: str) -> datetime:
    parsed = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _mean_int(values: list[float]) -> int | None:
    if not values:
        return None
    return int(round(sum(values) / len(values)))


def derive_metrics(snapshot: Mapping[str, Any]) -> dict[str, float | int | None]:
    """Reduce a v3 (or v2) snapshot to named scalar KPIs for the trend history."""

    risk_scores = snapshot.get("risk_scores", [])
    correlations = snapshot.get("detection_correlations", [])
    attack_runs = snapshot.get("attack_runs", [])
    findings = snapshot.get("findings", [])
    vulnerabilities = snapshot.get("vulnerabilities", [])
    compliance = snapshot.get("compliance_mappings", [])

    detected = [c for c in correlations if c.get("detected") is True]
    undetected = [c for c in correlations if c.get("detected") is False]
    latencies = [
        float(c["detection_latency_seconds"])
        for c in detected
        if isinstance(c.get("detection_latency_seconds"), (int, float))
    ]
    covered = sum(1 for m in compliance if m.get("status") == "covered")

    coverage: float | None = None
    if attack_runs:
        coverage = round(len(detected) / len(attack_runs), 4)

    return {
        "high_risk_assets": sum(1 for r in risk_scores if r.get("band") == "high"),
        "medium_risk_assets": sum(1 for r in risk_scores if r.get("band") == "medium"),
        "attack_runs": len(attack_runs),
        "detections": len(detected),
        "undetected_attacks": len(undetected),
        "mean_detection_latency_seconds": _mean_int(latencies),
        "attack_detection_coverage": coverage,
        "open_findings": sum(1 for f in findings if f.get("status") == "open"),
        "open_vulnerabilities": sum(1 for v in vulnerabilities if v.get("status") == "open"),
        "compliance_controls": len(compliance),
        "compliance_covered": covered,
        "quality_score": snapshot.get("quality", {}).get("score"),
    }


def _bucket_key(ts: str, resolution: str) -> str:
    moment = _parse(ts)
    if resolution == "daily":
        return moment.strftime("%Y-%m-%d")
    if resolution == "hourly":
        return moment.strftime("%Y-%m-%dT%H")
    return ts


def prune_points(
    points: list[dict[str, Any]],
    retention: Mapping[str, Any],
    *,
    now: datetime | None = None,
) -> list[dict[str, Any]]:
    """Collapse points into retention buckets and drop stale/excess ones."""

    resolution = str(retention.get("resolution", "daily"))
    max_points = int(retention.get("max_points", DEFAULT_RETENTION["max_points"]))
    max_age_days = int(retention.get("max_age_days", DEFAULT_RETENTION["max_age_days"]))
    reference = (now or datetime.now(UTC)).astimezone(UTC)
    cutoff = reference - timedelta(days=max_age_days)

    ordered = sorted(points, key=lambda point: _parse(point["generated_at"]))
    # Keep the most recent point per bucket.
    by_bucket: dict[str, dict[str, Any]] = {}
    for point in ordered:
        by_bucket[_bucket_key(point["generated_at"], resolution)] = point

    kept = [
        point
        for point in by_bucket.values()
        if _parse(point["generated_at"]) >= cutoff
    ]
    kept.sort(key=lambda point: _parse(point["generated_at"]))
    if len(kept) > max_points:
        kept = kept[-max_points:]
    return kept


class HistoryStore:
    """A JSON-backed, atomically-written trend history."""

    def __init__(self, path: str | Path, *, retention: Mapping[str, Any] | None = None):
        self.path = Path(path)
        self._retention = dict(retention or DEFAULT_RETENTION)

    def load(self) -> dict[str, Any]:
        if not self.path.exists():
            return {"retention": dict(self._retention), "points": []}
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise HistoryStoreError(f"History store illeggibile: {exc}") from exc
        if not isinstance(data, dict) or "points" not in data:
            raise HistoryStoreError("History store con struttura non valida.")
        data.setdefault("retention", dict(self._retention))
        return data

    def _write(self, history: Mapping[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(history, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
        temp_name: str | None = None
        try:
            with tempfile.NamedTemporaryFile(
                "w", encoding="utf-8", dir=self.path.parent, delete=False, suffix=".tmp"
            ) as handle:
                temp_name = handle.name
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_name, self.path)
            temp_name = None
        finally:
            if temp_name and os.path.exists(temp_name):
                os.unlink(temp_name)

    def record(
        self, snapshot: Mapping[str, Any], *, now: datetime | None = None
    ) -> dict[str, Any]:
        """Derive a point from ``snapshot``, append it, prune, and persist."""

        history = self.load()
        history["retention"] = dict(self._retention)
        point = {
            "snapshot_id": str(snapshot["snapshot_id"]),
            "generated_at": str(snapshot["generated_at"]),
            "metrics": derive_metrics(snapshot),
        }
        snapshot_id = point["snapshot_id"]
        points = [
            p for p in history.get("points", []) if p.get("snapshot_id") != snapshot_id
        ]
        points.append(point)
        history["points"] = prune_points(points, self._retention, now=now)
        self._write(history)
        return history
