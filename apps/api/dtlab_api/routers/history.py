"""Trend history and per-metric series."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from dtlab_api.deps import get_provider
from dtlab_api.security import require_role
from dtlab_api.snapshot_provider import SnapshotProvider

router = APIRouter(
    prefix="/api",
    tags=["history"],
    dependencies=[Depends(require_role("viewer"))],
)


def _history(provider: SnapshotProvider) -> dict:
    return provider.snapshot.get("history") or {"retention": {}, "points": []}


@router.get("/history")
def history(provider: SnapshotProvider = Depends(get_provider)) -> dict:
    return _history(provider)


@router.get("/history/metrics")
def history_metrics(provider: SnapshotProvider = Depends(get_provider)) -> dict:
    points = _history(provider)["points"]
    names: list[str] = []
    seen: set[str] = set()
    for point in points:
        for name in point.get("metrics", {}):
            if name not in seen:
                seen.add(name)
                names.append(name)
    return {"count": len(names), "items": names}


@router.get("/history/series/{metric}")
def history_series(metric: str, provider: SnapshotProvider = Depends(get_provider)) -> dict:
    points = _history(provider)["points"]
    series = [
        {
            "snapshot_id": point.get("snapshot_id"),
            "generated_at": point.get("generated_at"),
            "value": point.get("metrics", {}).get(metric),
        }
        for point in points
        if metric in point.get("metrics", {})
    ]
    if not series:
        raise HTTPException(status_code=404, detail=f"Metrica '{metric}' non trovata.")
    return {"metric": metric, "count": len(series), "points": series}
