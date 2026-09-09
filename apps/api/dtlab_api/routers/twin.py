"""Digital twin: Modbus process telemetry time series."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query

from dtlab_api.deps import get_provider
from dtlab_api.security import require_role
from dtlab_api.snapshot_provider import SnapshotProvider

router = APIRouter(
    prefix="/api",
    tags=["digital-twin"],
    dependencies=[Depends(require_role("viewer"))],
)


def _ordered(samples: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(samples, key=lambda s: s.get("sample_index", 0))


@router.get("/telemetry")
def list_telemetry(
    provider: SnapshotProvider = Depends(get_provider),
    asset_id: str | None = Query(None),
    limit: int = Query(500, ge=1, le=5000),
) -> dict:
    items = _ordered(provider.collection("process_telemetry"))
    if asset_id:
        items = [s for s in items if s.get("asset_id") == asset_id]
    items = items[-limit:]
    return {"count": len(items), "items": items}


@router.get("/telemetry/latest")
def latest_telemetry(provider: SnapshotProvider = Depends(get_provider)) -> dict:
    samples = _ordered(provider.collection("process_telemetry"))
    if not samples:
        raise HTTPException(status_code=404, detail="Nessun campione di telemetria.")
    return samples[-1]


@router.get("/telemetry/registers")
def register_names(provider: SnapshotProvider = Depends(get_provider)) -> dict:
    names: list[str] = []
    seen: set[str] = set()
    for sample in provider.collection("process_telemetry"):
        for register in sample.get("registers", []):
            name = register.get("name")
            if name and name not in seen:
                seen.add(name)
                names.append(name)
    return {"count": len(names), "items": names}


@router.get("/telemetry/series")
def register_series(
    register: str = Query(..., description="Nome del registro Modbus."),
    provider: SnapshotProvider = Depends(get_provider),
) -> dict:
    points = []
    for sample in _ordered(provider.collection("process_telemetry")):
        match = next(
            (r for r in sample.get("registers", []) if r.get("name") == register),
            None,
        )
        if match is None:
            continue
        points.append({
            "sample_index": sample.get("sample_index"),
            "captured_at": sample.get("captured_at"),
            "value": match.get("value"),
            "in_bounds": match.get("in_bounds"),
            "belt_state": sample.get("belt_state"),
            "anomaly": sample.get("anomaly"),
        })
    if not points:
        raise HTTPException(status_code=404, detail=f"Registro '{register}' non trovato.")
    unit = next((r.get("unit") for s in provider.collection("process_telemetry")
                 for r in s.get("registers", []) if r.get("name") == register), None)
    return {"register": register, "unit": unit, "count": len(points), "points": points}
