"""Security operations: events, risk, vulnerabilities, flows, baseline, findings."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from dtlab_api.deps import get_provider
from dtlab_api.security import require_role
from dtlab_api.snapshot_provider import SnapshotProvider

router = APIRouter(
    prefix="/api",
    tags=["security"],
    dependencies=[Depends(require_role("viewer"))],
)

_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}


def _envelope(items: list[dict]) -> dict:
    return {"count": len(items), "items": items}


@router.get("/events")
def list_events(
    provider: SnapshotProvider = Depends(get_provider),
    severity: str | None = Query(None),
) -> dict:
    items = provider.collection("events")
    if severity:
        items = [e for e in items if e.get("severity") == severity]
    items = sorted(items, key=lambda e: _SEVERITY_RANK.get(e.get("severity", "unknown"), 5))
    return _envelope(items)


@router.get("/risk-scores")
def list_risk_scores(provider: SnapshotProvider = Depends(get_provider)) -> dict:
    items = sorted(
        provider.collection("risk_scores"),
        key=lambda r: r.get("score", 0),
        reverse=True,
    )
    return _envelope(items)


@router.get("/vulnerabilities")
def list_vulnerabilities(provider: SnapshotProvider = Depends(get_provider)) -> dict:
    return _envelope(provider.collection("vulnerabilities"))


@router.get("/flows")
def list_flows(provider: SnapshotProvider = Depends(get_provider)) -> dict:
    return _envelope(provider.collection("flows"))


@router.get("/activities")
def list_activities(provider: SnapshotProvider = Depends(get_provider)) -> dict:
    return _envelope(provider.collection("activities"))


@router.get("/baselines")
def list_baselines(provider: SnapshotProvider = Depends(get_provider)) -> dict:
    return _envelope(provider.collection("baselines"))


@router.get("/baseline-differences")
def list_baseline_differences(provider: SnapshotProvider = Depends(get_provider)) -> dict:
    return _envelope(provider.collection("baseline_differences"))


@router.get("/findings")
def list_findings(provider: SnapshotProvider = Depends(get_provider)) -> dict:
    return _envelope(provider.collection("findings"))


@router.get("/vulnerability-catalog")
def vulnerability_catalog(provider: SnapshotProvider = Depends(get_provider)) -> dict:
    """Global Cisco CVE index, kept separate from per-device associations."""

    for source in provider.collection("sources"):
        if source.get("type") == "cisco_cyber_vision":
            catalog = source.get("details", {}).get("vulnerability_catalog", [])
            capability = source.get("capabilities", {}).get("vulnerabilities")
            return {
                "count": len(catalog),
                "items": catalog,
                "capability_available": bool(capability and capability.get("status") == "ok"),
            }
    return {"count": 0, "items": [], "capability_available": False}


@router.get("/risk/distribution")
def risk_distribution(provider: SnapshotProvider = Depends(get_provider)) -> dict:
    """Per-device Cisco risk bands. Read straight from the source, never recomputed."""

    scores = provider.collection("risk_scores")
    bands = {"low": 0, "medium": 0, "high": 0}
    for score in scores:
        band = score.get("band")
        if band in bands:
            bands[band] += 1
    return {"total": len(scores), "bands": bands, "methodology": "cisco_cyber_vision"}
