"""Compliance & architecture: Purdue/IEC 62443 zones and framework coverage."""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from fastapi import APIRouter, Depends, Query

from dtlab_api.deps import get_provider
from dtlab_api.security import require_role
from dtlab_api.snapshot_provider import SnapshotProvider

router = APIRouter(
    prefix="/api",
    tags=["compliance"],
    dependencies=[Depends(require_role("viewer"))],
)

_STATUSES = ("covered", "partial", "not_covered", "not_applicable", "planned")


@router.get("/security-zones")
def list_zones(provider: SnapshotProvider = Depends(get_provider)) -> dict:
    items = provider.collection("security_zones")
    return {"count": len(items), "items": items}


@router.get("/purdue")
def purdue_model(provider: SnapshotProvider = Depends(get_provider)) -> dict:
    """Zones grouped by Purdue level, for the interactive model."""

    by_level: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for zone in provider.collection("security_zones"):
        by_level[str(zone.get("purdue_level", "unknown"))].append(zone)
    levels = [
        {"level": level, "zones": by_level[level]}
        for level in sorted(by_level, key=lambda x: (x == "unknown", x))
    ]
    return {"levels": levels}


@router.get("/compliance-mappings")
def list_mappings(
    provider: SnapshotProvider = Depends(get_provider),
    framework: str | None = Query(None),
    status: str | None = Query(None),
) -> dict:
    items = provider.collection("compliance_mappings")
    if framework:
        items = [m for m in items if m.get("framework") == framework]
    if status:
        items = [m for m in items if m.get("status") == status]
    return {"count": len(items), "items": items}


@router.get("/compliance/coverage")
def coverage(provider: SnapshotProvider = Depends(get_provider)) -> dict:
    """Coverage per framework: counts by status plus a covered ratio."""

    per_framework: dict[str, dict[str, int]] = defaultdict(
        lambda: {status: 0 for status in _STATUSES}
    )
    for mapping in provider.collection("compliance_mappings"):
        framework = mapping.get("framework", "unknown")
        status = mapping.get("status", "not_covered")
        per_framework.setdefault(framework, {s: 0 for s in _STATUSES})
        per_framework[framework][status] = per_framework[framework].get(status, 0) + 1

    frameworks = []
    for framework, counts in sorted(per_framework.items()):
        total = sum(counts.values())
        applicable = total - counts.get("not_applicable", 0)
        covered = counts.get("covered", 0)
        frameworks.append({
            "framework": framework,
            "total": total,
            "counts": counts,
            "covered_ratio": round(covered / applicable, 4) if applicable else None,
        })
    return {"frameworks": frameworks}
