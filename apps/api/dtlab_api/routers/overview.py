"""War-room overview: a single aggregate for the dashboard landing page."""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from fastapi import APIRouter, Depends

from dtlab_api.deps import get_provider
from dtlab_api.security import require_role
from dtlab_api.snapshot_provider import SnapshotProvider

router = APIRouter(prefix="/api", tags=["overview"])

_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}


@router.get("/overview", dependencies=[Depends(require_role("viewer"))])
def overview(provider: SnapshotProvider = Depends(get_provider)) -> dict:
    snap = provider.snapshot
    metrics = provider.metrics()

    runs = provider.collection("attack_runs")
    correlations = provider.collection("detection_correlations")
    detected = [c for c in correlations if c.get("detected") is True]

    # Compliance coverage per framework (covered / applicable).
    per_framework: dict[str, dict[str, int]] = defaultdict(lambda: {"covered": 0, "applicable": 0})
    for mapping in provider.collection("compliance_mappings"):
        framework = mapping.get("framework", "unknown")
        status = mapping.get("status")
        if status != "not_applicable":
            per_framework[framework]["applicable"] += 1
        if status == "covered":
            per_framework[framework]["covered"] += 1
    compliance = {
        framework: round(v["covered"] / v["applicable"], 4) if v["applicable"] else None
        for framework, v in sorted(per_framework.items())
    }

    telemetry = sorted(
        provider.collection("process_telemetry"), key=lambda s: s.get("sample_index", 0)
    )
    latest_twin = telemetry[-1] if telemetry else None

    top_risk = sorted(
        provider.collection("risk_scores"), key=lambda r: r.get("score", 0), reverse=True
    )[:5]
    recent_events = sorted(
        provider.collection("events"),
        key=lambda e: (_SEVERITY_RANK.get(e.get("severity", "unknown"), 5),
                       e.get("occurred_at", "")),
    )[:5]

    attack_timeline: list[dict[str, Any]] = []
    correlations_by_run = {c.get("attack_run_id"): c for c in correlations}
    scenarios = {s["id"]: s for s in provider.collection("attack_scenarios")}
    for run in sorted(runs, key=lambda r: r.get("started_at") or ""):
        correlation = correlations_by_run.get(run["id"], {})
        scenario = scenarios.get(run.get("scenario_id"), {})
        attack_timeline.append({
            "run_id": run["id"],
            "scenario_name": scenario.get("name"),
            "started_at": run.get("started_at"),
            "outcome": run.get("outcome"),
            "detected": correlation.get("detected"),
            "detection_latency_seconds": correlation.get("detection_latency_seconds"),
        })

    return {
        "meta": provider.meta(),
        "sync": snap.get("sync"),
        "kpis": {
            "assets": len(provider.collection("assets")),
            "high_risk_assets": metrics["high_risk_assets"],
            "open_findings": metrics["open_findings"],
            "open_vulnerabilities": metrics["open_vulnerabilities"],
            "attack_runs": len(runs),
            "detections": len(detected),
            "detection_coverage": metrics["attack_detection_coverage"],
            "mean_detection_latency_seconds": metrics["mean_detection_latency_seconds"],
            "quality_score": metrics["quality_score"],
        },
        "compliance_coverage": compliance,
        "digital_twin": None if latest_twin is None else {
            "captured_at": latest_twin.get("captured_at"),
            "belt_state": latest_twin.get("belt_state"),
            "anomaly": latest_twin.get("anomaly"),
        },
        "top_risk_assets": top_risk,
        "recent_events": recent_events,
        "attack_timeline": attack_timeline,
    }
