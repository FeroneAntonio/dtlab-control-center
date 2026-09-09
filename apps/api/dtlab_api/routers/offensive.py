"""Offensive domain: attack scenarios, runs and detection correlations.

Read-only against the current snapshot. Runs are joined to their detection
correlation so the front-end can draw the attack→detection timeline and the
MITRE ATT&CK coverage matrix directly from one call.
"""

from __future__ import annotations

from statistics import median
from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from dtlab_api.deps import get_provider
from dtlab_api.security import require_role
from dtlab_api.snapshot_provider import SnapshotProvider

router = APIRouter(
    prefix="/api",
    tags=["offensive"],
    dependencies=[Depends(require_role("viewer"))],
)


def _correlations_by_run(provider: SnapshotProvider) -> dict[str, dict[str, Any]]:
    return {
        c["attack_run_id"]: c
        for c in provider.collection("detection_correlations")
        if c.get("attack_run_id")
    }


def _enrich_run(run: dict[str, Any], correlation: dict[str, Any] | None) -> dict[str, Any]:
    enriched = dict(run)
    if correlation is None:
        enriched["detection"] = None
        enriched["detected"] = None
    else:
        enriched["detection"] = {
            "detected": correlation.get("detected"),
            "detection_source": correlation.get("detection_source"),
            "detection_latency_seconds": correlation.get("detection_latency_seconds"),
            "detected_at": correlation.get("detected_at"),
            "event_id": correlation.get("event_id"),
            "mitre_technique_id": correlation.get("mitre_technique_id"),
        }
        enriched["detected"] = correlation.get("detected")
    return enriched


@router.get("/attack-scenarios")
def list_scenarios(provider: SnapshotProvider = Depends(get_provider)) -> dict:
    items = provider.collection("attack_scenarios")
    return {"count": len(items), "items": items}


@router.get("/attack-scenarios/{scenario_id}")
def get_scenario(scenario_id: str, provider: SnapshotProvider = Depends(get_provider)) -> dict:
    scenario = provider.find("attack_scenarios", scenario_id)
    if scenario is None:
        raise HTTPException(status_code=404, detail="Scenario non trovato.")
    runs = [r for r in provider.collection("attack_runs") if r.get("scenario_id") == scenario_id]
    correlations = _correlations_by_run(provider)
    return {
        "scenario": scenario,
        "runs": [_enrich_run(run, correlations.get(run["id"])) for run in runs],
    }


@router.get("/attack-runs")
def list_runs(provider: SnapshotProvider = Depends(get_provider)) -> dict:
    correlations = _correlations_by_run(provider)
    items = [
        _enrich_run(run, correlations.get(run["id"]))
        for run in provider.collection("attack_runs")
    ]
    items.sort(key=lambda r: r.get("started_at") or "")
    return {"count": len(items), "items": items}


@router.get("/attack-runs/{run_id}")
def get_run(run_id: str, provider: SnapshotProvider = Depends(get_provider)) -> dict:
    run = provider.find("attack_runs", run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Attack run non trovato.")
    correlation = _correlations_by_run(provider).get(run_id)
    scenario = provider.find("attack_scenarios", run.get("scenario_id"))
    telemetry = [
        s for s in provider.collection("process_telemetry")
        if s.get("attack_run_id") == run_id
    ]
    return {
        "run": _enrich_run(run, correlation),
        "scenario": scenario,
        "telemetry_samples": telemetry,
    }


@router.get("/detection-correlations")
def list_correlations(provider: SnapshotProvider = Depends(get_provider)) -> dict:
    items = provider.collection("detection_correlations")
    return {"count": len(items), "items": items}


@router.get("/detection/summary")
def detection_summary(provider: SnapshotProvider = Depends(get_provider)) -> dict:
    runs = provider.collection("attack_runs")
    correlations = provider.collection("detection_correlations")
    detected = [c for c in correlations if c.get("detected") is True]
    undetected = [c for c in correlations if c.get("detected") is False]
    latencies = [
        c["detection_latency_seconds"]
        for c in detected
        if isinstance(c.get("detection_latency_seconds"), (int, float))
    ]

    scenarios = {s["id"]: s for s in provider.collection("attack_scenarios")}
    runs_by_id = {r["id"]: r for r in runs}
    gaps = []
    for correlation in undetected:
        run = runs_by_id.get(correlation.get("attack_run_id"), {})
        scenario = scenarios.get(run.get("scenario_id"), {})
        gaps.append({
            "attack_run_id": correlation.get("attack_run_id"),
            "scenario_id": run.get("scenario_id"),
            "scenario_name": scenario.get("name"),
            "mitre_technique_id": correlation.get("mitre_technique_id"),
        })

    return {
        "attack_runs": len(runs),
        "correlations": len(correlations),
        "detected": len(detected),
        "undetected": len(undetected),
        "coverage": round(len(detected) / len(runs), 4) if runs else None,
        "latency_seconds": {
            "min": min(latencies) if latencies else None,
            "max": max(latencies) if latencies else None,
            "mean": round(sum(latencies) / len(latencies), 1) if latencies else None,
            "median": median(latencies) if latencies else None,
        },
        "detection_gaps": gaps,
    }
