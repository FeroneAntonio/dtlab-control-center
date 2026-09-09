"""Tests for the deterministic BeerFactory sandbox generator."""

from __future__ import annotations

from dtlab import contract_v3 as c3
from dtlab.sandbox import build_sandbox_snapshot


def test_sandbox_is_deterministic() -> None:
    first = c3.snapshot_sha256_v3(build_sandbox_snapshot())
    second = c3.snapshot_sha256_v3(build_sandbox_snapshot())
    assert first == second


def test_sandbox_runs_in_allow_demo_mode() -> None:
    snap = build_sandbox_snapshot()
    assert snap["sync"]["publication_mode"] == "allow_demo"
    assert "SANDBOX" in snap["environment"]["name"]


def test_sandbox_populates_every_v3_domain() -> None:
    snap = build_sandbox_snapshot()
    for domain in (
        "attack_scenarios",
        "attack_runs",
        "detection_correlations",
        "process_telemetry",
        "security_zones",
        "compliance_mappings",
    ):
        assert snap[domain], f"{domain} dovrebbe essere popolato"
    assert snap["history"]["points"]


def test_mitm_scenario_is_the_detection_gap() -> None:
    snap = build_sandbox_snapshot()
    mitm = next(c for c in snap["detection_correlations"] if c["attack_run_id"] == "run:mitm")
    assert mitm["detected"] is False
    assert mitm["detected_at"] is None
    assert mitm["detection_latency_seconds"] is None


def test_three_of_four_attacks_are_detected() -> None:
    snap = build_sandbox_snapshot()
    detected = [c for c in snap["detection_correlations"] if c["detected"]]
    assert len(detected) == 3
    assert len(snap["attack_runs"]) == 4


def test_write_attack_window_shows_tampering() -> None:
    snap = build_sandbox_snapshot()
    tampered = [s for s in snap["process_telemetry"] if s["anomaly"] == "unexpected_write"]
    assert tampered, "la finestra dell'attacco deve mostrare manomissione"
    for sample in tampered:
        assert sample["belt_state"] == "fault"
        assert sample["attack_run_id"] == "run:unauthorized-write"
        speed = next(r for r in sample["registers"] if r["name"] == "conveyor_speed_rpm")
        assert speed["in_bounds"] is False


def test_every_detection_maps_to_a_known_technique() -> None:
    snap = build_sandbox_snapshot()
    technique_ids = {
        t["technique_id"]
        for scenario in snap["attack_scenarios"]
        for t in scenario["mitre_techniques"]
    }
    for correlation in snap["detection_correlations"]:
        assert correlation["mitre_technique_id"] in technique_ids
