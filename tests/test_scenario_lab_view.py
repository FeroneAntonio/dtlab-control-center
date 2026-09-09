"""Pure helper tests for the isolated BeerFactory Scenario Lab view."""

from __future__ import annotations

from dtlab.sandbox import build_sandbox_snapshot
from dtlab.ui.views.lab import (
    _SIMULATION_BANNER,
    _attack_rows,
    _compliance_rows,
    _conduit_rows,
    _detection_summary,
    _history_rows,
    _telemetry_rows,
    _zone_rows,
)


def test_scenario_lab_banner_is_explicitly_non_live() -> None:
    assert _SIMULATION_BANNER == "SIMULAZIONE CONTROLLATA — NON DATI LIVE"


def test_attack_replay_exposes_coverage_and_the_detection_gap() -> None:
    snapshot = build_sandbox_snapshot()
    rows = _attack_rows(snapshot)
    summary = _detection_summary(snapshot)

    assert len(rows) == 4
    assert summary == {
        "scenarios": 4,
        "runs": 4,
        "detected": 3,
        "gaps": 1,
        "coverage_pct": 75.0,
        "mean_latency_seconds": 41.0,
    }
    gap = next(row for row in rows if row["Detection"] == "GAP")
    assert gap["Scenario"] == "MITM / Spoofing"
    assert gap["Latenza (s)"] is None
    assert {row["Modalità"] for row in rows} == {"simulated"}


def test_digital_twin_flattens_modbus_truth_without_hiding_out_of_range_values() -> None:
    rows = _telemetry_rows(build_sandbox_snapshot())

    assert len(rows) == 24 * 7
    assert any(
        row["Registro"] == "conveyor_speed_rpm"
        and row["Anomalia"] == "unexpected_write"
        and row["In range"] == "No"
        for row in rows
    )
    assert any(row["In range"] == "N/D" for row in rows)


def test_purdue_compliance_and_trend_are_complete_replay_views() -> None:
    snapshot = build_sandbox_snapshot()
    zones = _zone_rows(snapshot)
    conduits = _conduit_rows(snapshot)
    compliance = _compliance_rows(snapshot)
    history = _history_rows(snapshot)

    assert len(zones) == 4
    assert len(conduits) == 4
    assert {row["Framework"] for row in compliance} == {
        "IEC 62443",
        "NIS2",
        "MITRE ATT&CK for ICS",
        "Purdue",
    }
    assert {row["Stato"] for row in compliance} >= {
        "Coperto",
        "Parziale",
        "Non coperto",
    }
    assert len(history) == 7
    assert all(row["Copertura detection (%)"] == 75.0 for row in history)


def test_scenario_lab_helpers_fail_closed_when_domains_are_missing() -> None:
    empty: dict[str, object] = {}

    assert _attack_rows(empty) == []
    assert _detection_summary(empty)["coverage_pct"] is None
    assert _telemetry_rows(empty) == []
    assert _zone_rows(empty) == []
    assert _conduit_rows(empty) == []
    assert _compliance_rows(empty) == []
    assert _history_rows(empty) == []
