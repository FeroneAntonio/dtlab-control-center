"""Tests for the additive v3 contract and its isolation from the v2 data plane."""

from __future__ import annotations

from copy import deepcopy

import pytest

from dtlab import contract as v2
from dtlab import contract_v3 as c3
from dtlab.sandbox import build_sandbox_snapshot
from tests import factories


@pytest.fixture(scope="module")
def sandbox() -> dict:
    return build_sandbox_snapshot()


def test_sandbox_snapshot_is_valid_v3(sandbox: dict) -> None:
    # build_sandbox_snapshot already validates; re-validate a deep copy defensively.
    c3.validate_snapshot_v3(deepcopy(sandbox))


def test_v2_snapshot_is_accepted_as_v3_when_version_bumped() -> None:
    snap = factories.valid_snapshot()
    snap["schema_version"] = "3.0.0"
    c3.validate_snapshot_v3(snap)


def test_v3_schema_version_is_pinned() -> None:
    snap = factories.valid_snapshot()  # schema_version 2.0.0
    with pytest.raises(v2.ContractValidationError):
        c3.validate_snapshot_v3(snap)


def test_v2_contract_still_rejects_v3_only_fields() -> None:
    """Additive safety: v3 domains must not leak into a v2 document."""

    snap = factories.valid_snapshot()
    snap["attack_scenarios"] = []
    with pytest.raises(v2.ContractValidationError):
        v2.validate_snapshot(snap)


def test_real_execution_requires_roe(sandbox: dict) -> None:
    snap = deepcopy(sandbox)
    snap["attack_scenarios"][0]["execution_mode"] = "real"
    snap["attack_scenarios"][0]["roe_reference"] = None
    with pytest.raises(v2.ContractValidationError, match="roe_reference"):
        c3.validate_snapshot_v3(snap)


def test_real_execution_with_roe_is_allowed(sandbox: dict) -> None:
    snap = deepcopy(sandbox)
    snap["attack_scenarios"][0]["execution_mode"] = "real"
    snap["attack_scenarios"][0]["roe_reference"] = "ROE-2026-001"
    c3.validate_snapshot_v3(snap)


def test_detection_latency_must_be_consistent(sandbox: dict) -> None:
    snap = deepcopy(sandbox)
    # corr:discovery has attack_at t+120, detected_at t+188 (68s). Break it.
    snap["detection_correlations"][0]["detection_latency_seconds"] = 5
    with pytest.raises(v2.ContractValidationError, match="incoerente"):
        c3.validate_snapshot_v3(snap)


def test_undetected_correlation_must_have_null_latency(sandbox: dict) -> None:
    snap = deepcopy(sandbox)
    mitm = next(c for c in snap["detection_correlations"] if not c["detected"])
    mitm["detection_latency_seconds"] = 10
    with pytest.raises(v2.ContractValidationError, match="deve essere nullo"):
        c3.validate_snapshot_v3(snap)


def test_detected_correlation_requires_detected_at(sandbox: dict) -> None:
    snap = deepcopy(sandbox)
    snap["detection_correlations"][1]["detected_at"] = None
    with pytest.raises(v2.ContractValidationError, match="detected_at"):
        c3.validate_snapshot_v3(snap)


def test_register_in_bounds_flag_must_match_range(sandbox: dict) -> None:
    snap = deepcopy(sandbox)
    reg = snap["process_telemetry"][0]["registers"][0]  # conveyor_speed, in bounds
    reg["in_bounds"] = False
    with pytest.raises(v2.ContractValidationError, match="in_bounds"):
        c3.validate_snapshot_v3(snap)


def test_dangling_attack_run_reference_is_rejected(sandbox: dict) -> None:
    snap = deepcopy(sandbox)
    snap["detection_correlations"][0]["attack_run_id"] = "run:does-not-exist"
    with pytest.raises(v2.ContractValidationError, match="riferimento sconosciuto"):
        c3.validate_snapshot_v3(snap)


def test_mitre_compliance_reference_must_be_a_technique(sandbox: dict) -> None:
    snap = deepcopy(sandbox)
    mapping = next(m for m in snap["compliance_mappings"] if m["framework"] == "mitre_attack_ics")
    mapping["reference_id"] = "not-a-technique"
    with pytest.raises(v2.ContractValidationError, match="mitre_attack_ics"):
        c3.validate_snapshot_v3(snap)


def test_secret_leak_still_detected_in_v3(sandbox: dict) -> None:
    snap = deepcopy(sandbox)
    snap["environment"]["password"] = "hunter2"
    with pytest.raises(v2.ContractValidationError, match="campo sensibile"):
        c3.validate_snapshot_v3(snap)
