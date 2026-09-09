from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime, timedelta

import pytest

from dtlab.contract import (
    ContractValidationError,
    canonical_bytes,
    effective_sync_state,
    snapshot_age_seconds,
    validate_snapshot,
    with_stale_truth,
)
from tests.factories import FETCHED_AT, add_cisco_asset, valid_snapshot


def test_minimal_real_partial_snapshot_is_valid() -> None:
    snapshot = valid_snapshot()

    assert validate_snapshot(snapshot) is snapshot


def test_cisco_risk_score_is_valid_only_with_cisco_source_and_exact_band() -> None:
    snapshot = valid_snapshot()
    add_cisco_asset(snapshot, score=68)

    validate_snapshot(snapshot)
    snapshot["risk_scores"][0]["band"] = "high"

    with pytest.raises(ContractValidationError, match="deve essere 'medium'"):
        validate_snapshot(snapshot)


def test_risk_score_from_esxi_is_rejected() -> None:
    snapshot = valid_snapshot()
    add_cisco_asset(snapshot, score=30)
    snapshot["risk_scores"][0]["evidence"]["source_id"] = "src:vmware-esxi:dtlab-01"

    with pytest.raises(ContractValidationError, match="cisco_cyber_vision"):
        validate_snapshot(snapshot)


def test_fake_health_score_is_not_part_of_contract() -> None:
    snapshot = valid_snapshot()
    snapshot["health_score"] = 68

    with pytest.raises(ContractValidationError, match="health_score"):
        validate_snapshot(snapshot)


def test_real_only_mode_rejects_demo_evidence() -> None:
    snapshot = valid_snapshot()
    snapshot["environment"]["evidence"]["truth"] = "demo"

    with pytest.raises(ContractValidationError, match="dati demo vietati"):
        validate_snapshot(snapshot)


def test_duplicate_ids_and_unknown_references_are_rejected() -> None:
    snapshot = valid_snapshot()
    duplicate = deepcopy(snapshot["networks"][0])
    snapshot["networks"].append(duplicate)
    snapshot["virtual_machines"][0]["interfaces"][0]["network_id"] = "net:missing"

    with pytest.raises(ContractValidationError) as caught:
        validate_snapshot(snapshot)

    assert "ID duplicato" in str(caught.value)


def test_secret_like_fields_are_rejected_even_inside_source_details() -> None:
    snapshot = valid_snapshot()
    snapshot["activities"].append(
        {
            "id": "activity:cybervision:1",
            "evidence": {
                "source_id": "src:cisco-cyber-vision:dtlab-01",
                "source_record_id": "activity:1",
                "truth": "unavailable",
                "observed_at": None,
                "fetched_at": FETCHED_AT,
                "completeness": 0,
                "notes": [],
            },
            "asset_ids": [],
            "type": "not_available",
            "protocol": None,
            "first_seen_at": None,
            "last_seen_at": None,
            "packet_count": None,
            "byte_count": None,
            "flow_count": None,
            "event_count": None,
            "details": {"access_token": "must-never-appear"},
        }
    )

    with pytest.raises(ContractValidationError, match="nome campo sensibile"):
        validate_snapshot(snapshot)


def test_timestamp_order_is_validated() -> None:
    snapshot = valid_snapshot()
    snapshot["sync"]["completed_at"] = "2026-08-03T09:59:59Z"

    with pytest.raises(ContractValidationError, match="precedente"):
        validate_snapshot(snapshot)


def test_runtime_freshness_marks_copy_stale_without_mutating_source() -> None:
    snapshot = valid_snapshot()
    completed = datetime.fromisoformat(FETCHED_AT.replace("Z", "+00:00"))
    now = completed + timedelta(seconds=901)

    assert snapshot_age_seconds(snapshot, now=now) == 901
    assert effective_sync_state(snapshot, now=now) == "stale"

    display = with_stale_truth(snapshot, now=now)
    assert display["sync"]["state"] == "stale"
    assert display["virtual_machines"][0]["evidence"]["truth"] == "stale"
    assert snapshot["virtual_machines"][0]["evidence"]["truth"] == "observed"


def test_canonical_bytes_are_deterministic() -> None:
    first = valid_snapshot()
    second = deepcopy(first)
    second["quality"]["coverage"] = {
        "cyber_vision": 0.0,
        "vmware": 1.0,
    }

    assert canonical_bytes(first) == canonical_bytes(second)


def test_time_helpers_accept_utc_now() -> None:
    snapshot = valid_snapshot()
    now = datetime(2026, 8, 3, 10, 0, 3, tzinfo=UTC)

    assert snapshot_age_seconds(snapshot, now=now) == 1
