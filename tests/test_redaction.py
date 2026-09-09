from __future__ import annotations

import json

import pytest

from dtlab.services.redaction import RedactionError, redacted_snapshot, safe_csv_cell
from tests.factories import valid_snapshot


def test_public_export_pseudonymizes_ip_and_mac_deterministically() -> None:
    snapshot = valid_snapshot()
    salt = b"0123456789abcdef"

    first = redacted_snapshot(snapshot, mode="public", salt=salt)
    second = redacted_snapshot(snapshot, mode="public", salt=salt)
    encoded = json.dumps(first)

    assert first == second
    assert "172.16.10.10" not in encoded
    assert "00:00:00:00:00:01" not in encoded
    assert "ip-" in encoded
    assert "mac-" in encoded


def test_technical_export_preserves_infrastructure_addresses() -> None:
    snapshot = valid_snapshot()

    exported = redacted_snapshot(snapshot, mode="technical")

    assert (
        exported["virtual_machines"][0]["interfaces"][0]["ip_addresses"][0]
        == "172.16.10.10"
    )
    assert exported is not snapshot


def test_public_export_redacts_addresses_in_nested_new_ui_details_and_prose() -> None:
    snapshot = valid_snapshot()
    snapshot["sources"][0]["details"] = {
        "assets": [
            {
                "network_interfaces": [
                    {
                        "ip": "172.16.10.10",
                        "mac": "00:0c:29:02:03:cf",
                    }
                ]
            }
        ],
        "networks": [{"ip_range": "172.16.10.0/24"}],
        "diagnostic": "record:172.16.10.10",
        "note": "Indirizzo OT 172.16.10.10.",
    }

    technical = redacted_snapshot(snapshot, mode="technical")
    public = redacted_snapshot(
        snapshot,
        mode="public",
        salt=b"0123456789abcdef",
    )
    technical_json = json.dumps(technical)
    public_json = json.dumps(public)

    assert "172.16.10.10" in technical_json
    assert "172.16.10.0/24" in technical_json
    assert "00:0c:29:02:03:cf" in technical_json
    assert "172.16.10.10" not in public_json
    assert "172.16.10.0/24" not in public_json
    assert "00:0c:29:02:03:cf" not in public_json


def test_public_export_requires_nontrivial_salt() -> None:
    with pytest.raises(RedactionError, match="salt"):
        redacted_snapshot(valid_snapshot(), mode="public", salt=b"short")


@pytest.mark.parametrize("value", ["=1+1", " +SUM(A1:A2)", "-2+3", "@cmd"])
def test_csv_formula_injection_is_neutralized(value: str) -> None:
    assert safe_csv_cell(value).startswith("'")


def test_regular_csv_values_are_unchanged() -> None:
    assert safe_csv_cell("PLC-Desktop") == "PLC-Desktop"
    assert safe_csv_cell(42) == 42
