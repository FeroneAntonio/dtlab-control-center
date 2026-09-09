from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from dtlab.collector.cybervision_client import (
    CyberVisionError,
    CyberVisionFeatureUnavailable,
)
from dtlab.collector.cybervision_collection import collect_cybervision_raw

NOW = datetime(2026, 8, 3, 13, 0, tzinfo=UTC)


class FakeClient:
    def __init__(self) -> None:
        self.failures: dict[str, Exception] = {}
        self.values: dict[str, Any] = {}
        self.calls: list[str] = []

    def _value(self, key: str, default: Any) -> Any:
        self.calls.append(key)
        if key in self.failures:
            raise self.failures[key]
        return self.values.get(key, default)

    def classic_get(self, path: str, *, params=None) -> Any:
        defaults = {
            "/version": {"major": 5, "minor": 5, "incr": 0, "build": 123},
            "/dashboard/events/categories": {"centers": [], "total": []},
            "/dashboard/events/severities": {"centers": [], "events": []},
            "/dashboard/risk-score/devices/counts": {
                "centers": [],
                "total": {"high": 0, "medium": 0, "low": 1, "total": 1},
            },
            "/dashboard/protocols/counts": {"centers": [], "total": []},
        }
        return self._value(path, defaults.get(path, {}))

    def classic_pages(self, path: str, *, params=None) -> list[Any]:
        defaults = {
            "/devices": [
                {
                    "id": 42,
                    "label": "PLC",
                    "deviceType": "PLC",
                    "ip": ["172.16.10.10"],
                    "mac": [],
                    "lastActivity": 1785761995000,
                    "riskScore": 68,
                }
            ],
            "/components": [{"id": 99, "device": {"id": 42}}],
            "/activities": [{"id": 7, "direction": "leftRight", "packetsCount": 10}],
            "/flows": [
                {
                    "id": 8,
                    "direction": "leftRight",
                    "srcPort": 55000,
                    "dstPort": 502,
                }
            ],
            "/vulnerabilities": [{"id": 9, "CVSS": 8.1}],
            "/baselines": [{"id": 10, "countDifferences": {}}],
            "/sensors": [{"id": 11, "name": "DPI Sensor"}],
            "/reports2/reports-metadata": [],
        }
        return self._value(path, defaults.get(path, []))

    def new_ui_get(self, path: str, *, params=None) -> dict[str, Any]:
        return self._new_ui_value(path, params=params)

    def new_ui_pages(self, path: str, *, params=None) -> dict[str, Any]:
        return self._new_ui_value(path, params=params)

    def _new_ui_value(self, path: str, *, params=None) -> dict[str, Any]:
        defaults = {
            "/assets": {"centerId": "center-1", "items": [{"id": "asset-1"}]},
            "/assets/alerts": {"centerId": "center-1", "items": []},
            "/assets/vulnerabilities": {"centerId": "center-1", "items": []},
            "/networks": {"items": [{"id": "network-1"}]},
            "/oh": {"centerId": "center-1", "items": [{"id": "oh-1"}]},
        }
        status = params.get("status") if isinstance(params, dict) else None
        suffix = f":{status}" if status else ""
        return self._value(f"new-ui:{path}{suffix}", defaults.get(path, {}))

    def device_risk_score(self, device_id: Any) -> dict[str, Any]:
        return self._value(
            f"risk:{device_id}",
            {
                "deviceEngineLastRun": "2026-08-03T12:58:00Z",
                "activitiesRisk": {"score": 70},
                "deviceTypeRisk": {"score": 55},
                "groupRisk": {"score": 62},
                "vulnerabilitiesRisk": {"score": 80},
            },
        )

    def device_vulnerabilities(self, device_id: Any) -> list[Any]:
        return self._value(f"device-vulns:{device_id}", [{"id": 9}])

    def baseline_differences(self, baseline_id: Any) -> list[Any]:
        return self._value(f"baseline-diff:{baseline_id}", [{"id": 12}])

    def sensor_stats(self, sensor_id: Any, *, period: str) -> dict[str, Any]:
        return self._value(
            f"sensor-stats:{sensor_id}:{period}",
            {"cpu_usage": 10, "ram_usage": 20, "pkt_rate": 100},
        )

    def sensor_details(self, sensor_id: Any) -> dict[str, Any]:
        return self._value(f"sensor-details:{sensor_id}", {"version": "5.5.0"})


def test_collection_covers_documented_classic_capabilities() -> None:
    client = FakeClient()

    result = collect_cybervision_raw(client, now=NOW)

    assert result["api"]["version"] == "5.5.0.123"
    assert result["state"] == "complete"
    assert result["data"]["devices"][0]["label"] == "PLC"
    assert result["data"]["devices"][0]["riskScore"] == 68
    assert result["data"]["device_risk_scores"] == [
        {
            "device_id": 42,
            "payload": {
                "deviceEngineLastRun": "2026-08-03T12:58:00Z",
                "activitiesRisk": {"score": 70},
                "deviceTypeRisk": {"score": 55},
                "groupRisk": {"score": 62},
                "vulnerabilitiesRisk": {"score": 80},
            },
        }
    ]
    assert result["data"]["device_vulnerabilities"] == [{"device_id": 42, "items": [{"id": 9}]}]
    assert result["data"]["baseline_differences"] == [{"baseline_id": 10, "items": [{"id": 12}]}]
    assert result["data"]["sensor_stats"] == [
        {
            "sensor_id": 11,
            "payload": {"cpu_usage": 10, "ram_usage": 20, "pkt_rate": 100},
        }
    ]
    assert result["data"]["sensor_details"] == [{"sensor_id": 11, "payload": {"version": "5.5.0"}}]
    assert result["capabilities"]["device_risk_scores"]["status"] == "available"
    assert result["capabilities"]["device_risk_scores"]["attempted"] == 1
    assert result["capabilities"]["device_risk_scores"]["successful"] == 1
    assert result["capabilities"]["sensor_stats"]["status"] == "available"
    assert not any(name.startswith("device_risk_score:") for name in result["capabilities"])
    assert result["capabilities"]["new_ui"]["status"] == "not_configured"
    assert result["window"] == {
        "from": "2026-08-02T13:00:00Z",
        "to": "2026-08-03T13:00:00Z",
    }
    assert result["capabilities"]["event_categories"]["records"] == 0
    assert result["capabilities"]["event_severities"]["records"] == 0
    assert result["capabilities"]["risk_distribution"]["records"] == 1
    assert result["capabilities"]["protocol_distribution"]["records"] == 0


def test_new_ui_read_only_capabilities_are_collected_separately() -> None:
    client = FakeClient()

    result = collect_cybervision_raw(client, now=NOW, new_ui_enabled=True)

    assert result["api"]["new_ui"] == "1.0"
    assert result["capabilities"]["new_ui"]["status"] == "available"
    assert result["capabilities"]["new_ui"]["records"] == 3
    assert result["capabilities"]["new_ui_assets"]["records"] == 1
    assert result["capabilities"]["new_ui_alerts"]["records"] == 0
    assert result["capabilities"]["new_ui_alerts"]["statuses"] == {
        "Active": {"status": "available", "records": 0, "error_code": None},
        "Cleared": {"status": "available", "records": 0, "error_code": None},
        "Muted": {"status": "available", "records": 0, "error_code": None},
    }
    assert set(result["data"]["new_ui_alerts"]["byStatus"]) == {
        "Active",
        "Cleared",
        "Muted",
    }
    assert result["data"]["new_ui_networks"]["items"] == [{"id": "network-1"}]
    new_ui_calls = [call for call in client.calls if call.startswith("new-ui:")]
    assert len(new_ui_calls) == 7
    assert "new-ui:/assets/alerts:Active" in new_ui_calls
    assert "new-ui:/assets/alerts:Cleared" in new_ui_calls
    assert "new-ui:/assets/alerts:Muted" in new_ui_calls


def test_new_ui_authentication_failure_is_fail_soft_for_classic_data() -> None:
    client = FakeClient()
    client.failures["new-ui:/assets"] = CyberVisionError(
        "authentication_failed",
        "invalid New UI token",
        status_code=401,
    )

    result = collect_cybervision_raw(client, now=NOW, new_ui_enabled=True)

    assert result["data"]["devices"]
    assert result["capabilities"]["devices"]["status"] == "available"
    assert result["capabilities"]["new_ui_assets"]["status"] == "error"
    assert result["capabilities"]["new_ui"]["status"] == "partial"
    assert result["state"] == "partial"


def test_new_ui_alert_status_failure_is_partial_and_other_statuses_continue() -> None:
    client = FakeClient()
    client.values["new-ui:/assets/alerts:Active"] = {
        "centerId": "center-1",
        "items": [{"id": "active-asset"}],
        "pageSize": 1,
    }
    client.failures["new-ui:/assets/alerts:Cleared"] = CyberVisionError(
        "timeout",
        "safe timeout",
    )
    client.values["new-ui:/assets/alerts:Muted"] = {
        "centerId": "center-1",
        "items": [{"id": "muted-asset"}],
        "pageSize": 1,
    }

    result = collect_cybervision_raw(client, now=NOW, new_ui_enabled=True)

    capability = result["capabilities"]["new_ui_alerts"]
    assert capability["status"] == "partial"
    assert capability["records"] == 2
    assert capability["error_code"] == "partial_status_failure"
    assert capability["statuses"]["Active"]["status"] == "available"
    assert capability["statuses"]["Cleared"] == {
        "status": "error",
        "records": 0,
        "error_code": "timeout",
    }
    assert capability["statuses"]["Muted"]["status"] == "available"
    payload = result["data"]["new_ui_alerts"]
    assert payload["items"] == [
        {"id": "active-asset"},
        {"id": "muted-asset"},
    ]
    assert payload["centerId"] == "center-1"
    assert payload["pageSize"] == 1
    assert payload["byStatus"]["Cleared"] is None
    assert payload["byStatus"]["Active"]["items"] == [{"id": "active-asset"}]
    assert payload["byStatus"]["Muted"]["items"] == [{"id": "muted-asset"}]
    assert result["capabilities"]["new_ui"]["status"] == "partial"
    assert result["state"] == "partial"
    assert any(
        error["capability"] == "new_ui_alerts:cleared" and error["code"] == "timeout"
        for error in result["errors"]
    )
    assert "new-ui:/assets/alerts:Muted" in client.calls


def test_dashboard_wrapper_record_counts_follow_documented_payloads() -> None:
    client = FakeClient()
    original = client.classic_get
    dashboard_payloads = {
        "/dashboard/events/categories": {
            "centers": [],
            "total": [
                {"category": "Security", "count": 3},
                {"category": "Anomaly", "count": 1},
            ],
        },
        "/dashboard/events/severities": {
            "centers": [],
            "events": [{"id": "event-1"}],
        },
        "/dashboard/risk-score/devices/counts": {
            "centers": [],
            "total": {"high": 1, "medium": 2, "low": 3, "total": 6},
        },
        "/dashboard/protocols/counts": {
            "centers": [],
            "total": [
                {"tagId": "modbus", "tagLabel": "Modbus", "count": 10},
                {"tagId": "s7", "tagLabel": "S7", "count": 4},
            ],
        },
    }

    def classic_get(path: str, *, params=None):
        if path in dashboard_payloads:
            return dashboard_payloads[path]
        return original(path, params=params)

    client.classic_get = classic_get  # type: ignore[method-assign]

    result = collect_cybervision_raw(client, now=NOW)

    assert result["capabilities"]["event_categories"]["records"] == 2
    assert result["capabilities"]["event_severities"]["records"] == 1
    assert result["capabilities"]["risk_distribution"]["records"] == 1
    assert result["capabilities"]["protocol_distribution"]["records"] == 2


def test_empty_dashboard_mapping_has_zero_records() -> None:
    client = FakeClient()
    original = client.classic_get

    def classic_get(path: str, *, params=None):
        if path.startswith("/dashboard/"):
            return {}
        return original(path, params=params)

    client.classic_get = classic_get  # type: ignore[method-assign]

    result = collect_cybervision_raw(client, now=NOW)

    for capability in (
        "event_categories",
        "event_severities",
        "risk_distribution",
        "protocol_distribution",
    ):
        assert result["capabilities"][capability]["records"] == 0


def test_dashboard_wrapper_record_counts_use_the_wrapped_collection() -> None:
    client = FakeClient()
    original = client.classic_get

    def classic_get(path: str, *, params=None):
        payloads = {
            "/dashboard/events/categories": {
                "categories": [{"name": "security"}, {"name": "system"}]
            },
            "/dashboard/events/severities": {"events": [{"severity": "high"}]},
            "/dashboard/protocols/counts": {"items": [{"protocol": "modbus"}, {"protocol": "s7"}]},
        }
        if path in payloads:
            return payloads[path]
        return original(path, params=params)

    client.classic_get = classic_get  # type: ignore[method-assign]

    result = collect_cybervision_raw(client, now=NOW)

    assert result["capabilities"]["event_categories"]["records"] == 2
    assert result["capabilities"]["event_severities"]["records"] == 1
    assert result["capabilities"]["protocol_distribution"]["records"] == 2


def test_unlicensed_baseline_is_not_a_sync_failure() -> None:
    client = FakeClient()
    client.failures["/baselines"] = CyberVisionFeatureUnavailable(
        "feature_unlicensed",
        "not licensed",
        status_code=402,
    )

    result = collect_cybervision_raw(client, now=NOW)

    assert result["capabilities"]["baselines"]["status"] == "feature_unlicensed"
    assert result["data"]["baselines"] == []
    assert result["state"] == "complete"


def test_optional_timeout_marks_partial_and_keeps_other_data() -> None:
    client = FakeClient()
    client.failures["/flows"] = CyberVisionError("timeout", "timeout")

    result = collect_cybervision_raw(client, now=NOW)

    assert result["state"] == "partial"
    assert result["data"]["flows"] == []
    assert result["data"]["devices"]
    assert result["capabilities"]["flows"]["error_code"] == "timeout"


def test_authentication_failure_is_fatal() -> None:
    client = FakeClient()
    client.failures["/devices"] = CyberVisionError(
        "authentication_failed",
        "token invalid",
        status_code=401,
    )

    with pytest.raises(CyberVisionError) as caught:
        collect_cybervision_raw(client, now=NOW)

    assert caught.value.code == "authentication_failed"


def test_device_detail_limit_bounds_request_volume() -> None:
    client = FakeClient()
    original = client.classic_pages

    def pages(path: str, *, params=None):
        if path == "/devices":
            return [{"id": index} for index in range(10)]
        return original(path, params=params)

    client.classic_pages = pages  # type: ignore[method-assign]

    result = collect_cybervision_raw(
        client,
        now=NOW,
        max_device_details=2,
    )

    assert len(result["data"]["device_risk_scores"]) == 2
    assert len(result["data"]["device_vulnerabilities"]) == 2
    assert result["capabilities"]["device_risk_scores"]["status"] == "truncated"
    assert result["state"] == "partial"
