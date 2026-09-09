from __future__ import annotations

import json

from dtlab.adapters.cybervision_new_ui import normalize_cybervision_new_ui_source


def raw_new_ui() -> dict:
    capabilities = {
        name: {"status": "available", "records": records, "error_code": None}
        for name, records in {
            "new_ui_assets": 1,
            "new_ui_alerts": 1,
            "new_ui_vulnerability_assets": 1,
            "new_ui_networks": 1,
            "new_ui_org_hierarchy": 1,
        }.items()
    }
    capabilities["new_ui"] = {
        "status": "available",
        "records": 5,
        "error_code": None,
    }
    return {
        "collected_at": "2026-08-03T14:30:00Z",
        "api": {"version": "5.5.1.202606021546", "new_ui": "1.0"},
        "capabilities": capabilities,
        "data": {
            "new_ui_assets": {
                "centerId": "center-1",
                "items": [
                    {
                        "id": "asset-1",
                        "name": "PLC profile",
                        "type": "PLC",
                        "vendor": "Vendor",
                        "creationTime": "2026-07-01T00:00:00Z",
                        "firstActiveTime": "2026-07-02T00:00:00Z",
                        "lastActiveTime": "2026-08-03T14:29:00Z",
                        "functionalGroupId": "group-1",
                        "functionalGroupName": "Beer Factory",
                        "activeAlertCount": 1,
                        "vulnerabilityCount": 1,
                        "networkInterfaces": [
                            {
                                "ip": "172.16.10.10",
                                "mac": "00:11:22:33:44:55",
                                "networkName": "OT",
                                "isPrimary": True,
                                "vlan": 10,
                            }
                        ],
                        "sensorAssociations": [
                            {"id": "sensor-1", "label": "DPI", "isClose": True}
                        ],
                        "pcapAssociations": [
                            {"id": "pcap-1", "filename": "capture.pcap"}
                        ],
                        "customProperties": [
                            {
                                "id": "property-1",
                                "key": "internalSecret",
                                "value": "must-not-leak",
                            }
                        ],
                        "riskScore": 99,
                    }
                ],
            },
            "new_ui_alerts": {
                "centerId": "center-1",
                "items": [
                    {
                        "id": "asset-1",
                        "name": "PLC profile",
                        "networkInterfaces": [],
                        "alerts": [
                            {
                                "alertId": "alert-1",
                                "instanceId": "instance-1",
                                "alertType": "Communication",
                                "category": "Security",
                                "lastOccurrence": "2026-08-03T14:20:00Z",
                                "severity": "high",
                                "trigger": "New peer",
                            }
                        ],
                    }
                ],
            },
            "new_ui_vulnerability_assets": {
                "centerId": "center-1",
                "items": [
                    {
                        "id": "asset-1",
                        "name": "PLC profile",
                        "assetInterfaces": [],
                        "vulnerabilities": [
                            {
                                "cveId": "CVE-2026-0001",
                                "name": "Example",
                                "source": "public",
                                "csrsScore": "72",
                                "cvssScore": "8.1",
                            }
                        ],
                    }
                ],
            },
            "new_ui_networks": {
                "items": [
                    {
                        "id": "network-1",
                        "name": "172.16/12 private network",
                        "type": "OT",
                        "ipRange": "172.16.0.0/12",
                        "groupId": "group-1",
                        "vlanId": 10,
                        "duplicated": False,
                        "customProperties": [],
                    }
                ]
            },
            "new_ui_org_hierarchy": {
                "centerId": "center-1",
                "items": [
                    {
                        "id": "oh-1",
                        "name": "Global",
                        "description": "Global",
                        "hierarchy": "Global",
                    }
                ],
            },
        },
    }


def test_new_ui_is_source_owned_and_does_not_publish_classic_scores() -> None:
    result = normalize_cybervision_new_ui_source(raw_new_ui())
    source = result["source"]
    details = source["details"]

    assert source["type"] == "cisco_cyber_vision_new_ui"
    assert source["status"] == "connected"
    assert source["record_counts"] == {
        "assets": 1,
        "alert_assets": 1,
        "vulnerability_assets": 1,
        "networks": 1,
        "org_hierarchy": 1,
    }
    assert details["assets"][0]["network_interfaces"][0]["ip"] == "172.16.10.10"
    assert details["assets"][0]["active_alert_count"] == 1
    assert details["vulnerability_assets"][0]["vulnerabilities"][0] == {
        "cve_id": "CVE-2026-0001",
        "name": "Example",
        "source": "public",
        "csrs_score": "72",
        "cvss_score": "8.1",
    }
    encoded = json.dumps(result)
    assert "must-not-leak" not in encoded
    assert '"riskScore"' not in encoded
    assert "risk_scores" not in result
    assert "sensors" not in result


def test_zero_records_remain_available_not_unavailable() -> None:
    raw = raw_new_ui()
    raw["data"]["new_ui_alerts"]["items"] = []
    raw["capabilities"]["new_ui_alerts"]["records"] = 0

    result = normalize_cybervision_new_ui_source(raw)

    assert result["source"]["capabilities"]["alerts"]["status"] == "available"
    assert result["source"]["details"]["alert_assets"] == []
    assert result["coverage"]["new_ui_alerts"] == 1


def test_alert_query_status_is_preserved_from_collector_context() -> None:
    raw = raw_new_ui()
    active_payload = raw["data"]["new_ui_alerts"]
    raw["data"]["new_ui_alerts"] = {
        "centerId": "center-1",
        "items": active_payload["items"],
        "byStatus": {
            "Active": active_payload,
            "Cleared": {"centerId": "center-1", "items": []},
            "Muted": {"centerId": "center-1", "items": []},
        },
    }
    raw["capabilities"]["new_ui_alerts"]["statuses"] = {
        query_status: {
            "status": "available",
            "records": 1 if query_status == "Active" else 0,
            "error_code": None,
        }
        for query_status in ("Active", "Cleared", "Muted")
    }

    source = normalize_cybervision_new_ui_source(raw)["source"]

    assert source["details"]["alert_assets"][0]["query_status"] == "Active"
    assert source["details"]["alert_assets"][0]["alerts"][0]["status"] == "Active"
    assert source["details"]["alert_query_statuses"] == {
        "Active": {"status": "available", "records": 1, "error_code": None},
        "Cleared": {"status": "available", "records": 0, "error_code": None},
        "Muted": {"status": "available", "records": 0, "error_code": None},
    }


def test_unconfigured_new_ui_has_no_quality_penalty() -> None:
    raw = raw_new_ui()
    for name in tuple(raw["capabilities"]):
        raw["capabilities"][name] = {
            "status": "not_configured",
            "records": 0,
            "error_code": "new_ui_token_unavailable",
        }
    for name in tuple(raw["data"]):
        raw["data"][name] = {}

    result = normalize_cybervision_new_ui_source(raw)

    assert result["source"]["status"] == "not_configured"
    assert result["coverage"] == {}
