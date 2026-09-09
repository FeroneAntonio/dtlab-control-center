from __future__ import annotations

import json
from copy import deepcopy

import pytest

from dtlab.adapters.cybervision import (
    CyberVisionNormalizationError,
    normalize_cybervision_collection,
)
from dtlab.contract import validate_snapshot
from tests.factories import valid_snapshot


def raw_collection() -> dict:
    capability_names = (
        "devices",
        "components",
        "activities",
        "flows",
        "event_categories",
        "event_severities",
        "risk_distribution",
        "protocol_distribution",
        "vulnerabilities",
        "device_vulnerabilities",
        "baselines",
        "baseline_differences",
        "sensors",
        "sensor_details",
        "sensor_stats",
        "reports_metadata",
    )
    return {
        "collected_at": "2026-08-03T13:00:00Z",
        "window": {
            "from": "2026-08-02T13:00:00Z",
            "to": "2026-08-03T13:00:00Z",
        },
        "api": {"classic": "3.0", "new_ui": "pending", "version": "5.5.0.123"},
        "state": "complete",
        "capabilities": {
            **{
                name: {"status": "available", "records": 1, "error_code": None}
                for name in capability_names
            },
            "new_ui": {
                "status": "openapi_required",
                "records": 0,
                "error_code": None,
            },
        },
        "errors": [],
        "data": {
            "devices": [
                {
                    "id": 42,
                    "customLabel": "",
                    "label": "PLC BeerFactory",
                    "deviceType": "PLC",
                    "ip": ["172.16.10.10"],
                    "mac": ["00:11:22:33:44:55"],
                    "lastActivity": "2026-08-03T12:59:30Z",
                    "group": {"id": "group-1", "label": "Beer Factory"},
                    "normalizedProperties": [{"key": "firmware", "value": ["1.2.3"]}],
                    "riskScore": 68,
                    "internalToken": "must-not-leak",
                },
                {
                    "id": 43,
                    "customLabel": "HMI BeerFactory",
                    "deviceType": "HMI",
                    "ip": ["172.16.10.20"],
                    "mac": [],
                    "lastActivity": "2026-08-03T12:59:40Z",
                    "riskScore": 22,
                },
            ],
            "device_risk_scores": [
                {
                    "device_id": 42,
                    "payload": {
                        "deviceEngineLastRun": "2026-08-03T12:58:00Z",
                        "activitiesRisk": {"score": 70},
                        "deviceTypeRisk": {"score": 55},
                        "groupRisk": {"score": 62},
                        "vulnerabilitiesRisk": {"score": 80},
                        "matchingTag": {"label": "Critical asset"},
                        "mostImpactingActivity": {"id": 7},
                        "mostImpactingVulnerability": {"id": "vuln-1"},
                        "riskScoreDescription": "Rischio guidato dalla vulnerabilità.",
                    },
                }
            ],
            "components": [
                {
                    "id": "component-plc",
                    "label": "PLC Modbus endpoint",
                    "ip": "172.16.10.10",
                    "device": {"id": 42},
                },
                {
                    "id": "component-hmi",
                    "label": "HMI Modbus endpoint",
                    "ip": "172.16.10.20",
                    "device": {"id": 43},
                },
            ],
            "activities": [
                {
                    "id": 7,
                    "left": {"id": "component-hmi", "label": "HMI Modbus endpoint"},
                    "right": {"id": "component-plc", "label": "PLC Modbus endpoint"},
                    "direction": "leftRight",
                    "status": "active",
                    "tags": [{"label": "Industrial traffic"}],
                    "variables": [{"label": "Holding register 1"}],
                    "differences": [{"id": "difference-a"}],
                    "newVariableAccess": 1,
                    "variablesCount": 1,
                    "firstActivity": "2026-08-03T12:00:00Z",
                    "lastActivity": "2026-08-03T12:59:00Z",
                    "packetsCount": 120,
                    "bytesCount": 4096,
                    "flowCount": 1,
                    "eventsCount": 2,
                }
            ],
            "flows": [
                {
                    "id": 8,
                    "left": {"id": "component-hmi", "label": "HMI Modbus endpoint"},
                    "right": {"id": "component-plc", "label": "PLC Modbus endpoint"},
                    "protocol": "Modbus",
                    "direction": "leftRight",
                    "srcPort": 55000,
                    "dstPort": 502,
                    "firstActivity": "2026-08-03T12:00:00Z",
                    "lastActivity": "2026-08-03T12:59:00Z",
                    "packetsCount": 120,
                    "bytesCount": 4096,
                }
            ],
            "event_categories": {
                "centers": [
                    {
                        "id": "center-1",
                        "label": "DTLab Center",
                        "anomaly": 1,
                        "extension": 0,
                        "security": 3,
                        "signature": 2,
                        "total": 6,
                    }
                ],
                "total": [
                    {"category": "Security", "count": 3},
                    {"category": "Anomaly", "count": 1},
                ],
            },
            "event_severities": {
                "centers": [
                    {
                        "id": "center-1",
                        "label": "DTLab Center",
                        "critical": 1,
                        "high": 2,
                        "medium": 2,
                        "low": 1,
                        "total": 6,
                    }
                ],
                "events": [
                    {
                        "id": 14,
                        "date": "2026-08-03T12:55:00Z",
                        "severity": "high",
                        "category": "Security",
                        "centerId": "center-1",
                        "centerLabel": "DTLab Center",
                        "shortMessage": "Nuova comunicazione",
                    }
                ],
            },
            "risk_distribution": {
                "centers": [
                    {
                        "centerId": "center-1",
                        "centerName": "DTLab Center",
                        "high": 1,
                        "medium": 1,
                        "low": 0,
                        "total": 2,
                    }
                ],
                "total": {"high": 1, "medium": 1, "low": 0, "total": 2},
            },
            "protocol_distribution": {
                "centers": [
                    {
                        "centerId": "center-1",
                        "centerName": "DTLab Center",
                        "total": [{"tagId": "tag-modbus", "tagLabel": "Modbus", "count": 8}],
                    }
                ],
                "total": [{"tagId": "tag-modbus", "tagLabel": "Modbus", "count": 8}],
            },
            "vulnerabilities": [
                {
                    "id": "vuln-1",
                    "cve": "CVE-2026-0001",
                    "title": "Test vulnerability",
                    "CVSS": 8.1,
                    "CVSSTemporal": 7.4,
                    "CVSSVectorString": "CVSS:3.1/AV:N/AC:L",
                    "CVSSVersion": 3.1,
                    "csrsScore": 99,
                    "publishTime": "2026-07-01T00:00:00Z",
                    "fullDescription": "Descrizione tecnica completa.",
                    "solution": "Aggiornare il firmware.",
                    "reasons": ["Firmware vulnerabile"],
                }
            ],
            "device_vulnerabilities": [
                {
                    "device_id": 42,
                    "items": [
                        {
                            "id": "vuln-1",
                            "ackAuthor": "analyst",
                            "ackComment": "Mitigazione pianificata",
                            "vendorId": "vendor-42",
                        }
                    ],
                },
                {"device_id": 43, "items": []},
            ],
            "baselines": [
                {
                    "id": 10,
                    "label": "BeerFactory normale",
                    "description": "Comportamento appreso.",
                    "status": "active",
                    "creationTime": "2026-08-01T00:00:00Z",
                    "creationPeriodStart": "2026-08-01T00:00:00Z",
                    "creationPeriodEnd": "2026-08-02T00:00:00Z",
                    "lastScanTime": "2026-08-03T12:50:00Z",
                    "nextScanTime": "2026-08-03T13:50:00Z",
                    "countDifferences": {
                        "newComponent": 0,
                        "changedComponent": 0,
                        "newActivity": 1,
                        "changedActivity": 0,
                    },
                }
            ],
            "baseline_differences": [
                {
                    "baseline_id": 10,
                    "items": [
                        {
                            "id": 12,
                            "type": "newActivity",
                            "targetId": "component-plc",
                            "key": "protocol",
                            "value": "Modbus",
                            "detectionTime": "2026-08-03T12:55:00Z",
                        }
                    ],
                }
            ],
            "sensors": [
                {
                    "id": 11,
                    "name": "DPI Sensor",
                    "model": "CenterDPI",
                    "status": {
                        "operationalStatus": "operational",
                        "lastReceivedSysinfo": "2026-08-03T12:59:50Z",
                    },
                    "filter": {"capture_mode": "industrial only"},
                }
            ],
            "sensor_details": [
                {
                    "sensor_id": 11,
                    "payload": {
                        "id": 11,
                        "ip": "172.16.10.50",
                        "hardwareType": "DPI",
                        "version": "5.5.0",
                        "uptime": 7200,
                        "snortEnabled": True,
                        "activeDiscoveryEnabled": False,
                        "extensionCredentialsInvalid": False,
                    },
                }
            ],
            "sensor_stats": [
                {
                    "sensor_id": 11,
                    "payload": {
                        "system_date": 1785761995000,
                        "cpu_usage": 12.5,
                        "ram_usage": 44.0,
                        "disk_usage": 30.0,
                        "pkt_rate": 150,
                        "pkt_count": 9000,
                        "pkt_drop_count": 2,
                        "snort_enabled": True,
                        "active_discovery_enabled": False,
                        "extension_credentials_invalid": False,
                    },
                }
            ],
            "reports_metadata": [
                {
                    "id": "report-metadata-1",
                    "name": "Inventario OT",
                    "description": "Inventario schedulato",
                    "report_type": "inventory",
                    "report_out_type": ["pdf", "csv"],
                    "cron_expression": "0 6 * * 1",
                    "created_at": "2026-07-01T08:00:00Z",
                    "updated_at": "2026-08-01T08:00:00Z",
                    "reports": {
                        "status": "completed",
                        "last_run_at": "2026-08-03T06:00:00Z",
                        "error": "",
                        "reports_outputs": [
                            {
                                "document_id": "document-1",
                                "document_name": "inventory.pdf",
                                "document_type": "pdf",
                            }
                        ],
                    },
                }
            ],
        },
    }


def test_normalizes_real_cisco_entities_without_confusing_score_types() -> None:
    result = normalize_cybervision_collection(raw_collection())

    assert len(result["assets"]) == 2
    assert result["assets"][0]["name"] == "PLC BeerFactory"
    assert result["assets"][0]["status"] == "unknown"
    assert result["assets"][0]["zone"] == "Beer Factory"
    assert result["assets"][0]["protocols"] == ["Modbus"]
    assert result["source"]["details"]["collection_window"] == {
        "from": "2026-08-02T13:00:00Z",
        "to": "2026-08-03T13:00:00Z",
    }
    dashboard = result["source"]["details"]["dashboard_metrics"]
    assert dashboard["event_categories"]["total"] == [
        {"category": "Security", "count": 3},
        {"category": "Anomaly", "count": 1},
    ]
    assert dashboard["event_severities"]["centers"][0]["critical"] == 1
    assert dashboard["risk_distribution"]["total"]["total"] == 2
    assert dashboard["protocol_distribution"]["total"] == [
        {"tag_id": "tag-modbus", "tag_label": "Modbus", "count": 8}
    ]
    assert [score["score"] for score in result["risk_scores"]] == [68, 22]
    assert all(score["methodology"] == "cisco_cyber_vision" for score in result["risk_scores"])
    plc_score = next(score for score in result["risk_scores"] if score["score"] == 68)
    assert plc_score["band"] == "medium"
    assert plc_score["computed_at"] == "2026-08-03T12:58:00Z"
    assert [factor["value"] for factor in plc_score["factors"]] == [70, 55, 62, 80]
    assert plc_score["details"]["matching_tag"] == "Critical asset"
    assert plc_score["details"]["most_impacting_activity_id"] == "7"
    assert result["vulnerabilities"][0]["cvss_score"] == 8.1
    assert result["vulnerabilities"][0]["cvss_score"] != 99
    catalog = result["source"]["details"]["vulnerability_catalog"]
    assert catalog == [
        {
            "source_record_id": "vuln-1",
            "external_id": "CVE-2026-0001",
            "title": "Test vulnerability",
            "cvss_score": 8.1,
            "cvss_version": 3.1,
            "published_at": "2026-07-01T00:00:00Z",
            "vendor_id": None,
        }
    ]
    assert result["source"]["record_counts"]["vulnerability_catalog"] == 1
    details = result["vulnerabilities"][0]["details"]
    assert details["acknowledged_by"] == "analyst"
    assert details["acknowledgement_comment"] == "Mitigazione pianificata"
    assert details["vendor_id"] == "vendor-42"


def test_flow_activity_event_and_baseline_references_use_stable_ids() -> None:
    result = normalize_cybervision_collection(raw_collection())
    flow = result["flows"][0]
    difference = result["baseline_differences"][0]

    assert flow["left_asset_id"].endswith(":43")
    assert flow["right_asset_id"].endswith(":42")
    assert flow["left_port"] == 55000
    assert flow["right_port"] == 502
    assert flow["direction"] == "left_to_right"
    assert result["activities"][0]["asset_ids"] == [
        "asset:cybervision:dtlab-01:43",
        "asset:cybervision:dtlab-01:42",
    ]
    assert result["activities"][0]["packet_count"] == 120
    assert result["activities"][0]["details"]["direction"] == "left_to_right"
    assert result["activities"][0]["details"]["status"] == "active"
    assert result["activities"][0]["details"]["tags"] == ["Industrial traffic"]
    assert result["activities"][0]["details"]["variables_count"] == 1
    assert result["activities"][0]["details"]["left_asset_id"].endswith(":43")
    assert result["activities"][0]["details"]["right_asset_id"].endswith(":42")
    assert result["events"][0]["asset_ids"] == []
    assert result["events"][0]["center_id"] == "center-1"
    assert result["events"][0]["center_label"] == "DTLab Center"
    assert result["events"][0]["status"] is None
    assert result["events"][0]["acknowledged"] is None
    assert difference["flow_id"] is None
    assert difference["asset_ids"] == ["asset:cybervision:dtlab-01:42"]
    assert difference["detected_at"] == "2026-08-03T12:55:00Z"
    assert "Cisco cached" in result["events"][0]["evidence"]["notes"][0]


def test_right_left_flow_preserves_cisco_sides_ports_and_direction() -> None:
    raw = raw_collection()
    raw["data"]["flows"][0]["direction"] = "rightLeft"

    flow = normalize_cybervision_collection(raw)["flows"][0]

    assert flow["left_asset_id"].endswith(":43")
    assert flow["right_asset_id"].endswith(":42")
    assert flow["left_component_id"] == "component-hmi"
    assert flow["right_component_id"] == "component-plc"
    assert flow["left_port"] == 55000
    assert flow["right_port"] == 502
    assert flow["direction"] == "right_to_left"
    assert flow["direction_raw"] == "rightLeft"


def test_undetermined_flow_keeps_canonical_endpoints_without_inventing_direction() -> None:
    raw = raw_collection()
    raw["data"]["flows"][0]["direction"] = "undetermined"

    flow = normalize_cybervision_collection(raw)["flows"][0]

    assert flow["left_asset_id"].endswith(":43")
    assert flow["right_asset_id"].endswith(":42")
    assert flow["direction"] == "undetermined"
    assert flow["left_port"] == 55000
    assert flow["right_port"] == 502
    assert flow["evidence"]["completeness"] == 1.0


def test_unknown_flow_direction_is_preserved_and_marked_incomplete() -> None:
    raw = raw_collection()
    raw["data"]["flows"][0]["direction"] = "sideways"

    flow = normalize_cybervision_collection(raw)["flows"][0]

    assert flow["direction"] == "unknown"
    assert flow["direction_raw"] == "sideways"
    assert flow["evidence"]["completeness"] == 0.8


def test_sensor_stats_and_report_metadata_are_preserved_without_a_fake_health_score() -> None:
    result = normalize_cybervision_collection(raw_collection())

    sensor = result["sensors"][0]
    assert sensor["status"] == "operational"
    assert sensor["capture_mode"] == "industrial only"
    assert sensor["stats"]["cpu_percent"] == 12.5
    assert sensor["stats"]["drop_count"] == 2
    assert sensor["stats"]["snort_enabled"] is True
    assert sensor["stats"]["discovery_enabled"] is False
    assert sensor["stats"]["extension_access_valid"] is True
    assert "health_score" not in sensor
    report = result["reports"][0]
    assert report["name"] == "Inventario OT"
    assert report["status"] == "completed"
    assert report["documents"][0]["document_id"] == "document-1"


def test_sensor_detail_without_stats_response_does_not_claim_stats_available() -> None:
    raw = raw_collection()
    raw["data"]["sensor_stats"] = []

    sensor = normalize_cybervision_collection(raw)["sensors"][0]

    assert sensor["stats"] is None


def test_negative_sensor_timestamp_is_treated_as_unavailable() -> None:
    raw = raw_collection()
    raw["data"]["sensors"][0]["status"]["lastReceivedSysinfo"] = -1

    sensor = normalize_cybervision_collection(raw)["sensors"][0]

    assert sensor["last_seen_at"] is None


def test_unrecognized_raw_fields_are_not_copied_to_the_published_payload() -> None:
    raw = raw_collection()
    raw["data"]["risk_distribution"]["internalToken"] = "dashboard-must-not-leak"

    result = normalize_cybervision_collection(raw)
    encoded = json.dumps(result)

    assert "must-not-leak" not in encoded
    assert "dashboard-must-not-leak" not in encoded
    assert "internalToken" not in encoded


def test_cybervision_entities_pass_full_v2_contract() -> None:
    result = normalize_cybervision_collection(raw_collection())
    snapshot = valid_snapshot()
    snapshot["generated_at"] = "2026-08-03T13:00:00Z"
    snapshot["sync"]["started_at"] = "2026-08-03T12:59:55Z"
    snapshot["sync"]["completed_at"] = "2026-08-03T13:00:00Z"
    snapshot["sources"][2] = result["source"]
    for key in (
        "assets",
        "risk_scores",
        "activities",
        "flows",
        "events",
        "vulnerabilities",
        "baselines",
        "baseline_differences",
        "sensors",
        "reports",
    ):
        snapshot[key] = result[key]
    snapshot["quality"]["checks"] = result["quality_checks"]
    snapshot["quality"]["coverage"] = result["coverage"]
    snapshot["quality"]["score"] = result["quality_score"]

    validate_snapshot(snapshot)


def test_absent_score_stays_absent_instead_of_becoming_zero() -> None:
    raw = raw_collection()
    raw["data"]["devices"][0].pop("riskScore")
    raw["data"]["devices"][1].pop("riskScore")
    raw["data"]["device_risk_scores"] = []

    result = normalize_cybervision_collection(raw)

    assert result["risk_scores"] == []


def test_unlicensed_baseline_is_excluded_from_quality_denominator() -> None:
    raw = raw_collection()
    raw["capabilities"]["baselines"]["status"] = "feature_unlicensed"
    raw["data"]["baselines"] = []
    raw["data"]["baseline_differences"] = []

    result = normalize_cybervision_collection(raw)

    assert "baselines" not in result["coverage"]


def test_dashboard_capabilities_are_included_in_quality_coverage() -> None:
    raw = raw_collection()
    raw["capabilities"]["protocol_distribution"] = {
        "status": "error",
        "records": 0,
        "error_code": "timeout",
    }

    result = normalize_cybervision_collection(raw)

    assert result["coverage"]["event_categories"] == 1.0
    assert result["coverage"]["risk_distribution"] == 1.0
    assert result["coverage"]["protocol_distribution"] == 0.0
    check = next(
        item
        for item in result["quality_checks"]
        if item["code"] == "cybervision_protocol_distribution"
    )
    assert check["status"] == "warn"


def test_missing_collection_timestamp_fails_closed() -> None:
    raw = deepcopy(raw_collection())
    raw["collected_at"] = None

    with pytest.raises(CyberVisionNormalizationError, match="collected_at"):
        normalize_cybervision_collection(raw)
