"""Allowlisted normalization for the documented Cyber Vision New UI API."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

DEFAULT_SOURCE_ID = "src:cisco-cyber-vision-new-ui:dtlab-01"
_CAPABILITY_NAMES = (
    "new_ui_assets",
    "new_ui_alerts",
    "new_ui_vulnerability_assets",
    "new_ui_networks",
    "new_ui_org_hierarchy",
)
_ALERT_QUERY_STATUSES = ("Active", "Cleared", "Muted")
_MAC = re.compile(r"^(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")


def _text(value: Any) -> str | None:
    if isinstance(value, (str, int, float)) and not isinstance(value, bool):
        result = str(value).strip()
        return result or None
    return None


def _utc_text(value: Any) -> str | None:
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        seconds = float(value) / 1000 if abs(float(value)) > 10_000_000_000 else float(value)
        if seconds <= 0:
            return None
        try:
            return datetime.fromtimestamp(seconds, tz=UTC).isoformat().replace(
                "+00:00", "Z"
            )
        except (OverflowError, OSError, ValueError):
            return None
    text = str(value).strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _integer(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    return number if number >= 0 else None


def _items(value: Any) -> list[Mapping[str, Any]]:
    if isinstance(value, list):
        return [item for item in value if isinstance(item, Mapping)]
    if isinstance(value, Mapping) and isinstance(value.get("items"), list):
        return [item for item in value["items"] if isinstance(item, Mapping)]
    return []


def _interfaces(value: Any) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for interface in value if isinstance(value, list) else []:
        if not isinstance(interface, Mapping):
            continue
        ip = _text(interface.get("ip"))
        if ip:
            try:
                ip = str(ipaddress.ip_address(ip))
            except ValueError:
                ip = None
        mac = _text(interface.get("mac"))
        mac = mac.lower() if mac and _MAC.fullmatch(mac) else None
        if not ip and not mac:
            continue
        result.append(
            {
                "ip": ip,
                "mac": mac,
                "network_name": _text(interface.get("networkName")),
                "vlan": _integer(interface.get("vlan")),
                "is_primary": (
                    interface.get("isPrimary")
                    if isinstance(interface.get("isPrimary"), bool)
                    else None
                ),
            }
        )
    return result


def _asset_summary(asset: Mapping[str, Any]) -> dict[str, Any] | None:
    asset_id = _text(asset.get("id"))
    if not asset_id:
        return None
    sensors = []
    for sensor in asset.get("sensorAssociations", []):
        if not isinstance(sensor, Mapping) or not _text(sensor.get("id")):
            continue
        sensors.append(
            {
                "id": _text(sensor.get("id")),
                "label": _text(sensor.get("label")),
                "is_close": (
                    sensor.get("isClose")
                    if isinstance(sensor.get("isClose"), bool)
                    else None
                ),
            }
        )
    pcaps = []
    for pcap in asset.get("pcapAssociations", []):
        if not isinstance(pcap, Mapping) or not _text(pcap.get("id")):
            continue
        pcaps.append(
            {
                "id": _text(pcap.get("id")),
                "filename": _text(pcap.get("filename")),
            }
        )
    custom_properties = asset.get("customProperties")
    return {
        "id": asset_id,
        "name": _text(asset.get("name")) or f"Asset New UI {asset_id}",
        "type": _text(asset.get("type")) or "Unknown",
        "vendor": _text(asset.get("vendor")),
        "created_at": _utc_text(asset.get("creationTime")),
        "first_active_at": _utc_text(asset.get("firstActiveTime")),
        "last_active_at": _utc_text(asset.get("lastActiveTime")),
        "functional_group_id": _text(asset.get("functionalGroupId")),
        "functional_group_name": _text(asset.get("functionalGroupName")),
        "active_alert_count": _integer(asset.get("activeAlertCount")),
        "vulnerability_count": _integer(asset.get("vulnerabilityCount")),
        "network_interfaces": _interfaces(asset.get("networkInterfaces")),
        "sensor_associations": sensors,
        "pcap_associations": pcaps,
        "custom_property_count": (
            len(custom_properties) if isinstance(custom_properties, list) else 0
        ),
    }


def _alert_assets_for_status(
    value: Any,
    *,
    query_status: str | None,
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for asset in _items(value):
        asset_id = _text(asset.get("id"))
        if not asset_id:
            continue
        alerts = []
        for alert in asset.get("alerts", []):
            if not isinstance(alert, Mapping):
                continue
            alerts.append(
                {
                    "alert_id": _text(alert.get("alertId")),
                    "instance_id": _text(alert.get("instanceId")),
                    "alert_type": _text(alert.get("alertType")),
                    "category": _text(alert.get("category")),
                    "last_occurrence": _utc_text(alert.get("lastOccurrence")),
                    "severity": _text(alert.get("severity")),
                    "trigger": _text(alert.get("trigger")),
                    # The New UI response omits status; it is evidence from the
                    # exact read-only query that returned this alert.
                    "status": query_status,
                }
            )
        result.append(
            {
                "asset_id": asset_id,
                "asset_name": _text(asset.get("name")) or f"Asset {asset_id}",
                "query_status": query_status,
                "network_interfaces": _interfaces(asset.get("networkInterfaces")),
                "alerts": alerts,
            }
        )
    return result


def _alert_assets(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, Mapping) and isinstance(value.get("byStatus"), Mapping):
        result: list[dict[str, Any]] = []
        for query_status in _ALERT_QUERY_STATUSES:
            payload = value["byStatus"].get(query_status)
            if isinstance(payload, Mapping):
                result.extend(
                    _alert_assets_for_status(
                        payload,
                        query_status=query_status,
                    )
                )
        return result
    return _alert_assets_for_status(value, query_status=None)


def _alert_query_statuses(capabilities: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    capability = capabilities.get("new_ui_alerts", {})
    statuses = capability.get("statuses", {}) if isinstance(capability, Mapping) else {}
    result: dict[str, dict[str, Any]] = {}
    if not isinstance(statuses, Mapping):
        return result
    for query_status in _ALERT_QUERY_STATUSES:
        item = statuses.get(query_status)
        if not isinstance(item, Mapping):
            continue
        result[query_status] = {
            "status": str(item.get("status") or "unknown"),
            "records": max(0, int(item.get("records") or 0)),
            "error_code": _text(item.get("error_code")),
        }
    return result


def _vulnerability_assets(value: Any) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for asset in _items(value):
        asset_id = _text(asset.get("id"))
        if not asset_id:
            continue
        vulnerabilities = []
        for vulnerability in asset.get("vulnerabilities", []):
            if not isinstance(vulnerability, Mapping):
                continue
            vulnerabilities.append(
                {
                    "cve_id": _text(vulnerability.get("cveId")),
                    "name": _text(vulnerability.get("name")),
                    "source": _text(vulnerability.get("source")),
                    "csrs_score": _text(vulnerability.get("csrsScore")),
                    "cvss_score": _text(vulnerability.get("cvssScore")),
                }
            )
        result.append(
            {
                "asset_id": asset_id,
                "asset_name": _text(asset.get("name")) or f"Asset {asset_id}",
                "network_interfaces": _interfaces(asset.get("assetInterfaces")),
                "vulnerabilities": vulnerabilities,
            }
        )
    return result


def _networks(value: Any) -> list[dict[str, Any]]:
    result = []
    for network in _items(value):
        network_id = _text(network.get("id"))
        if not network_id:
            continue
        custom_properties = network.get("customProperties")
        result.append(
            {
                "id": network_id,
                "name": _text(network.get("name")) or f"Network {network_id}",
                "type": _text(network.get("type")),
                "ip_range": _text(network.get("ipRange")),
                "group_id": _text(network.get("groupId")),
                "vlan_id": _integer(network.get("vlanId")),
                "duplicated": (
                    network.get("duplicated")
                    if isinstance(network.get("duplicated"), bool)
                    else None
                ),
                "custom_property_count": (
                    len(custom_properties) if isinstance(custom_properties, list) else 0
                ),
            }
        )
    return result


def _org_hierarchy(value: Any) -> list[dict[str, Any]]:
    result = []
    for item in _items(value):
        item_id = _text(item.get("id"))
        if not item_id:
            continue
        result.append(
            {
                "id": item_id,
                "name": _text(item.get("name")) or f"Hierarchy {item_id}",
                "description": _text(item.get("description")),
                "hierarchy": _text(item.get("hierarchy")),
                "parent_level_id": _text(item.get("parentLevelId")),
            }
        )
    return result


def normalize_cybervision_new_ui_source(
    raw: Mapping[str, Any],
    *,
    source_id: str = DEFAULT_SOURCE_ID,
) -> dict[str, Any]:
    """Build a separate source so New UI entities never overwrite Classic data."""

    data = raw.get("data") if isinstance(raw.get("data"), Mapping) else {}
    capabilities = (
        raw.get("capabilities")
        if isinstance(raw.get("capabilities"), Mapping)
        else {}
    )
    collected_at = _utc_text(raw.get("collected_at"))
    if not collected_at:
        raise ValueError("collected_at New UI assente o non valido")

    assets_payload = data.get("new_ui_assets", {})
    assets = [
        normalized
        for item in _items(assets_payload)
        if (normalized := _asset_summary(item)) is not None
    ]
    alerts = _alert_assets(data.get("new_ui_alerts", {}))
    vulnerability_assets = _vulnerability_assets(
        data.get("new_ui_vulnerability_assets", {})
    )
    networks = _networks(data.get("new_ui_networks", {}))
    org_hierarchy = _org_hierarchy(data.get("new_ui_org_hierarchy", {}))
    center_id = None
    for payload in (
        assets_payload,
        data.get("new_ui_alerts"),
        data.get("new_ui_vulnerability_assets"),
        data.get("new_ui_org_hierarchy"),
    ):
        if isinstance(payload, Mapping) and _text(payload.get("centerId")):
            center_id = _text(payload.get("centerId"))
            break

    normalized_capabilities: dict[str, dict[str, Any]] = {}
    coverage: dict[str, float] = {}
    for raw_name in _CAPABILITY_NAMES:
        capability = capabilities.get(raw_name, {})
        if not isinstance(capability, Mapping):
            continue
        name = raw_name.removeprefix("new_ui_")
        status = str(capability.get("status") or "unknown")
        normalized_capabilities[name] = {
            "status": status,
            "records": max(0, int(capability.get("records") or 0)),
            "error_code": (
                str(capability["error_code"])
                if capability.get("error_code") is not None
                else None
            ),
        }
        if status == "available":
            coverage[raw_name] = 1.0
        elif status in {"partial", "truncated"}:
            coverage[raw_name] = 0.5
        elif status not in {"not_configured", "version_unsupported"}:
            coverage[raw_name] = 0.0

    aggregate = capabilities.get("new_ui", {})
    aggregate_status = (
        str(aggregate.get("status") or "unknown")
        if isinstance(aggregate, Mapping)
        else "unknown"
    )
    if aggregate_status == "available":
        source_status = "connected"
    elif aggregate_status in {"partial", "truncated"}:
        source_status = "degraded"
    elif aggregate_status == "not_configured":
        source_status = "not_configured"
    else:
        source_status = "unavailable"
    has_success = any(
        capability["status"] in {"available", "partial", "truncated"}
        for capability in normalized_capabilities.values()
    )
    source = {
        "id": source_id,
        "evidence": {
            "source_id": source_id,
            "source_record_id": "new-ui:assets",
            "truth": "real" if has_success else "unavailable",
            "observed_at": collected_at if has_success else None,
            "fetched_at": collected_at,
            "completeness": (
                sum(coverage.values()) / len(coverage) if coverage else 0.0
            ),
            "notes": [
                "Inventario New UI separato dai Device Classic; nessun merge implicito.",
                "CSRS e CVSS restano distinti dal risk score Classic per-device.",
            ],
        },
        "label": "Cisco Cyber Vision · New UI",
        "type": "cisco_cyber_vision_new_ui",
        "endpoint_label": "Cyber Vision Center · New UI API via VPN",
        "status": source_status,
        "version": _text(
            raw.get("api", {}).get("version")
            if isinstance(raw.get("api"), Mapping)
            else None
        ),
        "last_attempt_at": collected_at,
        "last_success_at": collected_at if has_success else None,
        "record_counts": {
            "assets": len(assets),
            "alert_assets": len(alerts),
            "vulnerability_assets": len(vulnerability_assets),
            "networks": len(networks),
            "org_hierarchy": len(org_hierarchy),
        },
        "capabilities": normalized_capabilities,
        "details": {
            "api": "1.0",
            "center_id": center_id,
            "max_records_per_endpoint": 500,
            "assets": assets,
            "alert_assets": alerts,
            "alert_query_statuses": _alert_query_statuses(capabilities),
            "vulnerability_assets": vulnerability_assets,
            "networks": networks,
            "org_hierarchy": org_hierarchy,
        },
        "error": (
            None
            if source_status == "connected"
            else {
                "code": (
                    str(aggregate.get("error_code") or aggregate_status)
                    if isinstance(aggregate, Mapping)
                    else aggregate_status
                ),
                "message": "Una o più capability New UI GET non sono disponibili.",
            }
        ),
    }
    checks = [
        {
            "code": f"cybervision_{name}",
            "label": f"Cyber Vision New UI · {name.removeprefix('new_ui_').replace('_', ' ')}",
            "status": "pass" if value == 1 else "warn",
            "details": f"Copertura capability {round(value * 100)}%.",
        }
        for name, value in coverage.items()
    ]
    return {
        "source": source,
        "coverage": coverage,
        "quality_checks": checks,
    }
