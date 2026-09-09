"""Normalize documented Cisco Cyber Vision responses into DTLab v2 entities."""

from __future__ import annotations

import hashlib
import ipaddress
import re
import uuid
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

from dtlab.adapters.cybervision_new_ui import normalize_cybervision_new_ui_source

DEFAULT_SOURCE_ID = "src:cisco-cyber-vision:dtlab-01"
ID_PREFIX = "cybervision:dtlab-01"
_MAC = re.compile(r"^(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")


class CyberVisionNormalizationError(ValueError):
    """A raw Cyber Vision collection cannot be represented safely."""


def _utc_text(value: Any) -> str | None:
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if value <= 0:
            return None
        seconds = float(value) / 1000 if abs(float(value)) > 10_000_000_000 else float(value)
        try:
            return datetime.fromtimestamp(seconds, tz=UTC).isoformat().replace("+00:00", "Z")
        except (OverflowError, OSError, ValueError):
            return None
    text = str(value).strip()
    if not text:
        return None
    if re.fullmatch(r"-?\d+(?:\.\d+)?", text):
        return _utc_text(float(text))
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _slug(value: Any) -> str:
    raw = str(value).strip()
    simple = re.sub(r"[^a-zA-Z0-9_.-]+", "-", raw).strip("-").lower()
    if simple and simple == raw.lower() and len(simple) <= 80:
        return simple
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:10]
    return f"{simple[:48] or 'record'}-{digest}"


def _dig(record: Any, *paths: str) -> Any:
    if not isinstance(record, Mapping):
        return None
    for path in paths:
        current: Any = record
        found = True
        for part in path.split("."):
            if not isinstance(current, Mapping) or part not in current:
                found = False
                break
            current = current[part]
        if found and current is not None:
            if isinstance(current, str) and not current.strip():
                continue
            return current
    return None


def _scalar_name(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, Mapping):
        nested = _dig(value, "name", "label", "value", "type")
        return str(nested) if nested is not None else None
    if isinstance(value, (str, int, float)) and not isinstance(value, bool):
        return str(value)
    return None


def _flatten_scalars(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        result: list[str] = []
        for item in value:
            name = _scalar_name(item)
            if name:
                result.append(name)
        return result
    name = _scalar_name(value)
    return [name] if name else []


def _addresses(record: Mapping[str, Any], *, kind: str) -> list[str]:
    if kind == "ip":
        fields = (
            "ipAddresses",
            "ip_addresses",
            "ips",
            "ipAddress",
            "ip",
            "interfaces",
        )
    else:
        fields = (
            "macAddresses",
            "mac_addresses",
            "macs",
            "macAddress",
            "mac",
            "interfaces",
        )

    values: list[Any] = []
    for field in fields:
        candidate = _dig(record, field)
        if candidate is None:
            continue
        if isinstance(candidate, list):
            for item in candidate:
                if isinstance(item, Mapping):
                    for nested_key in (
                        "ip",
                        "ipAddress",
                        "address",
                        "mac",
                        "macAddress",
                    ):
                        nested = item.get(nested_key)
                        if nested is not None:
                            values.extend(nested if isinstance(nested, list) else [nested])
                else:
                    values.append(item)
        else:
            values.append(candidate)

    normalized: list[str] = []
    for value in values:
        text = str(value).strip()
        if kind == "ip":
            try:
                text = str(ipaddress.ip_address(text))
            except ValueError:
                continue
        elif not _MAC.fullmatch(text):
            continue
        else:
            text = text.lower()
        if text not in normalized:
            normalized.append(text)
    return normalized


def _source_id(record: Mapping[str, Any], *keys: str) -> str | None:
    value = _dig(record, *keys)
    if value is None:
        return None
    if isinstance(value, Mapping):
        value = _dig(value, "id", "deviceId", "componentId")
    return str(value) if value is not None else None


def _number(value: Any) -> float | None:
    if isinstance(value, Mapping):
        value = _dig(value, "value", "score", "globalScore")
    try:
        result = float(value)
    except (TypeError, ValueError):
        return None
    return result


def _optional_integer(value: Any) -> int | None:
    number = _number(value)
    if number is None or number < 0:
        return None
    return int(number)


def _optional_nonnegative_number(value: Any) -> float | None:
    number = _number(value)
    return number if number is not None and number >= 0 else None


def _optional_percent(value: Any) -> float | None:
    number = _number(value)
    return number if number is not None and 0 <= number <= 100 else None


def _optional_boolean(value: Any) -> bool | None:
    return value if isinstance(value, bool) else None


def _latest_number(value: Any) -> float | None:
    if isinstance(value, list):
        for item in reversed(value):
            number = _latest_number(item)
            if number is not None:
                return number
        return None
    if isinstance(value, Mapping):
        for key in (
            "value",
            "data",
            "current",
            "last",
            "average",
            "avg",
            "count",
            "y",
        ):
            if key in value:
                number = _latest_number(value[key])
                if number is not None:
                    return number
        return None
    return _number(value)


def _metric(record: Mapping[str, Any], *paths: str) -> float | None:
    return _latest_number(_dig(record, *paths))


def _traffic_direction(value: Any) -> tuple[str, str | None]:
    """Normalize the appliance value without inventing an endpoint orientation."""

    raw = _scalar_name(value)
    key = re.sub(r"[^a-z0-9]+", "", (raw or "").lower())
    if key in {"leftright", "lefttoright", "ltr", "lr", "l2r"}:
        return "left_to_right", raw
    if key in {"rightleft", "righttoleft", "rtl", "rl", "r2l"}:
        return "right_to_left", raw
    if key == "undetermined":
        return "undetermined", raw
    return "unknown", raw


def _evidence(
    source_id: str,
    source_record_id: str | None,
    collected_at: str,
    *,
    completeness: float = 1.0,
    notes: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "source_id": source_id,
        "source_record_id": source_record_id,
        "truth": "real",
        "observed_at": collected_at,
        "fetched_at": collected_at,
        "completeness": completeness,
        "notes": notes or [],
    }


def _raw_items(value: Any) -> list[Mapping[str, Any]]:
    if isinstance(value, list):
        return [item for item in value if isinstance(item, Mapping)]
    if isinstance(value, Mapping):
        for key in ("events", "items", "content", "results", "recentEvents", "data"):
            nested = value.get(key)
            if isinstance(nested, list):
                return [item for item in nested if isinstance(item, Mapping)]
            if isinstance(nested, Mapping):
                result = _raw_items(nested)
                if result:
                    return result
    return []


def _identifier_text(value: Any) -> str | None:
    """Return a stable identifier without copying arbitrary dashboard payloads."""

    if isinstance(value, str):
        text = value.strip()
        return text or None
    if isinstance(value, int) and not isinstance(value, bool):
        return str(value)
    if (
        isinstance(value, list)
        and len(value) == 16
        and all(isinstance(item, int) and 0 <= item <= 255 for item in value)
    ):
        try:
            return str(uuid.UUID(bytes=bytes(value)))
        except ValueError:
            return None
    return None


def _center_count_rows(value: Any, counters: tuple[str, ...]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for record in _raw_items(value):
        row: dict[str, Any] = {
            "center_id": _identifier_text(_dig(record, "id", "centerId")),
            "center_label": _scalar_name(_dig(record, "label", "centerLabel", "centerName")),
        }
        for counter in counters:
            row[counter] = _optional_integer(_dig(record, counter))
        if any(item is not None for item in row.values()):
            rows.append(row)
    return rows


def _category_count_rows(value: Any) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for record in _raw_items(value):
        category = _scalar_name(_dig(record, "category"))
        count = _optional_integer(_dig(record, "count"))
        if category is not None and count is not None:
            rows.append({"category": category, "count": count})
    return rows


def _protocol_count_rows(value: Any) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for record in _raw_items(value):
        tag_id = _identifier_text(_dig(record, "tagId"))
        tag_label = _scalar_name(_dig(record, "tagLabel"))
        count = _optional_integer(_dig(record, "count"))
        if count is not None and (tag_id is not None or tag_label is not None):
            rows.append(
                {
                    "tag_id": tag_id,
                    "tag_label": tag_label,
                    "count": count,
                }
            )
    return rows


def _risk_distribution_row(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, Mapping):
        return None
    row = {
        "center_id": _identifier_text(_dig(value, "centerId")),
        "center_label": _scalar_name(_dig(value, "centerName")),
        "high": _optional_integer(_dig(value, "high")),
        "medium": _optional_integer(_dig(value, "medium")),
        "low": _optional_integer(_dig(value, "low")),
        "total": _optional_integer(_dig(value, "total")),
    }
    return row if any(item is not None for item in row.values()) else None


def _dashboard_metrics(data: Mapping[str, Any]) -> dict[str, Any]:
    """Allowlist documented Classic dashboard counters for publication."""

    event_categories = data.get("event_categories")
    event_categories = event_categories if isinstance(event_categories, Mapping) else {}
    event_severities = data.get("event_severities")
    event_severities = event_severities if isinstance(event_severities, Mapping) else {}
    risk_distribution = data.get("risk_distribution")
    risk_distribution = risk_distribution if isinstance(risk_distribution, Mapping) else {}
    protocol_distribution = data.get("protocol_distribution")
    protocol_distribution = (
        protocol_distribution if isinstance(protocol_distribution, Mapping) else {}
    )

    protocol_centers: list[dict[str, Any]] = []
    for center in _raw_items(protocol_distribution.get("centers")):
        center_id = _identifier_text(_dig(center, "centerId", "id"))
        center_label = _scalar_name(_dig(center, "centerName", "centerLabel", "label"))
        totals = _protocol_count_rows(center.get("total"))
        if center_id is not None or center_label is not None or totals:
            protocol_centers.append(
                {
                    "center_id": center_id,
                    "center_label": center_label,
                    "total": totals,
                }
            )

    risk_centers = [
        row
        for row in (
            _risk_distribution_row(center)
            for center in _raw_items(risk_distribution.get("centers"))
        )
        if row is not None
    ]
    return {
        "event_categories": {
            "total": _category_count_rows(event_categories.get("total")),
            "centers": _center_count_rows(
                event_categories.get("centers"),
                ("anomaly", "extension", "security", "signature", "total"),
            ),
        },
        "event_severities": {
            "centers": _center_count_rows(
                event_severities.get("centers"),
                ("critical", "high", "medium", "low", "total"),
            ),
        },
        "risk_distribution": {
            "total": _risk_distribution_row(risk_distribution.get("total")),
            "centers": risk_centers,
        },
        "protocol_distribution": {
            "total": _protocol_count_rows(protocol_distribution.get("total")),
            "centers": protocol_centers,
        },
    }


def _device_id(record: Mapping[str, Any]) -> str | None:
    return _source_id(record, "id", "deviceId", "uuid")


def _asset_id(device_id: str) -> str:
    return f"asset:{ID_PREFIX}:{_slug(device_id)}"


def _risk_id(device_id: str) -> str:
    return f"risk:{ID_PREFIX}:{_slug(device_id)}"


def _flow_id(flow_id: str) -> str:
    return f"flow:{ID_PREFIX}:{_slug(flow_id)}"


def _explicit_status(record: Mapping[str, Any]) -> str:
    active = _dig(record, "active", "isActive", "online")
    if active is True:
        return "online"
    if active is False:
        return "offline"
    status = str(_dig(record, "status", "state") or "").lower()
    if status in {"online", "active", "up", "connected"}:
        return "online"
    if status in {"offline", "inactive", "down", "disconnected"}:
        return "offline"
    if status == "stale":
        return "stale"
    return "unknown"


def _risk_factors(payload: Mapping[str, Any]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    official = (
        ("activitiesRisk", "Attività"),
        ("deviceTypeRisk", "Tipo dispositivo"),
        ("groupRisk", "Gruppo"),
        ("vulnerabilitiesRisk", "Vulnerabilità"),
    )
    for key, label in official:
        block = payload.get(key)
        if not isinstance(block, Mapping):
            continue
        score = _number(_dig(block, "score"))
        if score is None:
            continue
        result.append({"label": label, "value": score, "weight": None})
    if result:
        return result

    legacy = (
        ("activityFactor", "Attività"),
        ("deviceTypeFactor", "Tipo dispositivo"),
        ("groupFactor", "Gruppo"),
        ("vulnerabilityFactor", "Vulnerabilità"),
    )
    for key, label in legacy:
        value = payload.get(key)
        score = _number(_dig(value, "value", "score", "factor"))
        if score is not None:
            result.append(
                {
                    "label": label,
                    "value": score,
                    "weight": _number(_dig(value, "weight")),
                }
            )
    return result


def _asset_refs(record: Mapping[str, Any], device_to_asset: Mapping[str, str]) -> list[str]:
    references: list[str] = []
    fields = (
        "deviceId",
        "sourceDeviceId",
        "destinationDeviceId",
        "srcDeviceId",
        "dstDeviceId",
        "device.id",
        "sourceDevice.id",
        "destinationDevice.id",
    )
    for field in fields:
        value = _source_id(record, field)
        if value and value in device_to_asset and device_to_asset[value] not in references:
            references.append(device_to_asset[value])
    devices = _dig(record, "devices")
    if isinstance(devices, list):
        for device in devices:
            value = (
                _source_id(device, "id", "deviceId") if isinstance(device, Mapping) else str(device)
            )
            if value in device_to_asset and device_to_asset[value] not in references:
                references.append(device_to_asset[value])
    return references


def normalize_cybervision_collection(
    raw: Mapping[str, Any],
    *,
    source_id: str = DEFAULT_SOURCE_ID,
) -> dict[str, Any]:
    data = raw.get("data")
    if not isinstance(data, Mapping):
        raise CyberVisionNormalizationError("La raccolta non contiene data.")
    collected_at = _utc_text(raw.get("collected_at"))
    if not collected_at:
        raise CyberVisionNormalizationError("collected_at assente o non valido.")
    capabilities = raw.get("capabilities")
    if not isinstance(capabilities, Mapping):
        raise CyberVisionNormalizationError("capabilities assente o non valido.")
    raw_window = raw.get("window")
    raw_window = raw_window if isinstance(raw_window, Mapping) else {}

    assets: list[dict[str, Any]] = []
    device_to_asset: dict[str, str] = {}
    raw_devices_by_id: dict[str, Mapping[str, Any]] = {}
    for device in _raw_items(data.get("devices")):
        device_id = _device_id(device)
        if not device_id:
            continue
        asset_id = _asset_id(device_id)
        device_to_asset[device_id] = asset_id
        raw_devices_by_id[device_id] = device
        raw_name = _scalar_name(
            _dig(
                device,
                "customLabel",
                "label",
                "originalLabel",
                "device",
                "name",
                "deviceName",
            )
        )
        name = raw_name or f"Device Cyber Vision {device_id}"
        last_seen = _utc_text(
            _dig(
                device,
                "lastActiveTime",
                "lastSeen",
                "last_seen",
                "lastActivity",
            )
        )
        raw_device_type = _scalar_name(_dig(device, "deviceType", "type", "device_type"))
        device_type = raw_device_type or "Sconosciuto"
        vendor = _scalar_name(_dig(device, "vendor", "manufacturer", "brand"))
        category = (
            _scalar_name(
                _dig(
                    device,
                    "category",
                    "deviceType.category",
                    "type.category",
                )
            )
            or "Sconosciuta"
        )
        ips = _addresses(device, kind="ip")
        macs = _addresses(device, kind="mac")
        completeness_fields = (raw_name, raw_device_type, ips or macs, last_seen)
        completeness = sum(bool(value) for value in completeness_fields) / len(completeness_fields)
        assets.append(
            {
                "id": asset_id,
                "evidence": _evidence(
                    source_id,
                    f"device:{device_id}",
                    collected_at,
                    completeness=completeness,
                ),
                "name": name,
                "category": category,
                "device_type": device_type,
                "vendor": vendor,
                "ip_addresses": ips,
                "mac_addresses": macs,
                "network_ids": [],
                "zone": _scalar_name(_dig(device, "zone", "functionalGroup", "group")),
                "protocols": sorted(
                    set(
                        _flatten_scalars(
                            _dig(device, "protocols", "protocolNames", "activities.protocols")
                        )
                    )
                ),
                "status": _explicit_status(device),
                "last_seen_at": last_seen,
                "operational_role": "unknown",
            }
        )

    components_by_id: dict[str, Mapping[str, Any]] = {}
    component_to_asset: dict[str, str] = {}
    for component in _raw_items(data.get("components")):
        component_id = _source_id(component, "id", "componentId")
        if not component_id:
            continue
        components_by_id[component_id] = component
        device_id = _source_id(component, "device.id", "deviceId")
        if device_id and device_id in device_to_asset:
            component_to_asset[component_id] = device_to_asset[device_id]

    def endpoint(record: Mapping[str, Any], side: str) -> dict[str, str | None]:
        side_payload = _dig(record, side)
        side_mapping = side_payload if isinstance(side_payload, Mapping) else {}
        component_id = _source_id(side_mapping, "id", "componentId")
        component = components_by_id.get(component_id or "", {})
        asset_id = component_to_asset.get(component_id or "")
        label = _scalar_name(
            _dig(
                side_mapping,
                "customLabel",
                "label",
                "originalLabel",
            )
        ) or _scalar_name(_dig(component, "customLabel", "label", "originalLabel"))
        ip = _scalar_name(_dig(side_mapping, "ip")) or _scalar_name(_dig(component, "ip"))
        return {
            "component_id": component_id,
            "asset_id": asset_id,
            "label": label,
            "ip": ip,
        }

    risk_payload_by_device: dict[str, Mapping[str, Any]] = {}
    for wrapper in data.get("device_risk_scores") or []:
        if not isinstance(wrapper, Mapping):
            continue
        device_id = str(wrapper.get("device_id"))
        payload = wrapper.get("payload")
        if device_id and isinstance(payload, Mapping):
            risk_payload_by_device[device_id] = payload

    risk_scores: list[dict[str, Any]] = []
    for device_id, asset_id in device_to_asset.items():
        detailed = risk_payload_by_device.get(device_id, {})
        device = raw_devices_by_id[device_id]
        score = _number(_dig(device, "riskScore", "risk_score", "globalScore"))
        notes: list[str] = []
        source_record_id = f"device:{device_id}"
        if score is None or not 0 <= score <= 100:
            continue
        factors = _risk_factors(detailed)
        completeness = min(1.0, 0.6 + len(factors) * 0.1)
        if detailed and not factors:
            notes.append("Dettaglio risk score acquisito, ma nessun fattore Cisco riconosciuto.")
        band = "low" if score < 40 else "medium" if score < 70 else "high"
        risk_scores.append(
            {
                "id": _risk_id(device_id),
                "evidence": _evidence(
                    source_id,
                    source_record_id,
                    collected_at,
                    completeness=completeness,
                    notes=notes,
                ),
                "asset_id": asset_id,
                "score": score,
                "band": band,
                "methodology": "cisco_cyber_vision",
                "computed_at": _utc_text(
                    _dig(
                        detailed,
                        "deviceEngineLastRun",
                        "computedAt",
                        "lastRun",
                    )
                ),
                "factors": factors,
                "details": {
                    "matching_tag": _scalar_name(_dig(detailed, "matchingTag")),
                    "most_impacting_activity_id": _source_id(detailed, "mostImpactingActivity"),
                    "most_impacting_vulnerability_id": _source_id(
                        detailed, "mostImpactingVulnerability"
                    ),
                    "risk_score_description": _scalar_name(_dig(detailed, "riskScoreDescription")),
                },
            }
        )

    activities: list[dict[str, Any]] = []
    raw_activity_to_assets: dict[str, list[str]] = {}
    for index, activity in enumerate(_raw_items(data.get("activities"))):
        source_record_id = _source_id(activity, "id", "activityId") or str(index)
        left = endpoint(activity, "left")
        right = endpoint(activity, "right")
        activity_direction, activity_direction_raw = _traffic_direction(_dig(activity, "direction"))
        activity_asset_ids = list(
            dict.fromkeys(
                asset_id
                for asset_id in (
                    left["asset_id"],
                    right["asset_id"],
                    *_asset_refs(activity, device_to_asset),
                )
                if asset_id
            )
        )
        raw_activity_to_assets[source_record_id] = activity_asset_ids
        activities.append(
            {
                "id": f"activity:{ID_PREFIX}:{_slug(source_record_id)}",
                "evidence": _evidence(
                    source_id,
                    f"activity:{source_record_id}",
                    collected_at,
                ),
                "asset_ids": activity_asset_ids,
                "type": _scalar_name(_dig(activity, "type", "activityType", "name")),
                "protocol": _scalar_name(
                    _dig(activity, "protocol", "protocolName", "protocol.name")
                ),
                "first_seen_at": _utc_text(
                    _dig(
                        activity,
                        "firstActivity",
                        "firstSeen",
                        "firstActiveTime",
                        "startTime",
                    )
                ),
                "last_seen_at": _utc_text(
                    _dig(
                        activity,
                        "lastActivity",
                        "lastSeen",
                        "lastActiveTime",
                        "endTime",
                    )
                ),
                "packet_count": _optional_integer(_dig(activity, "packetsCount", "packetCount")),
                "byte_count": _optional_integer(_dig(activity, "bytesCount", "byteCount")),
                "flow_count": _optional_integer(_dig(activity, "flowCount")),
                "event_count": _optional_integer(_dig(activity, "eventsCount")),
                "details": {
                    "direction": activity_direction,
                    "direction_raw": activity_direction_raw,
                    "status": _scalar_name(_dig(activity, "status")),
                    "tags": _flatten_scalars(_dig(activity, "tags")),
                    "variable_labels": _flatten_scalars(_dig(activity, "variables")),
                    "differences_count": len(_raw_items(_dig(activity, "differences"))),
                    "new_variable_access": _optional_integer(_dig(activity, "newVariableAccess")),
                    "variables_count": _optional_integer(_dig(activity, "variablesCount")),
                    "left_asset_id": left["asset_id"],
                    "right_asset_id": right["asset_id"],
                    "left_component_id": left["component_id"],
                    "right_component_id": right["component_id"],
                    "left_label": left["label"],
                    "right_label": right["label"],
                },
            }
        )

    flows: list[dict[str, Any]] = []
    raw_flow_to_id: dict[str, str] = {}
    for index, flow in enumerate(_raw_items(data.get("flows"))):
        source_record_id = _source_id(flow, "id", "flowId") or str(index)
        normalized_id = _flow_id(source_record_id)
        raw_flow_to_id[source_record_id] = normalized_id
        left = endpoint(flow, "left")
        right = endpoint(flow, "right")
        direction, direction_raw = _traffic_direction(_dig(flow, "direction"))
        source_device = _source_id(
            flow,
            "sourceDeviceId",
            "srcDeviceId",
            "source.deviceId",
            "source.device.id",
        )
        destination_device = _source_id(
            flow,
            "destinationDeviceId",
            "dstDeviceId",
            "destination.deviceId",
            "destination.device.id",
        )
        flow_notes = []
        if direction == "unknown":
            flow_notes.append("Direzione flow assente o non riconosciuta; lati Cisco preservati.")
        flows.append(
            {
                "id": normalized_id,
                "evidence": _evidence(
                    source_id,
                    f"flow:{source_record_id}",
                    collected_at,
                    completeness=0.8 if flow_notes else 1.0,
                    notes=flow_notes,
                ),
                "left_asset_id": left["asset_id"] or device_to_asset.get(source_device or ""),
                "right_asset_id": right["asset_id"]
                or device_to_asset.get(destination_device or ""),
                "left_component_id": left["component_id"],
                "right_component_id": right["component_id"],
                "left_label": left["label"],
                "right_label": right["label"],
                "left_ip": left["ip"]
                or _scalar_name(_dig(flow, "sourceIp", "srcIp", "source.ip", "source.address")),
                "right_ip": right["ip"]
                or _scalar_name(
                    _dig(
                        flow,
                        "destinationIp",
                        "dstIp",
                        "destination.ip",
                        "destination.address",
                    )
                ),
                "protocol": _scalar_name(_dig(flow, "protocol", "protocolName", "protocol.name"))
                or "Sconosciuto",
                "direction": direction,
                "direction_raw": direction_raw,
                "left_port": _optional_integer(
                    _dig(
                        flow,
                        "srcPort",
                        "sourcePort",
                        "source.port",
                    )
                ),
                "right_port": _optional_integer(
                    _dig(
                        flow,
                        "dstPort",
                        "destinationPort",
                        "destination.port",
                        "port",
                    )
                ),
                "first_seen_at": _utc_text(
                    _dig(
                        flow,
                        "firstActivity",
                        "firstSeen",
                        "firstActiveTime",
                        "startTime",
                    )
                ),
                "last_seen_at": _utc_text(
                    _dig(
                        flow,
                        "lastActivity",
                        "lastSeen",
                        "lastActiveTime",
                        "endTime",
                    )
                ),
                "packet_count": _optional_integer(
                    _dig(flow, "packetsCount", "packetCount", "messageCount")
                ),
                "byte_count": _optional_integer(_dig(flow, "bytesCount", "byteCount", "bytes")),
            }
        )

    protocols_by_asset: dict[str, set[str]] = {
        asset["id"]: set(asset["protocols"]) for asset in assets
    }
    for flow in flows:
        protocol = flow["protocol"]
        if protocol == "Sconosciuto":
            continue
        for asset_id in (flow["left_asset_id"], flow["right_asset_id"]):
            if asset_id:
                protocols_by_asset.setdefault(asset_id, set()).add(protocol)
    for asset in assets:
        asset["protocols"] = sorted(protocols_by_asset.get(asset["id"], set()))
        if asset["protocols"]:
            asset["evidence"]["notes"].append(
                "Protocolli aggregati dai flow Cisco nella finestra temporale acquisita."
            )

    events: list[dict[str, Any]] = []
    event_payload = data.get("event_severities")
    for index, event in enumerate(_raw_items(event_payload)):
        source_record_id = _source_id(event, "id", "eventId", "uuid") or str(index)
        severity = str(_dig(event, "severity", "level") or "unknown").lower()
        if severity not in {"critical", "high", "medium", "low", "info"}:
            severity = "unknown"
        occurred_at = _utc_text(_dig(event, "date", "timestamp", "occurredAt", "lastOccurrence"))
        if not occurred_at:
            continue
        title = (
            _scalar_name(_dig(event, "shortMessage", "title", "name", "message"))
            or "Evento Cyber Vision"
        )
        events.append(
            {
                "id": f"event:{ID_PREFIX}:{_slug(source_record_id)}",
                "evidence": _evidence(
                    source_id,
                    f"dashboard-event:{source_record_id}",
                    collected_at,
                    notes=["Evento proveniente dal widget Cisco cached."],
                ),
                "occurred_at": occurred_at,
                "severity": severity,
                "category": _scalar_name(_dig(event, "category", "type")) or "Sconosciuta",
                "title": title,
                "description": _scalar_name(_dig(event, "description", "message", "shortMessage"))
                or title,
                "center_id": _identifier_text(_dig(event, "centerId")),
                "center_label": _scalar_name(_dig(event, "centerLabel")),
                "status": _scalar_name(_dig(event, "status")),
                "asset_ids": _asset_refs(event, device_to_asset),
                "acknowledged": _optional_boolean(_dig(event, "acknowledged", "isAcknowledged")),
            }
        )

    global_vulnerability_by_id: dict[str, Mapping[str, Any]] = {}
    for vulnerability in _raw_items(data.get("vulnerabilities")):
        vulnerability_id = _source_id(
            vulnerability,
            "id",
            "vulnerabilityId",
            "cveId",
            "cve",
        )
        if vulnerability_id:
            global_vulnerability_by_id[vulnerability_id] = vulnerability

    # Keep a compact, source-owned catalogue index in the canonical snapshot.  It is
    # intentionally separate from device associations: catalogue presence never
    # means that an asset is exposed.  Full remediation detail remains attached only
    # to explicit per-device matches below.
    vulnerability_catalog = []
    for vulnerability_id, vulnerability in global_vulnerability_by_id.items():
        external_id = _scalar_name(
            _dig(vulnerability, "cve", "cveId", "externalId", "name")
        )
        title = _scalar_name(
            _dig(vulnerability, "title", "summary", "name", "fullDescription")
        )
        vulnerability_catalog.append(
            {
                "source_record_id": vulnerability_id,
                "external_id": external_id,
                "title": title or external_id or f"Vulnerabilità {vulnerability_id}",
                "cvss_score": _number(
                    _dig(vulnerability, "CVSS", "cvssScore", "cvss", "cvss.score")
                ),
                "cvss_version": _number(_dig(vulnerability, "CVSSVersion")),
                "published_at": _utc_text(
                    _dig(
                        vulnerability,
                        "publishTime",
                        "publishedAt",
                        "publicationDate",
                        "published",
                    )
                ),
                "vendor_id": _scalar_name(_dig(vulnerability, "vendorId")),
            }
        )
    vulnerability_catalog.sort(
        key=lambda item: (
            str(item["external_id"] or "").casefold(),
            str(item["source_record_id"]),
        )
    )

    vulnerabilities: list[dict[str, Any]] = []
    vulnerability_keys: set[tuple[str, str]] = set()
    for wrapper in data.get("device_vulnerabilities") or []:
        if not isinstance(wrapper, Mapping):
            continue
        device_id = str(wrapper.get("device_id"))
        asset_id = device_to_asset.get(device_id)
        if not asset_id:
            continue
        for item in _raw_items(wrapper.get("items")):
            vulnerability_id = _source_id(
                item,
                "id",
                "vulnerabilityId",
                "cveId",
                "cve",
            )
            if not vulnerability_id:
                continue
            key = (asset_id, vulnerability_id)
            if key in vulnerability_keys:
                continue
            vulnerability_keys.add(key)
            global_item = global_vulnerability_by_id.get(vulnerability_id, {})

            def pick(
                *paths: str,
                _item: Mapping[str, Any] = item,
                _global_item: Mapping[str, Any] = global_item,
            ) -> Any:
                value = _dig(_item, *paths)
                return value if value is not None else _dig(_global_item, *paths)

            external_id = _scalar_name(pick("cve", "cveId", "externalId", "name"))
            title = _scalar_name(pick("title", "summary", "name", "fullDescription")) or (
                external_id or f"Vulnerabilità {vulnerability_id}"
            )
            reasons = [
                str(reason)
                for reason in (pick("reasons") or [])
                if isinstance(reason, (str, int, float))
            ]
            links = []
            for link in pick("links") or []:
                if not isinstance(link, Mapping):
                    continue
                url = _scalar_name(_dig(link, "link", "url"))
                if not url or not re.match(r"^https?://", url, re.IGNORECASE):
                    continue
                links.append(
                    {
                        "title": _scalar_name(_dig(link, "title")) or "Riferimento",
                        "url": url,
                    }
                )
            vulnerabilities.append(
                {
                    "id": (
                        f"vulnerability:{ID_PREFIX}:{_slug(device_id)}:{_slug(vulnerability_id)}"
                    ),
                    "evidence": _evidence(
                        source_id,
                        f"device:{device_id}:vulnerability:{vulnerability_id}",
                        collected_at,
                    ),
                    "asset_id": asset_id,
                    "external_id": external_id,
                    "title": title,
                    "severity": _scalar_name(pick("severity", "level")) or "unknown",
                    "cvss_score": _number(pick("CVSS", "cvssScore", "cvss", "cvss.score")),
                    "status": _scalar_name(pick("status", "state")) or "unknown",
                    "published_at": _utc_text(
                        pick(
                            "publishTime",
                            "publishedAt",
                            "publicationDate",
                            "published",
                        )
                    ),
                    "details": {
                        "summary": _scalar_name(pick("summary")),
                        "full_description": _scalar_name(pick("fullDescription", "description")),
                        "solution": _scalar_name(pick("solution", "remediation")),
                        "cvss_temporal": _number(pick("CVSSTemporal")),
                        "cvss_vector": _scalar_name(pick("CVSSVectorString", "cvssVectorString")),
                        "cvss_version": _number(pick("CVSSVersion")),
                        "created_at": _utc_text(pick("creationTime")),
                        "updated_at": _utc_text(pick("lastUpdate")),
                        "matching_at": _utc_text(pick("matchingTime")),
                        "acknowledged_at": _utc_text(pick("ackTime")),
                        "acknowledged_by": _scalar_name(pick("ackAuthor")),
                        "acknowledgement_comment": _scalar_name(pick("ackComment")),
                        "vendor_id": _scalar_name(pick("vendorId")),
                        "reasons": reasons,
                        "links": links,
                    },
                }
            )

    baselines: list[dict[str, Any]] = []
    raw_baseline_to_id: dict[str, str] = {}
    for index, baseline in enumerate(_raw_items(data.get("baselines"))):
        source_record_id = _source_id(baseline, "id", "baselineId") or str(index)
        normalized_id = f"baseline:{ID_PREFIX}:{_slug(source_record_id)}"
        raw_baseline_to_id[source_record_id] = normalized_id
        difference_counts = _dig(baseline, "countDifferences")
        difference_counts = difference_counts if isinstance(difference_counts, Mapping) else {}
        baseline_name = _scalar_name(_dig(baseline, "name", "label"))
        baseline_status = _scalar_name(_dig(baseline, "status", "state"))
        created_at = _utc_text(_dig(baseline, "creationTime", "createdAt"))
        period_start = _utc_text(
            _dig(
                baseline,
                "creationPeriodStart",
                "startDate",
                "startedAt",
            )
        )
        period_end = _utc_text(
            _dig(
                baseline,
                "creationPeriodEnd",
                "endDate",
                "endedAt",
            )
        )
        last_scan_at = _utc_text(_dig(baseline, "lastScanTime"))
        next_scan_at = _utc_text(_dig(baseline, "nextScanTime"))
        completeness_fields = (
            baseline_name,
            baseline_status,
            created_at,
            period_start,
            period_end,
            last_scan_at,
        )
        baselines.append(
            {
                "id": normalized_id,
                "evidence": _evidence(
                    source_id,
                    f"baseline:{source_record_id}",
                    collected_at,
                    completeness=sum(bool(value) for value in completeness_fields)
                    / len(completeness_fields),
                ),
                "name": baseline_name or f"Baseline {source_record_id}",
                "description": _scalar_name(_dig(baseline, "description")),
                "status": baseline_status or "unknown",
                "created_at": created_at,
                "creation_period_start": period_start,
                "creation_period_end": period_end,
                "last_scan_at": last_scan_at,
                "next_scan_at": next_scan_at,
                "difference_counts": {
                    "new_component": _optional_integer(_dig(difference_counts, "newComponent")),
                    "changed_component": _optional_integer(
                        _dig(difference_counts, "changedComponent")
                    ),
                    "new_activity": _optional_integer(_dig(difference_counts, "newActivity")),
                    "changed_activity": _optional_integer(
                        _dig(difference_counts, "changedActivity")
                    ),
                },
            }
        )

    baseline_differences: list[dict[str, Any]] = []
    for wrapper in data.get("baseline_differences") or []:
        if not isinstance(wrapper, Mapping):
            continue
        raw_baseline_id = str(wrapper.get("baseline_id"))
        baseline_id = raw_baseline_to_id.get(raw_baseline_id)
        if not baseline_id:
            continue
        for index, difference in enumerate(_raw_items(wrapper.get("items"))):
            source_record_id = _source_id(difference, "id", "differenceId") or str(index)
            raw_flow_id = _source_id(difference, "flowId", "flow.id")
            target_id = _source_id(difference, "targetId")
            detected_at = _utc_text(
                _dig(
                    difference,
                    "detectionTime",
                    "detectedAt",
                    "timestamp",
                    "date",
                )
            )
            difference_key = _scalar_name(_dig(difference, "key"))
            difference_value = _scalar_name(_dig(difference, "value"))
            difference_type = _scalar_name(_dig(difference, "type", "differenceType")) or "unknown"
            description_parts = [difference_type]
            if difference_key:
                description_parts.append(difference_key)
            if difference_value:
                description_parts.append(f"= {difference_value}")
            difference_asset_ids = _asset_refs(difference, device_to_asset)
            target_asset = component_to_asset.get(target_id or "") or device_to_asset.get(
                target_id or ""
            )
            if target_asset and target_asset not in difference_asset_ids:
                difference_asset_ids.append(target_asset)
            for activity_asset in raw_activity_to_assets.get(target_id or "", []):
                if activity_asset not in difference_asset_ids:
                    difference_asset_ids.append(activity_asset)
            baseline_differences.append(
                {
                    "id": (
                        f"baseline-difference:{ID_PREFIX}:{_slug(raw_baseline_id)}:"
                        f"{_slug(source_record_id)}"
                    ),
                    "evidence": _evidence(
                        source_id,
                        (f"baseline:{raw_baseline_id}:difference:{source_record_id}"),
                        collected_at,
                    ),
                    "baseline_id": baseline_id,
                    "difference_type": difference_type,
                    "target_id": target_id,
                    "key": difference_key,
                    "value": difference_value,
                    "asset_ids": difference_asset_ids,
                    "flow_id": raw_flow_to_id.get(raw_flow_id or ""),
                    "detected_at": detected_at,
                    "description": _scalar_name(_dig(difference, "description", "message", "name"))
                    or " ".join(description_parts),
                }
            )

    sensor_details_by_id: dict[str, Mapping[str, Any]] = {}
    for wrapper in data.get("sensor_details") or []:
        if not isinstance(wrapper, Mapping):
            continue
        sensor_id = str(wrapper.get("sensor_id"))
        payload = wrapper.get("payload")
        if sensor_id and isinstance(payload, Mapping):
            sensor_details_by_id[sensor_id] = payload

    sensor_stats_by_id: dict[str, Mapping[str, Any]] = {}
    for wrapper in data.get("sensor_stats") or []:
        if not isinstance(wrapper, Mapping):
            continue
        sensor_id = str(wrapper.get("sensor_id"))
        payload = wrapper.get("payload")
        if sensor_id and isinstance(payload, Mapping):
            sensor_stats_by_id[sensor_id] = payload

    sensors: list[dict[str, Any]] = []
    for index, sensor in enumerate(_raw_items(data.get("sensors"))):
        source_record_id = _source_id(sensor, "id", "sensorId", "uuid") or str(index)
        detail = sensor_details_by_id.get(source_record_id, {})
        stats_payload = sensor_stats_by_id.get(source_record_id)
        combined = {**sensor, **detail}
        stats = None
        if stats_payload is not None:
            stats_source = {**combined, **(stats_payload or {})}
            extension_invalid = _optional_boolean(
                _dig(
                    stats_source,
                    "extension_credentials_invalid",
                    "extensionCredentialsInvalid",
                )
            )
            stats = {
                "window": "2h",
                "observed_at": _utc_text(
                    _dig(
                        stats_source,
                        "system_date",
                        "end",
                        "observedAt",
                        "timestamp",
                        "date",
                        "to",
                        "currentTimeLastUpdate",
                        "lastUpdate",
                    )
                ),
                "cpu_percent": _optional_percent(
                    _metric(
                        stats_source,
                        "cpu_usage",
                        "cpuPercent",
                        "cpuUsage",
                        "cpu",
                        "system.cpu",
                    )
                ),
                "memory_percent": _optional_percent(
                    _metric(
                        stats_source,
                        "ram_usage",
                        "memoryPercent",
                        "memoryUsage",
                        "ramUsage",
                        "memory",
                        "ram",
                    )
                ),
                "disk_percent": _optional_percent(
                    _metric(
                        stats_source,
                        "disk_usage",
                        "diskPercent",
                        "diskUsage",
                        "disk",
                    )
                ),
                "uptime_seconds": _optional_integer(_dig(stats_source, "uptime", "uptimeSeconds")),
                "packet_rate_pps": _optional_nonnegative_number(
                    _metric(
                        stats_source,
                        "pkt_rate",
                        "packetRate",
                        "packetsPerSecond",
                        "packet_rate",
                    )
                ),
                "packet_count": _optional_integer(
                    _metric(
                        stats_source,
                        "pkt_count",
                        "packetsCount",
                        "packetCount",
                    )
                ),
                "drop_count": _optional_integer(
                    _metric(
                        stats_source,
                        "pkt_drop_count",
                        "dropCount",
                        "droppedPackets",
                        "packetsDropped",
                    )
                ),
                "snort_enabled": _optional_boolean(
                    _dig(stats_source, "snort_enabled", "snortEnabled")
                ),
                "discovery_enabled": _optional_boolean(
                    _dig(
                        stats_source,
                        "active_discovery_enabled",
                        "activeDiscoveryEnabled",
                    )
                ),
                "extension_access_valid": (
                    not extension_invalid if extension_invalid is not None else None
                ),
            }
        sensor_name = _scalar_name(_dig(combined, "name", "serialNumber", "hostname", "label"))
        sensor_type = _scalar_name(_dig(combined, "hardwareType", "model", "type", "sensorType"))
        sensor_status = _scalar_name(
            _dig(
                combined,
                "status.operationalStatus",
                "operationalStatus",
                "state",
            )
        )
        sensor_ips = _addresses(combined, kind="ip")
        sensor_last_seen = _utc_text(
            _dig(
                combined,
                "status.lastReceivedSysinfo",
                "lastReceivedSysinfo",
                "lastSeen",
                "lastActiveTime",
                "lastContact",
            )
        )
        capture_mode = _scalar_name(
            _dig(
                combined,
                "filter.capture_mode",
                "captureMode",
                "mode",
                "monitoringMode",
            )
        )
        sensor_version = _scalar_name(
            _dig(combined, "version", "softwareVersion", "firmwareVersion")
        )
        completeness_fields = (
            sensor_name,
            sensor_type,
            sensor_status,
            sensor_ips,
            sensor_last_seen,
            capture_mode,
            sensor_version,
        )
        sensors.append(
            {
                "id": f"sensor:{ID_PREFIX}:{_slug(source_record_id)}",
                "evidence": _evidence(
                    source_id,
                    f"sensor:{source_record_id}",
                    collected_at,
                    completeness=sum(bool(value) for value in completeness_fields)
                    / len(completeness_fields),
                ),
                "name": sensor_name or f"Sensor {source_record_id}",
                "sensor_type": sensor_type or "unknown",
                "status": sensor_status or "unknown",
                "ip_addresses": sensor_ips,
                "last_seen_at": sensor_last_seen,
                "capture_mode": capture_mode,
                "version": sensor_version,
                "stats": stats,
            }
        )

    reports: list[dict[str, Any]] = []
    for index, report in enumerate(_raw_items(data.get("reports_metadata"))):
        source_record_id = _source_id(report, "id", "metadataId") or str(index)
        report_state = _dig(report, "reports")
        report_state = report_state if isinstance(report_state, Mapping) else {}
        documents = []
        for document in _raw_items(_dig(report_state, "reports_outputs")):
            document_id = _scalar_name(_dig(document, "document_id", "id"))
            if not document_id:
                continue
            documents.append(
                {
                    "document_id": document_id,
                    "name": _scalar_name(_dig(document, "document_name", "name")) or document_id,
                    "document_type": _scalar_name(_dig(document, "document_type", "type"))
                    or "unknown",
                }
            )
        report_name = _scalar_name(_dig(report, "name"))
        report_type = _scalar_name(_dig(report, "report_type", "type"))
        output_types = _flatten_scalars(_dig(report, "report_out_type", "output_type"))
        report_status = _scalar_name(_dig(report_state, "status"))
        completeness_fields = (
            report_name,
            report_type,
            output_types,
            report_status,
        )
        reports.append(
            {
                "id": f"report:{ID_PREFIX}:{_slug(source_record_id)}",
                "evidence": _evidence(
                    source_id,
                    f"report-metadata:{source_record_id}",
                    collected_at,
                    completeness=sum(bool(value) for value in completeness_fields)
                    / len(completeness_fields),
                ),
                "name": report_name or f"Report {source_record_id}",
                "description": _scalar_name(_dig(report, "description")),
                "report_type": report_type,
                "output_types": output_types,
                "schedule": _scalar_name(_dig(report, "cron_expression")),
                "created_at": _utc_text(_dig(report, "created_at", "createdAt")),
                "updated_at": _utc_text(_dig(report, "updated_at", "updatedAt")),
                "last_run_at": _utc_text(_dig(report_state, "last_run_at", "lastRunAt")),
                "status": report_status,
                "error": _scalar_name(_dig(report_state, "error")),
                "documents": documents,
            }
        )

    capability_coverage: dict[str, float] = {}
    excluded_statuses = {
        "feature_unlicensed",
        "version_unsupported",
        "openapi_required",
        "not_applicable",
    }
    for name in (
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
    ):
        if name not in capabilities:
            continue
        capability = capabilities.get(name, {})
        status = capability.get("status")
        if status in excluded_statuses:
            continue
        if status == "available":
            capability_coverage[name] = 1.0
        elif status in {"partial", "truncated"} and capability.get("attempted"):
            capability_coverage[name] = round(
                min(
                    1.0,
                    int(capability.get("successful") or 0) / int(capability["attempted"]),
                ),
                4,
            )
        else:
            capability_coverage[name] = 0.0
    risk_coverage = (
        len(risk_scores) / len(assets)
        if assets
        else (1.0 if capabilities.get("devices", {}).get("status") == "available" else 0.0)
    )
    capability_coverage["risk_scores"] = round(risk_coverage, 4)
    classic_quality_score = (
        round(sum(capability_coverage.values()) / len(capability_coverage) * 100)
        if capability_coverage
        else 0
    )

    record_counts = {
        "assets": len(assets),
        "risk_scores": len(risk_scores),
        "activities": len(activities),
        "flows": len(flows),
        "events": len(events),
        "vulnerabilities": len(vulnerabilities),
        "baselines": len(baselines),
        "baseline_differences": len(baseline_differences),
        "sensors": len(sensors),
        "reports": len(reports),
        "vulnerability_catalog": len(vulnerability_catalog),
    }
    classic_problem_statuses = {"error", "endpoint_unavailable", "partial", "truncated"}
    partial = any(
        isinstance(capability, Mapping)
        and not str(name).startswith("new_ui")
        and capability.get("status") in classic_problem_statuses
        for name, capability in capabilities.items()
    )
    normalized_capabilities: dict[str, dict[str, Any]] = {}
    for name, capability in capabilities.items():
        if not isinstance(capability, Mapping):
            continue
        if str(name).startswith("new_ui"):
            continue
        normalized = {
            "status": str(capability.get("status") or "unknown"),
            "records": max(0, int(capability.get("records") or 0)),
            "error_code": (
                str(capability["error_code"]) if capability.get("error_code") is not None else None
            ),
        }
        for counter_name in ("attempted", "successful"):
            if capability.get(counter_name) is not None:
                normalized[counter_name] = max(0, int(capability.get(counter_name) or 0))
        normalized_capabilities[str(name)] = normalized
    source = {
        "id": source_id,
        "evidence": _evidence(
            source_id,
            "classic:version",
            collected_at,
            completeness=classic_quality_score / 100,
        ),
        "label": "Cisco Cyber Vision",
        "type": "cisco_cyber_vision",
        "endpoint_label": "Cyber Vision Center · accesso VPN",
        "status": "degraded" if partial else "connected",
        "version": _scalar_name(_dig(raw, "api.version")),
        "last_attempt_at": collected_at,
        "last_success_at": collected_at,
        "record_counts": record_counts,
        "capabilities": normalized_capabilities,
        "details": {
            "collection_window": {
                "from": _utc_text(raw_window.get("from")),
                "to": _utc_text(raw_window.get("to")),
            },
            "classic_api": "3.0",
            "dashboard_metrics": _dashboard_metrics(data),
            "vulnerability_catalog": vulnerability_catalog,
        },
        "error": (
            {
                "code": "partial_capabilities",
                "message": "Una o più capability GET non sono disponibili.",
            }
            if partial
            else None
        ),
    }
    checks = [
        {
            "code": f"cybervision_{name}",
            "label": f"Cyber Vision · {name.replace('_', ' ')}",
            "status": (
                "pass"
                if coverage == 1
                else "not_available"
                if name == "risk_scores" and not assets
                else "warn"
            ),
            "details": f"Copertura capability {round(coverage * 100)}%.",
        }
        for name, coverage in capability_coverage.items()
    ]
    new_ui = normalize_cybervision_new_ui_source(raw)
    combined_coverage = {
        **capability_coverage,
        **new_ui["coverage"],
    }
    quality_score = (
        round(sum(combined_coverage.values()) / len(combined_coverage) * 100)
        if combined_coverage
        else 0
    )
    return {
        "source": source,
        "additional_sources": [new_ui["source"]],
        "assets": assets,
        "risk_scores": risk_scores,
        "activities": activities,
        "flows": flows,
        "events": events,
        "vulnerabilities": vulnerabilities,
        "baselines": baselines,
        "baseline_differences": baseline_differences,
        "sensors": sensors,
        "reports": reports,
        "quality_checks": [*checks, *new_ui["quality_checks"]],
        "coverage": combined_coverage,
        "quality_score": quality_score,
    }
