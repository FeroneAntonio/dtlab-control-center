"""Capability-aware GET collection from the documented Cyber Vision API."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import UTC, datetime, timedelta
from typing import Any

from dtlab.collector.cybervision_client import (
    CyberVisionClient,
    CyberVisionError,
    CyberVisionFeatureUnavailable,
)

_FATAL_CODES = {
    "credential_unavailable",
    "authentication_failed",
    "permission_denied",
    "tls_verification_failed",
    "unexpected_redirect",
}
_NEW_UI_PAGE_SIZE = 500
_NEW_UI_ALERT_STATUSES = ("Active", "Cleared", "Muted")
_NEW_UI_CAPABILITIES = (
    "new_ui_assets",
    "new_ui_alerts",
    "new_ui_vulnerability_assets",
    "new_ui_networks",
    "new_ui_org_hierarchy",
)


def _utc_text(value: datetime) -> str:
    if value.tzinfo is None:
        raise ValueError("now deve includere il fuso orario")
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _record_id(record: Any) -> Any:
    if isinstance(record, Mapping):
        for key in ("id", "deviceId", "componentId", "sensorId", "baselineId", "uuid"):
            if record.get(key) is not None:
                return record[key]
    return None


def _version_text(payload: Any) -> str | None:
    if not isinstance(payload, Mapping):
        return None
    values = [payload.get(key) for key in ("major", "minor", "incr", "build")]
    present = [str(value) for value in values if value is not None]
    return ".".join(present) if present else None


def _version_tuple(payload: Any) -> tuple[int, int, int]:
    if not isinstance(payload, Mapping):
        return (0, 0, 0)
    values: list[int] = []
    for key in ("major", "minor", "incr"):
        try:
            values.append(int(payload.get(key) or 0))
        except (TypeError, ValueError):
            values.append(0)
    return tuple(values)  # type: ignore[return-value]


def _count(value: Any, *, wrapper_keys: tuple[str, ...] = ()) -> int:
    if isinstance(value, list):
        return len(value)
    if isinstance(value, Mapping):
        # Alcuni endpoint dashboard restituiscono collezioni avvolte in un
        # oggetto invece di una lista top-level. Contare il wrapper come un
        # record renderebbe falsa la copertura quando la collezione è vuota.
        for key in wrapper_keys:
            wrapped = value.get(key)
            if isinstance(wrapped, (list, tuple, set)):
                return len(wrapped)
            if isinstance(wrapped, Mapping):
                return 1 if wrapped else 0
        return 1 if value else 0
    if value is None:
        return 0
    return 1


def collect_cybervision_raw(
    client: CyberVisionClient,
    *,
    now: datetime | None = None,
    lookback: timedelta = timedelta(hours=24),
    max_device_details: int = 500,
    new_ui_enabled: bool = False,
) -> dict[str, Any]:
    """Collect documented GET resources and expose capability failures explicitly."""

    current = now or datetime.now(UTC)
    if current.tzinfo is None:
        raise ValueError("now deve includere il fuso orario")
    start = current - lookback
    start_ms = int(start.timestamp() * 1000)
    end_ms = int(current.timestamp() * 1000)

    capabilities: dict[str, dict[str, Any]] = {}
    errors: list[dict[str, Any]] = []
    data: dict[str, Any] = {}
    detail_counters: dict[str, dict[str, Any]] = {}

    version_payload = client.classic_get("/version")
    data["version"] = version_payload
    capabilities["version"] = {
        "status": "available",
        "records": 1,
        "error_code": None,
    }

    def optional(
        name: str,
        operation: Callable[[], Any],
        empty: Any,
        *,
        wrapper_keys: tuple[str, ...] = (),
        fatal_errors: bool = True,
    ) -> Any:
        try:
            value = operation()
        except CyberVisionFeatureUnavailable as exc:
            status = (
                "feature_unlicensed" if exc.code == "feature_unlicensed" else "endpoint_unavailable"
            )
            capabilities[name] = {
                "status": status,
                "records": 0,
                "error_code": exc.code,
            }
            errors.append(
                {
                    "capability": name,
                    "code": exc.code,
                    "status_code": exc.status_code,
                }
            )
            value = empty
        except CyberVisionError as exc:
            if fatal_errors and exc.code in _FATAL_CODES:
                raise
            capabilities[name] = {
                "status": "error",
                "records": 0,
                "error_code": exc.code,
            }
            errors.append(
                {
                    "capability": name,
                    "code": exc.code,
                    "status_code": exc.status_code,
                }
            )
            value = empty
        else:
            capabilities[name] = {
                "status": "available",
                "records": _count(value, wrapper_keys=wrapper_keys),
                "error_code": None,
            }
        data[name] = value
        return value

    def detail_optional(
        group: str,
        record_id: Any,
        operation: Callable[[], Any],
        empty: Any,
    ) -> Any:
        counter = detail_counters.setdefault(
            group,
            {
                "attempted": 0,
                "successful": 0,
                "records": 0,
                "statuses": [],
                "error_codes": [],
            },
        )
        counter["attempted"] += 1
        try:
            value = operation()
        except CyberVisionFeatureUnavailable as exc:
            status = (
                "feature_unlicensed" if exc.code == "feature_unlicensed" else "endpoint_unavailable"
            )
            counter["statuses"].append(status)
            counter["error_codes"].append(exc.code)
            errors.append(
                {
                    "capability": f"{group}:{record_id}",
                    "code": exc.code,
                    "status_code": exc.status_code,
                }
            )
            return empty
        except CyberVisionError as exc:
            if exc.code in _FATAL_CODES:
                raise
            counter["statuses"].append("error")
            counter["error_codes"].append(exc.code)
            errors.append(
                {
                    "capability": f"{group}:{record_id}",
                    "code": exc.code,
                    "status_code": exc.status_code,
                }
            )
            return empty
        counter["successful"] += 1
        counter["records"] += _count(value)
        return value

    def finalize_detail(group: str, *, truncated: bool = False) -> None:
        counter = detail_counters.get(group)
        if not counter or counter["attempted"] == 0:
            capabilities[group] = {
                "status": "not_applicable",
                "records": 0,
                "error_code": None,
            }
            return
        statuses = counter["statuses"]
        if truncated:
            status = "truncated"
            error_code = "max_device_details_reached"
        elif counter["successful"] == counter["attempted"]:
            status = "available"
            error_code = None
        elif counter["successful"] > 0:
            status = "partial"
            error_code = "partial_detail_failure"
        elif statuses and all(item == "feature_unlicensed" for item in statuses):
            status = "feature_unlicensed"
            error_code = "feature_unlicensed"
        elif statuses and all(item == "endpoint_unavailable" for item in statuses):
            status = "endpoint_unavailable"
            error_code = "endpoint_unavailable"
        else:
            status = "error"
            codes = sorted(set(counter["error_codes"]))
            error_code = codes[0] if len(codes) == 1 else "detail_failures"
        capabilities[group] = {
            "status": status,
            "records": counter["records"],
            "error_code": error_code,
            "attempted": counter["attempted"],
            "successful": counter["successful"],
        }

    devices = optional("devices", lambda: client.classic_pages("/devices"), [])
    optional("components", lambda: client.classic_pages("/components"), [])
    optional(
        "activities",
        lambda: client.classic_pages(
            "/activities",
            params={"from": start_ms, "to": end_ms},
        ),
        [],
    )
    optional(
        "flows",
        lambda: client.classic_pages(
            "/flows",
            params={"from": start_ms, "to": end_ms},
        ),
        [],
    )
    optional(
        "event_categories",
        lambda: client.classic_get("/dashboard/events/categories"),
        {},
        wrapper_keys=("total", "categories"),
    )
    optional(
        "event_severities",
        lambda: client.classic_get("/dashboard/events/severities"),
        {},
        wrapper_keys=("events",),
    )
    optional(
        "risk_distribution",
        lambda: client.classic_get(
            "/dashboard/risk-score/devices/counts",
            params={"limit": 50},
        ),
        {},
        wrapper_keys=("total",),
    )
    optional(
        "protocol_distribution",
        lambda: client.classic_get(
            "/dashboard/protocols/counts",
            params={"limit": 50},
        ),
        {},
        wrapper_keys=("total", "items"),
    )
    optional(
        "vulnerabilities",
        lambda: client.classic_pages("/vulnerabilities"),
        [],
    )
    baselines = optional("baselines", lambda: client.classic_pages("/baselines"), [])
    sensors = optional("sensors", lambda: client.classic_pages("/sensors"), [])
    optional(
        "reports_metadata",
        lambda: client.classic_pages("/reports2/reports-metadata"),
        [],
    )

    device_risk_scores: list[dict[str, Any]] = []
    device_vulnerabilities: list[dict[str, Any]] = []
    detailed_devices = devices[:max_device_details]
    for device in detailed_devices:
        device_id = _record_id(device)
        if device_id is None:
            errors.append(
                {
                    "capability": "device_details",
                    "code": "missing_device_id",
                    "status_code": None,
                }
            )
            continue
        risk = detail_optional(
            "device_risk_scores",
            device_id,
            lambda device_id=device_id: client.device_risk_score(device_id),
            None,
        )
        if risk is not None:
            device_risk_scores.append({"device_id": device_id, "payload": risk})
        vulnerabilities = detail_optional(
            "device_vulnerabilities",
            device_id,
            lambda device_id=device_id: client.device_vulnerabilities(device_id),
            [],
        )
        device_vulnerabilities.append(
            {
                "device_id": device_id,
                "items": vulnerabilities,
            }
        )
    data["device_risk_scores"] = device_risk_scores
    data["device_vulnerabilities"] = device_vulnerabilities
    details_truncated = len(devices) > len(detailed_devices)
    if details_truncated:
        errors.append(
            {
                "capability": "device_details",
                "code": "max_device_details_reached",
                "status_code": None,
            }
        )
    finalize_detail("device_risk_scores", truncated=details_truncated)
    finalize_detail("device_vulnerabilities", truncated=details_truncated)

    baseline_differences: list[dict[str, Any]] = []
    for baseline in baselines:
        baseline_id = _record_id(baseline)
        if baseline_id is None:
            continue
        differences = detail_optional(
            "baseline_differences",
            baseline_id,
            lambda baseline_id=baseline_id: client.baseline_differences(baseline_id),
            [],
        )
        baseline_differences.append(
            {
                "baseline_id": baseline_id,
                "items": differences,
            }
        )
    data["baseline_differences"] = baseline_differences
    finalize_detail("baseline_differences")

    sensor_details: list[dict[str, Any]] = []
    sensor_stats: list[dict[str, Any]] = []
    for sensor in sensors:
        sensor_id = _record_id(sensor)
        if sensor_id is None:
            continue
        details = detail_optional(
            "sensor_details",
            sensor_id,
            lambda sensor_id=sensor_id: client.sensor_details(sensor_id),
            None,
        )
        if details is not None:
            sensor_details.append({"sensor_id": sensor_id, "payload": details})
        stats = detail_optional(
            "sensor_stats",
            sensor_id,
            lambda sensor_id=sensor_id: client.sensor_stats(sensor_id, period="2h"),
            None,
        )
        if stats is not None:
            sensor_stats.append({"sensor_id": sensor_id, "payload": stats})
    data["sensor_details"] = sensor_details
    data["sensor_stats"] = sensor_stats
    finalize_detail("sensor_details")
    finalize_detail("sensor_stats")

    new_ui_supported = _version_tuple(version_payload) >= (5, 4, 0)
    if new_ui_supported and new_ui_enabled:
        new_ui_operations = (
            ("new_ui_assets", "/assets"),
            ("new_ui_vulnerability_assets", "/assets/vulnerabilities"),
            ("new_ui_networks", "/networks"),
            ("new_ui_org_hierarchy", "/oh"),
        )
        for name, path in new_ui_operations:
            optional(
                name,
                lambda path=path: client.new_ui_pages(
                    path,
                    params={"max": _NEW_UI_PAGE_SIZE},
                ),
                {},
                wrapper_keys=("items",),
                fatal_errors=False,
            )

        alert_payloads: dict[str, Any] = {}
        alert_statuses: dict[str, dict[str, Any]] = {}
        first_alert_envelope: dict[str, Any] | None = None
        combined_alert_items: list[Any] = []
        for query_status in _NEW_UI_ALERT_STATUSES:
            capability_name = f"new_ui_alerts:{query_status.lower()}"
            try:
                value = client.new_ui_pages(
                    "/assets/alerts",
                    params={
                        "max": _NEW_UI_PAGE_SIZE,
                        "status": query_status,
                    },
                )
            except CyberVisionFeatureUnavailable as exc:
                status = (
                    "feature_unlicensed"
                    if exc.code == "feature_unlicensed"
                    else "endpoint_unavailable"
                )
                alert_payloads[query_status] = None
                alert_statuses[query_status] = {
                    "status": status,
                    "records": 0,
                    "error_code": exc.code,
                }
                errors.append(
                    {
                        "capability": capability_name,
                        "code": exc.code,
                        "status_code": exc.status_code,
                    }
                )
            except CyberVisionError as exc:
                alert_payloads[query_status] = None
                alert_statuses[query_status] = {
                    "status": "error",
                    "records": 0,
                    "error_code": exc.code,
                }
                errors.append(
                    {
                        "capability": capability_name,
                        "code": exc.code,
                        "status_code": exc.status_code,
                    }
                )
            else:
                items = (
                    value.get("items", [])
                    if isinstance(value, Mapping) and isinstance(value.get("items"), list)
                    else []
                )
                if first_alert_envelope is None:
                    first_alert_envelope = dict(value)
                combined_alert_items.extend(items)
                alert_payloads[query_status] = value
                alert_statuses[query_status] = {
                    "status": "available",
                    "records": len(items),
                    "error_code": None,
                }

        combined_alert_envelope = first_alert_envelope or {"items": []}
        combined_alert_envelope["items"] = combined_alert_items
        combined_alert_envelope["byStatus"] = alert_payloads
        data["new_ui_alerts"] = combined_alert_envelope
        alert_states = [
            alert_statuses[query_status]["status"] for query_status in _NEW_UI_ALERT_STATUSES
        ]
        successful_alert_statuses = sum(status == "available" for status in alert_states)
        if successful_alert_statuses == len(_NEW_UI_ALERT_STATUSES):
            alert_status = "available"
            alert_error = None
        elif successful_alert_statuses:
            alert_status = "partial"
            alert_error = "partial_status_failure"
        elif all(status == "feature_unlicensed" for status in alert_states):
            alert_status = "feature_unlicensed"
            alert_error = "feature_unlicensed"
        elif all(status == "endpoint_unavailable" for status in alert_states):
            alert_status = "endpoint_unavailable"
            alert_error = "endpoint_unavailable"
        else:
            alert_status = "error"
            error_codes = sorted(
                {
                    str(item["error_code"])
                    for item in alert_statuses.values()
                    if item.get("error_code")
                }
            )
            alert_error = error_codes[0] if len(error_codes) == 1 else "status_failures"
        capabilities["new_ui_alerts"] = {
            "status": alert_status,
            "records": len(combined_alert_items),
            "error_code": alert_error,
            "statuses": alert_statuses,
        }

        new_ui_statuses = [capabilities[name]["status"] for name in _NEW_UI_CAPABILITIES]
        new_ui_available = sum(status == "available" for status in new_ui_statuses)
        if new_ui_available == len(new_ui_statuses):
            new_ui_status = "available"
            new_ui_error = None
        elif any(status in {"available", "partial"} for status in new_ui_statuses):
            new_ui_status = "partial"
            new_ui_error = "partial_capabilities"
        else:
            new_ui_status = "error"
            new_ui_error = "new_ui_unavailable"
        capabilities["new_ui"] = {
            "status": new_ui_status,
            "records": sum(int(capabilities[name]["records"]) for name in _NEW_UI_CAPABILITIES),
            "error_code": new_ui_error,
        }
    else:
        for name in _NEW_UI_CAPABILITIES:
            data[name] = {}
            capabilities[name] = {
                "status": ("not_configured" if new_ui_supported else "version_unsupported"),
                "records": 0,
                "error_code": ("new_ui_token_unavailable" if new_ui_supported else None),
            }
        capabilities["new_ui"] = {
            "status": "not_configured" if new_ui_supported else "version_unsupported",
            "records": 0,
            "error_code": "new_ui_token_unavailable" if new_ui_supported else None,
        }

    available = sum(
        1 for capability in capabilities.values() if capability["status"] == "available"
    )
    problem = sum(
        1
        for capability in capabilities.values()
        if capability["status"] in {"error", "endpoint_unavailable", "partial", "truncated"}
    )
    collection_state = "complete" if problem == 0 else "partial"
    return {
        "collected_at": _utc_text(current),
        "window": {
            "from": _utc_text(start),
            "to": _utc_text(current),
        },
        "api": {
            "classic": "3.0",
            "new_ui": "1.0" if new_ui_supported and new_ui_enabled else None,
            "version": _version_text(version_payload),
        },
        "state": collection_state,
        "available_capabilities": available,
        "capabilities": capabilities,
        "errors": errors,
        "data": data,
    }
