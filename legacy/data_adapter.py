from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, BinaryIO

import pandas as pd


ASSET_COLUMNS = [
    "asset_id",
    "name",
    "ip_address",
    "mac_address",
    "vendor",
    "asset_type",
    "zone",
    "protocol",
    "risk",
    "status",
    "last_seen",
    "firmware",
    "vulnerabilities",
]

ALERT_COLUMNS = [
    "alert_id",
    "timestamp",
    "severity",
    "category",
    "rule_id",
    "confidence",
    "attack_technique",
    "source_asset",
    "destination_asset",
    "source_ip",
    "destination_ip",
    "protocol",
    "function_code",
    "description",
    "status",
]

FLOW_COLUMNS = [
    "flow_id",
    "source_asset_id",
    "destination_asset_id",
    "source_ip",
    "destination_ip",
    "source_zone",
    "destination_zone",
    "protocol",
    "port",
    "baseline_status",
    "first_seen",
    "last_seen",
    "messages",
]

SOURCE_COLUMNS = ["source", "type", "status", "last_sync", "records", "endpoint"]


class SnapshotValidationError(ValueError):
    pass


@dataclass(frozen=True)
class Snapshot:
    assets: pd.DataFrame
    alerts: pd.DataFrame
    flows: pd.DataFrame
    sources: pd.DataFrame
    metadata: dict[str, Any]


def _frame(records: list[dict[str, Any]], columns: list[str]) -> pd.DataFrame:
    frame = pd.DataFrame(records)
    for column in columns:
        if column not in frame.columns:
            frame[column] = None
    return frame[columns]


def _duplicate_values(frame: pd.DataFrame, column: str) -> list[str]:
    values = frame[column].dropna().astype(str)
    return sorted(values[values.duplicated(keep=False)].unique().tolist())


def _quality_report(
    assets: pd.DataFrame, alerts: pd.DataFrame, flows: pd.DataFrame
) -> tuple[int, list[dict[str, Any]], list[dict[str, Any]]]:
    checks: list[dict[str, Any]] = []

    def add(control: str, ok: bool, details: str, penalty: int) -> None:
        checks.append(
            {
                "control": control,
                "status": "OK" if ok else "Attenzione",
                "details": details,
                "penalty": 0 if ok else penalty,
            }
        )

    asset_ids_ok = not assets["asset_id"].isna().any() and not assets["name"].isna().any()
    add(
        "Identità asset",
        asset_ids_ok,
        "Tutti gli asset hanno asset_id e name."
        if asset_ids_ok
        else "Sono presenti asset senza identificativo o nome.",
        25,
    )

    asset_duplicates = _duplicate_values(assets, "asset_id")
    add(
        "Unicità asset",
        not asset_duplicates,
        "Nessun asset_id duplicato."
        if not asset_duplicates
        else f"Duplicati: {', '.join(asset_duplicates[:5])}",
        20,
    )

    alert_id_missing = alerts["alert_id"].isna().sum()
    alert_duplicates = _duplicate_values(alerts, "alert_id")
    alert_ids_ok = alert_id_missing == 0 and not alert_duplicates
    add(
        "Identità alert",
        alert_ids_ok,
        "Tutti gli alert hanno un ID univoco."
        if alert_ids_ok
        else f"ID mancanti: {alert_id_missing}; duplicati: {len(alert_duplicates)}.",
        10,
    )

    invalid_alert_times = int(alerts["timestamp"].isna().sum())
    invalid_flow_times = int(flows["last_seen"].isna().sum()) if not flows.empty else 0
    timestamps_ok = invalid_alert_times == 0 and invalid_flow_times == 0
    add(
        "Timestamp",
        timestamps_ok,
        "Timestamp validi e normalizzati in UTC."
        if timestamps_ok
        else f"Alert senza timestamp valido: {invalid_alert_times}; flow: {invalid_flow_times}.",
        15,
    )

    asset_names = set(assets["name"].dropna().astype(str))
    referenced_names = set(alerts["source_asset"].dropna().astype(str)) | set(
        alerts["destination_asset"].dropna().astype(str)
    )
    unknown_alert_assets = sorted(referenced_names - asset_names)
    add(
        "Riferimenti alert",
        not unknown_alert_assets,
        "Sorgenti e destinazioni degli alert sono presenti nell'inventario."
        if not unknown_alert_assets
        else f"Asset non risolti: {', '.join(unknown_alert_assets[:5])}",
        10,
    )

    asset_ids = set(assets["asset_id"].dropna().astype(str))
    referenced_ids = set(flows["source_asset_id"].dropna().astype(str)) | set(
        flows["destination_asset_id"].dropna().astype(str)
    )
    unknown_flow_assets = sorted(referenced_ids - asset_ids)
    add(
        "Riferimenti flow",
        not unknown_flow_assets,
        "Tutti i flow puntano ad asset conosciuti."
        if not unknown_flow_assets
        else f"Asset non risolti: {', '.join(unknown_flow_assets[:5])}",
        10,
    )

    add(
        "Copertura comunicazioni",
        not flows.empty,
        f"Sono disponibili {len(flows)} flow normalizzati."
        if not flows.empty
        else "Lo snapshot non contiene flow; topologia e baseline saranno vuote.",
        10,
    )

    coverage_specs = {
        "Asset": (assets, ["ip_address", "asset_type", "zone", "protocol", "risk", "last_seen"]),
        "Alert": (alerts, ["timestamp", "severity", "category", "source_ip", "destination_ip", "protocol", "status"]),
        "Flow": (flows, ["source_asset_id", "destination_asset_id", "protocol", "baseline_status", "last_seen"]),
    }
    coverage: list[dict[str, Any]] = []
    for entity, (frame, columns) in coverage_specs.items():
        if frame.empty:
            percent = 0 if entity == "Flow" else 100
        else:
            total = len(frame) * len(columns)
            present = int(frame[columns].notna().sum().sum())
            percent = round(present / total * 100) if total else 100
        coverage.append({"entity": entity, "coverage": percent, "fields": len(columns)})

    average_coverage = round(sum(item["coverage"] for item in coverage) / len(coverage))
    coverage_ok = average_coverage >= 95
    add(
        "Completezza campi chiave",
        coverage_ok,
        f"Copertura media dei campi chiave: {average_coverage}%.",
        10 if average_coverage < 80 else 5,
    )

    score = max(0, 100 - sum(int(check["penalty"]) for check in checks))
    return score, checks, coverage


def _health_breakdown(
    assets: pd.DataFrame, alerts: pd.DataFrame, quality_score: int
) -> list[dict[str, Any]]:
    open_alerts = alerts[alerts["status"].isin(["Aperto", "In analisi"])]
    critical_open = int((open_alerts["severity"] == "Critica").sum())
    high_open = int((open_alerts["severity"] == "Alta").sum())
    medium_open = int((open_alerts["severity"] == "Media").sum())
    critical_assets = int((assets["risk"] == "Critico").sum())
    high_assets = int((assets["risk"] == "Alto").sum())
    vulnerabilities = int(assets["vulnerabilities"].sum())
    stale_assets = int((assets["status"] == "Non raggiungibile").sum())

    return [
        {
            "component": "Pressione alert",
            "penalty": min(35, round(critical_open * 2 + high_open * 0.5 + medium_open * 0.25)),
            "max_penalty": 35,
            "details": f"{critical_open} critici, {high_open} alti, {medium_open} medi aperti",
        },
        {
            "component": "Rischio asset",
            "penalty": min(25, critical_assets * 2 + high_assets),
            "max_penalty": 25,
            "details": f"{critical_assets} critici e {high_assets} alti",
        },
        {
            "component": "Vulnerabilità",
            "penalty": min(20, round(vulnerabilities / 8)),
            "max_penalty": 20,
            "details": f"{vulnerabilities} osservazioni aggregate",
        },
        {
            "component": "Disponibilità",
            "penalty": min(10, stale_assets * 5),
            "max_penalty": 10,
            "details": f"{stale_assets} asset non raggiungibili",
        },
        {
            "component": "Integrità dati",
            "penalty": min(10, round((100 - quality_score) / 10)),
            "max_penalty": 10,
            "details": f"qualità dataset {quality_score}%",
        },
    ]


def _parse_payload(payload: dict[str, Any]) -> Snapshot:
    if not isinstance(payload, dict):
        raise SnapshotValidationError("Lo snapshot deve essere un oggetto JSON.")

    for key in ("assets", "alerts"):
        if key not in payload or not isinstance(payload[key], list):
            raise SnapshotValidationError(f"Il campo '{key}' deve essere una lista.")
    if "flows" in payload and not isinstance(payload["flows"], list):
        raise SnapshotValidationError("Il campo 'flows' deve essere una lista.")

    assets = _frame(payload["assets"], ASSET_COLUMNS)
    alerts = _frame(payload["alerts"], ALERT_COLUMNS)
    flows = _frame(payload.get("flows", []), FLOW_COLUMNS)
    sources = _frame(payload.get("sources", []), SOURCE_COLUMNS)

    if assets.empty:
        raise SnapshotValidationError("Lo snapshot non contiene asset.")

    missing_asset_ids = assets["asset_id"].isna() | assets["name"].isna()
    if missing_asset_ids.any():
        raise SnapshotValidationError("Ogni asset deve avere asset_id e name.")
    duplicate_assets = _duplicate_values(assets, "asset_id")
    if duplicate_assets:
        raise SnapshotValidationError("Gli asset_id devono essere univoci.")

    assets["vulnerabilities"] = pd.to_numeric(
        assets["vulnerabilities"], errors="coerce"
    ).fillna(0).astype(int)
    assets["last_seen"] = pd.to_datetime(assets["last_seen"], utc=True, errors="coerce")
    alerts["timestamp"] = pd.to_datetime(alerts["timestamp"], utc=True, errors="coerce")
    flows["first_seen"] = pd.to_datetime(flows["first_seen"], utc=True, errors="coerce")
    flows["last_seen"] = pd.to_datetime(flows["last_seen"], utc=True, errors="coerce")
    flows["port"] = pd.to_numeric(flows["port"], errors="coerce").astype("Int64")
    flows["messages"] = pd.to_numeric(flows["messages"], errors="coerce").fillna(0).astype(int)
    sources["last_sync"] = pd.to_datetime(sources["last_sync"], utc=True, errors="coerce")
    sources["records"] = pd.to_numeric(sources["records"], errors="coerce").fillna(0).astype(int)

    quality_score, quality_checks, coverage = _quality_report(assets, alerts, flows)
    breakdown = _health_breakdown(assets, alerts, quality_score)
    health_score = max(0, min(100, 100 - sum(item["penalty"] for item in breakdown)))

    metadata = dict(payload.get("metadata", {}))
    metadata.setdefault("mode", "IMPORT")
    metadata.setdefault("environment", "Snapshot importato")
    metadata.setdefault("generated_at", datetime.now(timezone.utc).isoformat())
    metadata.setdefault("schema_version", "1.1")
    metadata["health_score"] = health_score
    metadata["health_score_method"] = "DTLab explainable score v1.1"
    metadata["health_breakdown"] = breakdown
    metadata["quality_score"] = quality_score
    metadata["quality_checks"] = quality_checks
    metadata["coverage"] = coverage

    return Snapshot(
        assets=assets,
        alerts=alerts,
        flows=flows,
        sources=sources,
        metadata=metadata,
    )


def load_snapshot(file: BinaryIO | bytes | str) -> Snapshot:
    try:
        if isinstance(file, bytes):
            payload = json.loads(file.decode("utf-8"))
        elif isinstance(file, str):
            payload = json.loads(file)
        else:
            payload = json.load(file)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SnapshotValidationError("Il file non contiene JSON valido.") from exc
    return _parse_payload(payload)


def snapshot_from_dict(payload: dict[str, Any]) -> Snapshot:
    return _parse_payload(payload)


def snapshot_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, ensure_ascii=False, indent=2)


def snapshot_schema() -> dict[str, Any]:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://modbus.sitoclone.it/schema/dtlab-snapshot-1.1.json",
        "title": "DTLab OT Security Snapshot 1.1",
        "type": "object",
        "required": ["assets", "alerts"],
        "properties": {
            "metadata": {"type": "object"},
            "assets": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": ["asset_id", "name"],
                    "properties": {column: {} for column in ASSET_COLUMNS},
                },
            },
            "alerts": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {column: {} for column in ALERT_COLUMNS},
                },
            },
            "flows": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {column: {} for column in FLOW_COLUMNS},
                },
            },
            "sources": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {column: {} for column in SOURCE_COLUMNS},
                },
            },
        },
        "additionalProperties": True,
    }
