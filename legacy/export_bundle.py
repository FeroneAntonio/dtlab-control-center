from __future__ import annotations

import io
import json
import zipfile
from typing import Any

import pandas as pd

from data_adapter import Snapshot


def _native(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, pd.Timestamp):
        return value.isoformat()
    try:
        if pd.isna(value):
            return None
    except (TypeError, ValueError):
        pass
    if hasattr(value, "item"):
        try:
            return value.item()
        except ValueError:
            pass
    return value


def frame_records(frame: pd.DataFrame) -> list[dict[str, Any]]:
    return [
        {column: _native(value) for column, value in row.items()}
        for row in frame.to_dict(orient="records")
    ]


def normalized_payload(snapshot: Snapshot) -> dict[str, Any]:
    metadata = {
        key: value
        for key, value in snapshot.metadata.items()
        if key not in {"quality_checks", "coverage", "health_breakdown"}
    }
    metadata.update(
        {
            "quality_checks": snapshot.metadata.get("quality_checks", []),
            "coverage": snapshot.metadata.get("coverage", []),
            "health_breakdown": snapshot.metadata.get("health_breakdown", []),
        }
    )
    return {
        "metadata": metadata,
        "assets": frame_records(snapshot.assets),
        "alerts": frame_records(snapshot.alerts),
        "flows": frame_records(snapshot.flows),
        "sources": frame_records(snapshot.sources),
    }


def _json_bytes(payload: Any) -> bytes:
    return json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")


def build_technical_bundle(snapshot: Snapshot) -> bytes:
    payload = normalized_payload(snapshot)
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("manifest.json", _json_bytes(payload["metadata"]))
        archive.writestr("snapshot-normalized.json", _json_bytes(payload))
        archive.writestr("assets.csv", snapshot.assets.to_csv(index=False).encode("utf-8-sig"))
        archive.writestr("alerts.csv", snapshot.alerts.to_csv(index=False).encode("utf-8-sig"))
        archive.writestr("flows.csv", snapshot.flows.to_csv(index=False).encode("utf-8-sig"))
        archive.writestr("sources.csv", snapshot.sources.to_csv(index=False).encode("utf-8-sig"))
        archive.writestr(
            "quality-report.json",
            _json_bytes(
                {
                    "score": snapshot.metadata.get("quality_score"),
                    "checks": snapshot.metadata.get("quality_checks", []),
                    "coverage": snapshot.metadata.get("coverage", []),
                }
            ),
        )
        archive.writestr(
            "health-score.json",
            _json_bytes(
                {
                    "score": snapshot.metadata.get("health_score"),
                    "method": snapshot.metadata.get("health_score_method"),
                    "breakdown": snapshot.metadata.get("health_breakdown", []),
                }
            ),
        )
        archive.writestr(
            "README.txt",
            (
                "DTLab OT Security - pacchetto tecnico\n"
                "======================================\n\n"
                f"Modalità: {snapshot.metadata.get('mode', '-')}\n"
                f"Ambiente: {snapshot.metadata.get('environment', '-')}\n"
                f"Generato: {snapshot.metadata.get('generated_at', '-')}\n\n"
                "Il pacchetto contiene dati normalizzati, report qualità, breakdown dello "
                "score e tabelle CSV. In modalità DEMO tutti i record sono sintetici e non "
                "provengono dall'ambiente Relatech.\n"
            ).encode("utf-8"),
        )
    return buffer.getvalue()


def build_evidence_bundle(snapshot: Snapshot, alert_id: str) -> bytes:
    matches = snapshot.alerts[snapshot.alerts["alert_id"] == alert_id]
    if matches.empty:
        raise ValueError(f"Alert non trovato: {alert_id}")

    alert = matches.iloc[0]
    related_names = {str(alert["source_asset"]), str(alert["destination_asset"])}
    related_assets = snapshot.assets[snapshot.assets["name"].isin(related_names)]
    related_ids = set(related_assets["asset_id"].astype(str))
    related_flows = snapshot.flows[
        snapshot.flows["source_asset_id"].astype(str).isin(related_ids)
        | snapshot.flows["destination_asset_id"].astype(str).isin(related_ids)
    ]

    manifest = {
        "bundle_type": "DTLab alert evidence",
        "alert_id": alert_id,
        "mode": snapshot.metadata.get("mode"),
        "environment": snapshot.metadata.get("environment"),
        "generated_at": snapshot.metadata.get("generated_at"),
        "schema_version": snapshot.metadata.get("schema_version"),
        "data_notice": snapshot.metadata.get(
            "dataset_notice",
            "Verificare la provenienza dei dati prima di usare il pacchetto come evidenza.",
        ),
        "files": ["alert.json", "assets.json", "related-flows.csv", "README.txt"],
    }

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("manifest.json", _json_bytes(manifest))
        archive.writestr("alert.json", _json_bytes(frame_records(matches)[0]))
        archive.writestr("assets.json", _json_bytes(frame_records(related_assets)))
        archive.writestr(
            "related-flows.csv", related_flows.to_csv(index=False).encode("utf-8-sig")
        )
        archive.writestr(
            "README.txt",
            (
                "DTLab OT Security - pacchetto evidenze alert\n"
                "=============================================\n\n"
                f"Alert: {alert_id}\n"
                f"Categoria: {_native(alert['category'])}\n"
                f"Regola: {_native(alert['rule_id'])}\n"
                f"Modalità dati: {snapshot.metadata.get('mode', '-')}\n\n"
                "Il pacchetto raccoglie il record dell'alert, i profili degli asset coinvolti "
                "e i flow correlati disponibili nello snapshot. Non contiene password, token "
                "o configurazioni riservate. In modalità DEMO non costituisce evidenza forense.\n"
            ).encode("utf-8"),
        )
    return buffer.getvalue()
