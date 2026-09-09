from __future__ import annotations

import io
import json
import zipfile
from copy import deepcopy
from types import SimpleNamespace
from typing import Any

from dtlab.contract import snapshot_sha256
from dtlab.ui.views import platform
from dtlab.ui.views.platform import (
    _operational_sensor_count,
    _safe_export_stem,
    _signal_option_label,
    _signal_options,
)
from tests.factories import FETCHED_AT, add_cisco_asset, evidence, valid_snapshot


class _Column:
    def __enter__(self) -> _Column:
        return self

    def __exit__(self, *_args: object) -> None:
        return None


class _FakeStreamlit:
    def __init__(self) -> None:
        self.session_state: dict[str, Any] = {}
        self.downloads: list[dict[str, Any]] = []

    def columns(self, specification: int | list[int]) -> list[_Column]:
        count = specification if isinstance(specification, int) else len(specification)
        return [_Column() for _ in range(count)]

    def download_button(self, label: str, **kwargs: Any) -> None:
        self.downloads.append({"label": label, **kwargs})

    def selectbox(self, _label: str, options: list[Any], **_kwargs: Any) -> Any:
        return options[0]

    def warning(self, *_args: object, **_kwargs: object) -> None:
        return None

    def info(self, *_args: object, **_kwargs: object) -> None:
        return None

    def subheader(self, *_args: object, **_kwargs: object) -> None:
        return None

    def markdown(self, *_args: object, **_kwargs: object) -> None:
        return None

    def caption(self, *_args: object, **_kwargs: object) -> None:
        return None

    def json(self, *_args: object, **_kwargs: object) -> None:
        return None


def test_running_is_counted_as_an_operational_sensor_state() -> None:
    sensors = [
        {"status": "RUNNING"},
        {"status": " operational "},
        {"status": "Online"},
        {"status": "active"},
        {"status": "offline"},
        {"status": None},
    ]

    assert _operational_sensor_count(sensors) == 4


def test_signal_options_keep_event_and_finding_identity_explicit() -> None:
    snapshot = valid_snapshot()
    snapshot["events"].append(
        {
            "id": "event:test:1",
            "title": "Comando Modbus anomalo",
        }
    )
    snapshot["findings"].append(
        {
            "id": "finding:test:1",
            "code": "vmware_drift",
        }
    )

    options = _signal_options(snapshot)

    assert options == [
        ("event", "event:test:1", "Comando Modbus anomalo"),
        ("finding", "finding:test:1", "vmware_drift"),
    ]
    assert _signal_option_label(options[0]) == (
        "Evento · Comando Modbus anomalo · event:test:1"
    )
    assert _signal_option_label(options[1]) == (
        "Finding · vmware_drift · finding:test:1"
    )
    assert _safe_export_stem("../PLC / Linea 1") == "PLC---Linea-1"


def test_evidence_view_preserves_old_bundles_and_exposes_new_direct_exports(
    monkeypatch,
) -> None:
    snapshot = valid_snapshot()
    asset_id = add_cisco_asset(snapshot, score=68)
    source_id = "src:cisco-cyber-vision:dtlab-01"
    snapshot["events"].append(
        {
            "id": "event:test:modbus-write",
            "evidence": evidence(source_id, "real", "event:test:modbus-write"),
            "occurred_at": FETCHED_AT,
            "severity": "high",
            "category": "Security",
            "title": "Comando Modbus anomalo",
            "description": "Evento restituito da Cisco.",
            "center_id": None,
            "center_label": None,
            "status": "open",
            "asset_ids": [asset_id],
            "acknowledged": False,
        }
    )
    digest = snapshot_sha256(snapshot)
    manifest = {
        "snapshot_id": snapshot["snapshot_id"],
        "sha256": digest,
        "object_name": f"{digest}.json",
    }
    display_snapshot = deepcopy(snapshot)
    display_snapshot["virtual_machines"][0]["evidence"]["truth"] = "stale"
    context = SimpleNamespace(
        snapshot=display_snapshot,
        canonical_snapshot=snapshot,
        manifest=manifest,
        cybervision_source=snapshot["sources"][2],
    )
    fake_streamlit = _FakeStreamlit()
    monkeypatch.setattr(platform, "st", fake_streamlit)
    monkeypatch.setattr(platform, "page_intro", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(platform, "empty_state", lambda *_args, **_kwargs: None)

    platform.render_evidence(context)

    downloads = {download["label"]: download for download in fake_streamlit.downloads}
    assert {
        "Scarica bundle tecnico",
        "Scarica bundle redatto",
        "Scarica bundle SIEM",
        "Scarica eventi NDJSON",
        "Scarica eventi CEF",
        "Scarica snapshot canonico JSON",
        "Scarica JSON Schema",
        "Scarica manifest JSON",
        "Scarica evidenza asset",
        "Scarica profilo asset JSON",
        "Scarica evidence bundle evento",
    } == set(downloads)
    assert json.loads(downloads["Scarica snapshot canonico JSON"]["data"]) == snapshot
    assert json.loads(downloads["Scarica snapshot canonico JSON"]["data"]) != (
        display_snapshot
    )
    assert downloads["Scarica JSON Schema"]["mime"] == "application/schema+json"
    assert json.loads(downloads["Scarica manifest JSON"]["data"]) == manifest
    ndjson_records = [
        json.loads(line)
        for line in downloads["Scarica eventi NDJSON"]["data"].decode("utf-8").splitlines()
    ]
    assert any(record["event_id"] for record in ndjson_records)
    assert all(record["snapshot_sha256"] == digest for record in ndjson_records)
    assert downloads["Scarica eventi CEF"]["data"].startswith(
        b"CEF:0|DTLab|Control Center|"
    )
    with zipfile.ZipFile(io.BytesIO(downloads["Scarica bundle SIEM"]["data"])) as archive:
        siem_manifest = json.loads(archive.read("manifest.json"))
    assert siem_manifest["record_count"] == len(ndjson_records)
    assert siem_manifest["snapshot_sha256"] == digest
    profile = json.loads(downloads["Scarica profilo asset JSON"]["data"])
    assert profile["asset"]["id"] == asset_id
    with zipfile.ZipFile(
        io.BytesIO(downloads["Scarica evidence bundle evento"]["data"])
    ) as archive:
        signal_manifest = json.loads(archive.read("manifest.json"))
    assert signal_manifest["signal_type"] == "event"
    assert signal_manifest["signal_id"] == "event:test:modbus-write"
