from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path

from streamlit.testing.v1 import AppTest

from dtlab.services.snapshot_store import AtomicSnapshotStore
from dtlab.ui.context import load_dashboard_context
from dtlab.ui.views.security import _event_rows
from tests.factories import add_cisco_asset, valid_snapshot

PUBLISHED_AT = datetime(2026, 8, 3, 14, 30, tzinfo=UTC)
APP_PATH = Path(__file__).resolve().parents[1] / "app.py"


def _publish(root, snapshot: dict) -> None:
    AtomicSnapshotStore(root).publish(snapshot, published_at=PUBLISHED_AT)


def _source_by_type(snapshot: dict, source_type: str) -> dict:
    return next(source for source in snapshot["sources"] if source["type"] == source_type)


def _render_vulnerabilities_for_test(context) -> None:
    from dtlab.ui.views.security import render_vulnerabilities

    render_vulnerabilities(context)


def test_app_fails_closed_when_no_trusted_snapshot_exists(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("DTLAB_SNAPSHOT_STORE", str(tmp_path / "missing"))

    app = AppTest.from_file(APP_PATH).run(timeout=20)

    assert len(app.exception) == 0
    assert any("fail-closed" in error.value for error in app.error)


def test_partial_dashboard_has_no_demo_or_fake_score(tmp_path, monkeypatch) -> None:
    store = tmp_path / "store"
    _publish(store, valid_snapshot())
    monkeypatch.setenv("DTLAB_SNAPSHOT_STORE", str(store))

    app = AppTest.from_file(APP_PATH).run(timeout=20)
    rendered = "\n".join(str(element.value) for element in [*app.markdown, *app.info, *app.warning])

    assert len(app.exception) == 0
    assert "DTLab Command Center" in rendered
    assert "Nessuno score Cisco acquisito" in rendered
    assert "demo" in rendered.lower()
    assert "0/100" not in rendered
    assert "OT Health Score" not in rendered


def test_real_cisco_score_is_rendered_with_per_device_label(
    tmp_path,
    monkeypatch,
) -> None:
    snapshot = valid_snapshot()
    add_cisco_asset(snapshot, score=68)
    snapshot["sync"]["state"] = "fresh"
    cybervision = _source_by_type(snapshot, "cisco_cyber_vision")
    cybervision["status"] = "connected"
    cybervision["capabilities"] = {
        "devices": {"status": "available", "records": 1, "error_code": None}
    }
    store = tmp_path / "store"
    _publish(store, snapshot)
    monkeypatch.setenv("DTLAB_SNAPSHOT_STORE", str(store))

    app = AppTest.from_file(APP_PATH).run(timeout=20)
    rendered = "\n".join(str(element.value) for element in app.markdown)

    assert len(app.exception) == 0
    assert "68/100" in rendered
    assert "Score Cisco massimo" in rendered


def test_command_center_exposes_classic_and_new_ui_as_separate_sources(
    tmp_path,
    monkeypatch,
) -> None:
    snapshot = valid_snapshot()
    classic = _source_by_type(snapshot, "cisco_cyber_vision")
    classic["status"] = "connected"
    new_ui = deepcopy(classic)
    new_ui.update(
        {
            "id": "src:cisco-cyber-vision-new-ui:test",
            "label": "Cisco Cyber Vision · New UI",
            "type": "cisco_cyber_vision_new_ui",
        }
    )
    new_ui["evidence"]["source_id"] = new_ui["id"]
    snapshot["sources"].append(new_ui)
    store = tmp_path / "store"
    _publish(store, snapshot)
    monkeypatch.setenv("DTLAB_SNAPSHOT_STORE", str(store))

    app = AppTest.from_file(APP_PATH).run(timeout=20)
    rendered = "\n".join(str(element.value) for element in app.markdown)

    assert len(app.exception) == 0
    assert "Cisco Cyber Vision: Connessa" in rendered
    assert "Cisco Cyber Vision · New UI: Connessa" in rendered


def test_command_center_shows_degraded_cisco_as_available_data(
    tmp_path,
    monkeypatch,
) -> None:
    snapshot = valid_snapshot()
    classic = _source_by_type(snapshot, "cisco_cyber_vision")
    classic["status"] = "degraded"
    classic["last_success_at"] = snapshot["generated_at"]
    classic["record_counts"] = {"devices": 3}
    classic["capabilities"] = {
        "devices": {"status": "available", "records": 3, "error_code": None},
        "sensor_stats": {"status": "error", "records": 0, "error_code": "http_500"},
    }
    store = tmp_path / "store"
    _publish(store, snapshot)
    monkeypatch.setenv("DTLAB_SNAPSHOT_STORE", str(store))

    app = AppTest.from_file(APP_PATH).run(timeout=20)
    rendered = "\n".join(str(element.value) for element in app.markdown)

    assert len(app.exception) == 0
    assert "Cisco Cyber Vision: Dati disponibili" in rendered
    assert "Cisco Cyber Vision: Degradata" not in rendered


def test_corrupt_current_uses_verified_fallback_and_labels_it(tmp_path, monkeypatch) -> None:
    store_path = tmp_path / "store"
    store = AtomicSnapshotStore(store_path)
    first = valid_snapshot()
    _publish(store_path, first)
    second = valid_snapshot()
    second["snapshot_id"] = "snapshot:test:current-corrupt"
    manifest = store.publish(second, published_at=PUBLISHED_AT)
    (store.objects / manifest["object_name"]).write_text("{}", encoding="utf-8")
    monkeypatch.setenv("DTLAB_SNAPSHOT_STORE", str(store_path))

    app = AppTest.from_file(APP_PATH).run(timeout=20)

    assert len(app.exception) == 0
    assert any("last_known_good" in warning.value for warning in app.warning)


def test_dynamic_html_is_escaped_before_rendering(tmp_path, monkeypatch) -> None:
    store = tmp_path / "store"
    snapshot = valid_snapshot()
    _source_by_type(snapshot, "vmware_esxi")["label"] = '<img src=x onerror="alert(1)">'
    _publish(store, snapshot)
    monkeypatch.setenv("DTLAB_SNAPSHOT_STORE", str(store))

    app = AppTest.from_file(APP_PATH).run(timeout=20)
    rendered = "\n".join(str(element.value) for element in app.markdown)

    assert len(app.exception) == 0
    assert "&lt;img" in rendered
    assert '<img src=x onerror="alert(1)">' not in rendered


def test_vulnerability_dossier_reports_nd_when_device_capability_failed(tmp_path) -> None:
    snapshot = valid_snapshot()
    cybervision = _source_by_type(snapshot, "cisco_cyber_vision")
    cybervision["status"] = "degraded"
    cybervision["last_success_at"] = snapshot["generated_at"]
    cybervision["details"] = {
        "vulnerability_catalog": [
            {
                "source_record_id": "cisco-cve:test",
                "external_id": "CVE-2026-0001",
                "title": "Catalog record",
                "cvss_score": 8.8,
            }
        ]
    }
    cybervision["capabilities"] = {
        "vulnerabilities": {
            "status": "available",
            "records": 1,
            "error_code": None,
        },
        "device_vulnerabilities": {
            "status": "error",
            "records": 0,
            "error_code": "http_500",
        },
    }
    store = tmp_path / "store"
    _publish(store, snapshot)
    context = load_dashboard_context(store, now=PUBLISHED_AT)

    app = AppTest.from_function(
        _render_vulnerabilities_for_test,
        args=(context,),
        default_timeout=30,
    ).run(timeout=30)

    assert len(app.exception) == 0
    assert any(
        "Asset associati" in str(element.value) and "N/D" in str(element.value)
        for element in app.markdown
    )
    assert any("non sono verificabili" in warning.value for warning in app.warning)


def test_event_rows_expose_center_metadata_without_inference() -> None:
    rows = _event_rows(
        [
            {
                "id": "event:test:1",
                "occurred_at": "2026-08-03T13:00:00Z",
                "severity": "high",
                "category": "Security",
                "center_id": "center-1",
                "center_label": "DTLab Center",
                "title": "Evento test",
                "evidence": {"truth": "real"},
            }
        ]
    )

    assert rows[0]["Center"] == "DTLab Center"
