from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

from streamlit.testing.v1 import AppTest

from dtlab.services.host_ot_status import store_sensor_status
from dtlab.services.snapshot_store import AtomicSnapshotStore
from dtlab.ui.theme import apply_theme
from dtlab.ui.views.monitoring import _priority_signals, host_ot_topology_rows
from tests.factories import FETCHED_AT, evidence, valid_snapshot

PUBLISHED_AT = datetime(2026, 8, 3, 14, 30, tzinfo=UTC)
APP_PATH = Path(__file__).resolve().parents[1] / "app.py"


def test_priority_signals_preserve_all_real_operational_sources() -> None:
    snapshot = {
        "assets": [{"id": "asset:1", "name": "PLC linea 1"}],
        "events": [
            {
                "id": "event:1",
                "occurred_at": "2026-08-03T10:04:00Z",
                "severity": "critical",
                "category": "Security",
                "title": "Comunicazione anomala",
                "asset_ids": ["asset:1"],
            }
        ],
        "findings": [
            {
                "id": "finding:open",
                "status": "open",
                "severity": "high",
                "title": "Configurazione da verificare",
                "description": "Conferma operativa necessaria.",
                "last_detected_at": "2026-08-03T10:03:00Z",
                "recommended_action": "Confermare con il referente OT.",
            },
            {
                "id": "finding:accepted",
                "status": "accepted",
                "severity": "high",
                "title": "Eccezione già accettata",
                "description": "Non deve entrare nella coda.",
                "last_detected_at": "2026-08-03T10:05:00Z",
                "recommended_action": "Nessuna.",
            },
        ],
        "baseline_differences": [
            {
                "id": "difference:1",
                "difference_type": "new_activity",
                "description": "Nuova attività Modbus",
                "asset_ids": ["asset:1"],
                "detected_at": "2026-08-03T10:02:00Z",
            }
        ],
        "vulnerabilities": [
            {
                "id": "vulnerability:1",
                "asset_id": "asset:1",
                "external_id": "CVE-2026-0001",
                "title": "Vulnerabilità PLC",
                "severity": "high",
                "cvss_score": 8.2,
                "published_at": "2026-08-03T10:01:00Z",
                "details": {"solution": "Applicare la mitigazione Cisco validata."},
            }
        ],
    }

    signals = _priority_signals(snapshot)

    assert [signal["kind"] for signal in signals] == [
        "Evento Cisco",
        "Finding ambiente",
        "Vulnerabilità associata",
        "Differenza baseline",
    ]
    assert signals[0]["severity"] == "critical"
    assert any(signal["action"] == "Confermare con il referente OT." for signal in signals)
    assert any(
        signal["action"] == "Applicare la mitigazione Cisco validata."
        for signal in signals
    )
    assert all(signal["id"] != "finding:accepted" for signal in signals)


def test_theme_contains_m3_cockpit_responsive_and_accessible_states() -> None:
    with patch("dtlab.ui.theme.st.markdown") as markdown:
        apply_theme()

    css = markdown.call_args.args[0]
    assert "--md-sys-color-surface-container-lowest" in css
    assert ".dt-priority-card" in css
    assert ".dt-live-strip" in css
    assert ".dt-journey" in css
    assert ".dt-baseline-signal" in css
    assert "--md-sys-color-tertiary-container" in css
    assert ".dt-action-link" in css
    assert ":focus-visible" in css
    assert "@media (max-width:760px)" in css
    assert "@media (prefers-reduced-motion:reduce)" in css


def test_command_center_renders_recommendation_and_infrastructure(
    tmp_path,
    monkeypatch,
) -> None:
    snapshot = valid_snapshot()
    esxi_id = "src:vmware-esxi:dtlab-01"
    vm_id = snapshot["virtual_machines"][0]["id"]
    snapshot["findings"].append(
        {
            "id": "finding:test:action",
            "evidence": evidence(esxi_id, "observed", "derived:test-action"),
            "code": "configuration_confirmation_required",
            "severity": "high",
            "title": "Verifica configurazione OT",
            "description": "La configurazione richiede una conferma operativa.",
            "status": "open",
            "entity_ids": [vm_id],
            "first_detected_at": FETCHED_AT,
            "last_detected_at": FETCHED_AT,
            "recommended_action": "Confermare la configurazione con il referente OT.",
            "exclude_from_operational_kpis": False,
        }
    )
    store = tmp_path / "store"
    AtomicSnapshotStore(store).publish(snapshot, published_at=PUBLISHED_AT)
    monkeypatch.setenv("DTLAB_SNAPSHOT_STORE", str(store))
    host_store = tmp_path / "host-ot"
    store_sensor_status(
        host_store,
        sensor_id="plc-endpoint-sensor",
        event={
            "event_type": "heartbeat",
            "event_id": "host-heartbeat:boot-1:1",
            "last_observed_at": "2026-09-01T10:30:00Z",
            "evidence": {"truth": "endpoint_heartbeat"},
        },
        document_sha256="a" * 64,
    )
    monkeypatch.setenv("DTLAB_HOST_OT_EVENT_STORE", str(host_store))

    app = AppTest.from_file(APP_PATH).run(timeout=20)
    rendered = "\n".join(str(element.value) for element in app.markdown)
    success_messages = "\n".join(str(element.value) for element in app.success)

    assert len(app.exception) == 0
    assert "Segnali da verificare" in rendered
    assert "Confermare la configurazione con il referente OT." in rendered
    assert "PLC-Desktop" in rendered
    assert "nessuna remediation è automatica" in rendered
    assert "Qualità dati" in rendered
    assert "Copertura host PLC attiva" in success_messages
    assert "plc-endpoint-sensor" in success_messages


def test_host_ot_topology_rows_keep_endpoint_truth_separate_from_cisco() -> None:
    signal = {
        "id": "signal:host-test",
        "signal_type": "host_modbus_write",
        "severity": "critical",
        "last_observed_at": "2026-09-01T10:40:00Z",
        "payload": {
            "source_ip": "172.16.10.10",
            "destination_ip": "172.16.10.10",
            "origin": "self_originated",
            "function_code": 6,
            "writes": [
                {"function_code": 6, "address": 3, "value": 0},
                {"function_code": 6, "address": 4, "value": 0},
                {"function_code": 6, "address": 16, "value": 0},
            ],
            "classification": "process_shutdown_manipulation",
        },
    }
    operational = {
        "signals": [signal],
        "ticket_by_signal": {
            signal["id"]: {"id": "ticket:test", "priority": "p1"}
        },
    }

    rows = host_ot_topology_rows(operational)

    assert len(rows) == 1
    row = rows[0]
    assert row["Relazione"] == "172.16.10.10 → 172.16.10.10"
    assert row["Self PLC"] == "Sì"
    assert row["Function Code"] == "FC6"
    assert json.loads(row["Registri / valori"])[-1]["address"] == 16
    assert row["Classificazione"] == "process_shutdown_manipulation"
    assert row["Severità"] == "Critico"
    assert row["Ticket"] == "ticket:test"
    assert row["Priorità"] == "P1"
    assert row["Fonte"] == "Sensore host PLC · non Cisco"
