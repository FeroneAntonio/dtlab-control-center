from __future__ import annotations

from dtlab.ui.views.new_ui_inventory import (
    _alert_rows,
    _asset_rows,
    _vulnerability_rows,
)


def test_new_ui_rows_keep_metrics_semantically_separate() -> None:
    assets = [
        {
            "name": "PLC profile",
            "type": "PLC",
            "vendor": "Vendor",
            "network_interfaces": [
                {
                    "ip": "172.16.10.10",
                    "mac": "00:11:22:33:44:55",
                    "is_primary": True,
                }
            ],
            "functional_group_name": None,
            "active_alert_count": 0,
            "vulnerability_count": 1,
            "sensor_associations": [
                {"id": "sensor-1", "label": "DPI", "is_close": True}
            ],
            "pcap_associations": [],
            "last_active_at": "2026-08-03T14:00:00Z",
        }
    ]
    alert_assets = [
        {
            "asset_name": "PLC profile",
            "alerts": [
                {
                    "status": "Active",
                    "severity": "high",
                    "category": "Security",
                    "alert_type": "Communication",
                    "trigger": "New peer",
                    "last_occurrence": "2026-08-03T14:00:00Z",
                }
            ],
        }
    ]
    vulnerability_assets = [
        {
            "asset_name": "PLC profile",
            "vulnerabilities": [
                {
                    "cve_id": "CVE-2026-0001",
                    "name": "Example",
                    "source": "public",
                    "csrs_score": "72",
                    "cvss_score": "8.1",
                }
            ],
        }
    ]

    asset_row = _asset_rows(assets)[0]
    alert_row = _alert_rows(alert_assets)[0]
    vulnerability_row = _vulnerability_rows(vulnerability_assets)[0]

    assert asset_row["Alert attivi"] == 0
    assert "172.16.10.10" in asset_row["Interfacce"]
    assert alert_row["Severità"] == "high"
    assert alert_row["Stato"] == "Active"
    assert vulnerability_row["CSRS (valore API)"] == "72"
    assert vulnerability_row["CVSS (valore API)"] == "8.1"
    assert "Risk score" not in vulnerability_row
