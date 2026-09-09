from __future__ import annotations

from datetime import datetime, timedelta, timezone


ASSET_BLUEPRINTS = [
    ("PLC-LINE-01", "PLC Linea 01", "10.40.10.11", "Siemens", "PLC", "Cella imbottigliamento", "Modbus TCP", "Alto", 3, "S7-1500 2.9"),
    ("PLC-UTIL-01", "PLC Utilities", "10.40.10.12", "Schneider Electric", "PLC", "Utilities", "Modbus TCP", "Medio", 1, "M580 4.20"),
    ("HMI-LINE-01", "HMI Operatore Linea", "10.40.10.21", "Siemens", "HMI", "Cella imbottigliamento", "Modbus TCP", "Medio", 2, "WinCC 19"),
    ("ENG-WS-01", "Engineering Workstation", "10.40.20.31", "Dell", "Workstation", "Engineering", "RDP", "Alto", 5, "Windows 11 23H2"),
    ("HIST-01", "Historian OT", "10.40.20.41", "AVEVA", "Server", "Operations", "OPC UA", "Medio", 2, "2023 R2"),
    ("SW-OT-CORE", "Switch OT Core", "10.40.0.2", "Cisco", "Switch", "Core OT", "SNMP", "Basso", 0, "IOS XE 17.12"),
    ("SW-CELL-01", "Switch Cella 01", "10.40.10.2", "Cisco", "Switch", "Cella imbottigliamento", "SNMP", "Basso", 0, "IOS XE 17.9"),
    ("SENSOR-LEVEL-01", "Sensore Livello", "10.40.10.51", "Endress+Hauser", "Sensore", "Cella imbottigliamento", "Modbus TCP", "Basso", 0, "1.8.4"),
    ("DRIVE-CONV-01", "Inverter Nastro", "10.40.10.61", "ABB", "Drive", "Cella imbottigliamento", "Modbus TCP", "Medio", 1, "3.14"),
    ("ROBOT-PACK-01", "Robot Pallettizzazione", "10.40.30.71", "KUKA", "Robot", "Packaging", "PROFINET", "Alto", 2, "KSS 8.7"),
    ("HMI-PACK-01", "HMI Packaging", "10.40.30.21", "Rockwell Automation", "HMI", "Packaging", "EtherNet/IP", "Medio", 1, "FactoryTalk 14"),
    ("PLC-PACK-01", "PLC Packaging", "10.40.30.11", "Rockwell Automation", "PLC", "Packaging", "EtherNet/IP", "Medio", 2, "Studio 5000 v35"),
    ("CAM-QA-01", "Camera Controllo Qualità", "10.40.40.81", "Cognex", "Vision System", "Quality", "HTTP", "Critico", 6, "In-Sight 6.3"),
    ("WS-QA-01", "Postazione Qualità", "10.40.40.31", "HP", "Workstation", "Quality", "SMB", "Alto", 4, "Windows 10 22H2"),
    ("GW-OT-IT", "Gateway OT/IT", "10.40.0.1", "Cisco", "Gateway", "Industrial DMZ", "HTTPS", "Basso", 0, "FTD 7.4"),
    ("SYSLOG-01", "Collector Syslog", "10.40.50.41", "Linux", "Server", "Industrial DMZ", "Syslog", "Basso", 0, "Ubuntu 24.04"),
    ("NTP-OT-01", "NTP OT", "10.40.50.42", "Meinberg", "Server", "Industrial DMZ", "NTP", "Medio", 1, "LANTIME 7.08"),
    ("AP-MAINT-01", "Access Point Manutenzione", "10.40.60.5", "Cisco", "Access Point", "Maintenance", "HTTPS", "Critico", 4, "17.12.2"),
]


ALERT_BLUEPRINTS = [
    ("Critica", "Scrittura non autorizzata", "OT-DET-001", "Alta", "T1692.001", "ENG-WS-01", "PLC-LINE-01", "Modbus TCP", "FC 06", "Scrittura di un holding register da sorgente non autorizzata", "Aperto"),
    ("Alta", "Nuovo asset", "OT-DET-002", "Alta", "-", "AP-MAINT-01", "SW-OT-CORE", "ARP", "-", "Asset non presente nella baseline rilevato nella zona Maintenance", "In analisi"),
    ("Alta", "Comunicazione inter-zona", "OT-DET-003", "Alta", "-", "WS-QA-01", "PLC-LINE-01", "Modbus TCP", "FC 03", "Flusso Modbus osservato tra Quality e Cella imbottigliamento", "Aperto"),
    ("Media", "Variazione firmware", "OT-DET-004", "Media", "-", "CAM-QA-01", "HIST-01", "HTTPS", "-", "Versione firmware differente rispetto all'ultimo inventario", "In analisi"),
    ("Media", "Frequenza anomala", "OT-DET-005", "Media", "-", "HMI-LINE-01", "PLC-LINE-01", "Modbus TCP", "FC 03", "Aumento delle richieste di lettura oltre la baseline", "Chiuso"),
    ("Bassa", "Asset non raggiungibile", "OT-DET-006", "Alta", "-", "NTP-OT-01", "SYSLOG-01", "ICMP", "-", "Asset temporaneamente non raggiungibile", "Chiuso"),
    ("Alta", "Servizio inatteso", "OT-DET-007", "Alta", "-", "ROBOT-PACK-01", "ENG-WS-01", "SMB", "-", "Servizio SMB osservato su asset di cella", "Aperto"),
    ("Media", "Cambio configurazione", "OT-DET-008", "Media", "-", "SW-CELL-01", "SYSLOG-01", "Syslog", "-", "Configurazione dello switch modificata", "Chiuso"),
]


FLOW_BLUEPRINTS = [
    ("HMI-LINE-01", "PLC-LINE-01", "Modbus TCP", 502, "Atteso", 18420),
    ("SENSOR-LEVEL-01", "PLC-LINE-01", "Modbus TCP", 502, "Atteso", 22108),
    ("DRIVE-CONV-01", "PLC-LINE-01", "Modbus TCP", 502, "Atteso", 17655),
    ("PLC-LINE-01", "HIST-01", "OPC UA", 4840, "Atteso", 6432),
    ("PLC-UTIL-01", "HIST-01", "Modbus TCP", 502, "Atteso", 7230),
    ("ENG-WS-01", "HMI-LINE-01", "RDP", 3389, "Atteso", 414),
    ("HMI-PACK-01", "PLC-PACK-01", "EtherNet/IP", 44818, "Atteso", 15331),
    ("PLC-PACK-01", "ROBOT-PACK-01", "PROFINET", 34964, "Atteso", 19882),
    ("ROBOT-PACK-01", "HIST-01", "OPC UA", 4840, "Atteso", 3108),
    ("WS-QA-01", "CAM-QA-01", "HTTP", 80, "Atteso", 5280),
    ("CAM-QA-01", "HIST-01", "HTTPS", 443, "Atteso", 1620),
    ("SW-OT-CORE", "SYSLOG-01", "Syslog", 6514, "Atteso", 612),
    ("SW-CELL-01", "SYSLOG-01", "Syslog", 6514, "Atteso", 784),
    ("GW-OT-IT", "SYSLOG-01", "Syslog", 6514, "Atteso", 902),
    ("PLC-LINE-01", "NTP-OT-01", "NTP", 123, "Atteso", 288),
    ("PLC-PACK-01", "NTP-OT-01", "NTP", 123, "Atteso", 288),
    ("ENG-WS-01", "PLC-LINE-01", "Modbus TCP", 502, "Deviazione", 18),
    ("WS-QA-01", "PLC-LINE-01", "Modbus TCP", 502, "Deviazione", 42),
    ("AP-MAINT-01", "SW-OT-CORE", "HTTPS", 443, "Nuovo", 36),
    ("ROBOT-PACK-01", "ENG-WS-01", "SMB", 445, "Nuovo", 12),
]


def build_demo_payload(now: datetime | None = None) -> dict:
    now = now or datetime.now(timezone.utc)
    assets = []
    for index, blueprint in enumerate(ASSET_BLUEPRINTS, start=1):
        asset_id, name, ip, vendor, asset_type, zone, protocol, risk, vulns, firmware = blueprint
        is_stale = asset_id == "NTP-OT-01"
        last_seen = now - (timedelta(hours=29) if is_stale else timedelta(minutes=index * 3))
        mac = f"02:40:10:{index:02X}:{(index * 7) % 255:02X}:{(index * 13) % 255:02X}"
        assets.append(
            {
                "asset_id": asset_id,
                "name": name,
                "ip_address": ip,
                "mac_address": mac,
                "vendor": vendor,
                "asset_type": asset_type,
                "zone": zone,
                "protocol": protocol,
                "risk": risk,
                "status": "Non raggiungibile" if is_stale else "Online",
                "last_seen": last_seen.isoformat(),
                "firmware": firmware,
                "vulnerabilities": vulns,
            }
        )

    alerts = []
    for index in range(32):
        (
            severity,
            category,
            rule_id,
            confidence,
            attack_technique,
            source,
            destination,
            protocol,
            function_code,
            description,
            status,
        ) = ALERT_BLUEPRINTS[index % len(ALERT_BLUEPRINTS)]
        source_asset = next(asset for asset in assets if asset["asset_id"] == source)
        destination_asset = next(asset for asset in assets if asset["asset_id"] == destination)
        alerts.append(
            {
                "alert_id": f"ALT-{2026001 + index}",
                "timestamp": (now - timedelta(minutes=43 * index + 7)).isoformat(),
                "severity": severity,
                "category": category,
                "rule_id": rule_id,
                "confidence": confidence,
                "attack_technique": attack_technique,
                "source_asset": source_asset["name"],
                "destination_asset": destination_asset["name"],
                "source_ip": source_asset["ip_address"],
                "destination_ip": destination_asset["ip_address"],
                "protocol": protocol,
                "function_code": function_code,
                "description": description,
                "status": status,
            }
        )

    flows = []
    for index, (source, destination, protocol, port, baseline_status, messages) in enumerate(
        FLOW_BLUEPRINTS, start=1
    ):
        source_asset = next(asset for asset in assets if asset["asset_id"] == source)
        destination_asset = next(asset for asset in assets if asset["asset_id"] == destination)
        flows.append(
            {
                "flow_id": f"FLW-{index:03d}",
                "source_asset_id": source,
                "destination_asset_id": destination,
                "source_ip": source_asset["ip_address"],
                "destination_ip": destination_asset["ip_address"],
                "source_zone": source_asset["zone"],
                "destination_zone": destination_asset["zone"],
                "protocol": protocol,
                "port": port,
                "baseline_status": baseline_status,
                "first_seen": (now - timedelta(days=30 - min(index, 25))).isoformat(),
                "last_seen": (now - timedelta(minutes=index * 4)).isoformat(),
                "messages": messages,
            }
        )

    return {
        "metadata": {
            "mode": "DEMO",
            "environment": "DTLab OT Security",
            "generated_at": now.isoformat(),
            "schema_version": "1.1",
            "dataset_notice": "Dati sintetici: nessun collegamento con l'ambiente Relatech",
        },
        "assets": assets,
        "alerts": alerts,
        "flows": flows,
        "sources": [
            {"source": "Generatore demo", "type": "JSON sintetico", "status": "Attivo", "last_sync": now.isoformat(), "records": len(assets) + len(alerts) + len(flows), "endpoint": "local://demo"},
            {"source": "Cisco Cyber Vision", "type": "REST API", "status": "Non connesso", "last_sync": None, "records": 0, "endpoint": "Da configurare"},
            {"source": "SIEM", "type": "Syslog / API", "status": "Non connesso", "last_sync": None, "records": 0, "endpoint": "Da configurare"},
            {"source": "Import manuale", "type": "JSON", "status": "Disponibile", "last_sync": None, "records": 0, "endpoint": "Upload browser"},
        ],
    }
