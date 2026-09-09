"""Authenticated, non-secret audit of Cisco Cyber Vision administrative settings.

The utility intentionally implements only GET operations.  It creates a timestamped
JSON backup of the configuration objects required before changing ingestion,
sensor-template, baseline or Snort settings.  Credentials are read interactively and
are never serialized.
"""

from __future__ import annotations

import argparse
import getpass
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import requests
import urllib3


def _login(
    session: requests.Session, base_url: str, username: str, password: str
) -> dict[str, Any]:
    response = session.post(
        f"{base_url}/scv/1.0/login",
        data={"u": username, "p": password},
        timeout=(5, 30),
        verify=False,
        allow_redirects=False,
    )
    response.raise_for_status()

    user_response = session.get(
        f"{base_url}/scv/3.0/user/check",
        timeout=(5, 30),
        verify=False,
        allow_redirects=False,
    )
    user_response.raise_for_status()

    session_response = session.get(
        f"{base_url}/scv/1.0/check_session",
        timeout=(5, 30),
        verify=False,
        allow_redirects=False,
    )
    session_response.raise_for_status()
    csrf_token = session_response.headers.get("x-csrf-token")
    if csrf_token:
        session.headers["X-CSRF-Token"] = csrf_token
    return {
        "user": user_response.json(),
        "session": session_response.json(),
    }


def _get_json(session: requests.Session, base_url: str, path: str) -> Any:
    response = session.get(
        f"{base_url}{path}",
        headers={"Accept": "application/json"},
        timeout=(5, 45),
        verify=False,
        allow_redirects=False,
    )
    if response.status_code in {402, 403, 404, 500}:
        return {
            "_http_status": response.status_code,
            "_content_type": response.headers.get("content-type"),
            "_body_excerpt": response.text[:500],
        }
    response.raise_for_status()
    if not response.content:
        return None
    try:
        return response.json()
    except requests.exceptions.JSONDecodeError:
        return response.text


def _items(payload: Any) -> list[Any]:
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        for key in ("items", "content", "results", "data"):
            if isinstance(payload.get(key), list):
                return payload[key]
    return []


def audit(session: requests.Session, base_url: str, output_dir: Path) -> Path:
    result: dict[str, Any] = {
        "captured_at": datetime.now(UTC).isoformat(),
        "base_url": base_url,
        "data_ingestion_settings": _get_json(
            session, base_url, "/scv/3.0/admin/dataIngestionSettings"
        ),
        "sensor_template_schema": _get_json(
            session, base_url, "/scv/3.0/admin/sensorTemplates/schema"
        ),
        "sensor_templates": _get_json(
            session,
            base_url,
            "/scv/3.0/admin/sensorTemplates?currentPage=1&pageSize=100",
        ),
        "default_sensor_template": _get_json(
            session, base_url, "/scv/3.0/admin/sensorTemplates/default"
        ),
        "admin_sensors": _get_json(session, base_url, "/scv/3.0/admin/sensors"),
        "sensor_tree": _get_json(session, base_url, "/scv/3.0/sensors/tree"),
        "snort_categories": _get_json(session, base_url, "/scv/3.0/snort/categories"),
        "snort_experimental_scada_rules": _get_json(
            session, base_url, "/scv/3.0/snort/categories/14/rules"
        ),
        "snort_custom_rules": _get_json(session, base_url, "/scv/3.0/snort/rules/custom"),
        "snort_sync": _get_json(session, base_url, "/scv/1.0/sensors/snort/sync"),
        "presets": _get_json(session, base_url, "/scv/3.0/presets?baselines=true"),
        "syslog": _get_json(session, base_url, "/scv/1.0/syslog/"),
    }

    preset_details: list[dict[str, Any]] = []
    for preset in _items(result["presets"]):
        preset_id = preset.get("id") if isinstance(preset, dict) else None
        if preset_id is None:
            continue
        preset_details.append(
            {
                "id": preset_id,
                "label": preset.get("label") or preset.get("name"),
                "settings": _get_json(session, base_url, f"/scv/3.0/presets/{preset_id}/settings"),
                "baselines": _get_json(
                    session, base_url, f"/scv/3.0/presets/{preset_id}/baselines"
                ),
            }
        )
    result["preset_details"] = preset_details

    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    output_path = output_dir / f"cybervision-admin-audit-{timestamp}.json"
    output_path.write_text(
        json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True),
        encoding="utf-8",
    )

    print(f"Backup: {output_path}")
    print(f"Template sensore: {len(_items(result['sensor_templates']))}")
    print(f"Sensori amministrativi: {len(_items(result['admin_sensors']))}")
    print(f"Categorie Snort: {len(_items(result['snort_categories']))}")
    scada_rules = result["snort_experimental_scada_rules"]
    scada_rule_count = (
        len(_items(scada_rules))
        if not isinstance(scada_rules, str)
        else len(scada_rules.splitlines())
    )
    print(f"Regole Experimental-Scada disponibili: {scada_rule_count}")
    custom_rules = result["snort_custom_rules"]
    custom_rule_count = (
        sum(line.startswith("alert ") for line in custom_rules.splitlines())
        if isinstance(custom_rules, str)
        else len(_items(custom_rules))
    )
    print(f"Regole Snort custom: {custom_rule_count}")
    print(f"Preset: {len(_items(result['presets']))}")
    print(f"Dettagli preset raccolti: {len(preset_details)}")
    syslog_configured = bool(result["syslog"]) and "_http_status" not in (result["syslog"] or {})
    print(f"Syslog configurato: {syslog_configured}")
    return output_path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", required=True)
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("backups") / "cybervision",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    username = input("Cyber Vision username: ").strip()
    password = getpass.getpass("Cyber Vision password: ")
    session = requests.Session()
    session.trust_env = False
    login_info = _login(session, args.base_url.rstrip("/"), username, password)
    print(f"Autenticazione riuscita per userId={login_info['user'].get('userId', 'N/D')}")
    audit(session, args.base_url.rstrip("/"), args.output_dir.resolve())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
