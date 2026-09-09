"""Configure Cisco Cyber Vision for DTLab Modbus visibility and alerting.

Changes are deliberately narrow and idempotent:

* enable Modbus variable processing on the already assigned Default template;
* import alert-only DTLab rules while preserving any existing custom rules;
* synchronize the resulting Snort ruleset to the CenterDPI sensor;
* verify every changed setting with a fresh read.

The utility never changes networking, powers devices, clears data, acknowledges
events, writes to the PLC, or creates blocking (``drop``) rules.
"""

from __future__ import annotations

import argparse
import getpass
import json
import re
import time
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import requests
import urllib3
from cybervision_admin_audit import audit

DEFAULT_RULES = Path(__file__).resolve().parents[1] / "config" / "cybervision-dtlab-modbus.rules"
MANAGED_START = "# BEGIN DTLAB MANAGED MODBUS RULES"
MANAGED_END = "# END DTLAB MANAGED MODBUS RULES"
EXPECTED_SILVERIO_SCRIPTS = {
    "attack_move_fill.py",
    "attack_move_fill2.py",
    "attack_shutdown.py",
    "attack_shutdown2.py",
    "attack_stop_fill.py",
    "attack_stop_fill2.py",
    "discovery.py",
    "set_registry.py",
}


def _parse_response(response: requests.Response) -> Any:
    if not response.content:
        return None
    try:
        return response.json()
    except requests.exceptions.JSONDecodeError:
        return response.text


def _request(
    session: requests.Session,
    method: str,
    base_url: str,
    path: str,
    **kwargs: Any,
) -> requests.Response:
    response = session.request(
        method,
        f"{base_url}{path}",
        timeout=(5, 60),
        verify=False,
        allow_redirects=False,
        **kwargs,
    )
    try:
        response.raise_for_status()
    except requests.HTTPError as exc:
        excerpt = response.text.strip().replace("\n", " ")[:1000]
        raise RuntimeError(
            f"Cyber Vision {method} {path} ha risposto HTTP "
            f"{response.status_code}: {excerpt or 'nessun dettaglio'}"
        ) from exc
    return response


def _login(session: requests.Session, base_url: str, username: str, password: str) -> None:
    _request(
        session,
        "POST",
        base_url,
        "/scv/1.0/login",
        data={"u": username, "p": password},
    )
    _request(session, "GET", base_url, "/scv/3.0/user/check")
    check = _request(session, "GET", base_url, "/scv/1.0/check_session")
    csrf_token = check.headers.get("x-csrf-token")
    if not csrf_token:
        raise RuntimeError("Cyber Vision non ha restituito il token CSRF di sessione.")
    session.headers.update({"X-CSRF-Token": csrf_token, "Accept": "application/json"})


def _get(session: requests.Session, base_url: str, path: str) -> Any:
    return _parse_response(_request(session, "GET", base_url, path))


def _json_list(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError:
            return []
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    return []


def _configure_default_template(session: requests.Session, base_url: str) -> bool:
    current = _get(session, base_url, "/scv/3.0/admin/sensorTemplates/default")
    if not isinstance(current, dict):
        raise RuntimeError("Il template Default non ha restituito un oggetto JSON.")

    config = json.loads(json.dumps(current.get("config") or {}))
    protocols = config.setdefault("protocols", {})
    modbus = protocols.setdefault("Modbus", {})
    already_enabled = modbus.get("variablesEnabled") is True and modbus.get("disabled") is not True
    if already_enabled:
        print("Variable Processing Modbus: già attivo")
        return False

    modbus["disabled"] = False
    modbus.setdefault("mapping", None)
    modbus["variablesEnabled"] = True
    payload = {
        "name": current.get("name") or "Default",
        "description": current.get("description") or "",
        "config": config,
        "sensorIds": current.get("sensorIds") or [],
    }
    response = _request(
        session,
        "PUT",
        base_url,
        "/scv/3.0/admin/sensorTemplates/default",
        json=payload,
    )
    print(f"Variable Processing Modbus: PUT HTTP {response.status_code}")
    readback: Any = None
    enabled = False
    for _ in range(10):
        time.sleep(3)
        readback = _get(session, base_url, "/scv/3.0/admin/sensorTemplates/default")
        enabled = (
            isinstance(readback, dict)
            and readback.get("config", {})
            .get("protocols", {})
            .get("Modbus", {})
            .get("variablesEnabled")
            is True
        )
        if enabled:
            break
    if not enabled:
        print(
            "ATTENZIONE: il Center ha accettato il PUT ma il read-back normalizza "
            "ancora il template a config vuota. La configurazione Snort prosegue; "
            "Variable Processing resta da confermare con telemetria variabili."
        )
        return False
    print("Variable Processing Modbus: attivato e verificato")
    return True


def _wait_template_deployment(session: requests.Session, base_url: str, timeout: int = 180) -> None:
    deadline = time.monotonic() + timeout
    last_status = "unknown"
    while time.monotonic() < deadline:
        sensors = _json_list(_get(session, base_url, "/scv/3.0/admin/sensors"))
        center = next(
            (item for item in sensors if item.get("isCenter")), sensors[0] if sensors else None
        )
        if center:
            last_status = str(center.get("templateDeploymentStatus") or "unknown")
            processing = str((center.get("processingStatus") or {}).get("label") or "unknown")
            if last_status == "deployed" and processing.lower() == "normally processing":
                print("Template sensore: deployed; CenterDPI: normally processing")
                return
        time.sleep(3)
    raise TimeoutError(
        f"Deployment template non concluso entro {timeout}s (ultimo stato: {last_status})."
    )


def _requested_sids(requested: str) -> set[str]:
    return set(re.findall(r"\bsid\s*:\s*(9001\d+)\s*;", requested))


def _validate_requested_rules(requested: str) -> set[str]:
    compact = requested.casefold()
    if " drop " in f" {compact} ":
        raise RuntimeError("Il file contiene una regola drop: import bloccato.")
    if MANAGED_START not in requested or MANAGED_END not in requested:
        raise RuntimeError("Marcatori del blocco DTLab gestito mancanti.")
    missing_scripts = sorted(
        name for name in EXPECTED_SILVERIO_SCRIPTS if name.casefold() not in compact
    )
    if missing_scripts:
        raise RuntimeError("Inventario Silverio incompleto: " + ", ".join(missing_scripts))
    sids = _requested_sids(requested)
    if len(sids) < 12:
        raise RuntimeError("Copertura Modbus generica insufficiente: meno di 12 SID.")
    return sids


def _merge_custom_rules(existing: Any, requested: str) -> str:
    existing_text = existing if isinstance(existing, str) else ""
    if requested.strip() in existing_text:
        return existing_text
    managed_block = re.compile(
        rf"(?ms)^\s*{re.escape(MANAGED_START)}.*?^{re.escape(MANAGED_END)}\s*$"
    )
    prefix = managed_block.sub("", existing_text)
    managed_sids = _requested_sids(requested) | {"9001998", "9001999"}

    def is_managed_legacy_line(line: str) -> bool:
        match = re.search(r"\bsid\s*:\s*(\d+)\s*;", line)
        return bool(match and match.group(1) in managed_sids)

    prefix = "\n".join(
        line for line in prefix.splitlines() if not is_managed_legacy_line(line)
    ).rstrip()
    return f"{prefix}\n\n{requested.strip()}\n" if prefix else f"{requested.strip()}\n"


def _configure_snort_rules(
    session: requests.Session,
    base_url: str,
    rules_path: Path,
    backup_dir: Path,
) -> bool:
    requested = rules_path.read_text(encoding="utf-8")
    required_sids = _validate_requested_rules(requested)
    existing = _get(session, base_url, "/scv/3.0/snort/rules/custom")
    merged = _merge_custom_rules(existing, requested)
    if isinstance(existing, str) and merged == existing:
        print("Regole Snort DTLab: già presenti")
        return False

    backup_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    backup_path = backup_dir / f"snort-custom-before-{timestamp}.rules"
    backup_path.write_text(existing if isinstance(existing, str) else "", encoding="utf-8")
    upload_path = backup_dir / f"snort-custom-merged-{timestamp}.rules"
    upload_path.write_text(merged, encoding="utf-8")

    with upload_path.open("rb") as handle:
        _request(
            session,
            "POST",
            base_url,
            "/scv/3.0/snort/rules/custom",
            files={"custom": (upload_path.name, handle, "text/plain")},
        )

    readback = _get(session, base_url, "/scv/3.0/snort/rules/custom")
    compact = readback.replace(" ", "") if isinstance(readback, str) else ""
    missing = sorted(sid for sid in required_sids if f"sid:{sid};" not in compact)
    if missing:
        raise RuntimeError(f"Read-back Snort incompleto; SID mancanti: {', '.join(missing)}")
    print(f"Regole Snort DTLab: importate e verificate ({len(required_sids)} SID)")
    return True


def _sync_snort(session: requests.Session, base_url: str, timeout: int = 180) -> None:
    _request(session, "POST", base_url, "/scv/1.0/sensors/snort/sync")
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        status = _get(session, base_url, "/scv/1.0/sensors/snort/sync")
        if isinstance(status, str):
            try:
                status = json.loads(status)
            except json.JSONDecodeError:
                status = {}
        if isinstance(status, dict) and status.get("in_progress") is False:
            print("Sincronizzazione Snort: completata")
            return
        time.sleep(3)
    raise TimeoutError(f"Sincronizzazione Snort non conclusa entro {timeout}s.")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--rules", type=Path, default=DEFAULT_RULES)
    parser.add_argument(
        "--backup-dir",
        type=Path,
        default=Path("backups") / "cybervision",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    username = input("Cyber Vision username: ").strip()
    password = getpass.getpass("Cyber Vision password: ")
    base_url = args.base_url.rstrip("/")
    backup_dir = args.backup_dir.resolve()

    session = requests.Session()
    session.trust_env = False
    _login(session, base_url, username, password)
    print("Audit pre-modifica")
    audit(session, base_url, backup_dir)

    template_changed = _configure_default_template(session, base_url)
    if template_changed:
        _wait_template_deployment(session, base_url)

    snort_changed = _configure_snort_rules(
        session,
        base_url,
        args.rules.resolve(),
        backup_dir,
    )
    if snort_changed:
        _sync_snort(session, base_url)

    print("Audit post-modifica")
    audit(session, base_url, backup_dir)
    with suppress(requests.RequestException):
        _request(session, "POST", base_url, "/scv/3.0/user/logout")
    print("Configurazione Cyber Vision completata senza azioni di blocco o power action.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
