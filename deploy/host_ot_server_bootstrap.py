"""Root-side, idempotent bootstrap for the DTLab PLC host-event receiver.

The default is a read-only plan.  ``--apply`` creates the isolated data/key
directories, installs the release-matched systemd unit and, for production,
adds the narrow write-only reverse proxy to the existing TLS vhost.  Existing
keys are never printed or rotated implicitly.
"""

from __future__ import annotations

import argparse
import base64
import http.client
import json
import os
import re
import secrets
import stat
import subprocess
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path

PRIVATE_ROOT = Path("/var/www/clients/client1/web75/private")
RELEASES_ROOT = PRIVATE_ROOT / "modbus-dashboard-releases"
VHOST = Path("/etc/apache2/sites-available/modbus.sitoclone.it.vhost")
BACKUP_ROOT = Path("/var/backups/dtlab-host-ot-ingress")
MARKER_START = "# BEGIN DTLAB HOST OT INGRESS"
MARKER_END = "# END DTLAB HOST OT INGRESS"

TARGETS = {
    "staging": {
        "release_link": PRIVATE_ROOT / "modbus-dashboard-staging-current",
        "unit_name": "modbus-dashboard-host-ot-ingress-staging.service",
        "port": 8521,
        "data": PRIVATE_ROOT / "modbus-dashboard-host-ot-data-staging",
        "secrets": PRIVATE_ROOT / "modbus-dashboard-host-ot-secrets-staging",
        "ticket": PRIVATE_ROOT
        / "modbus-dashboard-ticket-data-staging"
        / "tickets.sqlite3",
    },
    "production": {
        "release_link": PRIVATE_ROOT / "modbus-dashboard-current",
        "unit_name": "modbus-dashboard-host-ot-ingress.service",
        "port": 8520,
        "data": PRIVATE_ROOT / "modbus-dashboard-host-ot-data",
        "secrets": PRIVATE_ROOT / "modbus-dashboard-host-ot-secrets",
        "ticket": PRIVATE_ROOT / "modbus-dashboard-ticket-data" / "tickets.sqlite3",
    },
}


class BootstrapError(RuntimeError):
    pass


def _run(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(args, check=check, text=True, capture_output=True)
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or exc.stdout or "").strip()
        suffix = f": {detail}" if detail else ""
        raise BootstrapError(
            f"Comando fallito ({exc.returncode}): {' '.join(args)}{suffix}"
        ) from exc


def _identity() -> tuple[int, int]:
    import grp
    import pwd

    try:
        return pwd.getpwnam("web75").pw_uid, grp.getgrnam("dtlab-dashboard").gr_gid
    except KeyError as exc:
        raise BootstrapError("Identità web75/dtlab-dashboard non disponibile") from exc


def _release_directory(link: Path) -> Path:
    try:
        resolved = link.resolve(strict=True)
        resolved.relative_to(RELEASES_ROOT)
    except (OSError, ValueError) as exc:
        raise BootstrapError(f"Release link non sicuro: {link}") from exc
    if not resolved.is_dir():
        raise BootstrapError(f"Release corrente non valida: {resolved}")
    return resolved


def _atomic_write(path: Path, content: bytes, *, mode: int, uid: int, gid: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}-", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, mode)
        os.chown(temporary, uid, gid)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _ensure_directory(path: Path, *, mode: int, uid: int, gid: int) -> None:
    path.mkdir(parents=True, exist_ok=True)
    if not path.is_dir() or path.is_symlink():
        raise BootstrapError(f"Directory non sicura: {path}")
    os.chown(path, uid, gid)
    os.chmod(path, mode)


def _keyring(path: Path, *, gid: int) -> bool:
    if path.exists():
        if not path.is_file() or path.is_symlink():
            raise BootstrapError(f"Keyring non sicuro: {path}")
        payload = json.loads(path.read_text(encoding="utf-8"))
        records = payload.get("keys") if isinstance(payload, dict) else None
        if not isinstance(records, list) or len(records) != 1:
            raise BootstrapError("Keyring esistente non conforme")
        os.chown(path, 0, gid)
        os.chmod(path, 0o640)
        return False
    payload = {
        "keys": [
            {
                "key_id": "plc-desktop-v1",
                "sensor_id": "plc-endpoint-sensor",
                "secret_base64": base64.b64encode(secrets.token_bytes(32)).decode("ascii"),
            }
        ]
    }
    _atomic_write(
        path,
        (json.dumps(payload, sort_keys=True, indent=2) + "\n").encode(),
        mode=0o640,
        uid=0,
        gid=gid,
    )
    return True


def _install_unit(source: Path, destination: Path) -> None:
    content = source.read_bytes()
    if b"DTLAB_HOST_OT_BIND=127.0.0.1" not in content:
        raise BootstrapError("Unità ingress non vincolata al loopback")
    _atomic_write(destination, content, mode=0o644, uid=0, gid=0)


def _proxy_block() -> str:
    return (
        f"\t{MARKER_START}\n"
        '\t<Location "/api/host-ot/v1/events">\n'
        "\t\tAuthType None\n"
        "\t\tRequire all granted\n"
        "\t\tLimitRequestBody 65536\n"
        "\t</Location>\n"
        '\tProxyPass "/api/host-ot/v1/events" '
        '"http://127.0.0.1:8520/v1/events" retry=0 timeout=15\n'
        '\tProxyPassReverse "/api/host-ot/v1/events" '
        '"http://127.0.0.1:8520/v1/events"\n'
        f"\t{MARKER_END}\n"
    )


def _patched_vhost(content: str) -> str:
    blocks = re.split(r"(?=^<VirtualHost )", content, flags=re.MULTILINE)
    patched_count = 0
    output: list[str] = []
    for block in blocks:
        is_target = (
            block.startswith("<VirtualHost ")
            and ":443>" in block.splitlines()[0]
            and re.search(r"^\s*ServerName\s+modbus\.sitoclone\.it\s*$", block, re.MULTILINE)
        )
        if not is_target or MARKER_START in block:
            output.append(block)
            if is_target and MARKER_START in block:
                patched_count += 1
            continue
        anchor = '\tProxyPass "/_stcore/stream"'
        position = block.find(anchor)
        if position < 0:
            raise BootstrapError("Anchor ProxyPass Streamlit non trovato nel vhost TLS")
        block = block[:position] + _proxy_block() + block[position:]
        patched_count += 1
        output.append(block)
    if patched_count != 2:
        raise BootstrapError(f"Attesi 2 vhost TLS, trovati {patched_count}")
    return "".join(output)


def _install_vhost_proxy() -> bool:
    original = VHOST.read_bytes()
    text = original.decode("utf-8")
    patched = _patched_vhost(text).encode("utf-8")
    if patched == original:
        return False
    metadata = VHOST.stat()
    BACKUP_ROOT.mkdir(parents=True, exist_ok=True)
    os.chmod(BACKUP_ROOT, 0o700)
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    backup = BACKUP_ROOT / f"{timestamp}-{VHOST.name}"
    _atomic_write(backup, original, mode=0o600, uid=0, gid=0)
    _atomic_write(
        VHOST,
        patched,
        mode=stat.S_IMODE(metadata.st_mode),
        uid=metadata.st_uid,
        gid=metadata.st_gid,
    )
    check = _run("apache2ctl", "configtest", check=False)
    if check.returncode:
        _atomic_write(
            VHOST,
            original,
            mode=stat.S_IMODE(metadata.st_mode),
            uid=metadata.st_uid,
            gid=metadata.st_gid,
        )
        raise BootstrapError(f"Apache configtest fallito: {check.stderr.strip()}")
    try:
        _run("systemctl", "reload", "apache2")
    except BootstrapError:
        _atomic_write(
            VHOST,
            original,
            mode=stat.S_IMODE(metadata.st_mode),
            uid=metadata.st_uid,
            gid=metadata.st_gid,
        )
        raise
    return True


def _health(port: int, *, timeout_seconds: float = 10.0) -> dict[str, object]:
    deadline = time.monotonic() + timeout_seconds
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
        try:
            connection.request("GET", "/health")
            response = connection.getresponse()
            body = response.read()
            if response.status != 200:
                raise BootstrapError(f"Health ingress HTTP {response.status}")
            payload = json.loads(body)
            if not isinstance(payload, dict):
                raise BootstrapError("Health ingress non conforme")
            if payload.get("ok") is not True:
                raise BootstrapError("Health ingress non positivo")
            if payload.get("service") != "dtlab-host-ot-ingress":
                raise BootstrapError("Identità health ingress non conforme")
            configured = payload.get("configured_sensors")
            if (
                not isinstance(configured, int)
                or isinstance(configured, bool)
                or configured < 1
            ):
                raise BootstrapError("Health ingress senza sensori configurati")
            return payload
        except (
            OSError,
            TimeoutError,
            http.client.HTTPException,
            json.JSONDecodeError,
            BootstrapError,
        ) as exc:
            last_error = exc
            time.sleep(0.25)
        finally:
            connection.close()
    raise BootstrapError(f"Health ingress non raggiungibile: {last_error}")


def plan(target_name: str) -> dict[str, object]:
    target = TARGETS[target_name]
    release = _release_directory(target["release_link"])
    unit_source = release / "deploy" / target["unit_name"]
    if not unit_source.is_file():
        raise BootstrapError(f"Unità assente nella release: {unit_source}")
    return {
        "target": target_name,
        "release": str(release),
        "unit_source": str(unit_source),
        "unit_destination": f"/etc/systemd/system/{target['unit_name']}",
        "data_directory": str(target["data"]),
        "keyring": str(target["secrets"] / "keyring.json"),
        "ticket_store": str(target["ticket"]),
        "loopback_port": target["port"],
        "apache_proxy": target_name == "production",
    }


def apply(target_name: str) -> dict[str, object]:
    if os.geteuid() != 0:
        raise BootstrapError("Il bootstrap deve essere eseguito come root")
    target = TARGETS[target_name]
    details = plan(target_name)
    web_uid, dashboard_gid = _identity()
    _ensure_directory(target["data"], mode=0o700, uid=web_uid, gid=dashboard_gid)
    _ensure_directory(target["secrets"], mode=0o750, uid=0, gid=dashboard_gid)
    key_created = _keyring(target["secrets"] / "keyring.json", gid=dashboard_gid)
    unit_destination = Path("/etc/systemd/system") / target["unit_name"]
    _install_unit(Path(details["unit_source"]), unit_destination)
    _run("systemctl", "daemon-reload")
    _run("systemctl", "restart", target["unit_name"])
    health = _health(int(target["port"]))
    _run("systemctl", "enable", target["unit_name"])
    apache_changed = _install_vhost_proxy() if target_name == "production" else False
    return {
        **details,
        "applied": True,
        "key_created": key_created,
        "apache_changed": apache_changed,
        "health": health,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Bootstrap DTLab host OT ingress")
    parser.add_argument("target", choices=sorted(TARGETS))
    parser.add_argument("--apply", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        result = apply(args.target) if args.apply else plan(args.target)
    except (BootstrapError, OSError, ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, sort_keys=True))
        return 2
    print(json.dumps({"ok": True, **result}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
