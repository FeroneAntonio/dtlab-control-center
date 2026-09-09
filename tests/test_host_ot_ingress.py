from __future__ import annotations

import base64
import hashlib
import hmac
import json
import subprocess
from pathlib import Path

import pytest

import deploy.host_ot_server_bootstrap as bootstrap
from deploy.host_ot_server_bootstrap import MARKER_START, BootstrapError, _patched_vhost
from dtlab.services.host_ot_events import canonical_host_ot_event_bytes
from dtlab.services.host_ot_ingress import (
    HostOtIngressApplication,
    HostOtIngressConfig,
    HostOtIngressError,
    load_sensor_keys,
    verify_request_auth,
)
from dtlab.services.host_ot_status import load_sensor_statuses, sensor_coverage
from dtlab.services.ticket_store import TicketStore
from tests.test_host_ot_events import heartbeat_event, host_event

_SECRET = bytes(range(32))
_KEY_ID = "plc-desktop-v1"
_SENSOR_ID = "plc-endpoint-sensor"
_NOW = 1_788_259_200


def _write_keyring(path) -> None:
    path.write_text(
        json.dumps(
            {
                "keys": [
                    {
                        "key_id": _KEY_ID,
                        "sensor_id": _SENSOR_ID,
                        "secret_base64": base64.b64encode(_SECRET).decode("ascii"),
                    }
                ]
            }
        ),
        encoding="utf-8",
    )


def _headers(body: bytes, *, timestamp: int = _NOW) -> dict[str, str]:
    timestamp_text = str(timestamp)
    signature = hmac.new(
        _SECRET,
        timestamp_text.encode("ascii") + b"\n" + body,
        hashlib.sha256,
    ).hexdigest()
    return {
        "x-dtlab-key-id": _KEY_ID,
        "x-dtlab-timestamp": timestamp_text,
        "x-dtlab-signature": signature,
    }


def test_keyring_and_request_auth_bind_key_to_sensor(tmp_path) -> None:
    keyring = tmp_path / "keyring.json"
    _write_keyring(keyring)
    keys = load_sensor_keys(keyring)
    body = b"{}\n"

    authenticated = verify_request_auth(
        body=body,
        key_id=_KEY_ID,
        timestamp=str(_NOW),
        signature=_headers(body)["x-dtlab-signature"],
        keys=keys,
        now=_NOW,
    )

    assert authenticated.sensor_id == _SENSOR_ID
    with pytest.raises(HostOtIngressError, match="fuori tolleranza"):
        verify_request_auth(
            body=body,
            key_id=_KEY_ID,
            timestamp=str(_NOW - 301),
            signature=_headers(body, timestamp=_NOW - 301)["x-dtlab-signature"],
            keys=keys,
            now=_NOW,
        )


def test_authenticated_event_is_durable_and_creates_one_idempotent_ticket(
    tmp_path, monkeypatch
) -> None:
    keyring = tmp_path / "keyring.json"
    _write_keyring(keyring)
    config = HostOtIngressConfig(
        bind="127.0.0.1",
        port=0,
        key_file=keyring,
        object_store=tmp_path / "events",
        ticket_store=tmp_path / "tickets.sqlite3",
    )
    application = HostOtIngressApplication(config)
    event = host_event()
    body = canonical_host_ot_event_bytes(event)
    monkeypatch.setattr("dtlab.services.host_ot_ingress.time.time", lambda: _NOW)
    monkeypatch.setattr("dtlab.services.host_ot_status.time.time", lambda: _NOW)

    first, first_created = application.accept(body, _headers(body))
    second, second_created = application.accept(body, _headers(body))

    assert first_created is True
    assert second_created is False
    assert first["sha256"] == second["sha256"]
    assert (config.object_store / "objects" / f"{first['sha256']}.json").read_bytes() == body
    store = TicketStore(config.ticket_store)
    assert len(store.list_signals(signal_type="host_modbus_write")) == 1
    assert len(store.list_tickets()) == 1
    statuses = load_sensor_statuses(config.object_store)
    assert len(statuses) == 1
    assert statuses[0]["sensor_id"] == _SENSOR_ID
    assert statuses[0]["event_type"] == "modbus_write"
    assert statuses[0]["document_sha256"] == first["sha256"]
    assert sensor_coverage(statuses[0], now_epoch=_NOW)["coverage_state"] == "active"


def test_authenticated_heartbeat_updates_coverage_without_creating_ticket(
    tmp_path, monkeypatch
) -> None:
    keyring = tmp_path / "keyring.json"
    _write_keyring(keyring)
    config = HostOtIngressConfig(
        bind="127.0.0.1",
        port=0,
        key_file=keyring,
        object_store=tmp_path / "events",
        ticket_store=tmp_path / "tickets.sqlite3",
    )
    application = HostOtIngressApplication(config)
    event = heartbeat_event()
    body = canonical_host_ot_event_bytes(event)
    monkeypatch.setattr("dtlab.services.host_ot_ingress.time.time", lambda: _NOW)
    monkeypatch.setattr("dtlab.services.host_ot_status.time.time", lambda: _NOW)

    payload, created = application.accept(body, _headers(body))

    assert created is True
    assert payload["result"]["event_type"] == "heartbeat"
    assert TicketStore(config.ticket_store).list_tickets() == []
    statuses = load_sensor_statuses(config.object_store)
    assert len(statuses) == 1
    assert statuses[0]["event_type"] == "heartbeat"
    assert statuses[0]["truth"] == "endpoint_heartbeat"


def test_receiver_rejects_tampering_noncanonical_json_and_sensor_spoof(
    tmp_path, monkeypatch
) -> None:
    keyring = tmp_path / "keyring.json"
    _write_keyring(keyring)
    application = HostOtIngressApplication(
        HostOtIngressConfig(
            bind="127.0.0.1",
            port=0,
            key_file=keyring,
            object_store=tmp_path / "events",
            ticket_store=tmp_path / "tickets.sqlite3",
        )
    )
    monkeypatch.setattr("dtlab.services.host_ot_ingress.time.time", lambda: _NOW)
    event = host_event()
    canonical = canonical_host_ot_event_bytes(event)

    tampered_headers = _headers(canonical)
    tampered_headers["x-dtlab-signature"] = "0" * 64
    with pytest.raises(HostOtIngressError, match="Firma HMAC"):
        application.accept(canonical, tampered_headers)

    noncanonical = json.dumps(event, indent=2).encode("utf-8")
    with pytest.raises(HostOtIngressError, match="JSON canonico"):
        application.accept(noncanonical, _headers(noncanonical))

    event["sensor"]["id"] = "spoofed-sensor"
    spoofed = canonical_host_ot_event_bytes(event)
    with pytest.raises(HostOtIngressError, match="sensor_id"):
        application.accept(spoofed, _headers(spoofed))


@pytest.mark.parametrize(
    ("name", "port", "release_link"),
    [
        ("modbus-dashboard-host-ot-ingress.service", "8520", "modbus-dashboard-current"),
        (
            "modbus-dashboard-host-ot-ingress-staging.service",
            "8521",
            "modbus-dashboard-staging-current",
        ),
    ],
)
def test_ingress_systemd_units_are_loopback_only_and_hardened(
    name: str, port: str, release_link: str
) -> None:
    project_root = Path(__file__).resolve().parents[1]
    content = (project_root / "deploy" / name).read_text(encoding="utf-8")

    assert "Environment=DTLAB_HOST_OT_BIND=127.0.0.1" in content
    assert f"Environment=DTLAB_HOST_OT_PORT={port}" in content
    assert f"private/{release_link}/src" in content
    assert "NoNewPrivileges=true" in content
    assert "ProtectSystem=strict" in content
    assert "ReadWritePaths=" in content
    assert "Restart=on-failure" in content


@pytest.mark.parametrize(
    ("name", "event_store"),
    [
        ("modbus-dashboard-v2.service", "modbus-dashboard-host-ot-data"),
        (
            "modbus-dashboard-v2-staging.service",
            "modbus-dashboard-host-ot-data-staging",
        ),
    ],
)
def test_dashboard_units_receive_read_only_host_sensor_coverage(
    name: str, event_store: str
) -> None:
    project_root = Path(__file__).resolve().parents[1]
    content = (project_root / "deploy" / name).read_text(encoding="utf-8")

    path = f"/var/www/clients/client1/web75/private/{event_store}"
    assert f"Environment=DTLAB_HOST_OT_EVENT_STORE={path}" in content
    assert f"ReadOnlyPaths=-{path}" in content


def test_apache_patch_targets_both_tls_vhosts_and_is_idempotent() -> None:
    block = """<VirtualHost {address}:443>
\tServerName modbus.sitoclone.it
\t<Location \"/\">\n\t\tAuthType Basic\n\t\tRequire valid-user\n\t</Location>
\tProxyPass \"/_stcore/stream\" \"ws://127.0.0.1:8517/_stcore/stream\"
\tProxyPass \"/\" \"http://127.0.0.1:8517/\"
</VirtualHost>
"""
    original = block.format(address="162.55.0.81") + block.format(address="[::1]")

    first = _patched_vhost(original)
    second = _patched_vhost(first)

    assert first.count(MARKER_START) == 2
    assert first.count('ProxyPass "/api/host-ot/v1/events"') == 2
    assert first == second
    assert first.index('ProxyPass "/api/host-ot/v1/events"') < first.index(
        'ProxyPass "/"'
    )


def test_ingress_health_retries_until_exact_service_identity(monkeypatch) -> None:
    payloads = [
        {"ok": True},
        {
            "ok": True,
            "service": "dtlab-host-ot-ingress",
            "configured_sensors": 1,
        },
    ]

    class Response:
        status = 200

        def __init__(self, payload: dict[str, object]) -> None:
            self.payload = payload

        def read(self) -> bytes:
            return json.dumps(self.payload).encode("utf-8")

    class Connection:
        def __init__(self, *_args, **_kwargs) -> None:
            pass

        def request(self, *_args, **_kwargs) -> None:
            pass

        def getresponse(self) -> Response:
            return Response(payloads.pop(0))

        def close(self) -> None:
            pass

    monkeypatch.setattr(bootstrap.http.client, "HTTPConnection", Connection)
    monkeypatch.setattr(bootstrap.time, "sleep", lambda _seconds: None)

    result = bootstrap._health(8521, timeout_seconds=1)

    assert result["service"] == "dtlab-host-ot-ingress"
    assert payloads == []


def test_bootstrap_restarts_and_verifies_before_enabling(monkeypatch) -> None:
    operations: list[tuple[str, ...]] = []
    target = bootstrap.TARGETS["staging"]
    details = {
        "target": "staging",
        "release": "/release",
        "unit_source": "/release/deploy/unit.service",
        "unit_destination": "/etc/systemd/system/unit.service",
        "data_directory": str(target["data"]),
        "keyring": str(target["secrets"] / "keyring.json"),
        "ticket_store": str(target["ticket"]),
        "loopback_port": target["port"],
        "apache_proxy": False,
    }
    monkeypatch.setattr(bootstrap.os, "geteuid", lambda: 0, raising=False)
    monkeypatch.setattr(bootstrap, "plan", lambda _target: details)
    monkeypatch.setattr(bootstrap, "_identity", lambda: (75, 750))
    monkeypatch.setattr(bootstrap, "_ensure_directory", lambda *args, **kwargs: None)
    monkeypatch.setattr(bootstrap, "_keyring", lambda *args, **kwargs: False)
    monkeypatch.setattr(bootstrap, "_install_unit", lambda *args, **kwargs: None)

    def record_run(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        operations.append(args)
        return subprocess.CompletedProcess(args, 0, "", "")

    def record_health(_port: int) -> dict[str, object]:
        operations.append(("health",))
        return {
            "ok": True,
            "service": "dtlab-host-ot-ingress",
            "configured_sensors": 1,
        }

    monkeypatch.setattr(bootstrap, "_run", record_run)
    monkeypatch.setattr(bootstrap, "_health", record_health)

    bootstrap.apply("staging")

    assert operations == [
        ("systemctl", "daemon-reload"),
        ("systemctl", "restart", target["unit_name"]),
        ("health",),
        ("systemctl", "enable", target["unit_name"]),
    ]


def test_bootstrap_command_failures_are_reported_as_domain_errors(monkeypatch) -> None:
    def fail(*_args, **_kwargs):
        raise subprocess.CalledProcessError(7, ("systemctl", "restart"), stderr="boom")

    monkeypatch.setattr(bootstrap.subprocess, "run", fail)

    with pytest.raises(BootstrapError, match="systemctl restart: boom"):
        bootstrap._run("systemctl", "restart")
