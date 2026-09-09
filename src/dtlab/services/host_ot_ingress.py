"""Authenticated, write-only HTTP ingress for PLC host-side detections.

The service deliberately lives outside Streamlit.  Apache terminates TLS and
proxies only the dedicated write-only path to this loopback listener.  Every
accepted body is kept content-addressed before it is converted into an
operational signal and reconciled to an automatic ticket.

Authentication is HMAC-SHA256 over ``<unix timestamp>\n<raw body>``.  A key file
binds each key id to exactly one sensor id, so a valid PLC key cannot claim to be
Cisco Cyber Vision or another endpoint.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import tempfile
import time
from dataclasses import asdict, dataclass, is_dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from dtlab.services.host_ot_events import (
    canonical_host_ot_event_bytes,
    ingest_host_ot_event,
)
from dtlab.services.host_ot_status import (
    load_sensor_statuses,
    sensor_coverage,
    store_sensor_status,
)
from dtlab.services.ticket_store import TicketStore, TicketStoreError

DEFAULT_MAX_BODY_BYTES = 65_536
DEFAULT_MAX_CLOCK_SKEW_SECONDS = 300


class HostOtIngressError(RuntimeError):
    """A request cannot be accepted as trusted endpoint evidence."""


@dataclass(frozen=True, slots=True)
class SensorKey:
    key_id: str
    sensor_id: str
    secret: bytes


@dataclass(frozen=True, slots=True)
class HostOtIngressConfig:
    bind: str
    port: int
    key_file: Path
    object_store: Path
    ticket_store: Path
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES
    max_clock_skew_seconds: int = DEFAULT_MAX_CLOCK_SKEW_SECONDS


def _required_text(value: object, label: str, *, max_length: int = 256) -> str:
    text = str(value or "").strip()
    if not text or len(text) > max_length:
        raise HostOtIngressError(f"{label} non valido")
    return text


def load_sensor_keys(path: str | Path) -> dict[str, SensorKey]:
    """Load a root-owned JSON keyring without accepting weak shared secrets."""

    key_path = Path(path)
    try:
        payload = json.loads(key_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise HostOtIngressError("Keyring sensori non leggibile") from exc
    records = payload.get("keys") if isinstance(payload, dict) else None
    if not isinstance(records, list) or not records:
        raise HostOtIngressError("Il keyring non contiene chiavi sensore")
    result: dict[str, SensorKey] = {}
    for record in records:
        if not isinstance(record, dict):
            raise HostOtIngressError("Record keyring non valido")
        key_id = _required_text(record.get("key_id"), "key_id", max_length=128)
        sensor_id = _required_text(record.get("sensor_id"), "sensor_id", max_length=128)
        encoded = _required_text(
            record.get("secret_base64"), "secret_base64", max_length=1024
        )
        try:
            secret = base64.b64decode(encoded, validate=True)
        except (ValueError, TypeError) as exc:
            raise HostOtIngressError("Chiave sensore non codificata in base64") from exc
        if len(secret) < 32:
            raise HostOtIngressError("La chiave sensore deve contenere almeno 256 bit")
        if key_id in result:
            raise HostOtIngressError("key_id duplicato nel keyring")
        result[key_id] = SensorKey(key_id=key_id, sensor_id=sensor_id, secret=secret)
    return result


def verify_request_auth(
    *,
    body: bytes,
    key_id: object,
    timestamp: object,
    signature: object,
    keys: dict[str, SensorKey],
    now: int | None = None,
    max_clock_skew_seconds: int = DEFAULT_MAX_CLOCK_SKEW_SECONDS,
) -> SensorKey:
    """Verify timestamp and request HMAC, returning the bound sensor identity."""

    normalized_key_id = _required_text(key_id, "X-DTLab-Key-Id", max_length=128)
    sensor_key = keys.get(normalized_key_id)
    if sensor_key is None:
        raise HostOtIngressError("Credenziale sensore non riconosciuta")
    timestamp_text = _required_text(timestamp, "X-DTLab-Timestamp", max_length=20)
    try:
        timestamp_value = int(timestamp_text)
    except ValueError as exc:
        raise HostOtIngressError("Timestamp firma non valido") from exc
    reference = int(time.time()) if now is None else int(now)
    if abs(reference - timestamp_value) > max_clock_skew_seconds:
        raise HostOtIngressError("Timestamp firma fuori tolleranza")
    supplied = _required_text(signature, "X-DTLab-Signature", max_length=128).lower()
    if len(supplied) != 64 or any(char not in "0123456789abcdef" for char in supplied):
        raise HostOtIngressError("Firma HMAC non valida")
    signed = timestamp_text.encode("ascii") + b"\n" + body
    expected = hmac.new(sensor_key.secret, signed, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(supplied, expected):
        raise HostOtIngressError("Firma HMAC non valida")
    return sensor_key


def _atomic_store_body(object_store: Path, body: bytes) -> tuple[str, bool]:
    digest = hashlib.sha256(body).hexdigest()
    objects = object_store / "objects"
    objects.mkdir(parents=True, exist_ok=True, mode=0o700)
    destination = objects / f"{digest}.json"
    if destination.exists():
        if destination.read_bytes() != body:
            raise HostOtIngressError("Collisione nel content-addressed event store")
        return digest, False
    descriptor, temporary_name = tempfile.mkstemp(prefix=".event-", dir=objects)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(body)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)
    return digest, True


def _jsonable(value: object) -> object:
    if is_dataclass(value):
        return asdict(value)
    if isinstance(value, dict):
        return value
    if value is None or isinstance(value, (str, int, float, bool, list, tuple)):
        return value
    return str(value)


class HostOtIngressApplication:
    """Small request application independent from the HTTP transport."""

    def __init__(self, config: HostOtIngressConfig) -> None:
        self.config = config
        self.keys = load_sensor_keys(config.key_file)
        self.ticket_store = TicketStore(config.ticket_store)

    def health(self) -> dict[str, object]:
        configured_sensor_ids = {key.sensor_id for key in self.keys.values()}
        statuses = [
            sensor_coverage(status)
            for status in load_sensor_statuses(self.config.object_store)
            if status.get("sensor_id") in configured_sensor_ids
        ]
        return {
            "ok": True,
            "service": "dtlab-host-ot-ingress",
            "configured_sensors": len(self.keys),
            "sensors": statuses,
        }

    def accept(self, body: bytes, headers: dict[str, str]) -> tuple[dict[str, object], bool]:
        if not body or len(body) > self.config.max_body_bytes:
            raise HostOtIngressError("Dimensione evento non valida")
        sensor_key = verify_request_auth(
            body=body,
            key_id=headers.get("x-dtlab-key-id"),
            timestamp=headers.get("x-dtlab-timestamp"),
            signature=headers.get("x-dtlab-signature"),
            keys=self.keys,
            max_clock_skew_seconds=self.config.max_clock_skew_seconds,
        )
        try:
            event = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise HostOtIngressError("Il body non è JSON UTF-8 valido") from exc
        if not isinstance(event, dict):
            raise HostOtIngressError("L'evento deve essere un oggetto JSON")
        sensor = event.get("sensor") if isinstance(event.get("sensor"), dict) else {}
        if str(sensor.get("id") or "") != sensor_key.sensor_id:
            raise HostOtIngressError("sensor_id non coerente con la chiave usata")

        canonical_body = canonical_host_ot_event_bytes(event)
        if body != canonical_body:
            raise HostOtIngressError("Il body deve usare il JSON canonico DTLab")
        digest, created = _atomic_store_body(self.config.object_store, canonical_body)
        # The valid authenticated document is durable before ticket mutation.  A
        # temporary SQLite failure therefore becomes a safe, idempotent sender retry.
        result = ingest_host_ot_event(
            self.ticket_store,
            event,
            document_sha256=digest,
        )
        store_sensor_status(
            self.config.object_store,
            sensor_id=sensor_key.sensor_id,
            event=event,
            document_sha256=digest,
        )
        return {
            "ok": True,
            "sha256": digest,
            "stored": created,
            "result": _jsonable(result),
        }, created


class _RequestHandler(BaseHTTPRequestHandler):
    server_version = "DTLabHostOTIngress/1"

    @property
    def application(self) -> HostOtIngressApplication:
        return self.server.application  # type: ignore[attr-defined, no-any-return]

    def _send_json(self, status: HTTPStatus, payload: dict[str, object]) -> None:
        body = (json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")
        self.send_response(status.value)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        if self.path != "/health":
            self._send_json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "not_found"})
            return
        self._send_json(HTTPStatus.OK, self.application.health())

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/v1/events":
            self._send_json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "not_found"})
            return
        if self.headers.get_content_type() != "application/json":
            self._send_json(
                HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
                {"ok": False, "error": "content_type_must_be_application_json"},
            )
            return
        try:
            content_length = int(self.headers.get("Content-Length") or "")
        except ValueError:
            content_length = -1
        if content_length < 1 or content_length > self.application.config.max_body_bytes:
            self._send_json(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                {"ok": False, "error": "invalid_content_length"},
            )
            return
        body = self.rfile.read(content_length)
        headers = {name.lower(): value for name, value in self.headers.items()}
        try:
            payload, created = self.application.accept(body, headers)
        except HostOtIngressError as exc:
            self._send_json(HTTPStatus.UNAUTHORIZED, {"ok": False, "error": str(exc)})
            return
        except (OSError, ValueError, TicketStoreError) as exc:
            self._send_json(
                HTTPStatus.UNPROCESSABLE_ENTITY,
                {"ok": False, "error": str(exc)},
            )
            return
        self._send_json(HTTPStatus.CREATED if created else HTTPStatus.OK, payload)

    def log_message(self, format: str, *args: object) -> None:
        # Do not log bodies, signatures or key ids.  systemd captures this concise line.
        print(f"host_ot_ingress remote={self.client_address[0]} {format % args}", flush=True)


class HostOtIngressServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, config: HostOtIngressConfig) -> None:
        self.application = HostOtIngressApplication(config)
        super().__init__((config.bind, config.port), _RequestHandler)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="DTLab authenticated PLC host-event ingress")
    parser.add_argument("--bind", default=os.environ.get("DTLAB_HOST_OT_BIND", "127.0.0.1"))
    parser.add_argument(
        "--port", type=int, default=int(os.environ.get("DTLAB_HOST_OT_PORT", "8520"))
    )
    parser.add_argument("--key-file", default=os.environ.get("DTLAB_HOST_OT_KEY_FILE"))
    parser.add_argument("--object-store", default=os.environ.get("DTLAB_HOST_OT_EVENT_STORE"))
    parser.add_argument("--ticket-store", default=os.environ.get("DTLAB_TICKET_STORE"))
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    missing = [
        name
        for name, value in (
            ("key-file", args.key_file),
            ("object-store", args.object_store),
            ("ticket-store", args.ticket_store),
        )
        if not value
    ]
    if missing:
        raise SystemExit(f"Configurazione mancante: {', '.join(missing)}")
    config = HostOtIngressConfig(
        bind=args.bind,
        port=args.port,
        key_file=Path(args.key_file).resolve(),
        object_store=Path(args.object_store).resolve(),
        ticket_store=Path(args.ticket_store).resolve(),
    )
    server = HostOtIngressServer(config)
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
