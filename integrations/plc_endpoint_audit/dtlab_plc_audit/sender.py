# -*- coding: utf-8 -*-
"""Separate Python 2.7/3 sender for the signed endpoint event spool."""

from __future__ import absolute_import, print_function

import argparse
import hashlib
import hmac
import io
import json
import os
import ssl
import sys
import time
import uuid

try:
    from urllib.error import HTTPError, URLError
    from urllib.request import Request, urlopen
except ImportError:  # pragma: no cover - Python 2.7
    from urllib2 import HTTPError, Request, URLError, urlopen

from dtlab_plc_audit import __version__
from dtlab_plc_audit.core import canonical_json, make_heartbeat, sha256_text, utc_now_text
from dtlab_plc_audit.runtime import load_config
from dtlab_plc_audit.spool import (
    ZERO_HASH,
    EnvelopeValidationError,
    StateStore,
    load_hmac_key,
    verify_envelope,
    write_health,
)


CURSOR_SCHEMA_VERSION = "dtlab-plc-endpoint-sender-cursor-v1"

try:
    _text_type = unicode
except NameError:  # pragma: no cover - Python 3
    _text_type = str


def _bytes(value):
    if isinstance(value, bytes):
        return value
    return value.encode("utf-8")


def _unicode(value):
    if isinstance(value, _text_type):
        return value
    return value.decode("ascii")


def canonical_wire_body(event):
    """Return the exact UTF-8 body authenticated by the site receiver."""

    text = json.dumps(
        event,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ) + "\n"
    return _bytes(text)


def build_http_signature(timestamp, body, key):
    """Implement the receiver contract: HMAC(timestamp + newline + canonical body)."""

    material = _bytes(timestamp) + b"\n" + _bytes(body)
    return hmac.new(_bytes(key), material, hashlib.sha256).hexdigest()


def _atomic_text(path, text):
    directory = os.path.dirname(os.path.abspath(path))
    if not os.path.isdir(directory):
        os.makedirs(directory)
    temporary = "%s.tmp.%s" % (path, uuid.uuid4().hex)
    try:
        with io.open(temporary, "w", encoding="ascii") as handle:
            handle.write(_unicode(text))
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        try:
            os.rename(temporary, path)
        except OSError:
            if os.name == "nt" and os.path.exists(path):
                os.unlink(path)
                os.rename(temporary, path)
            else:
                raise
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


class SenderCursor(object):
    def __init__(self, path):
        self.path = path
        self.offset = 0
        self.previous_record_sha256 = ZERO_HASH
        if os.path.exists(path):
            try:
                with io.open(path, "r", encoding="ascii") as handle:
                    value = json.load(handle)
                if value.get("schema_version") != CURSOR_SCHEMA_VERSION:
                    raise ValueError("versione non supportata")
                self.offset = int(value.get("offset", 0))
                self.previous_record_sha256 = str(
                    value.get("previous_record_sha256") or ZERO_HASH
                )
            except (IOError, OSError, TypeError, ValueError) as exc:
                raise RuntimeError("Cursor sender non valido: %s" % exc)

    def save(self, offset, previous_record_sha256):
        value = {
            "schema_version": CURSOR_SCHEMA_VERSION,
            "offset": int(offset),
            "previous_record_sha256": str(previous_record_sha256),
            "updated_at": utc_now_text(),
        }
        _atomic_text(self.path, canonical_json(value) + "\n")
        self.offset = int(offset)
        self.previous_record_sha256 = str(previous_record_sha256)


def pending_envelopes(spool_path, cursor, key, limit=100):
    """Read complete lines only and verify the chain before yielding records."""

    records = []
    previous_hash = cursor.previous_record_sha256
    with io.open(spool_path, "rb") as handle:
        handle.seek(cursor.offset)
        while len(records) < int(limit):
            line_start = handle.tell()
            line = handle.readline()
            if not line:
                break
            if not line.endswith(b"\n"):
                handle.seek(line_start)
                break
            try:
                envelope = json.loads(line.decode("ascii"))
            except (UnicodeDecodeError, ValueError) as exc:
                raise EnvelopeValidationError("JSON spool non valido: %s" % exc)
            record_hash = verify_envelope(
                envelope,
                key,
                expected_previous_hash=previous_hash,
            )
            previous_hash = record_hash
            records.append((handle.tell(), record_hash, envelope))
    return records


def _ssl_context(ca_file=None):
    if ca_file:
        return ssl.create_default_context(cafile=ca_file)
    return ssl.create_default_context()


def post_event(endpoint_url, event, key_id, key, ca_file=None, timeout=10.0):
    if not endpoint_url.startswith("https://"):
        raise RuntimeError("Il receiver endpoint deve usare HTTPS.")
    body = canonical_wire_body(event)
    timestamp = str(int(time.time()))
    signature = build_http_signature(timestamp, body, key)
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": "DTLabPLCEndpointAudit/%s" % __version__,
        "X-DTLab-Key-Id": str(key_id),
        "X-DTLab-Timestamp": timestamp,
        "X-DTLab-Signature": signature,
    }
    request = Request(endpoint_url, data=body, headers=headers)
    context = _ssl_context(ca_file)
    try:
        response = urlopen(request, timeout=float(timeout), context=context)
    except TypeError:  # pragma: no cover - older Python 2 builds
        response = urlopen(request, timeout=float(timeout))
    try:
        status = getattr(response, "status", None) or response.getcode()
        response.read()
    finally:
        response.close()
    if int(status) < 200 or int(status) >= 300:
        raise RuntimeError("Receiver HTTP status %s" % status)
    return int(status)


def export_event(outbox_directory, event):
    """Atomically export a canonical event for a pull-based collector."""

    if not os.path.isdir(outbox_directory):
        os.makedirs(outbox_directory)
    digest = sha256_text(canonical_json(event))
    filename = "%s-r%s-%s.json" % (
        str(event["event_id"]).replace(":", "_"),
        event["revision"],
        digest[:16],
    )
    destination = os.path.join(outbox_directory, filename)
    content = canonical_json(event) + "\n"
    if os.path.exists(destination):
        with io.open(destination, "r", encoding="ascii") as handle:
            if handle.read() != content:
                raise RuntimeError("Collisione outbox con contenuto differente.")
        return destination
    _atomic_text(destination, content)
    return destination


class EventSender(object):
    def __init__(self, config):
        self.config = dict(config)
        self.key = load_hmac_key(self.config["hmac_key_file"])
        self.cursor = SenderCursor(self.config["sender_cursor_path"])
        self.state = StateStore(self.config["state_path"])
        self.last_heartbeat_epoch = 0.0

    def _deliver(self, event):
        endpoint_url = self.config.get("endpoint_url")
        outbox_directory = self.config.get("outbox_directory")
        if bool(endpoint_url) == bool(outbox_directory):
            raise RuntimeError(
                "Configurare esattamente uno tra endpoint_url e outbox_directory."
            )
        if endpoint_url:
            return post_event(
                str(endpoint_url),
                event,
                self.config["hmac_key_id"],
                self.key,
                ca_file=self.config.get("ca_file"),
                timeout=float(self.config.get("http_timeout_seconds", 10.0)),
            )
        return export_event(str(outbox_directory), event)

    def send_pending(self, limit=100):
        sent = 0
        records = pending_envelopes(
            self.config["spool_path"],
            self.cursor,
            self.key,
            limit=limit,
        )
        for offset, record_hash, envelope in records:
            self._deliver(envelope["event"])
            self.cursor.save(offset, record_hash)
            sent += 1
        return sent

    def send_heartbeat_if_due(self, force=False):
        interval = float(self.config.get("heartbeat_interval_seconds", 30.0))
        now_epoch = time.time()
        if not force and now_epoch - self.last_heartbeat_epoch < interval:
            return False
        sensor_health = self.config["health_path"]
        maximum_age = float(self.config.get("sensor_health_max_age_seconds", 15.0))
        try:
            age = now_epoch - os.path.getmtime(sensor_health)
            with io.open(sensor_health, "r", encoding="ascii") as handle:
                health = json.load(handle)
        except (IOError, OSError, ValueError) as exc:
            raise RuntimeError("Health sensore non leggibile: %s" % exc)
        if health.get("status") != "ready" or age > maximum_age:
            raise RuntimeError("Heartbeat sensore scaduto o in errore; invio rifiutato.")
        local_ips = self.config.get("local_ips") or []
        heartbeat_ip = self.config.get("destination_ip") or (
            local_ips[0] if local_ips else ""
        )
        heartbeat = make_heartbeat(
            self.config["sensor_id"],
            str(self.config.get("sensor_version") or __version__),
            self.state.boot_id,
            heartbeat_ip,
            int(now_epoch * 1000),
        )
        self._deliver(heartbeat)
        self.last_heartbeat_epoch = now_epoch
        return True

    def run_once(self):
        sent = self.send_pending(limit=int(self.config.get("batch_limit", 100)))
        self.send_heartbeat_if_due(force=False)
        write_health(
            self.config["sender_health_path"],
            "ready",
            {"records_sent": sent, "sender_checked_at": utc_now_text()},
        )
        return sent


def _parser():
    parser = argparse.ArgumentParser(description="Invia lo spool firmato del sensore PLC.")
    parser.add_argument("--config", required=True, help="File JSON locale senza segreti.")
    parser.add_argument("--loop", action="store_true", help="Resta attivo come sender sidecar.")
    return parser


def main(argv=None):
    args = _parser().parse_args(argv)
    try:
        config = load_config(args.config)
        sender = EventSender(config)
        if not args.loop:
            sender.run_once()
            return 0
        poll_interval = max(1.0, float(config.get("sender_poll_seconds", 5.0)))
        while True:
            try:
                sender.run_once()
            except (EnvelopeValidationError, HTTPError, URLError, IOError, RuntimeError) as exc:
                write_health(
                    config["sender_health_path"],
                    "error",
                    {"code": "sender_failed", "message": str(exc)},
                )
                print("sender_error: %s" % exc, file=sys.stderr)
            time.sleep(poll_interval)
    except KeyboardInterrupt:
        return 0
    except Exception as exc:
        print("fatal_sender_error: %s" % exc, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
