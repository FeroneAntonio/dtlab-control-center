# -*- coding: utf-8 -*-
"""Append-only, hash-chained and HMAC-authenticated local event spool."""

from __future__ import absolute_import

import hashlib
import hmac
import io
import json
import os
import re
import threading
import uuid
from binascii import unhexlify

from dtlab_plc_audit.core import canonical_json, sha256_text, utc_now_text


ENVELOPE_SCHEMA_VERSION = "dtlab-plc-endpoint-envelope-v1"
STATE_SCHEMA_VERSION = "dtlab-plc-endpoint-state-v1"
ZERO_HASH = "0" * 64
_HEX_KEY = re.compile(r"^[0-9a-fA-F]{64,}$")

try:
    _text_type = unicode
except NameError:  # pragma: no cover - Python 3
    _text_type = str


class SpoolError(RuntimeError):
    pass


class SpoolFullError(SpoolError):
    pass


class EnvelopeValidationError(SpoolError):
    pass


def _bytes(value):
    if isinstance(value, bytes):
        return value
    return value.encode("utf-8")


def _unicode(value):
    if isinstance(value, _text_type):
        return value
    return value.decode("ascii")


def _compare_digest(left, right):
    compare = getattr(hmac, "compare_digest", None)
    if compare is not None:
        return bool(compare(left, right))
    if len(left) != len(right):
        return False
    result = 0
    for left_character, right_character in zip(bytearray(left), bytearray(right)):
        result |= left_character ^ right_character
    return result == 0


def load_hmac_key(path):
    with io.open(path, "rb") as handle:
        raw = handle.read().strip()
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError:
        text = ""
    if text and _HEX_KEY.match(text) and len(text) % 2 == 0:
        try:
            raw = unhexlify(text)
        except (TypeError, ValueError):
            raise SpoolError("La chiave HMAC esadecimale non è valida.")
    if len(raw) < 32:
        raise SpoolError("La chiave HMAC deve contenere almeno 32 byte.")
    return raw


def read_boot_id(path="/proc/sys/kernel/random/boot_id"):
    try:
        with io.open(path, "r", encoding="ascii") as handle:
            value = handle.read().strip()
        if value:
            return value
    except (IOError, OSError):
        pass
    return str(uuid.uuid4())


def _atomic_json(path, value, mode=0o600):
    directory = os.path.dirname(os.path.abspath(path))
    if not os.path.isdir(directory):
        os.makedirs(directory)
    temporary = "%s.tmp.%s" % (path, uuid.uuid4().hex)
    try:
        with io.open(temporary, "w", encoding="ascii") as handle:
            handle.write(_unicode(canonical_json(value)))
            handle.write(u"\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        try:
            os.rename(temporary, path)
        except OSError:
            # Python 2 on Windows cannot replace an existing destination.  The
            # production target is Linux, where rename remains atomic.
            if os.name == "nt" and os.path.exists(path):
                os.unlink(path)
                os.rename(temporary, path)
            else:
                raise
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


class StateStore(object):
    """Persist boot identity and episode allocation before an episode is emitted."""

    def __init__(self, path, boot_id=None):
        self.path = path
        self._lock = threading.RLock()
        self.boot_id = str(boot_id or read_boot_id())
        self.next_episode_sequence = 0
        self._load()

    def _load(self):
        if not os.path.exists(self.path):
            self._save()
            return
        try:
            with io.open(self.path, "r", encoding="ascii") as handle:
                value = json.load(handle)
        except (IOError, OSError, ValueError) as exc:
            raise SpoolError("State file non valido: %s" % exc)
        if value.get("schema_version") != STATE_SCHEMA_VERSION:
            raise SpoolError("Versione state file non supportata.")
        stored_boot = str(value.get("boot_id") or "")
        if stored_boot == self.boot_id:
            self.next_episode_sequence = int(value.get("next_episode_sequence", 0))
        else:
            self.next_episode_sequence = 0
            self._save()

    def _save(self):
        _atomic_json(
            self.path,
            {
                "schema_version": STATE_SCHEMA_VERSION,
                "boot_id": self.boot_id,
                "next_episode_sequence": self.next_episode_sequence,
            },
        )

    def allocate_episode_sequence(self):
        with self._lock:
            value = self.next_episode_sequence
            self.next_episode_sequence += 1
            self._save()
            return value


def _unsigned_envelope(event, key_id, previous_hash):
    return {
        "schema_version": ENVELOPE_SCHEMA_VERSION,
        "event": event,
        "integrity": {
            "algorithm": "HMAC-SHA256",
            "key_id": str(key_id),
            "payload_sha256": sha256_text(canonical_json(event)),
            "previous_record_sha256": previous_hash,
        },
    }


def build_envelope(event, key_id, key, previous_hash=ZERO_HASH):
    unsigned = _unsigned_envelope(event, key_id, previous_hash)
    signature = hmac.new(_bytes(key), _bytes(canonical_json(unsigned)), hashlib.sha256).hexdigest()
    with_signature = json.loads(canonical_json(unsigned))
    with_signature["integrity"]["signature"] = signature
    record_hash = sha256_text(canonical_json(with_signature))
    with_signature["integrity"]["record_sha256"] = record_hash
    event_id = str(event["event_id"])
    revision = int(event["revision"])
    with_signature["record_id"] = "%s:r%s:%s" % (event_id, revision, record_hash[:16])
    return with_signature


def verify_envelope(envelope, key, expected_previous_hash=None):
    """Validate payload hash, signature, record hash and optional chain predecessor."""

    if envelope.get("schema_version") != ENVELOPE_SCHEMA_VERSION:
        raise EnvelopeValidationError("Schema envelope non supportato.")
    event = envelope.get("event")
    integrity = envelope.get("integrity")
    if not isinstance(event, dict) or not isinstance(integrity, dict):
        raise EnvelopeValidationError("Envelope incompleto.")
    if integrity.get("algorithm") != "HMAC-SHA256":
        raise EnvelopeValidationError("Algoritmo envelope non supportato.")
    payload_sha = sha256_text(canonical_json(event))
    if not _compare_digest(_bytes(payload_sha), _bytes(str(integrity.get("payload_sha256")))):
        raise EnvelopeValidationError("Hash payload non valido.")
    previous_hash = str(integrity.get("previous_record_sha256") or "")
    if expected_previous_hash is not None and previous_hash != expected_previous_hash:
        raise EnvelopeValidationError("Catena spool interrotta.")

    unsigned = _unsigned_envelope(event, integrity.get("key_id"), previous_hash)
    expected_signature = hmac.new(
        _bytes(key), _bytes(canonical_json(unsigned)), hashlib.sha256
    ).hexdigest()
    if not _compare_digest(
        _bytes(expected_signature), _bytes(str(integrity.get("signature") or ""))
    ):
        raise EnvelopeValidationError("Firma HMAC non valida.")

    with_signature = json.loads(canonical_json(unsigned))
    with_signature["integrity"]["signature"] = expected_signature
    expected_record_hash = sha256_text(canonical_json(with_signature))
    if not _compare_digest(
        _bytes(expected_record_hash), _bytes(str(integrity.get("record_sha256") or ""))
    ):
        raise EnvelopeValidationError("Hash record non valido.")
    expected_record_id = "%s:r%s:%s" % (
        event.get("event_id"),
        event.get("revision"),
        expected_record_hash[:16],
    )
    if str(envelope.get("record_id") or "") != expected_record_id:
        raise EnvelopeValidationError("Record ID envelope non valido.")
    return expected_record_hash


class SignedSpool(object):
    """Append one complete fsync'ed JSON line for every emitted episode revision."""

    def __init__(self, path, key_id, key, max_bytes=50 * 1024 * 1024):
        self.path = path
        self.key_id = str(key_id)
        self.key = key
        self.max_bytes = int(max_bytes)
        self._lock = threading.RLock()
        directory = os.path.dirname(os.path.abspath(path))
        if not os.path.isdir(directory):
            os.makedirs(directory)
        if not os.path.exists(path):
            with io.open(path, "a", encoding="ascii"):
                pass
            os.chmod(path, 0o600)
        self.previous_hash = self._last_record_hash()

    def _last_record_hash(self):
        last = None
        with io.open(self.path, "r", encoding="ascii") as handle:
            for line in handle:
                if line.strip():
                    last = line
        if last is None:
            return ZERO_HASH
        try:
            envelope = json.loads(last)
            return str(envelope["integrity"]["record_sha256"])
        except (KeyError, TypeError, ValueError):
            raise SpoolError("Ultimo record spool non valido; append rifiutato.")

    def append(self, event):
        with self._lock:
            envelope = build_envelope(event, self.key_id, self.key, self.previous_hash)
            line = canonical_json(envelope) + "\n"
            current_size = os.path.getsize(self.path)
            if current_size + len(_bytes(line)) > self.max_bytes:
                raise SpoolFullError("Spool pieno; nessun record è stato eliminato.")
            with io.open(self.path, "a", encoding="ascii") as handle:
                handle.write(_unicode(line))
                handle.flush()
                os.fsync(handle.fileno())
            self.previous_hash = envelope["integrity"]["record_sha256"]
            return envelope


def write_health(path, status, details=None):
    _atomic_json(
        path,
        {
            "schema_version": "dtlab-plc-endpoint-health-v1",
            "status": str(status),
            "observed_at": utc_now_text(),
            "details": details or {},
        },
    )
