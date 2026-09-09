from __future__ import annotations

import copy
import hashlib
import hmac
import json
import tempfile
import unittest
from pathlib import Path

from dtlab_plc_audit.core import make_heartbeat
from dtlab_plc_audit.sender import (
    SenderCursor,
    build_http_signature,
    canonical_wire_body,
    export_event,
    pending_envelopes,
)
from dtlab_plc_audit.spool import (
    EnvelopeValidationError,
    SignedSpool,
    StateStore,
    verify_envelope,
)


KEY = b"k" * 32


def event(sequence: int = 1, revision: int = 1):
    value = make_heartbeat(
        "sensor:plc",
        "1.0.0",
        "boot-test",
        "172.16.10.10",
        sequence,
        observed_at="2026-09-01T10:00:00.000000Z",
    )
    value["revision"] = revision
    return value


class SpoolSenderTests(unittest.TestCase):
    def test_state_sequence_is_persisted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "state.json"
            first = StateStore(str(path), boot_id="boot-test")
            self.assertEqual(first.allocate_episode_sequence(), 0)
            self.assertEqual(first.allocate_episode_sequence(), 1)
            second = StateStore(str(path), boot_id="boot-test")
            self.assertEqual(second.allocate_episode_sequence(), 2)

    def test_signed_spool_chain_and_tamper_detection(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "events.jsonl"
            spool = SignedSpool(str(path), "key-v1", KEY)
            first = spool.append(event(1))
            second = spool.append(event(2))

            first_hash = verify_envelope(first, KEY, expected_previous_hash="0" * 64)
            self.assertEqual(
                verify_envelope(second, KEY, expected_previous_hash=first_hash),
                second["integrity"]["record_sha256"],
            )

            tampered = copy.deepcopy(second)
            tampered["event"]["source"]["ip"] = "172.16.10.99"
            with self.assertRaises(EnvelopeValidationError):
                verify_envelope(tampered, KEY, expected_previous_hash=first_hash)

    def test_cursor_reads_only_verified_pending_records(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            spool_path = root / "events.jsonl"
            cursor_path = root / "cursor.json"
            spool = SignedSpool(str(spool_path), "key-v1", KEY)
            spool.append(event(1))
            spool.append(event(2))
            cursor = SenderCursor(str(cursor_path))

            records = pending_envelopes(str(spool_path), cursor, KEY)
            self.assertEqual(len(records), 2)
            offset, record_hash, _ = records[0]
            cursor.save(offset, record_hash)
            remaining = pending_envelopes(str(spool_path), cursor, KEY)
            self.assertEqual(len(remaining), 1)
            self.assertEqual(remaining[0][2]["event"]["episode_sequence"], 2)

    def test_http_body_and_signature_match_receiver_contract(self) -> None:
        value = event(1)
        value["evidence"]["notes"].append("verifica UTF-8: qualità")
        body = canonical_wire_body(value)
        self.assertTrue(body.endswith(b"\n"))
        self.assertIn("qualità".encode(), body)
        self.assertNotIn(b"qualit\\u00e0", body)
        timestamp = "1788256800"
        expected = hmac.new(KEY, timestamp.encode() + b"\n" + body, hashlib.sha256).hexdigest()
        self.assertEqual(build_http_signature(timestamp, body, KEY), expected)

    def test_outbox_export_is_deterministic_and_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            value = event(1)
            first = export_event(temporary, value)
            second = export_event(temporary, value)
            self.assertEqual(first, second)
            exported = json.loads(Path(first).read_text(encoding="ascii"))
            self.assertEqual(exported, value)


if __name__ == "__main__":
    unittest.main()

