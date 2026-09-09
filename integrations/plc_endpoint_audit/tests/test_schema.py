from __future__ import annotations

import json
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

from dtlab_plc_audit.core import EpisodeAggregator, make_heartbeat, make_observation

from test_core import CONFIG, FakeRequest


ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads(
    (ROOT / "schemas" / "dtlab-host-ot-event-v1.schema.json").read_text(encoding="utf-8")
)


class SchemaTests(unittest.TestCase):
    def _validator(self):
        return Draft202012Validator(SCHEMA, format_checker=FormatChecker())

    def test_generic_write_and_heartbeat_validate(self) -> None:
        sequence = iter(range(10))
        aggregator = EpisodeAggregator(
            "sensor:plc",
            "1.0.0",
            "boot-test",
            lambda: next(sequence),
        )
        observation = make_observation(
            FakeRequest(function_code=6, address=3, value=1),
            {"ip": "172.16.10.10", "port": 41000},
            {"ip": "172.16.10.10", "port": 502},
            "processed",
            CONFIG,
            observed_at="2026-09-01T10:00:00.000000Z",
            observed_epoch=100.0,
        )
        write = aggregator.observe(observation)[0]
        heartbeat = make_heartbeat(
            "sensor:plc",
            "1.0.0",
            "boot-test",
            "172.16.10.10",
            100,
            observed_at="2026-09-01T10:00:00.000000Z",
        )
        self.assertEqual(list(self._validator().iter_errors(write)), [])
        self.assertEqual(list(self._validator().iter_errors(heartbeat)), [])

    def test_schema_rejects_cisco_truth_label(self) -> None:
        heartbeat = make_heartbeat(
            "sensor:plc",
            "1.0.0",
            "boot-test",
            "172.16.10.10",
            100,
            observed_at="2026-09-01T10:00:00.000000Z",
        )
        heartbeat["evidence"]["truth"] = "real"
        self.assertTrue(list(self._validator().iter_errors(heartbeat)))


if __name__ == "__main__":
    unittest.main()
