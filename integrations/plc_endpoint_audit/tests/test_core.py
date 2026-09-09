from __future__ import annotations

import itertools
import unittest

from dtlab_plc_audit.core import (
    EpisodeAggregator,
    classify_source,
    extract_modbus_write,
    make_heartbeat,
    make_observation,
)


class FakeRequest:
    def __init__(
        self,
        *,
        function_code: int,
        address: int = 0,
        value: int | None = None,
        values: list[int] | None = None,
        unit_id: int = 0,
    ) -> None:
        self.function_code = function_code
        self.address = address
        self.unit_id = unit_id
        if value is not None:
            self.value = value
        if values is not None:
            self.values = values
            self.count = len(values)


CONFIG = {
    "destination_asset_id": "asset:plc",
    "destination_ip": "172.16.10.10",
    "local_ips": ["127.0.0.1", "172.16.10.10"],
    "authorized_hmi_ips": ["172.16.10.20"],
    "security_test_ips": ["172.16.10.30"],
}


class CoreTests(unittest.TestCase):
    def test_extracts_fc06_and_ignores_read(self) -> None:
        write = extract_modbus_write(FakeRequest(function_code=6, address=16, value=0))
        assert write is not None
        self.assertEqual(write["function_code"], 6)
        self.assertEqual(write["address"], 16)
        self.assertEqual(write["quantity"], 1)
        self.assertEqual(write["values"], [0])
        self.assertIsNone(extract_modbus_write(FakeRequest(function_code=3)))

    def test_source_classification_is_explicit(self) -> None:
        self.assertEqual(classify_source("172.16.10.10", "172.16.10.10", CONFIG), "plc_self")
        self.assertEqual(
            classify_source("172.16.10.20", "172.16.10.10", CONFIG),
            "authorized_hmi",
        )
        self.assertEqual(
            classify_source("172.16.10.30", "172.16.10.10", CONFIG),
            "security_test",
        )
        self.assertEqual(classify_source("172.16.10.99", "172.16.10.10", CONFIG), "unknown")

    def _observation(self, address: int, value: int, epoch: float):
        return make_observation(
            FakeRequest(function_code=6, address=address, value=value),
            {"ip": "172.16.10.10", "port": 41000},
            {"ip": "0.0.0.0", "port": 502},
            "processed",
            CONFIG,
            observed_at="2026-09-01T10:00:%06.3fZ" % (epoch - 100.0),
            observed_epoch=epoch,
        )

    def test_shutdown_sequence_escalates_same_episode(self) -> None:
        sequences = itertools.count()
        aggregator = EpisodeAggregator(
            "sensor:plc",
            "1.0.0",
            "boot-test",
            lambda: next(sequences),
            emit_interval_seconds=5,
            quiet_window_seconds=15,
            shutdown_window_seconds=2,
        )

        first = aggregator.observe(self._observation(3, 0, 100.0))
        second = aggregator.observe(self._observation(4, 0, 100.1))
        third = aggregator.observe(self._observation(16, 0, 100.2))

        self.assertEqual(len(first), 1)
        self.assertEqual(second, [])
        self.assertEqual(len(third), 1)
        self.assertEqual(first[0]["event_id"], third[0]["event_id"])
        self.assertEqual(first[0]["revision"], 1)
        self.assertEqual(third[0]["revision"], 2)
        self.assertEqual(first[0]["detection"]["severity"], "high")
        self.assertEqual(third[0]["detection"]["severity"], "critical")
        self.assertEqual(third[0]["detection"]["priority"], "p1")
        self.assertEqual(
            third[0]["detection"]["classification"],
            "process_shutdown_sequence",
        )
        self.assertEqual(third[0]["modbus"]["request_count"], 3)
        self.assertEqual(sum(item["count"] for item in third[0]["modbus"]["writes"]), 3)
        self.assertEqual(third[0]["evidence"]["truth"], "endpoint_server_processed")
        self.assertEqual(third[0]["source"]["classification"], "plc_self")
        self.assertEqual(third[0]["destination"]["ip"], "172.16.10.10")

    def test_shutdown_requires_values_inside_window(self) -> None:
        sequences = itertools.count()
        aggregator = EpisodeAggregator(
            "sensor:plc",
            "1.0.0",
            "boot-test",
            lambda: next(sequences),
            quiet_window_seconds=30,
            shutdown_window_seconds=2,
        )
        aggregator.observe(self._observation(3, 0, 100.0))
        aggregator.observe(self._observation(4, 0, 103.0))
        emitted = aggregator.observe(self._observation(16, 0, 104.0))
        self.assertFalse(any(item["detection"]["severity"] == "critical" for item in emitted))

    def test_quiet_episode_flushes_one_final_revision(self) -> None:
        sequences = itertools.count()
        aggregator = EpisodeAggregator(
            "sensor:plc",
            "1.0.0",
            "boot-test",
            lambda: next(sequences),
            emit_interval_seconds=60,
            quiet_window_seconds=5,
        )
        first = aggregator.observe(self._observation(3, 1, 100.0))[0]
        aggregator.observe(self._observation(3, 1, 101.0))
        final = aggregator.flush_expired(106.1)
        self.assertEqual(len(final), 1)
        self.assertEqual(final[0]["event_id"], first["event_id"])
        self.assertEqual(final[0]["revision"], 2)
        self.assertEqual(final[0]["modbus"]["request_count"], 2)
        self.assertEqual(aggregator.flush_expired(120.0), [])

    def test_heartbeat_has_no_detection_or_modbus_claim(self) -> None:
        heartbeat = make_heartbeat(
            "sensor:plc",
            "1.0.0",
            "boot-test",
            "172.16.10.10",
            42,
            observed_at="2026-09-01T10:00:00.000000Z",
        )
        self.assertEqual(heartbeat["event_type"], "heartbeat")
        self.assertIsNone(heartbeat["destination"])
        self.assertIsNone(heartbeat["modbus"])
        self.assertIsNone(heartbeat["detection"])
        self.assertEqual(heartbeat["event_id"], heartbeat["episode_id"])
        self.assertEqual(heartbeat["event_id"], heartbeat["evidence"]["source_record_id"])


if __name__ == "__main__":
    unittest.main()

