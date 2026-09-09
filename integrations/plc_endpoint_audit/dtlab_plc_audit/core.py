# -*- coding: utf-8 -*-
"""Python 2.7 compatible Modbus write extraction and episode aggregation."""

from __future__ import absolute_import

import copy
import datetime
import hashlib
import json
import time


EVENT_SCHEMA_VERSION = "dtlab-host-ot-event-v1"
SOURCE_ID = "src:dtlab-host-ot:plc-desktop"
GENERIC_RULE_ID = "DTLAB-MODBUS-WRITE-OBSERVED"
SHUTDOWN_RULE_ID = "DTLAB-MODBUS-SHUTDOWN-SEQUENCE"
WRITE_FUNCTION_CODES = frozenset((5, 6, 15, 16, 22, 23))
DEFAULT_MAX_OPERATION_BUCKETS = 64
DEFAULT_MAX_VALUES = 32


def utc_now_text():
    """Return a timezone-explicit UTC timestamp accepted by the site receiver."""

    try:
        now = datetime.datetime.now(datetime.timezone.utc)
    except AttributeError:  # pragma: no cover - Python 2.7
        now = datetime.datetime.utcnow()
    return now.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def canonical_json(value):
    """Return deterministic ASCII JSON on Python 2.7 and Python 3."""

    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def sha256_text(value):
    if not isinstance(value, bytes):
        value = value.encode("utf-8")
    return hashlib.sha256(value).hexdigest()


def _integer(value, default=None):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _bounded_values(values, maximum):
    if values is None:
        return [], False
    if not isinstance(values, (list, tuple)):
        values = [values]
    normalized = []
    for value in values:
        integer = _integer(value)
        if integer is not None:
            normalized.append(integer)
    return normalized[:maximum], len(normalized) > maximum


def extract_modbus_write(request, max_values=DEFAULT_MAX_VALUES):
    """Extract one normalized write from a Pymodbus 2.5.3 request object.

    The function uses only public request attributes and therefore can be unit
    tested without importing Pymodbus.  Unsupported/read-only function codes
    return ``None``.
    """

    function_code = _integer(getattr(request, "function_code", None))
    if function_code not in WRITE_FUNCTION_CODES:
        return None

    unit_id = _integer(getattr(request, "unit_id", None), 0)
    if function_code == 23:
        address = _integer(getattr(request, "write_address", None))
        raw_values = getattr(request, "write_registers", None)
        if raw_values is None:
            raw_values = getattr(request, "values", None)
    else:
        address = _integer(getattr(request, "address", None))
        raw_values = getattr(request, "values", None)
        if raw_values is None and hasattr(request, "value"):
            raw_values = [getattr(request, "value")]

    values, values_truncated = _bounded_values(raw_values, max_values)
    quantity = _integer(getattr(request, "count", None))
    if function_code == 23:
        quantity = _integer(getattr(request, "write_count", None), quantity)
    if quantity is None:
        quantity = len(values) or 1

    full_values = raw_values
    if full_values is None:
        full_values = []
    if not isinstance(full_values, (list, tuple)):
        full_values = [full_values]
    value_fingerprint = sha256_text(canonical_json(list(full_values)))

    return {
        "function_code": function_code,
        "unit_id": unit_id,
        "address": address if address is not None else 0,
        "quantity": max(1, quantity),
        "values": values,
        "values_sha256": value_fingerprint,
        "values_truncated": bool(values_truncated),
    }


def classify_source(source_ip, destination_ip, config):
    """Classify an address without treating an IP as cryptographic identity."""

    source_ip = str(source_ip or "")
    destination_ip = str(destination_ip or "")
    local_ips = set(str(item) for item in config.get("local_ips", []))
    if source_ip and (source_ip == destination_ip or source_ip in local_ips):
        return "plc_self"
    if source_ip in set(str(item) for item in config.get("authorized_hmi_ips", [])):
        return "authorized_hmi"
    if source_ip in set(str(item) for item in config.get("security_test_ips", [])):
        return "security_test"
    return "unknown"


def make_observation(
    request,
    source,
    destination,
    outcome_state,
    config,
    observed_at=None,
    observed_epoch=None,
):
    """Build the small internal observation consumed by :class:`EpisodeAggregator`."""

    operation = extract_modbus_write(
        request,
        max_values=int(config.get("max_values_per_write", DEFAULT_MAX_VALUES)),
    )
    if operation is None:
        return None
    observed_at = observed_at or utc_now_text()
    observed_epoch = time.time() if observed_epoch is None else float(observed_epoch)
    source_ip = str(source.get("ip") or "")
    destination_ip = str(config.get("destination_ip") or destination.get("ip") or "")
    return {
        "observed_at": observed_at,
        "observed_epoch": observed_epoch,
        "source": {
            "ip": source_ip,
            "port": _integer(source.get("port")),
            "classification": classify_source(source_ip, destination_ip, config),
        },
        "destination": {
            "asset_id": str(config.get("destination_asset_id") or ""),
            "ip": destination_ip,
            "port": 502,
            "unit_id": operation["unit_id"],
        },
        "operation": operation,
        "outcome_state": (
            outcome_state
            if outcome_state in ("processed", "rejected", "unknown")
            else "unknown"
        ),
    }


class EpisodeAggregator(object):
    """Aggregate a write storm into stable, incrementally revised episodes."""

    def __init__(
        self,
        sensor_id,
        sensor_version,
        boot_id,
        allocate_sequence,
        emit_interval_seconds=5.0,
        quiet_window_seconds=15.0,
        shutdown_window_seconds=2.0,
        max_operation_buckets=DEFAULT_MAX_OPERATION_BUCKETS,
    ):
        self.sensor_id = str(sensor_id)
        self.sensor_version = str(sensor_version)
        self.boot_id = str(boot_id)
        self.allocate_sequence = allocate_sequence
        self.emit_interval_seconds = float(emit_interval_seconds)
        self.quiet_window_seconds = float(quiet_window_seconds)
        self.shutdown_window_seconds = float(shutdown_window_seconds)
        self.max_operation_buckets = int(max_operation_buckets)
        self._episodes = {}

    @staticmethod
    def _episode_key(observation):
        source = observation["source"]
        destination = observation["destination"]
        return (
            source.get("ip"),
            source.get("port"),
            destination.get("ip"),
            destination.get("port"),
            destination.get("unit_id"),
        )

    def _new_episode(self, observation):
        sequence = int(self.allocate_sequence())
        identity = "%s|%s|%s" % (self.sensor_id, self.boot_id, sequence)
        episode_id = "episode:dtlab-host-ot:%s" % sha256_text(identity)
        return {
            "episode_id": episode_id,
            "episode_sequence": sequence,
            "revision": 0,
            "first_observed_at": observation["observed_at"],
            "last_observed_at": observation["observed_at"],
            "first_epoch": observation["observed_epoch"],
            "last_epoch": observation["observed_epoch"],
            "last_emit_epoch": None,
            "source": copy.deepcopy(observation["source"]),
            "destination": copy.deepcopy(observation["destination"]),
            "function_codes": set(),
            "writes": {},
            "request_count": 0,
            "dropped_operation_buckets": 0,
            "outcome_states": {"processed": 0, "rejected": 0, "unknown": 0},
            "last_outcome_state": "unknown",
            "shutdown_seen": {},
            "shutdown": False,
            "dirty": False,
        }

    @staticmethod
    def _write_key(operation):
        return (
            operation["function_code"],
            operation["address"],
            operation["quantity"],
            operation["values_sha256"],
        )

    def _update_shutdown_correlation(self, episode, operation, now_epoch):
        if operation["function_code"] != 6 or operation["quantity"] != 1:
            return False
        if len(operation["values"]) != 1 or operation["values"][0] != 0:
            return False
        address = operation["address"]
        if address not in (3, 4, 16):
            return False
        episode["shutdown_seen"][address] = now_epoch
        if set(episode["shutdown_seen"]) != set((3, 4, 16)):
            return False
        timestamps = [episode["shutdown_seen"][item] for item in (3, 4, 16)]
        matched = max(timestamps) - min(timestamps) <= self.shutdown_window_seconds
        was_shutdown = episode["shutdown"]
        episode["shutdown"] = bool(matched)
        return episode["shutdown"] and not was_shutdown

    def _update_episode(self, episode, observation):
        operation = observation["operation"]
        now_epoch = observation["observed_epoch"]
        episode["last_observed_at"] = observation["observed_at"]
        episode["last_epoch"] = now_epoch
        episode["request_count"] += 1
        episode["function_codes"].add(operation["function_code"])
        outcome_state = observation["outcome_state"]
        episode["outcome_states"][outcome_state] += 1
        episode["last_outcome_state"] = outcome_state

        key = self._write_key(operation)
        bucket = episode["writes"].get(key)
        if bucket is None:
            if len(episode["writes"]) >= self.max_operation_buckets:
                episode["dropped_operation_buckets"] += 1
            else:
                bucket = {
                    "function_code": operation["function_code"],
                    "address": operation["address"],
                    "quantity": operation["quantity"],
                    "values": list(operation["values"]),
                    "values_sha256": operation["values_sha256"],
                    "values_truncated": operation["values_truncated"],
                    "count": 0,
                }
                episode["writes"][key] = bucket
        if bucket is not None:
            bucket["count"] += 1

        escalated = self._update_shutdown_correlation(episode, operation, now_epoch)
        episode["dirty"] = True
        return escalated

    def _render(self, episode):
        episode["revision"] += 1
        episode["last_emit_epoch"] = episode["last_epoch"]
        episode["dirty"] = False
        shutdown = episode["shutdown"]
        outcome_state = episode["last_outcome_state"]
        if outcome_state == "processed":
            truth = "endpoint_server_processed"
        elif outcome_state == "rejected":
            truth = "endpoint_server_rejected"
        else:
            truth = "endpoint_request_observed"
        rule_id = SHUTDOWN_RULE_ID if shutdown else GENERIC_RULE_ID
        classification = "process_shutdown_sequence" if shutdown else "modbus_write"
        severity = "critical" if shutdown else "high"
        priority = "p1" if shutdown else "p2"
        reason = (
            "FC06 3=0, 4=0 e 16=0 osservati nella finestra di correlazione."
            if shutdown
            else "Scrittura Modbus/TCP osservata dal sensore endpoint PLC."
        )
        writes = list(episode["writes"].values())
        writes.sort(
            key=lambda item: (
                item["function_code"],
                item["address"],
                item["quantity"],
                item["values_sha256"],
            )
        )
        event_id = episode["episode_id"]
        return {
            "schema_version": EVENT_SCHEMA_VERSION,
            "event_type": "modbus_write",
            "event_id": event_id,
            "episode_id": event_id,
            "revision": episode["revision"],
            "episode_sequence": episode["episode_sequence"],
            "boot_id": self.boot_id,
            "first_observed_at": episode["first_observed_at"],
            "last_observed_at": episode["last_observed_at"],
            "timestamp_basis": "endpoint_utc",
            "sensor": {
                "id": self.sensor_id,
                "version": self.sensor_version,
                "capture_kind": "server_hook",
            },
            "source": copy.deepcopy(episode["source"]),
            "destination": copy.deepcopy(episode["destination"]),
            "modbus": {
                "operation": "write",
                "function_codes": sorted(episode["function_codes"]),
                "writes": writes,
                "request_count": episode["request_count"],
                "dropped_operation_buckets": episode["dropped_operation_buckets"],
            },
            "outcome": {
                "states": copy.deepcopy(episode["outcome_states"]),
                "last_state": outcome_state,
            },
            "detection": {
                "rule_id": rule_id,
                "classification": classification,
                "severity": severity,
                "priority": priority,
                "policy_decision": "alert",
                "reason": reason,
            },
            "evidence": {
                "truth": truth,
                "source_id": SOURCE_ID,
                "source_record_id": event_id,
                "notes": [
                    "Evidenza prodotta dal sensore endpoint PLC, non da Cisco Cyber Vision.",
                    "L'indirizzo IP non identifica il processo o l'intento dell'operatore.",
                ],
            },
            "process": None,
        }

    def observe(self, observation):
        """Consume one normalized observation and return zero or more event revisions."""

        emitted = self.flush_expired(observation["observed_epoch"])
        key = self._episode_key(observation)
        episode = self._episodes.get(key)
        if episode is None:
            episode = self._new_episode(observation)
            self._episodes[key] = episode
        escalated = self._update_episode(episode, observation)
        due = (
            episode["last_emit_epoch"] is None
            or observation["observed_epoch"] - episode["last_emit_epoch"]
            >= self.emit_interval_seconds
        )
        if due or escalated:
            emitted.append(self._render(episode))
        return emitted

    def flush_expired(self, now_epoch=None):
        """Flush and close episodes quiet for longer than the configured window."""

        now_epoch = time.time() if now_epoch is None else float(now_epoch)
        emitted = []
        expired = []
        for key, episode in list(self._episodes.items()):
            if now_epoch - episode["last_epoch"] < self.quiet_window_seconds:
                continue
            if episode["dirty"]:
                emitted.append(self._render(episode))
            expired.append(key)
        for key in expired:
            del self._episodes[key]
        return emitted

    def flush_source(self, source_ip, source_port):
        """Flush episodes associated with a closing TCP peer."""

        emitted = []
        matched = []
        for key, episode in list(self._episodes.items()):
            if key[0] == source_ip and key[1] == source_port:
                if episode["dirty"]:
                    emitted.append(self._render(episode))
                matched.append(key)
        for key in matched:
            del self._episodes[key]
        return emitted

    def flush_all(self):
        emitted = []
        for episode in list(self._episodes.values()):
            if episode["dirty"]:
                emitted.append(self._render(episode))
        self._episodes = {}
        return emitted


def make_heartbeat(sensor_id, sensor_version, boot_id, source_ip, sequence, observed_at=None):
    """Build one receiver-compatible endpoint heartbeat."""

    observed_at = observed_at or utc_now_text()
    identity = "%s|%s|heartbeat|%s" % (sensor_id, boot_id, sequence)
    episode_id = "episode:dtlab-host-ot:%s" % sha256_text(identity)
    return {
        "schema_version": EVENT_SCHEMA_VERSION,
        "event_type": "heartbeat",
        "event_id": episode_id,
        "episode_id": episode_id,
        "revision": 1,
        "episode_sequence": int(sequence),
        "boot_id": str(boot_id),
        "first_observed_at": observed_at,
        "last_observed_at": observed_at,
        "timestamp_basis": "endpoint_utc",
        "sensor": {
            "id": str(sensor_id),
            "version": str(sensor_version),
            "capture_kind": "server_hook",
        },
        "source": {
            "ip": str(source_ip or ""),
            "port": None,
            "classification": "plc_self",
        },
        "destination": None,
        "modbus": None,
        "outcome": None,
        "detection": None,
        "evidence": {
            "truth": "endpoint_heartbeat",
            "source_id": SOURCE_ID,
            "source_record_id": episode_id,
            "notes": ["Heartbeat del sensore endpoint PLC; non è un evento Cisco."],
        },
        "process": None,
    }
