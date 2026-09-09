# -*- coding: utf-8 -*-
"""Configuration and event emission runtime shared by the Pymodbus hook."""

from __future__ import absolute_import

import io
import json
import logging
import threading
import time

from dtlab_plc_audit import __version__
from dtlab_plc_audit.core import EpisodeAggregator, make_observation
from dtlab_plc_audit.spool import SignedSpool, StateStore, load_hmac_key, write_health


_LOGGER = logging.getLogger(__name__)


def load_config(path):
    with io.open(path, "r", encoding="utf-8") as handle:
        value = json.load(handle)
    required = (
        "sensor_id",
        "destination_asset_id",
        "destination_ip",
        "local_ips",
        "hmac_key_id",
        "hmac_key_file",
        "spool_path",
        "state_path",
        "health_path",
        "sender_health_path",
        "sender_cursor_path",
    )
    missing = [name for name in required if not value.get(name)]
    if missing:
        raise ValueError("Configurazione incompleta: %s" % ", ".join(missing))
    if not isinstance(value.get("local_ips"), list) or not value["local_ips"]:
        raise ValueError("local_ips deve contenere almeno un indirizzo del PLC.")
    if bool(value.get("endpoint_url")) == bool(value.get("outbox_directory")):
        raise ValueError(
            "Configurare esattamente uno tra endpoint_url e outbox_directory."
        )
    return value


def _endpoint(address):
    return {
        "ip": str(getattr(address, "host", "") or ""),
        "port": getattr(address, "port", None),
    }


class AuditRuntime(object):
    """Convert decoded requests to signed episode revisions without blocking Modbus."""

    def __init__(self, config):
        self.config = dict(config)
        self.state = StateStore(self.config["state_path"])
        self.key = load_hmac_key(self.config["hmac_key_file"])
        self.spool = SignedSpool(
            self.config["spool_path"],
            self.config["hmac_key_id"],
            self.key,
            max_bytes=int(self.config.get("max_spool_bytes", 50 * 1024 * 1024)),
        )
        self.aggregator = EpisodeAggregator(
            sensor_id=self.config["sensor_id"],
            sensor_version=str(self.config.get("sensor_version") or __version__),
            boot_id=self.state.boot_id,
            allocate_sequence=self.state.allocate_episode_sequence,
            emit_interval_seconds=float(self.config.get("emit_interval_seconds", 30.0)),
            quiet_window_seconds=float(self.config.get("quiet_window_seconds", 15.0)),
            shutdown_window_seconds=float(self.config.get("shutdown_window_seconds", 2.0)),
            max_operation_buckets=int(self.config.get("max_operation_buckets", 64)),
        )
        self._lock = threading.RLock()
        self._last_health_epoch = 0.0
        self._failure_code = None
        self._last_event_id = None
        self._touch_health(force=True)

    def _touch_health(self, force=False, details=None):
        now_epoch = time.time()
        interval = float(self.config.get("hook_health_interval_seconds", 5.0))
        if self._failure_code is not None:
            return
        if force or now_epoch - self._last_health_epoch >= interval:
            current_details = dict(details or {})
            if self._last_event_id is not None:
                current_details["last_event_id"] = self._last_event_id
            write_health(self.config["health_path"], "ready", current_details)
            self._last_health_epoch = now_epoch

    def _append_events(self, events):
        for event in events:
            self.spool.append(event)
        if events:
            self._failure_code = None
            self._last_event_id = events[-1]["event_id"]
            self._touch_health(
                force=True,
            )

    def observe(self, request, response, peer, local, outcome_state=None):
        """Observe one decoded request.  Exceptions are raised to the hook logger."""

        if outcome_state is None:
            outcome_state = "unknown"
            try:
                outcome_state = "rejected" if response.isError() else "processed"
            except (AttributeError, TypeError):
                pass
        observation = make_observation(
            request,
            _endpoint(peer),
            _endpoint(local),
            outcome_state,
            self.config,
        )
        if observation is None:
            return 0
        with self._lock:
            events = self.aggregator.observe(observation)
            self._append_events(events)
        return len(events)

    def flush_expired(self):
        with self._lock:
            events = self.aggregator.flush_expired(time.time())
            self._append_events(events)
            self._touch_health()
        return len(events)

    def flush_peer(self, peer):
        endpoint = _endpoint(peer)
        with self._lock:
            events = self.aggregator.flush_source(endpoint["ip"], endpoint["port"])
            self._append_events(events)
        return len(events)

    def flush_all(self):
        with self._lock:
            events = self.aggregator.flush_all()
            self._append_events(events)
        return len(events)

    def report_failure(self, code, message):
        _LOGGER.error("PLC endpoint audit failure [%s]: %s", code, message)
        self._failure_code = str(code)
        try:
            write_health(
                self.config["health_path"],
                "error",
                {"code": str(code), "message": str(message)},
            )
        except Exception:
            _LOGGER.exception("Impossibile aggiornare il file health del sensore.")


def runtime_from_file(path):
    return AuditRuntime(load_config(path))
