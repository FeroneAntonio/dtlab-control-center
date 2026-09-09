"""Durable coverage status for authenticated PLC endpoint sensors."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import time
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

STATUS_SCHEMA_VERSION = "dtlab-host-ot-status-v1"
DEFAULT_STALE_AFTER_SECONDS = 120


def _utc_text(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, UTC).isoformat().replace("+00:00", "Z")


def _status_path(object_store: Path, sensor_id: str) -> Path:
    digest = hashlib.sha256(sensor_id.encode("utf-8")).hexdigest()
    return object_store / "status" / f"{digest}.json"


def store_sensor_status(
    object_store: str | Path,
    *,
    sensor_id: str,
    event: Mapping[str, Any],
    document_sha256: str,
    received_at_epoch: float | None = None,
) -> dict[str, object]:
    """Atomically persist only the liveness metadata of one accepted event."""

    received_epoch = time.time() if received_at_epoch is None else received_at_epoch
    evidence = event.get("evidence")
    evidence_record = evidence if isinstance(evidence, Mapping) else {}
    status: dict[str, object] = {
        "schema_version": STATUS_SCHEMA_VERSION,
        "sensor_id": sensor_id,
        "received_at": _utc_text(float(received_epoch)),
        "event_type": str(event.get("event_type") or ""),
        "event_id": str(event.get("event_id") or ""),
        "last_observed_at": str(event.get("last_observed_at") or ""),
        "truth": str(evidence_record.get("truth") or ""),
        "document_sha256": document_sha256,
    }
    destination = _status_path(Path(object_store), sensor_id)
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    content = (
        json.dumps(status, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")
    descriptor, temporary_name = tempfile.mkstemp(prefix=".status-", dir=destination.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)
    return status


def load_sensor_statuses(object_store: str | Path) -> list[dict[str, object]]:
    """Read valid status records; corrupt or foreign files never become coverage claims."""

    status_root = Path(object_store) / "status"
    if not status_root.is_dir() or status_root.is_symlink():
        return []
    records: list[dict[str, object]] = []
    for path in sorted(status_root.glob("*.json")):
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            continue
        if (
            not isinstance(value, dict)
            or value.get("schema_version") != STATUS_SCHEMA_VERSION
            or not str(value.get("sensor_id") or "").strip()
            or not str(value.get("received_at") or "").strip()
        ):
            continue
        records.append(value)
    return records


def sensor_coverage(
    status: Mapping[str, object],
    *,
    now_epoch: float | None = None,
    stale_after_seconds: int = DEFAULT_STALE_AFTER_SECONDS,
) -> dict[str, object]:
    """Add a fail-closed active/stale state to a persisted status record."""

    received_text = str(status.get("received_at") or "")
    try:
        received_at = datetime.fromisoformat(received_text.replace("Z", "+00:00"))
        received_epoch = received_at.timestamp()
    except (ValueError, OverflowError):
        received_epoch = 0.0
    reference = time.time() if now_epoch is None else float(now_epoch)
    age_seconds = max(0, int(reference - received_epoch)) if received_epoch else None
    active = age_seconds is not None and age_seconds <= stale_after_seconds
    return {
        **status,
        "coverage_state": "active" if active else "stale",
        "age_seconds": age_seconds,
        "stale_after_seconds": stale_after_seconds,
    }
