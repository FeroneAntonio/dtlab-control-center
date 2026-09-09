"""Loads and caches the canonical v3 snapshot the API serves.

The provider is the single seam between the HTTP layer and the data plane. Today
it serves the deterministic sandbox fixture or a v3 JSON file; in Fase 5 the same
seam will read verified snapshots from the operational store without changing any
router.
"""

from __future__ import annotations

import threading
from datetime import UTC, datetime
from typing import Any

from dtlab import contract_v3
from dtlab.sandbox import build_sandbox_snapshot
from dtlab.services.history_store import derive_metrics


class SnapshotProvider:
    def __init__(self, source: str = "sandbox") -> None:
        self._source = source
        self._lock = threading.Lock()
        self._snapshot: dict[str, Any] = {}
        self._sha256: str = ""
        self._loaded_at: str = ""
        self.reload()

    def reload(self) -> None:
        snapshot = self._build()
        sha = contract_v3.snapshot_sha256_v3(snapshot)
        with self._lock:
            self._snapshot = snapshot
            self._sha256 = sha
            self._loaded_at = datetime.now(UTC).isoformat().replace("+00:00", "Z")

    def _build(self) -> dict[str, Any]:
        if self._source == "sandbox":
            return build_sandbox_snapshot()
        return contract_v3.load_snapshot_v3(self._source)

    @property
    def snapshot(self) -> dict[str, Any]:
        return self._snapshot

    @property
    def source(self) -> str:
        return self._source

    def collection(self, name: str) -> list[dict[str, Any]]:
        value = self._snapshot.get(name, [])
        return value if isinstance(value, list) else []

    def find(self, collection: str, record_id: str) -> dict[str, Any] | None:
        for record in self.collection(collection):
            if record.get("id") == record_id:
                return record
        return None

    def meta(self) -> dict[str, Any]:
        snap = self._snapshot
        collections = [
            "sources", "virtual_machines", "networks", "assets", "identity_links",
            "risk_scores", "activities", "flows", "events", "vulnerabilities",
            "baselines", "baseline_differences", "sensors", "reports", "findings",
            "attack_scenarios", "attack_runs", "detection_correlations",
            "process_telemetry", "security_zones", "compliance_mappings",
        ]
        return {
            "snapshot_id": snap.get("snapshot_id"),
            "schema_version": snap.get("schema_version"),
            "generated_at": snap.get("generated_at"),
            "source": self._source,
            "content_sha256": self._sha256,
            "loaded_at": self._loaded_at,
            "sync": snap.get("sync"),
            "environment": {
                "id": snap.get("environment", {}).get("id"),
                "name": snap.get("environment", {}).get("name"),
                "kind": snap.get("environment", {}).get("kind"),
                "status": snap.get("environment", {}).get("status"),
            },
            "counts": {name: len(snap.get(name, [])) for name in collections},
        }

    def metrics(self) -> dict[str, Any]:
        return derive_metrics(self._snapshot)
