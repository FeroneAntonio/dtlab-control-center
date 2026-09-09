"""Validated dashboard context loaded only from the trusted collector store."""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from dtlab.contract import (
    effective_sync_state,
    snapshot_age_seconds,
    with_stale_truth,
)
from dtlab.services.snapshot_store import AtomicSnapshotStore


def default_store_path() -> Path:
    configured = os.environ.get("DTLAB_SNAPSHOT_STORE")
    if configured:
        return Path(configured).expanduser().resolve()
    return Path(__file__).resolve().parents[3] / "runtime" / "store"


@dataclass(frozen=True)
class DashboardContext:
    canonical_snapshot: dict[str, Any]
    snapshot: dict[str, Any]
    manifest: dict[str, Any]
    pointer: str
    effective_state: str
    age_seconds: int
    loaded_at: datetime

    @property
    def sources_by_type(self) -> dict[str, dict[str, Any]]:
        return {source["type"]: source for source in self.snapshot["sources"]}

    @property
    def cybervision_source(self) -> dict[str, Any] | None:
        return self.sources_by_type.get("cisco_cyber_vision")

    @property
    def cybervision_new_ui_source(self) -> dict[str, Any] | None:
        return self.sources_by_type.get("cisco_cyber_vision_new_ui")

    @property
    def esxi_source(self) -> dict[str, Any] | None:
        return self.sources_by_type.get("vmware_esxi")

    @property
    def cybervision_available(self) -> bool:
        source = self.cybervision_source
        return bool(source and source["status"] in {"connected", "degraded", "stale"})

    def cybervision_capability_available(self, name: str) -> bool:
        source = self.cybervision_source or {}
        status = source.get("capabilities", {}).get(name, {}).get("status")
        return status in {"available", "partial", "truncated"}


def load_dashboard_context(
    store_path: str | Path | None = None,
    *,
    now: datetime | None = None,
) -> DashboardContext:
    loaded_at = now or datetime.now(UTC)
    stored = AtomicSnapshotStore(
        store_path or default_store_path(),
        create_layout=False,
    ).load_best_available()
    state = effective_sync_state(stored.snapshot, now=loaded_at)
    snapshot = with_stale_truth(stored.snapshot, now=loaded_at)
    return DashboardContext(
        canonical_snapshot=stored.snapshot,
        snapshot=snapshot,
        manifest=stored.manifest,
        pointer=stored.pointer,
        effective_state=state,
        age_seconds=snapshot_age_seconds(stored.snapshot, now=loaded_at),
        loaded_at=loaded_at,
    )
