"""Near-real-time snapshot watcher for active Streamlit sessions."""

from __future__ import annotations

import os
from datetime import UTC, datetime
from pathlib import Path

import streamlit as st

from dtlab.services.snapshot_store import AtomicSnapshotStore, SnapshotStoreError
from dtlab.ui.components import format_age


def refresh_interval_seconds() -> int:
    """Return a bounded UI polling interval from the runtime configuration."""

    raw = os.environ.get("DTLAB_UI_REFRESH_SECONDS", "5")
    try:
        value = int(raw)
    except ValueError:
        return 5
    return min(max(value, 2), 300)


def file_revision(path: str | Path) -> int:
    """Return a cheap revision marker for an operational data file."""

    try:
        return Path(path).stat().st_mtime_ns
    except OSError:
        return 0


def manifest_revision(store_path: str | Path) -> int:
    """Return a cache key that changes whenever the current pointer changes."""

    path = Path(store_path) / "current" / "manifest.json"
    try:
        return path.stat().st_mtime_ns
    except OSError:
        return 0


def revision_changed(
    latest_sha256: str,
    latest_pointer: str,
    latest_state: str,
    *,
    displayed_sha256: str,
    displayed_pointer: str,
    displayed_state: str,
) -> bool:
    """Detect data, fallback-pointer, and freshness-state changes independently."""

    return (latest_sha256, latest_pointer, latest_state) != (
        displayed_sha256,
        displayed_pointer,
        displayed_state,
    )


@st.fragment(run_every=f"{refresh_interval_seconds()}s")
def render_live_watcher(
    store_path: str,
    displayed_sha256: str,
    displayed_pointer: str,
    displayed_state: str,
    completed_at: str,
    max_age_seconds: int,
    collected_state: str,
    ticket_store_path: str = "",
    displayed_ticket_revision: int = 0,
) -> None:
    """Poll small pointer metadata and rerun only when data or freshness changes."""

    store = AtomicSnapshotStore(store_path, create_layout=False)
    try:
        latest_manifest = store.probe_manifest("current")
    except SnapshotStoreError:
        if displayed_pointer == "current":
            # The full rerun tries trusted fallback pointers and otherwise enters the
            # fail-closed path.  Never leave a broken current state labelled as live.
            st.rerun()
        latest_sha256 = displayed_sha256
        latest_pointer = displayed_pointer
    else:
        latest_sha256 = str(latest_manifest["sha256"])
        latest_pointer = "current"

    try:
        completed = datetime.fromisoformat(completed_at.replace("Z", "+00:00")).astimezone(UTC)
    except (TypeError, ValueError):
        st.rerun()
    age_seconds = max(0, int((datetime.now(UTC) - completed).total_seconds()))
    latest_state = collected_state
    if latest_state not in {"offline", "failed", "stale"} and age_seconds > max_age_seconds:
        latest_state = "stale"

    snapshot_changed = revision_changed(
        latest_sha256,
        latest_pointer,
        latest_state,
        displayed_sha256=displayed_sha256,
        displayed_pointer=displayed_pointer,
        displayed_state=displayed_state,
    )
    ticket_changed = bool(ticket_store_path) and file_revision(
        ticket_store_path
    ) != displayed_ticket_revision
    if snapshot_changed or ticket_changed:
        st.rerun()

    interval = refresh_interval_seconds()
    st.caption(
        f":material/sync: Auto-refresh {interval}s · dato di {format_age(age_seconds)} fa"
    )
