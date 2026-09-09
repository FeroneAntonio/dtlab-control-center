from __future__ import annotations

from dtlab.ui.live import (
    file_revision,
    manifest_revision,
    refresh_interval_seconds,
    revision_changed,
)


def test_refresh_interval_is_bounded(monkeypatch) -> None:
    monkeypatch.setenv("DTLAB_UI_REFRESH_SECONDS", "1")
    assert refresh_interval_seconds() == 2
    monkeypatch.setenv("DTLAB_UI_REFRESH_SECONDS", "999")
    assert refresh_interval_seconds() == 300
    monkeypatch.setenv("DTLAB_UI_REFRESH_SECONDS", "invalid")
    assert refresh_interval_seconds() == 5


def test_file_revision_tracks_operational_database_changes(tmp_path) -> None:
    database = tmp_path / "tickets.sqlite3"
    assert file_revision(database) == 0
    database.write_bytes(b"first")
    first = file_revision(database)
    assert first > 0
    database.write_bytes(b"second revision")
    assert file_revision(database) >= first


def test_manifest_revision_changes_with_pointer(tmp_path) -> None:
    manifest = tmp_path / "current" / "manifest.json"
    manifest.parent.mkdir(parents=True)
    assert manifest_revision(tmp_path) == 0
    manifest.write_text("{}", encoding="utf-8")
    assert manifest_revision(tmp_path) > 0


def test_revision_detects_staleness_and_fallback_even_with_same_sha() -> None:
    common = {
        "latest_sha256": "a" * 64,
        "displayed_sha256": "a" * 64,
        "displayed_pointer": "current",
        "displayed_state": "fresh",
    }

    assert revision_changed(
        latest_pointer="current",
        latest_state="stale",
        **common,
    )
    assert revision_changed(
        latest_pointer="last_known_good",
        latest_state="fresh",
        **common,
    )
    assert not revision_changed(
        latest_pointer="current",
        latest_state="fresh",
        **common,
    )
