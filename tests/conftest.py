from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def isolate_default_ticket_store(tmp_path, monkeypatch) -> None:
    """Keep UI tests from sharing or mutating the developer's operational database."""

    monkeypatch.setenv(
        "DTLAB_TICKET_STORE",
        str(tmp_path / "default-ticket-store" / "tickets.sqlite3"),
    )
