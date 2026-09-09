"""Tests for the operational workflow API (signals + tickets) over the reused engine."""

from __future__ import annotations


def test_signals_ingested_from_snapshot(client, auth) -> None:
    body = client.get("/api/signals", headers=auth()).json()
    assert body["count"] == 7  # 3 events + 2 vulns + 1 finding + 1 baseline diff
    kinds = {s["signal_type"] for s in body["items"]}
    assert {"event", "vulnerability", "finding", "baseline_difference"} <= kinds
    assert all("ticket_state" in s for s in body["items"])


def test_signals_requires_auth(client) -> None:
    assert client.get("/api/signals").status_code == 401


def test_ticketing_policy_and_summary(client, auth) -> None:
    policy = client.get("/api/ticketing/policy", headers=auth()).json()
    assert "p1" in policy["priorities"]
    assert policy["sla_hours"]["p1"] < policy["sla_hours"]["p4"]
    summary = client.get("/api/ticketing/summary", headers=auth()).json()
    assert summary["signals"] == 7


def test_viewer_cannot_create_ticket(client, auth) -> None:
    signal_id = client.get("/api/signals", headers=auth()).json()["items"][0]["id"]
    res = client.post(f"/api/signals/{signal_id}/ticket", json={}, headers=auth("viewer"))
    assert res.status_code == 403


def test_full_ticket_workflow(client, auth) -> None:
    # pick a signal without a ticket yet
    signals = client.get("/api/signals", headers=auth()).json()["items"]
    signal = next(s for s in signals if s["ticket_state"] == "unassigned")

    created = client.post(
        f"/api/signals/{signal['id']}/ticket",
        json={"priority": "p2", "owner": "SOC"},
        headers=auth("analyst"),
    )
    assert created.status_code == 200
    ticket_id = created.json()["id"]

    # detail carries the full workspace document
    document = client.get(f"/api/tickets/{ticket_id}", headers=auth()).json()
    assert document["ticket"]["priority"] == "p2"
    assert document["ticket"]["sla"]["state"] in {"on_time", "due_soon", "overdue", "stopped"}
    assert "tasks" in document and "audit" in document and "comments" in document
    assert document["tasks"], "la checklist manual-first deve essere inizializzata"

    # transition with a note
    moved = client.post(
        f"/api/tickets/{ticket_id}/transition",
        json={"target": "investigating", "note": "Preso in carico."},
        headers=auth("analyst"),
    )
    assert moved.status_code == 200
    assert moved.json()["status"] == "investigating"

    # comment
    commented = client.post(
        f"/api/tickets/{ticket_id}/comments",
        json={"body": "Analisi avviata."},
        headers=auth("analyst"),
    )
    assert commented.status_code == 200

    # audit grew, export works
    document = client.get(f"/api/tickets/{ticket_id}", headers=auth()).json()
    assert len(document["audit"]) >= 2
    export = client.get(f"/api/tickets/{ticket_id}/export", headers=auth())
    assert export.status_code == 200
    assert export.headers["content-type"].startswith("application/json")


def test_tickets_list_and_summary_reflect_creation(client, auth) -> None:
    # after the workflow test at least one ticket exists
    tickets = client.get("/api/tickets", headers=auth()).json()
    assert tickets["count"] >= 1
    assert all("sla" in t for t in tickets["items"])
