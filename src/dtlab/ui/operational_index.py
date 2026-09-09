"""Pure operational projections shared by the dashboard and Asset 360.

The immutable snapshot remains the source of technical evidence.  This module only
joins it with the persistent analyst workflow using explicit signal and ticket IDs.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import Any

import pandas as pd

from dtlab.services.ticket_store import derive_ticket_sla
from dtlab.ui.views.operations import signal_is_actionable, signal_needs_review

TERMINAL_TICKET_STATES = frozenset(
    {"closed", "false_positive", "accepted_risk", "suppressed"}
)

_PRIORITY_RANK = {"p1": 0, "p2": 1, "p3": 2, "p4": 3}
_SEVERITY_RANK = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
    "unknown": 5,
}


def _timestamp_rank(value: object) -> int:
    parsed = pd.to_datetime(value, utc=True, errors="coerce")
    return 0 if pd.isna(parsed) else -int(parsed.value)


def build_operational_index(
    signals: Sequence[Mapping[str, Any]],
    tickets: Sequence[Mapping[str, Any]],
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Return a deterministic, ticket-first queue without inventing correlations."""

    evaluated_at = now or datetime.now(UTC)
    if evaluated_at.tzinfo is None:
        raise ValueError("now deve includere il fuso orario")

    ticket_by_signal = {str(ticket["signal_id"]): dict(ticket) for ticket in tickets}
    active_tickets = [
        dict(ticket)
        for ticket in tickets
        if str(ticket.get("status")) not in TERMINAL_TICKET_STATES
    ]
    sla_by_ticket: dict[str, dict[str, Any]] = {
        str(ticket["id"]): derive_ticket_sla(ticket, now=evaluated_at)
        for ticket in tickets
    }
    queue: list[dict[str, Any]] = []
    all_signals = [dict(signal) for signal in signals]
    actionable = [signal for signal in all_signals if signal_is_actionable(signal)]

    for signal in all_signals:
        signal_id = str(signal["id"])
        ticket = ticket_by_signal.get(signal_id)
        actionable_signal = signal_is_actionable(signal)
        active_ticket = bool(
            ticket and str(ticket.get("status")) not in TERMINAL_TICKET_STATES
        )
        if not actionable_signal and not active_ticket:
            continue
        needs_review = actionable_signal and signal_needs_review(signal, ticket)
        if not needs_review and not active_ticket:
            continue

        sla = sla_by_ticket.get(str(ticket["id"])) if ticket else None
        sla_state = str(sla.get("state")) if sla else None
        priority = str(ticket.get("priority")) if ticket else None
        severity = str(signal.get("severity") or "unknown").lower()
        resurfaced = bool(ticket and needs_review)
        if active_ticket and sla_state == "overdue":
            queue_rank = 0
        elif resurfaced:
            queue_rank = 1
        elif active_ticket and sla_state == "due_soon" and priority in {"p1", "p2"}:
            queue_rank = 2
        elif ticket is None and severity in {"critical", "high"}:
            queue_rank = 3
        elif active_ticket and not ticket.get("owner"):
            queue_rank = 4
        elif active_ticket:
            queue_rank = 5
        else:
            queue_rank = 6

        queue.append(
            {
                "signal_id": signal_id,
                "ticket_id": str(ticket["id"]) if ticket else None,
                "title": str(signal.get("title") or "Segnalazione senza titolo"),
                "description": str(signal.get("description") or ""),
                "signal_type": str(signal.get("signal_type") or "unknown"),
                "severity": severity,
                "priority": priority,
                "status": str(ticket.get("status")) if ticket else "da_valutare",
                "owner": ticket.get("owner") if ticket else None,
                "sla_state": sla_state,
                "sla_due_at": sla.get("due_at") if sla else None,
                "asset_ids": list(signal.get("asset_ids") or []),
                "recommended_action": signal.get("recommended_action"),
                "occurrence_count": int(signal.get("occurrence_count") or 1),
                "resurfaced": resurfaced,
                "needs_review": needs_review,
                "last_observed_at": signal.get("last_observed_at"),
                "queue_rank": queue_rank,
            }
        )

    queue.sort(
        key=lambda item: (
            int(item["queue_rank"]),
            _PRIORITY_RANK.get(str(item.get("priority")), 9),
            _SEVERITY_RANK.get(str(item.get("severity")), 9),
            _timestamp_rank(item.get("last_observed_at")),
            str(item["signal_id"]),
        )
    )
    review_signals = [
        signal
        for signal in actionable
        if signal_needs_review(signal, ticket_by_signal.get(str(signal["id"])))
    ]
    return {
        "evaluated_at": evaluated_at,
        "signals": all_signals,
        "tickets": [dict(ticket) for ticket in tickets],
        "ticket_by_signal": ticket_by_signal,
        "sla_by_ticket": sla_by_ticket,
        "queue": queue,
        "summary": {
            "unassigned": len(review_signals),
            "without_ticket": sum(
                str(signal["id"]) not in ticket_by_signal for signal in review_signals
            ),
            "resurfaced": sum(
                str(signal["id"]) in ticket_by_signal for signal in review_signals
            ),
            "active": len(active_tickets),
            "high_priority": sum(
                str(ticket.get("priority")) in {"p1", "p2"}
                for ticket in active_tickets
            ),
            "unowned": sum(not ticket.get("owner") for ticket in active_tickets),
            "sla_overdue": sum(
                sla_by_ticket[str(ticket["id"])]["state"] == "overdue"
                for ticket in active_tickets
            ),
            "sla_due_soon": sum(
                sla_by_ticket[str(ticket["id"])]["state"] == "due_soon"
                for ticket in active_tickets
            ),
            "queue_total": len(queue),
            "truncated": int(len(signals) == 1000 or len(tickets) == 1000),
        },
    }


def asset_workflow_records(
    operational_index: Mapping[str, Any],
    *,
    asset_id: str,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Return only signals and tickets explicitly linked to ``asset_id``."""

    signals = [
        dict(signal)
        for signal in operational_index.get("signals", [])
        if asset_id in set(signal.get("asset_ids") or [])
    ]
    signal_ids = {str(signal["id"]) for signal in signals}
    tickets = [
        dict(ticket)
        for ticket in operational_index.get("tickets", [])
        if str(ticket.get("signal_id")) in signal_ids
    ]
    return signals, tickets
