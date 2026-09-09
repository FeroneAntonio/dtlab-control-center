"""Narrow automatic ticket policy for authenticated PLC endpoint evidence.

The default DTLab workflow remains manual-first.  This module contains the one
explicit exception requested for host-side Modbus write detections.  It never
executes remediation, never closes a ticket and never downgrades priority.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from dtlab.services.playbooks import tasks_for_signal
from dtlab.services.ticket_store import TicketStore, TicketValidationError

HOST_OT_SOURCE_ID = "src:dtlab-host-ot:plc-desktop"
HOST_OT_SIGNAL_TYPE = "host_modbus_write"
HOST_OT_SOURCE_SCOPE = "plc_host_side"
HOST_OT_POLICY_ACTOR = "dtlab-system:host-ot-policy"

_PRIORITY_RANK = {"p1": 0, "p2": 1, "p3": 2, "p4": 3}


@dataclass(frozen=True, slots=True)
class HostOtTicketPolicyResult:
    """Outcome of one idempotent automatic-ticket reconciliation."""

    ticket: dict[str, Any]
    created: bool
    escalated: bool
    tasks_added: int


def _desired_priority(signal: dict[str, Any]) -> str:
    payload = signal.get("payload")
    event = payload.get("event") if isinstance(payload, dict) else None
    detection = event.get("detection") if isinstance(event, dict) else None
    if isinstance(detection, dict) and detection.get("classification") == (
        "process_shutdown_sequence"
    ):
        return "p1"
    return "p1" if signal.get("severity") == "critical" else "p2"


def apply_host_ot_ticket_policy(
    store: TicketStore,
    signal_id: str,
    *,
    actor: str = HOST_OT_POLICY_ACTOR,
) -> HostOtTicketPolicyResult:
    """Create or reconcile exactly one ticket for a trusted host OT signal.

    Eligibility is deliberately redundant: signal type, fixed non-Cisco source and
    normalized payload scope must all match.  Repeated calls are safe because both
    signal fingerprint and ``tickets.signal_id`` are unique in :class:`TicketStore`.
    """

    signal = store.get_signal(signal_id)
    payload = signal.get("payload")
    if (
        signal.get("signal_type") != HOST_OT_SIGNAL_TYPE
        or signal.get("source_id") != HOST_OT_SOURCE_ID
        or not isinstance(payload, dict)
        or payload.get("source_scope") != HOST_OT_SOURCE_SCOPE
    ):
        raise TicketValidationError(
            "La policy automatica host OT accetta solo segnali endpoint normalizzati."
        )

    desired_priority = _desired_priority(signal)
    before = store.get_ticket_for_signal(signal_id)
    ticket, tasks_added = store.create_ticket_with_tasks(
        signal_id,
        actor=actor,
        tasks=(
            {"title": task.title, "description": task.description}
            for task in tasks_for_signal(HOST_OT_SIGNAL_TYPE)
        ),
        priority=desired_priority,
        owner=None,
    )
    created = before is None
    escalated = False
    current_priority = str(ticket["priority"])
    if _PRIORITY_RANK[desired_priority] < _PRIORITY_RANK[current_priority]:
        ticket = store.set_ticket_priority(
            str(ticket["id"]),
            desired_priority,
            actor=actor,
        )
        escalated = True

    return HostOtTicketPolicyResult(
        ticket=ticket,
        created=created,
        escalated=escalated,
        tasks_added=tasks_added,
    )

