"""Operational workflow: deduplicated signals and persistent tickets.

Reuses the existing v2 ticketing engine (SQLite store, idempotent ingest, SLA,
playbook tasks, audit) via the TicketService. Reads require viewer; every
mutation requires analyst or above and is attributed to the caller's principal
in the append-only audit trail.
"""

from __future__ import annotations

from dtlab.services.ticket_store import TicketStoreError
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel

from dtlab_api.security import Principal, require_role
from dtlab_api.ticketing import POLICY, TicketService

router = APIRouter(prefix="/api", tags=["operations"])


def get_tickets(request: Request) -> TicketService:
    return request.app.state.tickets


# -- request bodies -------------------------------------------------------
class CreateTicket(BaseModel):
    priority: str | None = None
    owner: str | None = None


class Transition(BaseModel):
    target: str
    note: str | None = None


class Governance(BaseModel):
    owner: str | None = None
    priority: str | None = None


class Comment(BaseModel):
    body: str


class NewTask(BaseModel):
    title: str
    description: str | None = None
    owner: str | None = None
    due_at: str | None = None


class TaskStatus(BaseModel):
    status: str


def _guard(call):
    try:
        return call()
    except TicketStoreError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


# -- reads ----------------------------------------------------------------
@router.get("/signals", dependencies=[Depends(require_role("viewer"))])
def list_signals(svc: TicketService = Depends(get_tickets)) -> dict:
    items = svc.signals()
    return {"count": len(items), "items": items}


@router.get("/signals/{signal_id:path}", dependencies=[Depends(require_role("viewer"))])
def get_signal(signal_id: str, svc: TicketService = Depends(get_tickets)) -> dict:
    signal = svc.signal(signal_id)
    if signal is None:
        raise HTTPException(status_code=404, detail="Segnale non trovato.")
    return signal


@router.get("/tickets", dependencies=[Depends(require_role("viewer"))])
def list_tickets(svc: TicketService = Depends(get_tickets)) -> dict:
    items = svc.tickets()
    return {"count": len(items), "items": items}


@router.get("/tickets/{ticket_id:path}/export", dependencies=[Depends(require_role("viewer"))])
def export_ticket(ticket_id: str, svc: TicketService = Depends(get_tickets)) -> Response:
    payload = svc.ticket_json(ticket_id)
    if payload is None:
        raise HTTPException(status_code=404, detail="Ticket non trovato.")
    return Response(content=payload, media_type="application/json")


@router.get("/tickets/{ticket_id:path}", dependencies=[Depends(require_role("viewer"))])
def get_ticket(ticket_id: str, svc: TicketService = Depends(get_tickets)) -> dict:
    document = svc.ticket_document(ticket_id)
    if document is None:
        raise HTTPException(status_code=404, detail="Ticket non trovato.")
    return document


@router.get("/ticketing/summary", dependencies=[Depends(require_role("viewer"))])
def ticketing_summary(svc: TicketService = Depends(get_tickets)) -> dict:
    return svc.kpis()


@router.get("/ticketing/policy", dependencies=[Depends(require_role("viewer"))])
def ticketing_policy() -> dict:
    return POLICY


# -- writes (analyst+) ----------------------------------------------------
@router.post("/signals/{signal_id:path}/ticket")
def create_ticket(
    signal_id: str,
    body: CreateTicket,
    svc: TicketService = Depends(get_tickets),
    principal: Principal = Depends(require_role("analyst")),
) -> dict:
    return _guard(lambda: svc.create_ticket(
        signal_id, actor=principal.subject, priority=body.priority, owner=body.owner
    ))


@router.post("/tickets/{ticket_id:path}/transition")
def transition_ticket(
    ticket_id: str,
    body: Transition,
    svc: TicketService = Depends(get_tickets),
    principal: Principal = Depends(require_role("analyst")),
) -> dict:
    return _guard(lambda: svc.transition(
        ticket_id, body.target, actor=principal.subject, note=body.note
    ))


@router.post("/tickets/{ticket_id:path}/governance")
def update_governance(
    ticket_id: str,
    body: Governance,
    svc: TicketService = Depends(get_tickets),
    principal: Principal = Depends(require_role("analyst")),
) -> dict:
    return _guard(lambda: svc.governance(
        ticket_id, owner=body.owner, priority=body.priority, actor=principal.subject
    ))


@router.post("/tickets/{ticket_id:path}/comments")
def add_comment(
    ticket_id: str,
    body: Comment,
    svc: TicketService = Depends(get_tickets),
    principal: Principal = Depends(require_role("analyst")),
) -> dict:
    if not body.body.strip():
        raise HTTPException(status_code=422, detail="Il commento non può essere vuoto.")
    return _guard(lambda: svc.add_comment(ticket_id, author=principal.subject, body=body.body))


@router.post("/tickets/{ticket_id:path}/tasks")
def add_task(
    ticket_id: str,
    body: NewTask,
    svc: TicketService = Depends(get_tickets),
    principal: Principal = Depends(require_role("analyst")),
) -> dict:
    if not body.title.strip():
        raise HTTPException(status_code=422, detail="Il titolo dell'attività è obbligatorio.")
    return _guard(lambda: svc.add_task(
        ticket_id, actor=principal.subject, title=body.title,
        description=body.description, owner=body.owner, due_at=body.due_at,
    ))


@router.post("/tasks/{task_id:path}/status")
def update_task(
    task_id: str,
    body: TaskStatus,
    svc: TicketService = Depends(get_tickets),
    principal: Principal = Depends(require_role("analyst")),
) -> dict:
    return _guard(lambda: svc.update_task(task_id, body.status, actor=principal.subject))
