"""Health, snapshot metadata and admin operations."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from dtlab_api.deps import get_provider
from dtlab_api.security import Principal, require_role
from dtlab_api.snapshot_provider import SnapshotProvider

router = APIRouter(tags=["meta"])


@router.get("/health")
def health() -> dict[str, str]:
    """Liveness probe. Unauthenticated by design."""

    return {"status": "ok"}


@router.get("/api/meta", dependencies=[Depends(require_role("viewer"))])
def meta(provider: SnapshotProvider = Depends(get_provider)) -> dict:
    return provider.meta()


@router.get("/api/me")
def me(principal: Principal = Depends(require_role("viewer"))) -> dict:
    return {"subject": principal.subject, "role": principal.role}


@router.post("/api/admin/reload")
def reload_snapshot(
    request: Request,
    provider: SnapshotProvider = Depends(get_provider),
    _: Principal = Depends(require_role("admin")),
) -> dict:
    provider.reload()
    request.app.state.tickets.ingest(provider.snapshot)
    return {"reloaded": True, "meta": provider.meta()}
