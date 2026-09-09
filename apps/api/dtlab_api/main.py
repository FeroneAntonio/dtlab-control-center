"""FastAPI application factory for the DTLab Control Center API."""

from __future__ import annotations

import tempfile
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from dtlab_api import __version__
from dtlab_api.config import Settings, get_settings
from dtlab_api.routers import (
    compliance,
    exports,
    history,
    inventory,
    meta,
    offensive,
    operations,
    overview,
    security_ops,
    twin,
)
from dtlab_api.snapshot_provider import SnapshotProvider
from dtlab_api.ticketing import TicketService

_DESCRIPTION = (
    "API del cockpit OT DTLab. Espone il data plane v2 (asset, flow, rischio, "
    "eventi) e i domini v3 (attacchi + detection, digital twin, compliance "
    "Purdue/62443/NIS2/ATT&CK, trend). Autenticazione bearer con ruoli "
    "viewer/analyst/admin."
)


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    app = FastAPI(
        title=settings.title,
        version=__version__,
        description=_DESCRIPTION,
    )
    app.state.settings = settings
    app.state.provider = SnapshotProvider(settings.snapshot_source)
    ticket_db = Path(tempfile.mkdtemp(prefix="dtlab-api-")) / "tickets.sqlite3"
    app.state.tickets = TicketService(db_path=ticket_db)
    app.state.tickets.ingest(app.state.provider.snapshot)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(settings.cors_origins),
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    for module in (
        meta,
        overview,
        inventory,
        security_ops,
        offensive,
        twin,
        compliance,
        history,
        operations,
        exports,
    ):
        app.include_router(module.router)

    return app


app = create_app()
