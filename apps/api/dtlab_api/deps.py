"""Shared FastAPI dependencies."""

from __future__ import annotations

from fastapi import Request

from dtlab_api.snapshot_provider import SnapshotProvider


def get_provider(request: Request) -> SnapshotProvider:
    return request.app.state.provider
