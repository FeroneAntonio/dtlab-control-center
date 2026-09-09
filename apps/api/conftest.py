"""Test setup for the API package: make ``dtlab_api`` importable and give tests
an authenticated client per role."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent))

os.environ.setdefault(
    "DTLAB_API_TOKENS",
    json.dumps(
        {
            "dtlab-viewer-dev": "viewer",
            "dtlab-analyst-dev": "analyst",
            "dtlab-admin-dev": "admin",
        }
    ),
)

from dtlab_api.main import create_app  # noqa: E402

_TOKENS = {
    "viewer": "dtlab-viewer-dev",
    "analyst": "dtlab-analyst-dev",
    "admin": "dtlab-admin-dev",
}


@pytest.fixture(scope="session")
def client() -> TestClient:
    return TestClient(create_app())


@pytest.fixture
def auth():
    def _headers(role: str = "viewer") -> dict[str, str]:
        return {"Authorization": f"Bearer {_TOKENS[role]}"}

    return _headers
