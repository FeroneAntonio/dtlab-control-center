"""API configuration resolved from the environment.

The API can run against the generated BeerFactory fixture without infrastructure
credentials. Access tokens never have source-code defaults: they must be supplied
through the environment in every environment, including local development.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from functools import lru_cache

_ALLOWED_ROLES = frozenset({"viewer", "analyst", "admin"})


@dataclass(frozen=True)
class Settings:
    # "sandbox" builds the deterministic fixture; otherwise a path to a v3 JSON.
    snapshot_source: str = "sandbox"
    tokens: dict[str, str] = field(default_factory=dict)
    cors_origins: tuple[str, ...] = ("http://localhost:3000", "http://127.0.0.1:3000")
    title: str = "DTLab Control Center API"

    @property
    def using_default_tokens(self) -> bool:
        return False


def _load_tokens() -> dict[str, str]:
    raw = os.environ.get("DTLAB_API_TOKENS")
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"DTLAB_API_TOKENS non è JSON valido: {exc}") from exc
    if not isinstance(parsed, dict) or not all(
        isinstance(k, str) and isinstance(v, str) for k, v in parsed.items()
    ):
        raise ValueError("DTLAB_API_TOKENS deve essere un oggetto {token: ruolo}.")
    if not parsed or any(
        not token.strip() or role not in _ALLOWED_ROLES for token, role in parsed.items()
    ):
        raise ValueError("DTLAB_API_TOKENS richiede token non vuoti e ruoli viewer/analyst/admin.")
    return parsed


def _load_cors() -> tuple[str, ...]:
    raw = os.environ.get("DTLAB_API_CORS_ORIGINS")
    if not raw:
        return Settings.cors_origins
    return tuple(origin.strip() for origin in raw.split(",") if origin.strip())


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings(
        snapshot_source=os.environ.get("DTLAB_API_SNAPSHOT", "sandbox"),
        tokens=_load_tokens(),
        cors_origins=_load_cors(),
    )
