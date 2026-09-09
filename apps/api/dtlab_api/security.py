"""Bearer-token authentication and role-based access control.

Roles form a strict hierarchy: viewer < analyst < admin. A dependency built with
``require_role`` admits any principal at or above the requested level. Tokens map
to roles in the settings; comparison is constant-time to avoid leaking token
material through timing.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from dtlab_api.config import Settings, get_settings

ROLE_ORDER: dict[str, int] = {"viewer": 1, "analyst": 2, "admin": 3}

_bearer = HTTPBearer(auto_error=False, description="Token DTLab (bearer).")


@dataclass(frozen=True)
class Principal:
    subject: str
    role: str

    def has_at_least(self, role: str) -> bool:
        return ROLE_ORDER[self.role] >= ROLE_ORDER[role]


def _resolve_token(token: str, settings: Settings) -> str | None:
    """Return the role for ``token`` using a constant-time comparison."""

    matched: str | None = None
    for known_token, role in settings.tokens.items():
        if secrets.compare_digest(token, known_token):
            matched = role
    return matched


def get_principal(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
    settings: Settings = Depends(get_settings),
) -> Principal:
    if credentials is None or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token di autenticazione mancante.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    role = _resolve_token(credentials.credentials, settings)
    if role is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token non valido.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    # The subject is derived, never the token itself, so it is safe to log/return.
    return Principal(subject=f"{role}-principal", role=role)


def require_role(minimum: str):
    """Build a dependency that requires at least ``minimum`` role."""

    if minimum not in ROLE_ORDER:
        raise ValueError(f"Ruolo sconosciuto: {minimum}")

    def _dependency(principal: Principal = Depends(get_principal)) -> Principal:
        if not principal.has_at_least(minimum):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Richiede il ruolo '{minimum}' o superiore.",
            )
        return principal

    return _dependency
