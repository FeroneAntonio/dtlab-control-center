"""DTLab Control Center v3 — FastAPI backend.

Exposes the existing Python data plane (collector/contract/store) and the v3
domains (offensive, digital twin, compliance, history) over a versioned,
RBAC-protected HTTP API. The API never re-implements the data plane: it imports
``dtlab`` and serves canonical snapshots.
"""

__version__ = "3.0.0.dev0"
