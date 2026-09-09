"""Deterministic sandbox fixtures for the DTLab v3 rebuild.

Everything produced here is synthetic demonstration data (``truth: demo``,
``publication_mode: allow_demo``) that models the BeerFactory OT lab. It is meant
for development, tests, the thesis walkthrough and UI previews. It is never real
telemetry and must never be published to the operational, real-only store.
"""

from dtlab.sandbox.generator import build_sandbox_snapshot

__all__ = ["build_sandbox_snapshot"]
