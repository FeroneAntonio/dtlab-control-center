"""CLI wrapper: generate the BeerFactory v3 sandbox snapshot.

Usage:
    python tools/generate_sandbox.py [--output PATH]
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from dtlab.sandbox.generator import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
