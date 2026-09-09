"""Bound local raw evidence while preserving the newest snapshots."""

from __future__ import annotations

import argparse
from pathlib import Path


def prune(root: Path, *, retain: int) -> list[Path]:
    root = root.resolve()
    if root == Path(root.anchor) or len(root.parts) < 4:
        raise ValueError("Refusing to prune an unsafe root")
    if retain < 1:
        raise ValueError("retain must be positive")
    files = sorted(
        (path for path in root.rglob("*.json.gz") if path.is_file()),
        key=lambda path: path.stat().st_mtime_ns,
        reverse=True,
    )
    removed: list[Path] = []
    for path in files[retain:]:
        path.unlink()
        removed.append(path)
    return removed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--retain", type=int, default=100)
    args = parser.parse_args()
    removed = prune(args.root, retain=args.retain)
    print(f"removed={len(removed)} retained={args.retain}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
