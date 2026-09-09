"""Evidence & report exports: canonical snapshot, manifest and per-asset bundles."""

from __future__ import annotations

import hashlib
import json

from dtlab import contract_v3
from fastapi import APIRouter, Depends, HTTPException, Response

from dtlab_api.deps import get_provider
from dtlab_api.security import require_role
from dtlab_api.snapshot_provider import SnapshotProvider

router = APIRouter(
    prefix="/api/export",
    tags=["evidence"],
    dependencies=[Depends(require_role("viewer"))],
)


@router.get("/snapshot")
def export_snapshot(provider: SnapshotProvider = Depends(get_provider)) -> Response:
    """Canonical snapshot JSON, byte-for-byte reproducible (content-addressed)."""

    payload = contract_v3.canonical_bytes_v3(provider.snapshot)
    return Response(
        content=payload,
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=dtlab-snapshot.json"},
    )


@router.get("/manifest")
def export_manifest(provider: SnapshotProvider = Depends(get_provider)) -> dict:
    payload = contract_v3.canonical_bytes_v3(provider.snapshot)
    meta = provider.meta()
    return {
        "manifest_version": "1.0",
        "contract_version": provider.snapshot.get("schema_version"),
        "snapshot_id": provider.snapshot.get("snapshot_id"),
        "generated_at": provider.snapshot.get("generated_at"),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "byte_length": len(payload),
        "trusted_origin": "dtlab_sandbox",
        "record_counts": meta["counts"],
    }


@router.get("/asset/{asset_id:path}")
def export_asset_evidence(
    asset_id: str, provider: SnapshotProvider = Depends(get_provider)
) -> Response:
    """Evidence bundle for one asset: only records explicitly linked to it."""

    asset = provider.find("assets", asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset non trovato.")

    bundle = {
        "export_type": "dtlab_asset_evidence",
        "asset": asset,
        "risk_scores": [
            r for r in provider.collection("risk_scores") if r.get("asset_id") == asset_id
        ],
        "vulnerabilities": [
            v for v in provider.collection("vulnerabilities") if v.get("asset_id") == asset_id
        ],
        "flows": [
            f for f in provider.collection("flows")
            if asset_id in (f.get("left_asset_id"), f.get("right_asset_id"))
        ],
        "events": [
            e for e in provider.collection("events") if asset_id in e.get("asset_ids", [])
        ],
        "identity_links": [
            link for link in provider.collection("identity_links")
            if link.get("asset_id") == asset_id
        ],
        "correlation_policy": "explicit_links_only_no_inference",
    }
    body = json.dumps(bundle, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    stem = "".join(c if c.isalnum() else "-" for c in asset_id).strip("-") or "asset"
    return Response(
        content=body,
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename={stem}-evidence.json"},
    )
