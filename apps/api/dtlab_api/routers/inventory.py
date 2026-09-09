"""Inventory: assets, VMs, networks, sources, sensors, identity links."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query

from dtlab_api.deps import get_provider
from dtlab_api.security import require_role
from dtlab_api.snapshot_provider import SnapshotProvider

router = APIRouter(
    prefix="/api",
    tags=["inventory"],
    dependencies=[Depends(require_role("viewer"))],
)


def _envelope(items: list[dict]) -> dict:
    return {"count": len(items), "items": items}


@router.get("/assets")
def list_assets(
    provider: SnapshotProvider = Depends(get_provider),
    role: str | None = Query(None, description="Filtra per operational_role."),
    status: str | None = Query(None, description="Filtra per status."),
) -> dict:
    items = provider.collection("assets")
    if role:
        items = [a for a in items if a.get("operational_role") == role]
    if status:
        items = [a for a in items if a.get("status") == status]
    return _envelope(items)


@router.get("/assets/{asset_id}")
def get_asset(asset_id: str, provider: SnapshotProvider = Depends(get_provider)) -> dict:
    asset = provider.find("assets", asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset non trovato.")
    return asset


@router.get("/virtual-machines")
def list_vms(provider: SnapshotProvider = Depends(get_provider)) -> dict:
    return _envelope(provider.collection("virtual_machines"))


@router.get("/networks")
def list_networks(provider: SnapshotProvider = Depends(get_provider)) -> dict:
    return _envelope(provider.collection("networks"))


@router.get("/sources")
def list_sources(provider: SnapshotProvider = Depends(get_provider)) -> dict:
    return _envelope(provider.collection("sources"))


@router.get("/sensors")
def list_sensors(provider: SnapshotProvider = Depends(get_provider)) -> dict:
    return _envelope(provider.collection("sensors"))


@router.get("/identity-links")
def list_identity_links(provider: SnapshotProvider = Depends(get_provider)) -> dict:
    return _envelope(provider.collection("identity_links"))


@router.get("/new-ui-inventory")
def new_ui_inventory(provider: SnapshotProvider = Depends(get_provider)) -> dict:
    """Cisco Cyber Vision New UI inventory, separate from the Classic devices."""

    for source in provider.collection("sources"):
        if source.get("type") == "cisco_cyber_vision_new_ui":
            inv = source.get("details", {}).get("new_ui_inventory", {})
            profiles = inv.get("profiles", [])
            networks = inv.get("networks", [])
            return {
                "profiles": profiles,
                "networks": networks,
                "active_alerts": sum(p.get("active_alerts", 0) for p in profiles),
                "vulnerabilities": sum(p.get("vulnerabilities", 0) for p in profiles),
                "available": source.get("status") == "connected",
            }
    return {"profiles": [], "networks": [], "active_alerts": 0,
            "vulnerabilities": 0, "available": False}


@router.get("/quality")
def quality(provider: SnapshotProvider = Depends(get_provider)) -> dict:
    snap = provider.snapshot
    return {
        "quality": snap.get("quality", {}),
        "sync": snap.get("sync", {}),
        "snapshot_id": snap.get("snapshot_id"),
        "content_sha256": provider.meta()["content_sha256"],
    }


@router.get("/topology")
def topology(provider: SnapshotProvider = Depends(get_provider)) -> dict:
    """Purdue-layered graph: zones as bands, assets as nodes, flows as edges."""

    zones = provider.collection("security_zones")
    assets = {a["id"]: a for a in provider.collection("assets")}
    asset_zone = {}
    for zone in zones:
        for asset_id in zone.get("asset_ids", []):
            asset_zone[asset_id] = zone["id"]

    nodes = [
        {
            "id": a["id"],
            "name": a.get("name"),
            "device_type": a.get("device_type"),
            "role": a.get("operational_role"),
            "ip": (a.get("ip_addresses") or [None])[0],
            "zone_id": asset_zone.get(a["id"]),
        }
        for a in assets.values()
    ]
    edges = [
        {
            "id": f["id"],
            "source": f.get("left_asset_id"),
            "target": f.get("right_asset_id"),
            "protocol": f.get("protocol"),
            "direction": f.get("direction"),
        }
        for f in provider.collection("flows")
        if f.get("left_asset_id") and f.get("right_asset_id")
    ]
    zone_bands = [
        {
            "id": z["id"],
            "name": z.get("name"),
            "purdue_level": z.get("purdue_level"),
            "target_security_level": z.get("target_security_level"),
        }
        for z in zones
    ]
    return {"zones": zone_bands, "nodes": nodes, "edges": edges}
