"""End-to-end tests for the DTLab v3 API against the sandbox snapshot."""

from __future__ import annotations


def test_health_is_public(client) -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_meta_requires_authentication(client) -> None:
    assert client.get("/api/meta").status_code == 401


def test_invalid_token_is_rejected(client) -> None:
    response = client.get("/api/meta", headers={"Authorization": "Bearer nope"})
    assert response.status_code == 401


def test_meta_with_viewer(client, auth) -> None:
    response = client.get("/api/meta", headers=auth("viewer"))
    assert response.status_code == 200
    body = response.json()
    assert body["schema_version"] == "3.0.0"
    assert body["counts"]["attack_runs"] == 4
    assert len(body["content_sha256"]) == 64


def test_me_reports_role(client, auth) -> None:
    body = client.get("/api/me", headers=auth("analyst")).json()
    assert body["role"] == "analyst"


def test_admin_reload_is_role_gated(client, auth) -> None:
    assert client.post("/api/admin/reload", headers=auth("viewer")).status_code == 403
    assert client.post("/api/admin/reload", headers=auth("admin")).status_code == 200


def test_assets_filtering(client, auth) -> None:
    response = client.get("/api/assets", params={"role": "target"}, headers=auth())
    assert response.status_code == 200
    items = response.json()["items"]
    assert items and all(a["operational_role"] == "target" for a in items)


def test_asset_not_found(client, auth) -> None:
    assert client.get("/api/assets/does-not-exist", headers=auth()).status_code == 404


def test_attack_runs_are_enriched_with_detection(client, auth) -> None:
    body = client.get("/api/attack-runs", headers=auth()).json()
    assert body["count"] == 4
    mitm = next(r for r in body["items"] if r["id"] == "run:mitm")
    assert mitm["detected"] is False
    assert mitm["detection"]["detection_latency_seconds"] is None


def test_detection_summary_coverage_and_gap(client, auth) -> None:
    body = client.get("/api/detection/summary", headers=auth()).json()
    assert body["detected"] == 3
    assert body["undetected"] == 1
    assert body["coverage"] == 0.75
    assert body["latency_seconds"]["max"] is not None
    gaps = body["detection_gaps"]
    assert any(g["mitre_technique_id"] == "T0830" for g in gaps)


def test_attack_run_detail_includes_telemetry(client, auth) -> None:
    body = client.get("/api/attack-runs/run:unauthorized-write", headers=auth()).json()
    assert body["scenario"]["id"] == "scenario:unauthorized-write"
    assert body["telemetry_samples"], "il write attack deve avere campioni collegati"


def test_telemetry_series_shows_tampering(client, auth) -> None:
    body = client.get(
        "/api/telemetry/series", params={"register": "conveyor_speed_rpm"}, headers=auth()
    ).json()
    assert body["count"] > 0
    assert any(p["in_bounds"] is False for p in body["points"])


def test_compliance_coverage_has_frameworks(client, auth) -> None:
    body = client.get("/api/compliance/coverage", headers=auth()).json()
    frameworks = {f["framework"] for f in body["frameworks"]}
    assert {"iec_62443", "nis2", "mitre_attack_ics", "purdue"} <= frameworks


def test_purdue_groups_zones_by_level(client, auth) -> None:
    body = client.get("/api/purdue", headers=auth()).json()
    levels = {entry["level"] for entry in body["levels"]}
    assert "1" in levels and "2" in levels


def test_history_series(client, auth) -> None:
    body = client.get("/api/history/series/detections", headers=auth()).json()
    assert body["metric"] == "detections"
    assert body["count"] >= 1


def test_overview_aggregate(client, auth) -> None:
    body = client.get("/api/overview", headers=auth()).json()
    assert body["kpis"]["attack_runs"] == 4
    assert body["kpis"]["detection_coverage"] == 0.75
    assert body["digital_twin"]["belt_state"] in {"running", "stopped", "fault"}
    assert len(body["attack_timeline"]) == 4
    assert "iec_62443" in body["compliance_coverage"]


def test_openapi_is_available(client) -> None:
    response = client.get("/openapi.json")
    assert response.status_code == 200
    assert response.json()["info"]["title"]
