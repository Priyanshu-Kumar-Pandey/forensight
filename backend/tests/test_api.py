"""End-to-end API integration tests (TestClient against the full app)."""
from __future__ import annotations


def test_health(client):
    r = client.get("/api/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"


def test_investigation_crud(client):
    r = client.post("/api/investigations", json={"name": "Case A", "description": "test"})
    assert r.status_code == 200
    inv = r.json()
    assert inv["name"] == "Case A" and inv["status"] == "open"

    r = client.get("/api/investigations")
    assert any(i["id"] == inv["id"] for i in r.json())

    r = client.get(f"/api/investigations/{inv['id']}")
    assert r.status_code == 200

    r = client.delete(f"/api/investigations/{inv['id']}")
    assert r.status_code == 200
    assert client.get(f"/api/investigations/{inv['id']}").status_code == 404


def test_evidence_upload_validation_and_listing(client):
    inv = client.post("/api/investigations", json={"name": "Evidence case"}).json()

    # valid upload
    r = client.post(
        "/api/evidence/upload",
        data={"investigation_id": inv["id"]},
        files={"file": ("auth.csv", b"timestamp,username\n2026-08-20 02:00:00,jdoe\n", "text/csv")},
    )
    assert r.status_code == 200
    ev = r.json()
    assert ev["file_type"] == "csv" and len(ev["sha256"]) == 64

    r = client.get("/api/evidence", params={"investigation_id": inv["id"]})
    assert len(r.json()) == 1

    # dangerous extension rejected
    r = client.post(
        "/api/evidence/upload",
        data={"investigation_id": inv["id"]},
        files={"file": ("evil.exe", b"MZ", "application/octet-stream")},
    )
    assert r.status_code == 400

    # delete evidence
    assert client.delete(f"/api/evidence/{ev['id']}").status_code == 200
    assert client.get("/api/evidence", params={"investigation_id": inv["id"]}).json() == []


def test_analyze_requires_evidence(client):
    inv = client.post("/api/investigations", json={"name": "Empty case"}).json()
    r = client.post(f"/api/investigations/{inv['id']}/analyze")
    assert r.status_code == 400
    assert "no evidence" in r.json()["detail"].lower()


def test_demo_load_full_pipeline_and_outputs(client, demo_investigation):
    inv_id = demo_investigation["investigation_id"]
    summary = demo_investigation["summary"]

    assert summary["total_artifacts"] > 0
    assert summary["total_relationships"] > 0
    assert summary["total_timeline_events"] > 0
    assert set(summary["risk_counts"].keys()) == {"LOW", "MEDIUM", "HIGH", "CRITICAL"}

    # artifacts ranked with explanations
    arts = client.get(f"/api/investigations/{inv_id}/artifacts").json()
    assert arts[0]["priority_rank"] == 1
    assert all("indicators" in a for a in arts)
    scores = [a["importance_score"] for a in arts]
    assert scores == sorted(scores, reverse=True)

    # timeline chronological with flags
    timeline = client.get(f"/api/investigations/{inv_id}/timeline").json()
    stamps = [e["timestamp"] for e in timeline]
    assert stamps == sorted(stamps)
    all_flags = {f for e in timeline for f in (e["flags"] or [])}
    assert "failed_logins_then_success" in all_flags
    assert "download_then_execute" in all_flags
    assert "execute_then_connect" in all_flags

    # graph payload for Cytoscape
    graph = client.get(f"/api/investigations/{inv_id}/graph").json()
    assert graph["nodes"] and graph["edges"]
    node_ids = {n["id"] for n in graph["nodes"]}
    for edge in graph["edges"]:
        assert edge["source"] in node_ids and edge["target"] in node_ids

    # insights with all sections
    insights = client.get(f"/api/investigations/{inv_id}/insights").json()
    sections = {i["section"] for i in insights}
    assert "executive_summary" in sections and "possible_incident_sequence" in sections

    # report renders
    r = client.get(f"/api/investigations/{inv_id}/report")
    assert r.status_code == 200
    assert "ForenSight Investigation Report" in r.text


def test_re_analysis_is_idempotent(client, demo_investigation):
    inv_id = demo_investigation["investigation_id"]
    first = client.get(f"/api/investigations/{inv_id}/artifacts").json()
    r = client.post(f"/api/investigations/{inv_id}/analyze")
    assert r.status_code == 200
    second = client.get(f"/api/investigations/{inv_id}/artifacts").json()
    assert len(first) == len(second)  # no duplicated artifacts after re-run
    assert {a["value"] for a in first} == {a["value"] for a in second}
