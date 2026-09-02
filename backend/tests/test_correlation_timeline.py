"""Tests for correlation engine and timeline reconstruction."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.correlation import correlate
from app.timeline import build_timeline
from app.models.models import Artifact


def ts(minute: int, second: int = 0) -> datetime:
    return datetime(2026, 8, 20, 2, minute, second, tzinfo=timezone.utc)


def _persist(db, artifacts: list[Artifact]) -> list[Artifact]:
    db.add_all(artifacts)
    db.flush()
    return artifacts


def test_download_then_execution_chain(db_session):
    arts = _persist(
        db_session,
        [
            Artifact(
                evidence_id=1, artifact_type="download", value="download tool.exe",
                timestamp=ts(16), source="edr.json", metadata_json={"file": "tool.exe"},
            ),
            Artifact(
                evidence_id=1, artifact_type="execution", value="execute tool.exe",
                timestamp=ts(17), source="edr.json", metadata_json={"process": "tool.exe"},
            ),
        ],
    )
    rels = correlate(1, arts, db_session)
    chain = [r for r in rels if r.relationship_type == "downloaded_then_executed"]
    assert len(chain) == 1
    assert chain[0].source_artifact_id == arts[0].id
    assert chain[0].confidence_score >= 0.5
    assert "later" in chain[0].explanation  # explainable text


def test_no_false_chain_when_gap_too_large(db_session):
    arts = _persist(
        db_session,
        [
            Artifact(evidence_id=1, artifact_type="download", value="download a.exe",
                     timestamp=ts(0), source="x", metadata_json={}),
            Artifact(evidence_id=1, artifact_type="execution", value="execute a.exe",
                     timestamp=ts(0) + timedelta(hours=2), source="x", metadata_json={}),  # 2h later
        ],
    )
    rels = correlate(1, arts, db_session)
    assert not [r for r in rels if r.relationship_type == "downloaded_then_executed"]


def test_user_entity_linked_to_login_event(db_session):
    arts = _persist(
        db_session,
        [
            Artifact(evidence_id=1, artifact_type="user", value="jdoe",
                     timestamp=ts(15), source="auth.csv", line_number=2, metadata_json={}),
            Artifact(evidence_id=1, artifact_type="login", value="login user=jdoe",
                     timestamp=ts(15), source="auth.csv", line_number=2,
                     metadata_json={"user": "jdoe"}),
        ],
    )
    rels = correlate(1, arts, db_session)
    performed = [r for r in rels if r.relationship_type == "performed_by"]
    assert len(performed) == 1
    assert performed[0].confidence_score >= 0.9  # same log record


def test_timeline_orders_events_and_flags_sequence(db_session):
    arts = _persist(
        db_session,
        [
            Artifact(evidence_id=1, artifact_type="execution", value="execute tool.exe",
                     timestamp=ts(17), source="edr.json",
                     metadata_json={"process": "tool.exe"}, risk_level="HIGH"),
            Artifact(evidence_id=1, artifact_type="download", value="download tool.exe",
                     timestamp=ts(16), source="edr.json",
                     metadata_json={"file": "tool.exe"}, risk_level="CRITICAL"),
            Artifact(evidence_id=1, artifact_type="network_connection", value="connect 198.51.100.23:4444",
                     timestamp=ts(18), source="fw.txt",
                     metadata_json={"dst_ip": "198.51.100.23", "port": "4444"}, risk_level="HIGH"),
        ],
    )
    events = build_timeline(1, arts, db_session)
    times = [e.timestamp for e in events]
    assert times == sorted(times)  # chronological
    flags = {f for e in events for f in (e.flags or [])}
    assert "download_then_execute" in flags
    assert "execute_then_connect" in flags
    # risk levels carried from artifacts
    by_type = {e.event_type: e for e in events}
    assert by_type["download"].risk_level == "CRITICAL"


def test_timeline_marks_failed_login_burst(db_session):
    arts = _persist(
        db_session,
        [
            Artifact(evidence_id=1, artifact_type="failed_login", value="failed login jdoe",
                     timestamp=ts(2 * i), source="auth.csv",
                     metadata_json={"user": "jdoe", "ip": "203.0.113.45"})
            for i in range(1, 4)
        ],
    )
    build_timeline(1, arts, db_session)
    burst = [a for a in arts if str((a.metadata_json or {}).get("burst", "")).lower() == "true"]
    assert len(burst) == 2  # first attempt starts the window, the next two are in-burst
