"""Tests for the AI insight generator and HTML report."""
from __future__ import annotations

from datetime import datetime, timezone

from app.insights import generate_insights
from app.models.models import Artifact, Relationship, TimelineEvent
from app.services.report import build_report_data, render_html


def ts(minute: int) -> datetime:
    return datetime(2026, 8, 20, 2, minute, 0, tzinfo=timezone.utc)


def _seed(db) -> tuple[list[Artifact], list[Relationship], list[TimelineEvent], object]:
    """Minimal investigation with a suspicious story: burst -> login -> download -> execute -> connect."""
    inv = _get_or_create_investigation(db)

    arts = [
        Artifact(evidence_id=1, artifact_type="failed_login", value="failed login jdoe",
                 timestamp=ts(5), source="auth.csv", metadata_json={"user": "jdoe", "burst": "true"},
                 risk_score=60, risk_level="HIGH", importance_score=60),
        Artifact(evidence_id=1, artifact_type="login", value="login user=jdoe src=203.0.113.45",
                 timestamp=ts(15), source="auth.csv", metadata_json={"user": "jdoe", "ip": "203.0.113.45"},
                 risk_score=70, risk_level="HIGH", importance_score=70),
        Artifact(evidence_id=1, artifact_type="download", value="download invoice_scanner.exe",
                 timestamp=ts(16), source="edr.json",
                 metadata_json={"file": "C:/Users/jdoe/Downloads/invoice_scanner.exe"},
                 risk_score=90, risk_level="CRITICAL", importance_score=90),
        Artifact(evidence_id=1, artifact_type="execution", value="execute invoice_scanner.exe",
                 timestamp=ts(17), source="edr.json", metadata_json={"process": "invoice_scanner.exe"},
                 risk_score=80, risk_level="HIGH", importance_score=80),
    ]
    db.add_all(arts)
    db.flush()

    rels = [
        Relationship(investigation_id=inv.id, source_artifact_id=arts[2].id,
                     target_artifact_id=arts[3].id, relationship_type="downloaded_then_executed",
                     confidence_score=0.9, explanation="download followed by execution 60s later"),
    ]
    events = [
        TimelineEvent(investigation_id=inv.id, artifact_id=arts[1].id, timestamp=ts(15),
                      event_type="login", description="User login user=jdoe", risk_level="HIGH",
                      flags=["failed_logins_then_success"]),
        TimelineEvent(investigation_id=inv.id, artifact_id=arts[2].id, timestamp=ts(16),
                      event_type="download", description="File downloaded invoice_scanner.exe",
                      risk_level="CRITICAL", flags=["download_then_execute"]),
        TimelineEvent(investigation_id=inv.id, artifact_id=arts[3].id, timestamp=ts(17),
                      event_type="execution", description="Process executed invoice_scanner.exe",
                      risk_level="HIGH", flags=["download_then_execute"]),
    ]
    db.add_all(rels)
    db.add_all(events)
    db.flush()
    return arts, rels, events, inv


def _get_or_create_investigation(db):
    from app.models.models import Investigation

    inv = Investigation(name="Insight test case", description="synthetic")
    db.add(inv)
    db.flush()
    return inv


def test_insights_cover_all_sections_and_cite_artifacts(db_session):
    arts, rels, events, inv = _seed(db_session)
    insights = generate_insights(inv.id, arts, rels, events, db_session)

    sections = {i.section for i in insights}
    assert {
        "executive_summary", "key_findings", "suspicious_activity",
        "evidence_connections", "possible_incident_sequence",
    } <= sections

    for ins in insights:
        # Every insight is explainable: cites supporting artifacts and marks its generator.
        assert isinstance(ins.supporting_artifact_ids, list)
        assert ins.generated_by == "rules_v1"

    seq = next(i for i in insights if i.section == "possible_incident_sequence")
    # The AI interpretation must use hedged language, not assert verified fact.
    assert "AI interpretation" in seq.text
    assert "suggests" in seq.text
    assert set(seq.supporting_artifact_ids) <= {a.id for a in arts}


def test_report_html_separates_facts_from_ai_interpretation(db_session):
    arts, rels, events, inv = _seed(db_session)
    generate_insights(inv.id, arts, rels, events, db_session)
    db_session.commit()

    data = build_report_data(db_session, inv)
    html = render_html(data)

    assert "ForenSight Investigation Report" in html
    assert "AI-generated interpretation" in html          # explicit AI banner
    assert "Key Findings (verified facts)" in html        # facts section
    assert "Possible Incident Sequence (AI interpretation)" in html
    assert "invoice_scanner.exe" in html                  # evidence present
    # facts sections come before the AI section ("Key Findings" also appears
    # inside insight prose, so compare against the unambiguous artifacts heading)
    facts_pos = html.find("Important Artifacts")
    ai_pos = html.find("AI Investigation Insights")
    assert 0 < facts_pos < ai_pos
