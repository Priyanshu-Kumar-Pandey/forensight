"""Investigation analysis pipeline.

Runs the full ForenSight pipeline over all evidence in an investigation:
  extraction -> AI/ML scoring -> ranking -> correlation -> timeline -> insights
and stamps the investigation as analyzed.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import delete
from sqlalchemy.orm import Session

from app.correlation import correlate
from app.forensic.extractors import extract_file
from app.insights import generate_insights
from app.ml import analyze_artifacts, rank_artifacts
from app.models.models import (
    Artifact,
    Evidence,
    Insight,
    Investigation,
    Relationship,
    TimelineEvent,
)
from app.timeline import build_timeline


def analyze_investigation(db: Session, investigation: Investigation) -> dict:
    evidence = list(investigation.evidence)
    if not evidence:
        raise ValueError("Investigation has no evidence to analyze.")

    # Fresh analysis: clear previous derived rows for this investigation.
    for model in (Insight, TimelineEvent, Relationship):
        db.execute(delete(model).where(model.investigation_id == investigation.id))
    artifact_ids = [a.id for ev in evidence for a in ev.artifacts]
    if artifact_ids:
        db.execute(delete(Artifact).where(Artifact.id.in_(artifact_ids)))
    db.flush()

    # 1. Artifact extraction
    artifacts: list[Artifact] = []
    for ev in evidence:
        path_obj = Path(ev.stored_path)
        if not path_obj.exists():
            continue
        for extracted in extract_file(path_obj, ev.file_type):
            artifacts.append(
                Artifact(
                    evidence_id=ev.id,
                    artifact_type=extracted.artifact_type,
                    value=extracted.value,
                    timestamp=extracted.timestamp,
                    source=extracted.source,
                    line_number=extracted.line_number,
                    metadata_json=extracted.metadata,
                )
            )
    if not artifacts:
        raise ValueError("No artifacts could be extracted from the evidence files.")
    db.add_all(artifacts)
    db.flush()  # assign IDs before scoring/correlation

    # 2. AI/ML scoring (rules + Isolation Forest), 3. Ranking
    analyze_artifacts(artifacts)
    relationships = correlate(investigation.id, artifacts, db)
    ranked = rank_artifacts(artifacts, relationships)

    # 4. Timeline, 5. Insights (burst flags need to be visible to rules too)
    timeline = build_timeline(investigation.id, artifacts, db)
    insights = generate_insights(investigation.id, artifacts, relationships, timeline, db)

    investigation.analyzed_at = datetime.now(timezone.utc)
    investigation.status = "analyzed"
    db.commit()

    risk_counts: dict[str, int] = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    for a in artifacts:
        risk_counts[a.risk_level] = risk_counts.get(a.risk_level, 0) + 1

    return {
        "investigation_id": investigation.id,
        "total_artifacts": len(artifacts),
        "total_relationships": len(relationships),
        "total_timeline_events": len(timeline),
        "total_insights": len(insights),
        "risk_counts": risk_counts,
        "top_artifacts": ranked[:10],
    }
