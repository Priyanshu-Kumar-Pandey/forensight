"""ForenSight API routes (v1)."""
from __future__ import annotations

import hashlib
from pathlib import Path

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from fastapi.responses import HTMLResponse
from sqlalchemy import delete, func
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import get_db
from app.demo_data import DEMO_FILES
from app.forensic.storage import validate_and_store
from app.models.models import (
    Artifact,
    Evidence,
    Insight,
    Investigation,
    Relationship,
    TimelineEvent,
)
from app.schemas.schemas import (
    AnalysisSummary,
    ArtifactOut,
    EvidenceOut,
    GraphEdge,
    GraphNode,
    GraphOut,
    InsightOut,
    InvestigationCreate,
    InvestigationOut,
    RelationshipOut,
    TimelineEventOut,
)
from app.services.analysis import analyze_investigation
from app.services.report import build_report_data, render_html

router = APIRouter()
api_router = APIRouter()


# --------------------------------------------------------------------------
# Investigations
# --------------------------------------------------------------------------

@router.post("/investigations", response_model=InvestigationOut)
def create_investigation(payload: InvestigationCreate, db: Session = Depends(get_db)):
    inv = Investigation(name=payload.name.strip(), description=payload.description.strip())
    db.add(inv)
    db.commit()
    db.refresh(inv)
    return inv


@router.get("/investigations", response_model=list[InvestigationOut])
def list_investigations(db: Session = Depends(get_db)):
    return db.query(Investigation).order_by(Investigation.created_at.desc()).all()


@router.get("/investigations/{inv_id}", response_model=InvestigationOut)
def get_investigation(inv_id: int, db: Session = Depends(get_db)):
    inv = db.get(Investigation, inv_id)
    if not inv:
        raise HTTPException(404, "Investigation not found")
    return inv


@router.delete("/investigations/{inv_id}")
def delete_investigation(inv_id: int, db: Session = Depends(get_db)):
    inv = db.get(Investigation, inv_id)
    if not inv:
        raise HTTPException(404, "Investigation not found")
    db.delete(inv)
    db.commit()
    return {"ok": True}


# --------------------------------------------------------------------------
# Evidence
# --------------------------------------------------------------------------

@router.post("/evidence/upload", response_model=EvidenceOut)
def upload_evidence(
    investigation_id: int = Form(...),
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
):
    inv = db.get(Investigation, investigation_id)
    if not inv:
        raise HTTPException(404, "Investigation not found")
    stored = validate_and_store(file)
    ev = Evidence(
        investigation_id=investigation_id,
        file_name=stored.file_name,
        file_type=stored.file_type,
        file_size=stored.file_size,
        sha256=stored.sha256,
        stored_path=str(stored.stored_path),
    )
    db.add(ev)
    db.commit()
    db.refresh(ev)
    return ev


@router.get("/evidence", response_model=list[EvidenceOut])
def list_evidence(investigation_id: int, db: Session = Depends(get_db)):
    return (
        db.query(Evidence)
        .filter(Evidence.investigation_id == investigation_id)
        .order_by(Evidence.uploaded_at)
        .all()
    )


@router.get("/evidence/{ev_id}", response_model=EvidenceOut)
def get_evidence(ev_id: int, db: Session = Depends(get_db)):
    ev = db.get(Evidence, ev_id)
    if not ev:
        raise HTTPException(404, "Evidence not found")
    return ev


@router.delete("/evidence/{ev_id}")
def delete_evidence(ev_id: int, db: Session = Depends(get_db)):
    ev = db.get(Evidence, ev_id)
    if not ev:
        raise HTTPException(404, "Evidence not found")
    Path(ev.stored_path).unlink(missing_ok=True)
    db.delete(ev)
    db.commit()
    return {"ok": True}


# --------------------------------------------------------------------------
# Analysis
# --------------------------------------------------------------------------

@router.post("/investigations/{inv_id}/analyze", response_model=AnalysisSummary)
def analyze(inv_id: int, db: Session = Depends(get_db)):
    inv = db.get(Investigation, inv_id)
    if not inv:
        raise HTTPException(404, "Investigation not found")
    try:
        result = analyze_investigation(db, inv)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return AnalysisSummary(
        investigation_id=inv_id,
        total_artifacts=result["total_artifacts"],
        total_relationships=result["total_relationships"],
        total_timeline_events=result["total_timeline_events"],
        risk_counts=result["risk_counts"],
        top_artifacts=result["top_artifacts"],
    )


@router.get("/investigations/{inv_id}/artifacts", response_model=list[ArtifactOut])
def list_artifacts(inv_id: int, db: Session = Depends(get_db)):
    return (
        db.query(Artifact)
        .join(Evidence, Artifact.evidence_id == Evidence.id)
        .filter(Evidence.investigation_id == inv_id)
        .order_by(Artifact.importance_score.desc())
        .all()
    )


@router.get("/investigations/{inv_id}/relationships", response_model=list[RelationshipOut])
def list_relationships(inv_id: int, db: Session = Depends(get_db)):
    return db.query(Relationship).filter(Relationship.investigation_id == inv_id).all()


# --------------------------------------------------------------------------
# Timeline / Graph / Insights
# --------------------------------------------------------------------------

@router.get("/investigations/{inv_id}/timeline", response_model=list[TimelineEventOut])
def get_timeline(inv_id: int, db: Session = Depends(get_db)):
    return (
        db.query(TimelineEvent)
        .filter(TimelineEvent.investigation_id == inv_id)
        .order_by(TimelineEvent.timestamp)
        .all()
    )


@router.get("/investigations/{inv_id}/graph", response_model=GraphOut)
def get_graph(inv_id: int, db: Session = Depends(get_db)):
    artifacts = (
        db.query(Artifact)
        .join(Evidence, Artifact.evidence_id == Evidence.id)
        .filter(Evidence.investigation_id == inv_id)
        .all()
    )
    relationships = db.query(Relationship).filter(Relationship.investigation_id == inv_id).all()

    nodes: dict[str, GraphNode] = {}
    edges: list[GraphEdge] = []

    def node_for(art: Artifact) -> str:
        if art.artifact_type in ("user", "ip", "file", "process"):
            node_id = f"{art.artifact_type}:{art.value}"
            if node_id not in nodes:
                nodes[node_id] = GraphNode(
                    id=node_id,
                    label=art.value[:48],
                    type=art.artifact_type,
                    risk_level=art.risk_level,
                    detail=art.value,
                )
        else:
            node_id = f"event:{art.id}"
            if node_id not in nodes:
                ts = art.timestamp.strftime("%H:%M:%S") if art.timestamp else "no time"
                nodes[node_id] = GraphNode(
                    id=node_id,
                    label=f"{art.artifact_type} ({ts})",
                    type="event",
                    risk_level=art.risk_level,
                    detail=art.value,
                )
        return node_id

    for rel in relationships:
        src = db.get(Artifact, rel.source_artifact_id)
        tgt = db.get(Artifact, rel.target_artifact_id)
        if not src or not tgt:
            continue
        s_id, t_id = node_for(src), node_for(tgt)
        edges.append(
            GraphEdge(
                id=f"e{rel.id}",
                source=s_id,
                target=t_id,
                relationship_type=rel.relationship_type,
                confidence_score=rel.confidence_score,
            )
        )
    return GraphOut(nodes=list(nodes.values()), edges=edges)


@router.get("/investigations/{inv_id}/insights", response_model=list[InsightOut])
def get_insights(inv_id: int, db: Session = Depends(get_db)):
    return db.query(Insight).filter(Insight.investigation_id == inv_id).all()


# --------------------------------------------------------------------------
# Report
# --------------------------------------------------------------------------

@router.get("/investigations/{inv_id}/report")
def get_report(inv_id: int, db: Session = Depends(get_db)):
    inv = db.get(Investigation, inv_id)
    if not inv:
        raise HTTPException(404, "Investigation not found")
    data = build_report_data(db, inv)
    return HTMLResponse(render_html(data))


# --------------------------------------------------------------------------
# Demo data loader
# --------------------------------------------------------------------------

@router.post("/demo/load")
def load_demo(db: Session = Depends(get_db)):
    inv = Investigation(
        name="Demo — Incident #2026-0820 (synthetic)",
        description="Fictional incident: failed logins, download, execution, external connection.",
    )
    db.add(inv)
    db.flush()

    for name, (ftype, content) in DEMO_FILES.items():
        digest = hashlib.sha256(content.encode()).hexdigest()
        evidence_dir = Path(settings.evidence_dir)
        evidence_dir.mkdir(parents=True, exist_ok=True)
        stored_path = evidence_dir / f"{digest[:16]}_{name}"
        stored_path.write_text(content, encoding="utf-8")
        db.add(
            Evidence(
                investigation_id=inv.id,
                file_name=name,
                file_type=ftype,
                file_size=len(content.encode()),
                sha256=digest,
                stored_path=str(stored_path),
            )
        )
    db.commit()
    db.refresh(inv)
    try:
        summary = analyze_investigation(db, inv)
    except ValueError as exc:
        raise HTTPException(500, f"Demo analysis failed: {exc}") from exc
    return {"investigation_id": inv.id, "summary": summary}


@router.get("/health")
def health(db: Session = Depends(get_db)):
    return {
        "status": "ok",
        "investigations": db.query(func.count(Investigation.id)).scalar(),
        "artifacts": db.query(func.count(Artifact.id)).scalar(),
    }


# Include last so every decorated route is registered.
api_router.include_router(router)
