"""Pydantic schemas used by the API layer."""
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict

from app.models.models import RiskLevel


class InvestigationCreate(BaseModel):
    name: str
    description: str = ""


class InvestigationOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    description: str
    status: str
    created_at: datetime
    analyzed_at: datetime | None = None


class EvidenceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    investigation_id: int
    file_name: str
    file_type: str
    file_size: int
    sha256: str
    uploaded_at: datetime


class ArtifactOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    evidence_id: int
    artifact_type: str
    value: str
    timestamp: datetime | None
    source: str
    line_number: int | None
    metadata_json: dict = {}

    anomaly_score: float
    risk_score: float
    risk_level: str
    indicators: list = []
    importance_score: float
    priority_rank: int | None = None


class RelationshipOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    source_artifact_id: int
    target_artifact_id: int
    relationship_type: str
    confidence_score: float
    explanation: str


class GraphNode(BaseModel):
    id: str
    label: str
    type: str
    risk_level: str
    detail: str = ""


class GraphEdge(BaseModel):
    id: str
    source: str
    target: str
    relationship_type: str
    confidence_score: float


class GraphOut(BaseModel):
    nodes: list[GraphNode]
    edges: list[GraphEdge]


class TimelineEventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    artifact_id: int | None
    timestamp: datetime
    event_type: str
    description: str
    risk_level: str
    flags: list = []


class InsightOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    section: str
    text: str
    supporting_artifact_ids: list = []
    confidence: float
    generated_by: str


class AnalysisSummary(BaseModel):
    investigation_id: int
    total_artifacts: int
    total_relationships: int
    total_timeline_events: int
    risk_counts: dict[str, int]
    top_artifacts: list[ArtifactOut]


class ReportOut(BaseModel):
    investigation: InvestigationOut
    generated_at: datetime
    evidence: list[EvidenceOut]
    important_artifacts: list[ArtifactOut]
    timeline: list[TimelineEventOut]
    insights: list[InsightOut]
    html_url: str
