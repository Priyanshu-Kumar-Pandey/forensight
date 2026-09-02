"""Explainable artifact ranking.

importance_score = weighted combination of:
  risk score, anomaly score, suspicious indicator count, cross-reference
  count (connections to other suspicious artifacts), and timeline weight.
Every rank decision is returned with an explanation.
"""
from __future__ import annotations

from app.models.models import Artifact, RiskLevel

WEIGHTS = {
    "risk": 0.45,
    "anomaly": 0.20,
    "indicators": 0.15,
    "connections": 0.10,
    "timeline": 0.10,
}

EVENT_TYPES = {
    "login", "failed_login", "download", "file_creation",
    "execution", "network_connection", "logoff", "log_event",
}


def rank_artifacts(artifacts: list[Artifact], relationships: list | None = None) -> list[Artifact]:
    """Compute importance_score and priority_rank in place; returns sorted list."""
    if not artifacts:
        return []

    relationships = relationships or []
    conn_count: dict[int, int] = {}
    suspicious_ids = {a.id for a in artifacts if a.risk_level in ("HIGH", "CRITICAL")}
    for rel in relationships:
        if rel.source_artifact_id in suspicious_ids or rel.target_artifact_id in suspicious_ids:
            conn_count[rel.source_artifact_id] = conn_count.get(rel.source_artifact_id, 0) + 1
            conn_count[rel.target_artifact_id] = conn_count.get(rel.target_artifact_id, 0) + 1

    max_connections = max(conn_count.values()) if conn_count else 0

    for a in artifacts:
        n_indicators = 0 if a.indicators == ["no suspicious indicators matched"] else len(a.indicators)
        indicator_component = min(1.0, n_indicators / 4.0)
        conn_component = (conn_count.get(a.id, 0) / max_connections) if max_connections else 0.0
        timeline_component = 1.0 if (a.artifact_type in EVENT_TYPES and a.timestamp) else 0.0

        a.importance_score = round(
            100.0 * (
                WEIGHTS["risk"] * (a.risk_score / 100.0)
                + WEIGHTS["anomaly"] * a.anomaly_score
                + WEIGHTS["indicators"] * indicator_component
                + WEIGHTS["connections"] * conn_component
                + WEIGHTS["timeline"] * timeline_component
            ),
            2,
        )

    ordered = sorted(artifacts, key=lambda x: x.importance_score, reverse=True)
    for rank, a in enumerate(ordered, start=1):
        a.priority_rank = rank
    return ordered
