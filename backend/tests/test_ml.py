"""Tests for ML scoring and ranking (explainability + risk levels)."""
from __future__ import annotations

from datetime import datetime, timezone

from app.ml.scoring import analyze_artifacts, risk_level_for
from app.ml.ranking import rank_artifacts
from app.models.models import Artifact


def make_artifact(**overrides) -> Artifact:
    base = dict(
        evidence_id=1,
        artifact_type="login",
        value="login user=jdoe",
        timestamp=datetime(2026, 8, 20, 2, 15, 0, tzinfo=timezone.utc),
        source="auth.csv",
        line_number=2,
        metadata_json={"user": "jdoe", "ip": "203.0.113.45"},
    )
    base.update(overrides)
    return Artifact(**base)


def test_risk_level_thresholds():
    assert risk_level_for(10) == "LOW"
    assert risk_level_for(30) == "MEDIUM"
    assert risk_level_for(60) == "HIGH"
    assert risk_level_for(90) == "CRITICAL"


def test_analyze_attaches_scores_and_explainable_indicators():
    artifacts = [
        make_artifact(),  # off-hours login from external IP -> indicators
        make_artifact(
            artifact_type="login",
            value="login user=asmith",
            timestamp=datetime(2026, 8, 20, 14, 0, 0, tzinfo=timezone.utc),
            metadata_json={"user": "asmith", "ip": "10.0.0.23"},
        ),
    ]
    analyze_artifacts(artifacts)

    for a in artifacts:
        assert 0.0 <= a.anomaly_score <= 1.0
        assert 0.0 <= a.risk_score <= 100.0
        assert a.risk_level in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
        assert isinstance(a.indicators, list) and a.indicators  # always explained

    suspicious = artifacts[0]
    assert any("unusual hour" in i for i in suspicious.indicators)
    assert any("external IP" in i for i in suspicious.indicators)
    assert suspicious.risk_score > artifacts[1].risk_score


def test_suspicious_extension_and_port_rules():
    artifacts = [
        make_artifact(
            artifact_type="download",
            value="download file=C:/Users/jdoe/Downloads/tool.exe",
            metadata_json={"file": "C:/Users/jdoe/Downloads/tool.exe", "user": "jdoe"},
        ),
        make_artifact(
            artifact_type="network_connection",
            value="connect dst=198.51.100.23 port=4444",
            metadata_json={"dst_ip": "198.51.100.23", "port": "4444"},
        ),
    ]
    analyze_artifacts(artifacts)
    assert any("suspicious file extension" in i for i in artifacts[0].indicators)
    assert any("abused port" in i for i in artifacts[1].indicators)


def test_rank_orders_and_explains():
    artifacts = [
        make_artifact(),  # high risk
        make_artifact(
            artifact_type="login",
            value="login user=asmith",
            timestamp=datetime(2026, 8, 20, 14, 0, 0, tzinfo=timezone.utc),
            metadata_json={"user": "asmith", "ip": "10.0.0.23"},
        ),
    ]
    analyze_artifacts(artifacts)
    ranked = rank_artifacts(artifacts, relationships=[])

    assert [a.priority_rank for a in ranked] == [1, 2]
    assert ranked[0].importance_score >= ranked[1].importance_score
    assert all(0.0 <= a.importance_score <= 100.0 for a in ranked)


def test_isolation_forest_runs_on_larger_dataset():
    # >10 artifacts so the Isolation Forest path (not the fallback) is used.
    artifacts = [
        make_artifact(
            value=f"event number {i}",
            line_number=i,
            timestamp=datetime(2026, 8, 20, i % 24, 0, 0, tzinfo=timezone.utc),
        )
        for i in range(25)
    ]
    analyze_artifacts(artifacts)
    assert len({a.anomaly_score for a in artifacts}) > 1  # differentiated scores
