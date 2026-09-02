"""Explainable AI/ML analysis: rule-based indicators + Isolation Forest anomaly
detection + combined risk scoring.

Every scored artifact carries its `indicators` list so each score can be
explained (no black-box decisions).
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field

from sklearn.ensemble import IsolationForest

from app.models.models import RiskLevel

# ---------------------------------------------------------------------------
# Rule-based suspicious indicators (explainable)
# ---------------------------------------------------------------------------

SUSPICIOUS_EXTENSIONS = (".exe", ".bat", ".cmd", ".ps1", ".vbs", ".scr", ".dll")
SUSPICIOUS_PATH_HINTS = ("temp", "tmp", "appdata", "downloads", "public", "perflogs")
HIGH_RISK_PORTS = {4444, 5555, 1337, 31337, 6667, 9999}  # common C2/backdoor ports in training material
OFF_HOURS = range(0, 6)  # 00:00–05:59 local


@dataclass
class RuleResult:
    indicators: list[str] = field(default_factory=list)
    hits: int = 0


def rule_indicators(artifact) -> RuleResult:
    """Evaluate explainable rules against one artifact. Returns human-readable hits."""
    result = RuleResult()
    meta = artifact.metadata_json or {}
    value_low = (artifact.value or "").lower()

    event_type = artifact.artifact_type
    hour = artifact.timestamp.hour if artifact.timestamp else None

    # 1. Login at unusual hours (only meaningful for login-type events)
    if event_type in ("login", "failed_login") and hour is not None and hour in OFF_HOURS:
        result.indicators.append(f"login activity at unusual hour ({hour:02d}:00)")

    # 2. Multiple failed login attempts (counted per artifact via metadata flag)
    if event_type == "failed_login":
        result.indicators.append("failed login attempt")
        if str(meta.get("burst", "")).lower() == "true":
            result.indicators.append("part of a burst of failed logins")

    # 3. Unknown/unexpected IP: private vs external
    ip = meta.get("ip") or meta.get("dst_ip")
    if ip:
        parts = ip.split(".")
        is_private = (
            len(parts) == 4
            and (parts[0] == "10" or (parts[0] == "192" and parts[1] == "168")
                 or (parts[0] == "172" and parts[1].isdigit() and 16 <= int(parts[1]) <= 31)
                 or parts[0] == "127")
        )
        if not is_private and event_type in ("network_connection", "download", "login"):
            result.indicators.append(f"external IP address {ip}")

    # 4. Suspicious file extension / location
    file_path = meta.get("file") or ""
    if file_path and file_path.lower().endswith(SUSPICIOUS_EXTENSIONS):
        result.indicators.append(f"suspicious file extension ({file_path.rsplit('.', 1)[-1]})")
    if any(hint in file_path.lower() for hint in SUSPICIOUS_PATH_HINTS):
        result.indicators.append("executable-like file in user-writable directory")

    # 5. Rare process: low global frequency is added later in extract_features
    process = meta.get("process") or ""
    if process:
        name_low = process.lower()
        if name_low.endswith((".bat", ".ps1", ".vbs")):
            result.indicators.append("script-based process")

    # 6. High-risk ports
    port_raw = meta.get("port")
    if port_raw and str(port_raw).isdigit() and int(port_raw) in HIGH_RISK_PORTS:
        result.indicators.append(f"connection on commonly abused port {port_raw}")

    # 7. Download followed by execution is handled at correlation stage.
    return result


# ---------------------------------------------------------------------------
# Feature extraction for Isolation Forest
# ---------------------------------------------------------------------------

def extract_features(artifacts) -> list[list[float]]:
    """Numeric features per artifact (order preserved)."""
    # Global frequencies for rarity computation.
    value_counts: dict[str, int] = {}
    type_counts: dict[str, int] = {}
    for a in artifacts:
        value_counts[a.value] = value_counts.get(a.value, 0) + 1
        type_counts[a.artifact_type] = type_counts.get(a.artifact_type, 0) + 1

    features: list[list[float]] = []
    for a in artifacts:
        meta = a.metadata_json or {}
        hour = a.timestamp.hour if a.timestamp else 12
        is_event = 1.0 if a.artifact_type not in ("user", "ip", "file", "process") else 0.0
        is_failed = 1.0 if a.artifact_type == "failed_login" else 0.0
        is_off_hours = 1.0 if hour in OFF_HOURS else 0.0
        external_ip = 0.0
        ip = meta.get("ip") or meta.get("dst_ip")
        if ip:
            parts = ip.split(".")
            private = len(parts) == 4 and (
                parts[0] == "10"
                or (parts[0] == "192" and parts[1] == "168")
                or (parts[0] == "172" and parts[1].isdigit() and 16 <= int(parts[1]) <= 31)
                or parts[0] == "127"
            )
            external_ip = 0.0 if private else 1.0
        suspicious_ext = 1.0 if (meta.get("file") or "").lower().endswith(SUSPICIOUS_EXTENSIONS) else 0.0
        value_rarity = 1.0 / math.sqrt(value_counts.get(a.value, 1))
        type_rarity = 1.0 / math.sqrt(type_counts.get(a.artifact_type, 1))
        features.append([
            is_event,
            is_failed,
            is_off_hours,
            external_ip,
            suspicious_ext,
            value_rarity,
            type_rarity,
            float(hour),
        ])
    return features


# ---------------------------------------------------------------------------
# Anomaly detection + combined scoring
# ---------------------------------------------------------------------------

def _sigmoid(x: float) -> float:
    return 1.0 / (1.0 + math.exp(-x))


def anomaly_scores(artifacts) -> list[float]:
    """Isolation Forest decision scores normalized to 0..1 (1 = most anomalous)."""
    if not artifacts:
        return []
    X = extract_features(artifacts)
    if len(X) < 10:
        # Too little data for a meaningful forest; fall back to neutral-low scores.
        return [0.2] * len(X)
    model = IsolationForest(n_estimators=100, contamination=0.12, random_state=42)
    raw = -model.fit(X).decision_function(X)  # higher = more anomalous
    lo, hi = min(raw), max(raw)
    spread = (hi - lo) or 1.0
    return [round(0.2 + 0.8 * (v - lo) / spread, 4) for v in raw]


def risk_level_for(risk_score: float) -> str:
    if risk_score >= 75:
        return RiskLevel.CRITICAL.value
    if risk_score >= 50:
        return RiskLevel.HIGH.value
    if risk_score >= 25:
        return RiskLevel.MEDIUM.value
    return RiskLevel.LOW.value


def analyze_artifacts(artifacts) -> None:
    """Score artifacts in place: sets anomaly_score, risk_score, risk_level, indicators."""
    scores = anomaly_scores(artifacts)
    for artifact, anomaly in zip(artifacts, scores):
        rules = rule_indicators(artifact)
        artifact.anomaly_score = anomaly
        n_hits = len(rules.indicators)
        rule_component = min(1.0, n_hits / 4.0)
        risk = 100.0 * (0.45 * anomaly + 0.55 * rule_component)
        # Small boost for event artifacts that chain suspicious verbs in one record.
        if artifact.artifact_type in ("execution", "download", "network_connection") and n_hits:
            risk = min(100.0, risk + 5.0)
        artifact.risk_score = round(risk, 2)
        artifact.risk_level = risk_level_for(artifact.risk_score)
        artifact.indicators = rules.indicators or ["no suspicious indicators matched"]
