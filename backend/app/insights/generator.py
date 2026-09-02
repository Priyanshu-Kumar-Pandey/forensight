"""AI Investigation Insights engine (deterministic, explainable MVP).

Rule-based generator that turns artifacts + relationships + timeline events
into a human-readable investigation summary. Rules:

- Never invent facts: every insight cites the artifact IDs that support it.
- Clearly separate verified facts from interpretation ("suggests", "possible").
- Modular: an LLM-backed generator can be added later behind the same API.
"""
from __future__ import annotations

from collections import Counter

from sqlalchemy.orm import Session

from app.models.models import Artifact, Insight, Relationship, TimelineEvent


def _fmt_users(artifacts: list[Artifact]) -> str:
    users = sorted({(a.metadata_json or {}).get("user") for a in artifacts if (a.metadata_json or {}).get("user")})
    return ", ".join(users) if users else "unknown user(s)"


def generate_insights(
    investigation_id: int,
    artifacts: list[Artifact],
    relationships: list[Relationship],
    timeline: list[TimelineEvent],
    db: Session,
) -> list[Insight]:
    insights: list[Insight] = []

    def add(section: str, text: str, support: list[int], confidence: float) -> None:
        insights.append(
            Insight(
                investigation_id=investigation_id,
                section=section,
                text=text,
                supporting_artifact_ids=support,
                confidence=round(confidence, 2),
                generated_by="rules_v1",
            )
        )

    event_types = Counter(a.artifact_type for a in artifacts if a.artifact_type not in ("user", "ip", "file", "process"))
    critical = [a for a in artifacts if a.risk_level == "CRITICAL"]
    high = [a for a in artifacts if a.risk_level == "HIGH"]
    risky = critical + high
    risky.sort(key=lambda a: a.importance_score, reverse=True)

    # ---------------- Executive summary ----------------
    exec_parts = [
        f"{len(artifacts)} artifacts extracted from evidence, "
        f"{len(relationships)} cross-artifact relationships and {len(timeline)} timeline events reconstructed."
    ]
    if risky:
        exec_parts.append(
            f"{len(risky)} artifacts were rated HIGH or CRITICAL risk; the top ranked item is "
            f"'{risky[0].value[:80]}' (importance {risky[0].importance_score})."
        )
    else:
        exec_parts.append("No artifacts exceeded the HIGH risk threshold in this dataset.")
    add(
        "executive_summary",
        "Investigation Summary: " + " ".join(exec_parts),
        [a.id for a in risky[:5]],
        0.9,
    )

    # ---------------- Key findings (facts) ----------------
    facts: list[str] = []
    support: list[int] = []
    if event_types.get("failed_login"):
        facts.append(f"{event_types['failed_login']} failed login attempts were recorded.")
        support += [a.id for a in artifacts if a.artifact_type == "failed_login"][:5]
    if event_types.get("download"):
        files = sorted({(a.metadata_json or {}).get("file") for a in artifacts
                        if a.artifact_type == "download" and (a.metadata_json or {}).get("file")})
        facts.append(f"{event_types['download']} download event(s) recorded"
                     + (f" involving {', '.join(f or '?' for f in files)}" if files else "") + ".")
        support += [a.id for a in artifacts if a.artifact_type == "download"][:5]
    if event_types.get("execution"):
        procs = sorted({(a.metadata_json or {}).get("process") for a in artifacts
                        if a.artifact_type == "execution" and (a.metadata_json or {}).get("process")})
        facts.append(f"{event_types['execution']} process execution event(s) recorded"
                     + (f" ({', '.join(p or '?' for p in procs)})" if procs else "") + ".")
        support += [a.id for a in artifacts if a.artifact_type == "execution"][:5]
    if event_types.get("network_connection"):
        ext_ips = set()
        for a in artifacts:
            if a.artifact_type != "network_connection":
                continue
            for key in ("dst_ip", "ip"):
                ip = (a.metadata_json or {}).get(key)
                if ip and not ip.startswith(("10.", "192.168.", "127.")):
                    ext_ips.add(ip)
        facts.append("External network connection(s) observed"
                     + (f" to {', '.join(sorted(ext_ips))}" if ext_ips else "") + ".")
        support += [a.id for a in artifacts if a.artifact_type == "network_connection"][:5]
    if facts:
        add("key_findings", "Key Findings (extracted from evidence): " + " ".join(facts), support[:15], 0.95)

    # ---------------- Suspicious activity ----------------
    susp_lines: list[str] = []
    susp_support: list[int] = []
    bursts = [a for a in artifacts if a.artifact_type == "failed_login"
              and str((a.metadata_json or {}).get("burst", "")).lower() == "true"]
    if bursts:
        susp_lines.append(
            f"A burst of {len(bursts)} failed login attempts was detected within a 10 minute window "
            f"(users: {_fmt_users(bursts)})."
        )
        susp_support += [a.id for a in bursts[:5]]
    off_hours = [a for a in artifacts if a.timestamp and a.timestamp.hour < 6
                 and a.artifact_type in ("login", "failed_login")]
    if off_hours:
        susp_lines.append("Login activity occurred during unusual hours (00:00-06:00).")
        susp_support += [a.id for a in off_hours[:5]]
    for a in risky[:3]:
        if a.indicators and a.indicators != ["no suspicious indicators matched"]:
            susp_lines.append(f"'{a.value[:70]}' flagged: {'; '.join(a.indicators[:3])}.")
            susp_support.append(a.id)
    if susp_lines:
        add("suspicious_activity", "Suspicious Activity: " + " ".join(susp_lines), susp_support[:15], 0.8)

    # ---------------- Evidence connections ----------------
    strong = sorted(relationships, key=lambda r: r.confidence_score, reverse=True)[:5]
    if strong:
        conn_lines = [f"{r.relationship_type.replace('_', ' ')} (confidence {r.confidence_score:.0%}): {r.explanation}"
                      for r in strong]
        add("evidence_connections",
            "Evidence Connections: strongest cross-artifact links — " + " ".join(conn_lines),
            [r.source_artifact_id for r in strong] + [r.target_artifact_id for r in strong], 0.85)

    # ---------------- Possible incident sequence ----------------
    flags = Counter()
    for ev in timeline:
        for f in ev.flags or []:
            flags[f] += 1
    seq_lines: list[str] = []
    if flags.get("failed_logins_then_success"):
        seq_lines.append("failed login attempts were followed by a successful login")
    if flags.get("download_then_execute"):
        seq_lines.append("a downloaded file was executed shortly afterwards")
    if flags.get("execute_then_connect"):
        seq_lines.append("an executed process opened an external network connection")
    if seq_lines:
        text = ("Possible Incident Sequence (AI interpretation, not verified fact): within the timeline, "
                + "; then ".join(seq_lines)
                + ". The sequence of events suggests potentially malicious activity consistent with "
                "credential compromise followed by payload execution and possible command-and-control "
                "communication. Recommend correlating with additional evidence sources.")
        seq_support = [ev.artifact_id for ev in timeline if ev.flags and ev.artifact_id][:10]
        add("possible_incident_sequence", text, seq_support, 0.7)
    else:
        add("possible_incident_sequence",
            "No suspicious multi-step sequences (download→execute, failed-login→login, "
            "execute→connect) were detected in the reconstructed timeline.",
            [], 0.9)

    for ins in insights:
        db.add(ins)
    db.flush()
    return insights
