"""Investigation report generation.

Produces a JSON report structure and a standalone HTML report. The HTML clearly
distinguishes VERIFIED FACTS (extracted from evidence) from AI INTERPRETATION.
Architecture allows a PDF exporter to reuse the same JSON payload later.
"""
from __future__ import annotations

import html as html_mod
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.models.models import (
    Artifact,
    Evidence,
    Insight,
    Investigation,
    Relationship,
    TimelineEvent,
)

SECTION_ORDER = [
    "executive_summary",
    "key_findings",
    "suspicious_activity",
    "evidence_connections",
    "possible_incident_sequence",
]

SECTION_TITLES = {
    "executive_summary": "Executive Summary",
    "key_findings": "Key Findings (verified facts)",
    "suspicious_activity": "Suspicious Activity",
    "evidence_connections": "Evidence Connections",
    "possible_incident_sequence": "Possible Incident Sequence (AI interpretation)",
}


def build_report_data(db: Session, investigation: Investigation) -> dict:
    evidence = list(investigation.evidence)
    artifacts = (
        db.query(Artifact)
        .join(Evidence, Artifact.evidence_id == Evidence.id)
        .filter(Evidence.investigation_id == investigation.id)
        .order_by(Artifact.importance_score.desc())
        .all()
    )
    timeline = (
        db.query(TimelineEvent)
        .filter(TimelineEvent.investigation_id == investigation.id)
        .order_by(TimelineEvent.timestamp)
        .all()
    )
    insights = (
        db.query(Insight)
        .filter(Insight.investigation_id == investigation.id)
        .all()
    )
    insights.sort(key=lambda i: SECTION_ORDER.index(i.section) if i.section in SECTION_ORDER else 99)
    relationships = (
        db.query(Relationship)
        .filter(Relationship.investigation_id == investigation.id)
        .order_by(Relationship.confidence_score.desc())
        .limit(25)
        .all()
    )

    return {
        "investigation": investigation,
        "generated_at": datetime.now(timezone.utc),
        "evidence": evidence,
        "artifacts": artifacts,
        "timeline": timeline,
        "insights": insights,
        "relationships": relationships,
    }


def render_html(data: dict) -> str:
    e = html_mod.escape
    inv: Investigation = data["investigation"]
    rows = []

    rows.append(f"<h1>ForenSight Investigation Report</h1>")
    rows.append(f"<p class='muted'>Investigation: <b>{e(inv.name)}</b> &mdash; {e(inv.description or 'no description')}<br>"
                f"Generated: {data['generated_at']:%Y-%m-%d %H:%M:%S} UTC</p>")

    # Evidence summary
    rows.append("<h2>1. Evidence Summary</h2><table><tr><th>File</th><th>Type</th><th>Size (B)</th><th>SHA-256</th><th>Uploaded</th></tr>")
    for ev in data["evidence"]:
        rows.append(f"<tr><td>{e(ev.file_name)}</td><td>{e(ev.file_type)}</td><td>{ev.file_size}</td>"
                    f"<td class='mono'>{e(ev.sha256[:32])}&hellip;</td><td>{ev.uploaded_at:%Y-%m-%d %H:%M:%S}</td></tr>")
    rows.append("</table>")

    # Important artifacts
    rows.append("<h2>2. Important Artifacts (ranked)</h2><table><tr><th>Rank</th><th>Type</th><th>Value</th><th>Risk</th><th>Score</th><th>Indicators</th></tr>")
    for a in data["artifacts"][:15]:
        inds = "; ".join(a.indicators or []) if a.indicators else "-"
        rows.append(f"<tr><td>{a.priority_rank or '-'}</td><td>{e(a.artifact_type)}</td>"
                    f"<td>{e(a.value[:90])}</td><td><span class='risk {a.risk_level.lower()}'>{a.risk_level}</span></td>"
                    f"<td>{a.importance_score}</td><td>{e(inds[:140])}</td></tr>")
    rows.append("</table>")

    # Timeline
    rows.append("<h2>3. Timeline</h2><table><tr><th>Timestamp (UTC)</th><th>Event</th><th>Risk</th><th>Flags</th></tr>")
    for t in data["timeline"]:
        flags = ", ".join(t.flags) if t.flags else "-"
        rows.append(f"<tr><td>{t.timestamp:%Y-%m-%d %H:%M:%S}</td><td>{e(t.description)}</td>"
                    f"<td><span class='risk {t.risk_level.lower()}'>{t.risk_level}</span></td><td>{e(flags)}</td></tr>")
    rows.append("</table>")

    # Relationships
    rows.append("<h2>4. Evidence Relationships</h2><table><tr><th>Type</th><th>Source &rarr; Target</th><th>Confidence</th><th>Explanation</th></tr>")
    art_map = {a.id: a for a in data["artifacts"]}
    for r in data["relationships"]:
        s = art_map.get(r.source_artifact_id)
        t = art_map.get(r.target_artifact_id)
        s_txt = e(f"{s.artifact_type}:{s.value[:40]}") if s else str(r.source_artifact_id)
        t_txt = e(f"{t.artifact_type}:{t.value[:40]}") if t else str(r.target_artifact_id)
        rows.append(f"<tr><td>{e(r.relationship_type)}</td><td>{s_txt} &rarr; {t_txt}</td>"
                    f"<td>{r.confidence_score:.0%}</td><td>{e(r.explanation[:140])}</td></tr>")
    rows.append("</table>")

    # Insights (AI)
    rows.append("<h2>5. AI Investigation Insights</h2>")
    rows.append("<p class='ai-note'>Everything in this section is <b>AI-generated interpretation</b> "
                "based on rule-based analysis. It is not verified forensic fact.</p>")
    for ins in data["insights"]:
        title = SECTION_TITLES.get(ins.section, ins.section)
        support = ", ".join(str(i) for i in (ins.supporting_artifact_ids or [])[:8]) or "-"
        rows.append(f"<div class='insight'><h3>{e(title)}</h3><p>{e(ins.text)}</p>"
                    f"<p class='muted'>Supporting artifact IDs: {e(support)} &middot; "
                    f"confidence {ins.confidence:.0%} &middot; generator: {e(ins.generated_by)}</p></div>")

    # Conclusion
    rows.append("<h2>6. Conclusion</h2><p class='muted'>This report was generated automatically by ForenSight. "
                "Facts in sections 1&ndash;4 are extracted directly from uploaded evidence; section 5 contains "
                "AI-generated interpretation and should be validated by a human investigator before being "
                "treated as fact.</p>")

    css = """
    body { font-family: 'Segoe UI', Arial, sans-serif; max-width: 980px; margin: 24px auto; padding: 0 16px; color: #1a2332; }
    h1 { border-bottom: 3px solid #0e7c66; padding-bottom: 8px; }
    h2 { color: #0e7c66; margin-top: 28px; }
    table { border-collapse: collapse; width: 100%; margin: 8px 0 16px; font-size: 13px; }
    th { background: #10233f; color: #fff; text-align: left; padding: 6px 8px; }
    td { border: 1px solid #d7dee8; padding: 5px 8px; vertical-align: top; }
    tr:nth-child(even) td { background: #f4f7fb; }
    .risk { font-weight: 700; padding: 2px 8px; border-radius: 10px; font-size: 11px; }
    .risk.low { background: #e2f3e8; color: #1c7c3c; }
    .risk.medium { background: #fff3d6; color: #9a6b00; }
    .risk.high { background: #ffe0d6; color: #c2410c; }
    .risk.critical { background: #ffd6d6; color: #b91c1c; }
    .insight { border-left: 4px solid #6d5cd3; padding: 8px 14px; margin: 10px 0; background: #f6f4ff; }
    .muted { color: #5b6b7f; font-size: 12px; }
    .ai-note { background: #fff8e6; border: 1px solid #e6c96a; padding: 8px 12px; border-radius: 6px; }
    .mono { font-family: Consolas, monospace; }
    """

    body = "\n".join(rows)
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>ForenSight Report &mdash; {e(inv.name)}</title>
<style>{css}</style>
</head>
<body>
{body}
</body>
</html>"""
