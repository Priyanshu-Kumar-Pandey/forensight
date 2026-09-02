import { useEffect, useState } from "react";
import { fetchInsights } from "../api";
import { useInvestigation } from "../state/InvestigationContext";
import type { Insight } from "../types";

const TITLES: Record<string, string> = {
  executive_summary: "Executive Summary",
  key_findings: "Key Findings (verified facts)",
  suspicious_activity: "Suspicious Activity",
  evidence_connections: "Evidence Connections",
  possible_incident_sequence: "Possible Incident Sequence (AI interpretation)",
};

export default function InsightsPage() {
  const { investigation } = useInvestigation();
  const [insights, setInsights] = useState<Insight[]>([]);

  useEffect(() => {
    if (investigation) fetchInsights(investigation.id).then(setInsights);
  }, [investigation]);

  if (!investigation) return <p className="muted">Select an investigation first.</p>;

  return (
    <div>
      <h1>AI Investigation Insights</h1>
      <div className="ai-banner">
        ⚠️ Insights are <b>AI-generated interpretation</b> (rule-based MVP). Every claim lists the artifacts that
        support it — validate before treating as fact.
      </div>
      {insights.map((ins) => (
        <section className="panel insight" key={ins.id}>
          <h2>{TITLES[ins.section] ?? ins.section}</h2>
          <p>{ins.text}</p>
          <p className="muted small">
            Supporting artifacts: {(ins.supporting_artifact_ids ?? []).join(", ") || "—"} · confidence{" "}
            {(ins.confidence * 100).toFixed(0)}% · generator: {ins.generated_by}
          </p>
        </section>
      ))}
      {insights.length === 0 && <p className="muted">No insights yet. Run analysis first.</p>}
    </div>
  );
}
