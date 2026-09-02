import { useEffect, useMemo, useState } from "react";
import { fetchArtifacts } from "../api";
import { useInvestigation } from "../state/InvestigationContext";
import type { Artifact } from "../types";

export default function ArtifactsPage() {
  const { investigation } = useInvestigation();
  const [artifacts, setArtifacts] = useState<Artifact[]>([]);
  const [riskFilter, setRiskFilter] = useState<string>("ALL");
  const [query, setQuery] = useState("");

  useEffect(() => {
    if (investigation) fetchArtifacts(investigation.id).then(setArtifacts);
  }, [investigation]);

  const filtered = useMemo(() => {
    return artifacts
      .filter((a) => (riskFilter === "ALL" ? true : a.risk_level === riskFilter))
      .filter((a) => (query ? a.value.toLowerCase().includes(query.toLowerCase()) : true));
  }, [artifacts, riskFilter, query]);

  if (!investigation) return <p className="muted">Select an investigation first.</p>;

  return (
    <div>
      <h1>Artifact Analysis</h1>
      <p className="muted small">
        Artifacts are ranked by explainable importance (risk, anomaly, indicators, connections, timeline role).
      </p>
      <div className="row filters">
        <select value={riskFilter} onChange={(e) => setRiskFilter(e.target.value)}>
          {["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"].map((r) => (
            <option key={r}>{r}</option>
          ))}
        </select>
        <input placeholder="Search values…" value={query} onChange={(e) => setQuery(e.target.value)} />
      </div>
      <table>
        <thead>
          <tr>
            <th>Rank</th>
            <th>Type</th>
            <th>Value</th>
            <th>Risk</th>
            <th>Risk score</th>
            <th>Anomaly</th>
            <th>Importance</th>
            <th>Why?</th>
          </tr>
        </thead>
        <tbody>
          {filtered.map((a) => (
            <tr key={a.id}>
              <td>#{a.priority_rank ?? "—"}</td>
              <td>
                <span className="pill">{a.artifact_type}</span>
              </td>
              <td className="mono small">{a.value}</td>
              <td>
                <span className={`risk ${a.risk_level.toLowerCase()}`}>{a.risk_level}</span>
              </td>
              <td>{a.risk_score.toFixed(1)}</td>
              <td>{a.anomaly_score.toFixed(2)}</td>
              <td>
                <b>{a.importance_score.toFixed(1)}</b>
              </td>
              <td className="small muted">{(a.indicators ?? []).join("; ")}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {filtered.length === 0 && <p className="muted">No artifacts. Upload evidence and run analysis.</p>}
    </div>
  );
}
