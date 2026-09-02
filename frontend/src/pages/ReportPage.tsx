import { useInvestigation } from "../state/InvestigationContext";

export default function ReportPage() {
  const { investigation } = useInvestigation();
  if (!investigation) return <p className="muted">Select an investigation first.</p>;

  return (
    <div>
      <h1>Investigation Report</h1>
      <p>
        The full report is generated server-side as a standalone HTML document, clearly separating verified
        facts (evidence, artifacts, timeline) from AI-generated interpretation.
      </p>
      <a
        className="btn btn-accent"
        href={`/api/investigations/${investigation.id}/report`}
        target="_blank"
        rel="noreferrer"
      >
        Open report for #{investigation.id} — {investigation.name}
      </a>
      <p className="muted small">Tip: print to PDF from the browser (Ctrl/Cmd+P) for distribution.</p>
    </div>
  );
}
