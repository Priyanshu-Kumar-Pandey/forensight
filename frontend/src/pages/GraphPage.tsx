import { useEffect, useRef, useState } from "react";
import cytoscape from "cytoscape";
import { fetchGraph } from "../api";
import { useInvestigation } from "../state/InvestigationContext";
import type { GraphData } from "../types";

const NODE_COLORS: Record<string, string> = {
  user: "#4f8cff",
  ip: "#9a6bff",
  file: "#e0a63a",
  process: "#2fb6a8",
  event: "#8aa0b8",
};

const RISK_COLORS: Record<string, string> = {
  CRITICAL: "#e5484d",
  HIGH: "#f76b15",
  MEDIUM: "#f5d90a",
  LOW: "#30a46c",
};

export default function GraphPage() {
  const { investigation } = useInvestigation();
  const [graph, setGraph] = useState<GraphData | null>(null);
  const [selected, setSelected] = useState<{ label: string; type: string; risk: string; detail: string } | null>(
    null
  );
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (investigation) fetchGraph(investigation.id).then(setGraph);
  }, [investigation]);

  useEffect(() => {
    if (!graph || !containerRef.current) return;
    const cy = cytoscape({
      container: containerRef.current,
      elements: [
        ...graph.nodes.map((n) => ({
          data: {
            id: n.id,
            label: n.label,
            color: NODE_COLORS[n.type] ?? NODE_COLORS.event,
            border: RISK_COLORS[n.risk_level] ?? "#30a46c",
            nodeType: n.type,
            risk: n.risk_level,
            detail: n.detail,
          },
        })),
        ...graph.edges.map((e) => ({
          data: {
            id: e.id,
            source: e.source,
            target: e.target,
            label: e.relationship_type.replace(/_/g, " "),
            weight: String(e.confidence_score),
          },
        })),
      ],
      style: [
        {
          selector: "node",
          style: {
            "background-color": "data(color)",
            "border-width": 3,
            "border-color": "data(border)",
            label: "data(label)",
            color: "#dce6f5",
            "font-size": 10,
            "text-valign": "bottom",
            "text-margin-y": 4,
            width: 28,
            height: 28,
          },
        },
        {
          selector: "edge",
          style: {
            width: 2,
            "line-color": "#3c4c63",
            "target-arrow-color": "#3c4c63",
            "target-arrow-shape": "triangle",
            "curve-style": "bezier",
            label: "data(label)",
            "font-size": 8,
            color: "#93a7c4",
            "text-background-color": "#0d1522",
            "text-background-opacity": 0.85,
            "text-background-padding": "2px",
          },
        },
      ],
      layout: { name: "cose", animate: false, padding: 30 } as never,
    });

    cy.on("tap", "node", (evt) => {
      const d = evt.target.data();
      setSelected({ label: d.label, type: d.nodeType, risk: d.risk, detail: d.detail });
    });

    return () => cy.destroy();
  }, [graph]);

  if (!investigation) return <p className="muted">Select an investigation first.</p>;

  return (
    <div>
      <h1>Relationship Graph</h1>
      <p className="muted small">
        Node border = risk level. Click a node for details. Drag to arrange, scroll to zoom.
      </p>
      <div className="legend">
        {Object.entries(NODE_COLORS).map(([t, c]) => (
          <span key={t}>
            <span className="dot" style={{ background: c }} /> {t}
          </span>
        ))}
        {Object.entries(RISK_COLORS).map(([r, c]) => (
          <span key={r}>
            <span className="dot ring" style={{ background: "transparent", borderColor: c }} /> {r}
          </span>
        ))}
      </div>
      <div className="graph-wrap">
        <div ref={containerRef} className="graph" />
        {selected && (
          <aside className="graph-side">
            <h3>Node details</h3>
            <p>
              <span className="pill">{selected.type}</span>{" "}
              <span className={`risk ${selected.risk.toLowerCase()}`}>{selected.risk}</span>
            </p>
            <p className="mono small">{selected.detail}</p>
          </aside>
        )}
      </div>
      {!graph || graph.nodes.length === 0 ? (
        <p className="muted">No graph data. Run analysis first.</p>
      ) : null}
    </div>
  );
}
