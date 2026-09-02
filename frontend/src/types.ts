export type RiskLevel = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export interface Investigation {
  id: number;
  name: string;
  description: string;
  status: string;
  created_at: string;
  analyzed_at: string | null;
}

export interface Evidence {
  id: number;
  investigation_id: number;
  file_name: string;
  file_type: string;
  file_size: number;
  sha256: string;
  uploaded_at: string;
}

export interface Artifact {
  id: number;
  evidence_id: number;
  artifact_type: string;
  value: string;
  timestamp: string | null;
  source: string;
  line_number: number | null;
  metadata_json: Record<string, string>;
  anomaly_score: number;
  risk_score: number;
  risk_level: RiskLevel;
  indicators: string[];
  importance_score: number;
  priority_rank: number | null;
}

export interface Relationship {
  id: number;
  source_artifact_id: number;
  target_artifact_id: number;
  relationship_type: string;
  confidence_score: number;
  explanation: string;
}

export interface TimelineEvent {
  id: number;
  artifact_id: number | null;
  timestamp: string;
  event_type: string;
  description: string;
  risk_level: RiskLevel;
  flags: string[];
}

export interface GraphNode {
  id: string;
  label: string;
  type: string;
  risk_level: RiskLevel;
  detail: string;
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  relationship_type: string;
  confidence_score: number;
}

export interface GraphData {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface Insight {
  id: number;
  section: string;
  text: string;
  supporting_artifact_ids: number[];
  confidence: number;
  generated_by: string;
}

export interface AnalysisSummary {
  investigation_id: number;
  total_artifacts: number;
  total_relationships: number;
  total_timeline_events: number;
  risk_counts: Record<RiskLevel, number>;
  top_artifacts: Artifact[];
}
