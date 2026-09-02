import axios from "axios";

const api = axios.create({ baseURL: "/api" });

// --- lightweight session (MVP auth) ---
const KEY = "forensight_session";
export interface SessionUser {
  username: string;
}

export function getSession(): SessionUser | null {
  try {
    const raw = localStorage.getItem(KEY);
    return raw ? (JSON.parse(raw) as SessionUser) : null;
  } catch {
    return null;
  }
}

export function setSession(username: string) {
  localStorage.setItem(KEY, JSON.stringify({ username }));
}

export function clearSession() {
  localStorage.removeItem(KEY);
}

// --- API calls ---

export async function fetchInvestigations() {
  const r = await api.get("/investigations");
  return r.data;
}

export async function fetchInvestigation(id: number) {
  const r = await api.get(`/investigations/${id}`);
  return r.data;
}

export async function createInvestigation(name: string, description: string) {
  const r = await api.post("/investigations", { name, description });
  return r.data;
}

export async function deleteInvestigation(id: number) {
  const r = await api.delete(`/investigations/${id}`);
  return r.data;
}

export async function fetchEvidence(investigationId: number) {
  const r = await api.get("/evidence", { params: { investigation_id: investigationId } });
  return r.data;
}

export async function uploadEvidence(investigationId: number, file: File) {
  const form = new FormData();
  form.append("investigation_id", String(investigationId));
  form.append("file", file);
  const r = await api.post("/evidence/upload", form);
  return r.data;
}

export async function analyzeInvestigation(id: number) {
  const r = await api.post(`/investigations/${id}/analyze`);
  return r.data;
}

export async function fetchArtifacts(investigationId: number) {
  const r = await api.get(`/investigations/${investigationId}/artifacts`);
  return r.data;
}

export async function fetchTimeline(investigationId: number) {
  const r = await api.get(`/investigations/${investigationId}/timeline`);
  return r.data;
}

export async function fetchGraph(investigationId: number) {
  const r = await api.get(`/investigations/${investigationId}/graph`);
  return r.data;
}

export async function fetchInsights(investigationId: number) {
  const r = await api.get(`/investigations/${investigationId}/insights`);
  return r.data;
}

export async function fetchRelationships(investigationId: number) {
  const r = await api.get(`/investigations/${investigationId}/relationships`);
  return r.data;
}

export async function loadDemo() {
  const r = await api.post("/demo/load");
  return r.data;
}
