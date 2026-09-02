import { useCallback, useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { analyzeInvestigation, fetchEvidence, uploadEvidence } from "../api";
import { useInvestigation } from "../state/InvestigationContext";
import type { Evidence } from "../types";

export default function EvidencePage() {
  const { investigation } = useInvestigation();
  const [evidence, setEvidence] = useState<Evidence[]>([]);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const fileRef = useRef<HTMLInputElement>(null);
  const navigate = useNavigate();

  const refresh = useCallback(async () => {
    if (!investigation) return;
    setEvidence(await fetchEvidence(investigation.id));
  }, [investigation]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  if (!investigation) return <p className="muted">Select an investigation first.</p>;

  async function handleUpload() {
    const inv = investigation;
    const file = fileRef.current?.files?.[0];
    if (!inv) return;
    if (!file) {
      setMessage("Choose a CSV, JSON or TXT file first.");
      return;
    }
    setBusy(true);
    setMessage("");
    try {
      await uploadEvidence(inv.id, file);
      if (fileRef.current) fileRef.current.value = "";
      await refresh();
      setMessage("Evidence uploaded and hashed (SHA-256).");
    } catch (err: unknown) {
      const detail =
        (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail ?? "Upload failed.";
      setMessage(detail);
    } finally {
      setBusy(false);
    }
  }

  async function handleAnalyze() {
    const inv = investigation;
    if (!inv) return;
    setBusy(true);
    setMessage("");
    try {
      const summary = await analyzeInvestigation(inv.id);
      setMessage(
        `Analysis complete: ${summary.total_artifacts} artifacts, ` +
          `${summary.total_relationships} relationships, ${summary.total_timeline_events} timeline events.`
      );
      navigate(`/investigation/${inv.id}/artifacts`);
    } catch (err: unknown) {
      const detail =
        (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail ?? "Analysis failed.";
      setMessage(detail);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div>
      <h1>Evidence — {investigation.name}</h1>
      <div className="two-col">
        <section className="panel">
          <h2>Upload evidence</h2>
          <p className="muted small">
            Accepted: .csv, .json, .txt, .log (max 25 MB). Files are hashed and stored read-only — they are
            never executed.
          </p>
          <input type="file" ref={fileRef} accept=".csv,.json,.txt,.log" />
          <div className="row">
            <button className="btn btn-accent" onClick={handleUpload} disabled={busy}>
              Upload
            </button>
            <button className="btn btn-outline" onClick={handleAnalyze} disabled={busy}>
              Run full analysis
            </button>
          </div>
          {message && <p className="notice">{message}</p>}
        </section>

        <section className="panel">
          <h2>Evidence files ({evidence.length})</h2>
          <table>
            <thead>
              <tr>
                <th>File</th>
                <th>Type</th>
                <th>Size</th>
                <th>SHA-256</th>
                <th>Uploaded</th>
              </tr>
            </thead>
            <tbody>
              {evidence.map((ev) => (
                <tr key={ev.id}>
                  <td>{ev.file_name}</td>
                  <td>
                    <span className="pill">{ev.file_type}</span>
                  </td>
                  <td>{(ev.file_size / 1024).toFixed(1)} KB</td>
                  <td className="mono small">{ev.sha256.slice(0, 16)}…</td>
                  <td className="small">{new Date(ev.uploaded_at).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      </div>
    </div>
  );
}
