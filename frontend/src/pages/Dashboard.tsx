import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { createInvestigation, deleteInvestigation, fetchInvestigations, fetchArtifacts } from "../api";
import { useInvestigation } from "../state/InvestigationContext";
import type { Artifact, Investigation } from "../types";

export default function Dashboard() {
  const { investigation, setInvestigation } = useInvestigation();
  const [investigations, setInvestigations] = useState<Investigation[]>([]);
  const [stats, setStats] = useState<{ total: number; high: number; critical: number }>({
    total: 0,
    high: 0,
    critical: 0,
  });
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const navigate = useNavigate();

  async function refresh() {
    const list: Investigation[] = await fetchInvestigations();
    setInvestigations(list);
    if (investigation) {
      const arts: Artifact[] = await fetchArtifacts(investigation.id);
      setStats({
        total: arts.length,
        high: arts.filter((a) => a.risk_level === "HIGH").length,
        critical: arts.filter((a) => a.risk_level === "CRITICAL").length,
      });
    } else {
      setStats({ total: 0, high: 0, critical: 0 });
    }
  }

  useEffect(() => {
    refresh();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [investigation?.id]);

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault();
    if (!name.trim()) return;
    const inv = await createInvestigation(name.trim(), description.trim());
    setName("");
    setDescription("");
    setInvestigation(inv);
    localStorage.setItem("forensight_inv", String(inv.id));
    navigate(`/investigation/${inv.id}/evidence`);
  }

  async function handleDelete(id: number) {
    await deleteInvestigation(id);
    if (investigation?.id === id) {
      setInvestigation(null);
      localStorage.removeItem("forensight_inv");
    }
    refresh();
  }

  return (
    <div>
      <h1>Dashboard</h1>
      <div className="cards">
        <div className="card">
          <div className="card-value">{investigation ? investigation.name : "—"}</div>
          <div className="card-label">Selected investigation</div>
        </div>
        <div className="card">
          <div className="card-value">{stats.total}</div>
          <div className="card-label">Total artifacts</div>
        </div>
        <div className="card warn">
          <div className="card-value">{stats.high}</div>
          <div className="card-label">High risk artifacts</div>
        </div>
        <div className="card danger">
          <div className="card-value">{stats.critical}</div>
          <div className="card-label">Critical alerts</div>
        </div>
      </div>

      <div className="two-col">
        <section className="panel">
          <h2>New investigation</h2>
          <form onSubmit={handleCreate} className="stack">
            <input
              placeholder="Case name, e.g. Incident #2026-0901"
              value={name}
              onChange={(e) => setName(e.target.value)}
            />
            <input
              placeholder="Short description (optional)"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
            />
            <button className="btn btn-accent" type="submit">
              Create investigation
            </button>
          </form>
          <p className="muted small">
            Tip: click <b>Load demo investigation</b> in the top bar to explore the platform with a safe,
            synthetic incident dataset.
          </p>
        </section>

        <section className="panel">
          <h2>Investigations</h2>
          {investigations.length === 0 && <p className="muted">No investigations yet.</p>}
          <table>
            <thead>
              <tr>
                <th>#</th>
                <th>Name</th>
                <th>Status</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {investigations.map((i) => (
                <tr key={i.id} className={investigation?.id === i.id ? "selected" : ""}>
                  <td>{i.id}</td>
                  <td>{i.name}</td>
                  <td>
                    <span className={`pill ${i.status === "analyzed" ? "ok" : ""}`}>{i.status}</span>
                  </td>
                  <td className="row-actions">
                    <button
                      className="btn btn-small"
                      onClick={() => {
                        setInvestigation(i);
                        localStorage.setItem("forensight_inv", String(i.id));
                      }}
                    >
                      Select
                    </button>
                    <button className="btn btn-small btn-danger" onClick={() => handleDelete(i.id)}>
                      Delete
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      </div>
    </div>
  );
}
