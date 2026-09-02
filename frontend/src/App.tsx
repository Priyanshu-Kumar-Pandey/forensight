import { useEffect, useState } from "react";
import { NavLink, Outlet, useNavigate } from "react-router-dom";
import {
  clearSession,
  getSession,
  fetchInvestigations,
  loadDemo,
} from "./api";
import { InvestigationContext } from "./state/InvestigationContext";
import type { Investigation } from "./types";

export default function App() {
  const [investigation, setInvestigation] = useState<Investigation | null>(null);
  const [investigations, setInvestigations] = useState<Investigation[]>([]);
  const [busy, setBusy] = useState(false);
  const navigate = useNavigate();
  const username = getSession()?.username ?? "analyst";

  async function refresh() {
    const list: Investigation[] = await fetchInvestigations();
    setInvestigations(list);
    return list;
  }

  useEffect(() => {
    refresh().then((list) => {
      const saved = localStorage.getItem("forensight_inv");
      const found = saved ? list.find((i) => String(i.id) === saved) : undefined;
      if (found) setInvestigation(found);
    });
  }, []);

  function selectInv(id: string) {
    const inv = investigations.find((i) => String(i.id) === id) ?? null;
    setInvestigation(inv);
    if (inv) localStorage.setItem("forensight_inv", String(inv.id));
    else localStorage.removeItem("forensight_inv");
  }

  async function handleLoadDemo() {
    setBusy(true);
    try {
      const data = await loadDemo();
      await refresh();
      const inv = await fetchInvestigation(data.investigation_id);
      setInvestigation(inv);
      localStorage.setItem("forensight_inv", String(inv.id));
    } finally {
      setBusy(false);
    }
  }

  async function fetchInvestigation(id: number) {
    const r = await fetch(`/api/investigations/${id}`).then((r) => r.json());
    return r as Investigation;
  }

  const invId = investigation?.id;
  const base = invId ? `/investigation/${invId}` : "";

  const navItems = [
    { to: "/", label: "Dashboard", end: true },
    { to: `${base}/evidence`, label: "Evidence" },
    { to: `${base}/artifacts`, label: "Artifacts" },
    { to: `${base}/timeline`, label: "Timeline" },
    { to: `${base}/graph`, label: "Graph" },
    { to: `${base}/insights`, label: "AI Insights" },
    { to: `${base}/report`, label: "Report" },
  ];

  return (
    <InvestigationContext.Provider value={{ investigation, setInvestigation }}>
      <div className="app">
        <header className="topbar">
          <div className="brand">
            <span className="logo">🛡️</span> ForenSight
            <span className="tagline">AI Forensic Investigation Platform</span>
          </div>
          <div className="topbar-right">
            <button className="btn btn-accent" onClick={handleLoadDemo} disabled={busy}>
              {busy ? "Loading demo…" : "Load demo investigation"}
            </button>
            <span className="user">{username}</span>
            <button
              className="btn btn-ghost"
              onClick={() => {
                clearSession();
                navigate("/login");
              }}
            >
              Logout
            </button>
          </div>
        </header>
        <div className="body">
          <aside className="sidebar">
            <label className="sidebar-label">Investigation</label>
            <select
              className="select"
              value={investigation?.id ?? ""}
              onChange={(e) => selectInv(e.target.value)}
            >
              <option value="">— select —</option>
              {investigations.map((i) => (
                <option key={i.id} value={i.id}>
                  #{i.id} {i.name}
                </option>
              ))}
            </select>
            <button className="btn btn-outline" onClick={() => navigate("/")}>
              + New investigation
            </button>
            <nav>
              {navItems.map((item) =>
                item.end || item.to === "/" ? (
                  <NavLink key={item.label} to={item.to} end className={({ isActive }) => (isActive ? "active" : "")}>
                    {item.label}
                  </NavLink>
                ) : (
                  <NavLink
                    key={item.label}
                    to={item.to}
                    className={({ isActive }) =>
                      `navlink ${isActive ? "active" : ""} ${!invId ? "disabled" : ""}`
                    }
                    onClick={(e) => {
                      if (!invId) e.preventDefault();
                    }}
                  >
                    {item.label}
                  </NavLink>
                )
              )}
            </nav>
          </aside>
          <main className="content">
            <Outlet />
          </main>
        </div>
      </div>
    </InvestigationContext.Provider>
  );
}
