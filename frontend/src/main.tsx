import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import App from "./App";
import Login from "./pages/Login";
import Dashboard from "./pages/Dashboard";
import EvidencePage from "./pages/EvidencePage";
import ArtifactsPage from "./pages/ArtifactsPage";
import TimelinePage from "./pages/TimelinePage";
import GraphPage from "./pages/GraphPage";
import InsightsPage from "./pages/InsightsPage";
import ReportPage from "./pages/ReportPage";
import { getSession } from "./api";
import "./styles.css";

function RequireAuth({ children }: { children: React.ReactNode }) {
  if (!getSession()) return <Navigate to="/login" replace />;
  return <>{children}</>;
}

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route
          path="/"
          element={
            <RequireAuth>
              <App />
            </RequireAuth>
          }
        >
          <Route index element={<Dashboard />} />
          <Route path="investigation/:invId/evidence" element={<EvidencePage />} />
          <Route path="investigation/:invId/artifacts" element={<ArtifactsPage />} />
          <Route path="investigation/:invId/timeline" element={<TimelinePage />} />
          <Route path="investigation/:invId/graph" element={<GraphPage />} />
          <Route path="investigation/:invId/insights" element={<InsightsPage />} />
          <Route path="investigation/:invId/report" element={<ReportPage />} />
        </Route>
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  </React.StrictMode>
);
