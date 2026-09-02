# ForenSight 🛡️

**AI-powered digital forensic investigation and cyber-triage platform.**

ForenSight ingests log evidence (CSV / JSON / TXT), extracts forensic artifacts, scores them with
explainable AI/ML, correlates related artifacts across evidence sources, reconstructs a timeline,
and generates a human-readable investigation report — clearly separating verified facts from
AI interpretation.

Built as an MVP for a college project / hackathon. All demo data is synthetic and safe
(no real malware, RFC 5737 documentation IPs only).

## Pipeline

```
Evidence Collection → Artifact Extraction → AI/ML Analysis → Artifact Ranking
       → Cross-Artifact Correlation → Timeline Reconstruction → AI Insights → Visualization & Report
```

## Tech stack

| Layer | Technology |
|---|---|
| Backend | Python 3.12, FastAPI, SQLAlchemy 2.x |
| Database | SQLite (default, zero-config) — Postgres-ready via `FORENSIGHT_DB_URL` |
| AI/ML | Scikit-learn Isolation Forest + explainable rule engine |
| Frontend | React 18, TypeScript, Vite |
| Graph | Cytoscape.js |
| Timeline | Custom React timeline |

## Architecture

```
backend/
  app/
    core/         config (env-driven), database
    models/       Investigation, Evidence, Artifact, Relationship, TimelineEvent, Insight
    schemas/      Pydantic API schemas
    forensic/     safe upload storage + modular extractors (csv/json/txt)
    ml/           rule indicators, Isolation Forest scoring, explainable ranking
    correlation/  cross-artifact relationship engine
    timeline/     timeline reconstruction + suspicious sequence flags
    insights/     deterministic insight generator (LLM-ready)
    services/     analysis pipeline, HTML report builder
    api/          REST routes
    demo_data.py  safe synthetic incident dataset
frontend/
  src/pages/      Login, Dashboard, Evidence, Artifacts, Timeline, Graph, Insights, Report
```

## Quickstart

### 1. Backend

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

The SQLite database and evidence directory are created automatically.
Interactive API docs: http://127.0.0.1:8000/docs

### 2. Frontend

```bash
cd frontend
npm install
npm run dev                      # http://localhost:5173 (proxies /api to :8000)
```

### 3. Try it in 30 seconds

1. Open http://localhost:5173 and sign in (demo mode — any credentials).
2. Click **Load demo investigation** — loads a synthetic incident:
   failed-login burst → suspicious login → `.exe` download → execution → C2-style connection.
3. Explore **Artifacts** (ranked + explained), **Timeline** (sequence flags),
   **Graph** (correlation), **AI Insights**, and the **Report**.

You can also create your own investigation, upload CSV/JSON/TXT evidence, and press
**Run full analysis**.

## API overview

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/investigations` | create investigation |
| GET/DELETE | `/api/investigations/{id}` | inspect / delete |
| POST | `/api/evidence/upload` | upload evidence (multipart) |
| GET/DELETE | `/api/evidence/{id}` | evidence metadata / delete |
| POST | `/api/investigations/{id}/analyze` | run full pipeline |
| GET | `/api/investigations/{id}/artifacts` | ranked artifacts + explanations |
| GET | `/api/investigations/{id}/relationships` | correlated relationships |
| GET | `/api/investigations/{id}/timeline` | chronological events + flags |
| GET | `/api/investigations/{id}/graph` | Cytoscape-ready nodes/edges |
| GET | `/api/investigations/{id}/insights` | AI insights w/ supporting artifact IDs |
| GET | `/api/investigations/{id}/report` | standalone HTML report |
| POST | `/api/demo/load` | load synthetic demo investigation |

## Security & integrity notes

- Uploaded evidence is **never executed** — only hashed (SHA-256), stored and parsed as text.
- Extension allow-list (`.csv`, `.json`, `.txt`, `.log`), size limit, sanitized file names.
- Risk/importance scores are explainable: every artifact carries its indicator list.
- The report separates **verified facts** (sections 1–4) from **AI interpretation** (section 5),
  and every insight cites the artifacts that support it.

## Roadmap (post-MVP)

- Windows Registry / PCAP / memory dump extractors (drop-in via `forensic/extractors.py` registry)
- LLM-backed insight generator behind the same interface
- PDF report export, per-user auth, Postgres deployment
