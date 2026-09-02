# ForenSight — Project Report & Test Results

**AI-powered digital forensic investigation and cyber-triage platform**

Generated: 2026-09-02 · Repo: `pkpog/ForenSight` · Status: **MVP complete, all tests passing**

---

## 1. Project Overview

ForenSight ingests log evidence (CSV / JSON / TXT), extracts forensic artifacts, scores them with
explainable AI/ML (rules + Isolation Forest), correlates related artifacts across evidence sources,
reconstructs a chronological timeline, and generates a human-readable investigation report —
clearly separating **verified facts** from **AI interpretation**.

### Pipeline

```
Evidence Collection → Artifact Extraction → AI/ML Analysis → Artifact Ranking
     → Cross-Artifact Correlation → Timeline Reconstruction → AI Insights → Visualization & Report
```

### Tech stack

| Layer | Technology |
|---|---|
| Backend | Python 3.12, FastAPI, SQLAlchemy 2.x |
| Database | SQLite (default) — Postgres-ready via `FORENSIGHT_DB_URL` |
| AI/ML | Scikit-learn Isolation Forest + explainable rule engine |
| Frontend | React 18, TypeScript, Vite |
| Graph | Cytoscape.js |

### Repository layout

```
backend/
  app/
    core/         config (env-driven), database
    models/       Investigation, Evidence, Artifact, Relationship, TimelineEvent, Insight
    schemas/      Pydantic API schemas
    forensic/     safe upload storage + modular extractors (csv/json/txt) + parsing helpers
    ml/           rule indicators, Isolation Forest scoring, explainable ranking
    correlation/  cross-artifact relationship engine
    timeline/     timeline reconstruction + suspicious sequence flags
    insights/     deterministic insight generator (LLM-ready)
    services/     analysis pipeline, HTML report builder
    api/          REST routes
    demo_data.py  safe synthetic incident dataset
  tests/          35 pytest tests (unit + integration)
frontend/
  src/pages/      Login, Dashboard, Evidence, Artifacts, Timeline, Graph, Insights, Report
```

---

## 2. How to Run

### Backend

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

API docs: http://127.0.0.1:8000/docs

### Frontend

```bash
cd frontend
npm install
npm run dev                        # http://localhost:5173 (proxies /api to :8000)
```

### Demo in 30 seconds

Sign in (demo mode, any credentials) → **Load demo investigation** → explore Artifacts, Timeline,
Graph, AI Insights, and Report. The synthetic scenario: failed-login burst → suspicious login →
`.exe` download → execution → C2-style connection on port 4444.

---

## 3. Test Results ✅

**Command:** `cd backend && python -m pytest -v`
**Result: 35 passed, 0 failed (7.4s)**

| Test file | Tests | What is verified |
|---|---|---|
| `test_parsing.py` | 6 | Timestamp formats (ISO, microseconds, syslog year-fill), invalid input handling, IPv4 extraction & dedupe |
| `test_extractors.py` | 5 | CSV/JSON/TXT artifact extraction, event classification keywords, entity dedupe, line-number provenance |
| `test_storage.py` | 6 | SHA-256 hashing, extension allow-list (`.exe` rejected), empty/oversized rejection, path-traversal sanitization, byte-identical storage (no execution) |
| `test_ml.py` | 5 | Risk thresholds LOW→CRITICAL, explainable indicators (off-hours login, external IP, suspicious extension, abused port), ranking order, Isolation Forest differentiation |
| `test_correlation_timeline.py` | 5 | download→execute chains, no false chains on large time gaps, entity→event links with confidence, chronological timeline, sequence flags, failed-login burst marking |
| `test_insights_report.py` | 2 | All 5 insight sections generated, every insight cites supporting artifacts, hedged "AI interpretation" language, report separates facts from AI sections |
| `test_api.py` | 6 | Health, investigation CRUD, evidence upload validation, analyze-without-evidence error, full demo pipeline outputs (graph/insights/report), re-analysis idempotency |

### Frontend build

**Command:** `cd frontend && npm run build`
**Result: ✅ success** — `tsc -b` typecheck clean, Vite production build 684 KB JS (gzip 222 KB) + 6 KB CSS.

### Live end-to-end verification (real server, HTTP)

| Check | Result |
|---|---|
| `GET /api/health` | `200 {"status":"ok"}` |
| `POST /api/demo/load` | `200` — 36 artifacts, 10 relationships, 18 timeline events, 5 insights |
| Risk distribution | LOW 17 · MEDIUM 8 · HIGH 10 · CRITICAL 1 |
| Top ranked artifact | `download user=jdoe src=203.0.113.45 file=C:\Users\jdoe\Downloads\invoice_scanner.exe` — CRITICAL, importance 83.8 |
| `GET .../graph` | 11 nodes, 10 edges (Cytoscape-ready) |
| `GET .../report` | `200` — 14.4 KB standalone HTML |
| `POST /api/evidence/upload` | `200` — stored + SHA-256 hashed |

---

## 4. Bugs Found & Fixed During Testing

The test suite caught two real pipeline bugs, which were fixed:

1. **Event misclassification** — a `process_create` record whose file path contained
   `...\Downloads\tool.exe` was classified as `download` (the download keyword was checked before
   the execution keyword). **Fix:** execution keywords now take precedence in `extractors.py`.
2. **Entity→event correlation never matched** — the engine compared entity values against the
   event's human-readable summary string instead of its metadata fields, so `performed_by` /
   `involves_file` / `executed_by` links only fired by accident. **Fix:** entity values are now
   matched against the event's `user` / `ip` / `dst_ip` / `file` / `process` metadata (or same
   log record), with confidence scoring.

Plus two test-side corrections (invalid minute value in a fixture; a report-ordering assertion
that matched a phrase also present in insight prose).

---

## 5. Security & Integrity Notes

- Uploaded evidence is **never executed** — only hashed, stored, and parsed as text.
- Extension allow-list (`.csv`, `.json`, `.txt`, `.log`), 25 MB limit, sanitized filenames.
- Every score is explainable: each artifact carries its indicator list; every insight cites the
  artifacts that support it.
- The report keeps **verified facts** (evidence, artifacts, timeline, relationships) separate from
  **AI-generated interpretation**, which uses hedged language ("suggests", "possible").

## 6. Roadmap (post-MVP)

- Registry / PCAP / memory-dump extractors (drop-in via the extractor registry)
- LLM-backed insight generator behind the same interface
- PDF report export, real authentication, Postgres deployment, CI workflow
