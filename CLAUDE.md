# CLAUDE.md

## Project overview
- **Name**: `bugbounty` (Unified security research / bug bounty API security assessment platform)
- **Purpose**: Local, scope-bounded API security assessment with CLI and dashboard workflows: config/import-driven discovery, controlled HTTP checks, evidence/findings capture, and report generation.
- **Core stack**: Python 3.11+ (`bugbounty/` package), React + TypeScript + Vite dashboard (`dashboard/`), file-based workspace artifacts.

## Repository structure (quick map)
- `bugbounty/`: core implementation (CLI, assessment engine, checks, discovery, HTTP client, importers, policy, evidence/findings, reports, dashboard API, routing utilities)
- `dashboard/`: frontend SPA (`src/App.tsx`, `main.tsx`, `styles.css`) calling local API at `http://127.0.0.1:8765`
- `docs/`: existing `architecture.md` + detailed docs in `docs/architecture/`
- `examples/`: sample engagement/config and import files
- `tests/`: pytest suite + `fixtures/vulnerable_api.py`
- Assessment/output folders (e.g. `assessment-output/`, `demo-assessment/`) and caches/venvs are artifacts, not source

## Architecture documentation
- `docs/architecture/SYSTEM_ARCHITECTURE.md` — system components, communication, and Mermaid diagrams
- `docs/architecture/REPOSITORY_STRUCTURE.md` — directory/file inventory and status
- `docs/architecture/COMPONENT_INTERACTIONS.md` — runtime interaction flows
- `docs/architecture/DATA_FLOW.md` — data contracts, transformations, artifacts
- `docs/architecture/SECURITY_ENGINE.md` — implemented API1–API10 check behavior
- `docs/architecture/API_REFERENCE.md` — CLI commands and dashboard HTTP endpoints
- `docs/architecture/DEVELOPMENT_GUIDE.md` — setup, config, local execution
- `docs/architecture/TESTING_GUIDE.md` — test layout and commands
- `docs/architecture/FUTURE_ROADMAP.md` — proposed/not implemented roadmap

## Development and testing commands
- **Install (Python)**: `python -m venv .venv` → activate → `pip install -e .`
- **Tests**: `python -m pytest -q tests` (targeted: `python -m pytest -q tests/test_assessment_engine.py`)
- **CLI examples**:
  - `bugbounty init --workspace ./workspace`
  - `bugbounty discover --target https://authorized-api.test --dry-run`
  - `bugbounty assess --config ./examples/engagement.yaml`
  - `bugbounty dashboard --host 127.0.0.1 --port 8765`
- **Dashboard frontend** (`dashboard/`): `npm install`, `npm run dev`, `npm run build`, `npm run preview`

## Critical implementation constraints
- **Preserve existing architecture and contracts**: CLI behavior, dashboard API routes/payloads, workspace artifacts (`evidence.json`, `findings.json`, `audit.jsonl`, `report.json/.md/.html`), and check semantics.
- **Safety boundaries are core**: `Engagement` + `SafetyPolicy` + `HttpClient` enforce scope/scheme/method allowlists, budgets, rate limits, timeouts, redirects, and dry-run behavior. Do not bypass them.
- **Evidence-first**: checks must produce evidence-backed results; do not treat routing/signals/parameter names alone as confirmed vulnerabilities.
- **Passive import principle**: imported Burp observations are recorded without replay; maintain redaction/sanitization in import/evidence/HTTP paths.
- **Known structural notes**: `agents.py`/`orchestration.py` and `specialists.py` are utility subsystems not central to assessment execution; README mentions `research.py` but it is not present (do not invent it).

## Security restrictions
- Use only **explicitly authorized** targets, hosts, and credentials; keep assessments in-scope and bounded.
- Never commit or expose secrets (`.env`, tokens, cookies, credentials). `.env.example` is placeholders only.
- Do not enable destructive/high-volume testing; respect program policies (e.g. DoS prohibitions) and request limits.
- Dashboard API has no built-in auth and is intended for local use; do not expose it publicly without adding proper controls.

## Before modifying code
- Inspect relevant modules and tests first (e.g. `bugbounty/assessment.py`, `checks.py`, `http_client.py`, `importers.py`, `dashboard_api.py`, `cli.py`, corresponding `tests/test_*.py`).
- Confirm current behavior and data contracts from `docs/architecture/*` and source, not assumptions.
- Identify affected artifacts/APIs and update tests/docs when behavior changes.

## Preserve existing architecture
- Keep module responsibilities and directory layout intact unless explicitly requested.
- Prefer incremental, compatible changes; avoid renaming/moving core components.
- Maintain separation between **current implemented behavior** and any proposed/future features (document proposals in `docs/architecture/FUTURE_ROADMAP.md`, not as implemented).