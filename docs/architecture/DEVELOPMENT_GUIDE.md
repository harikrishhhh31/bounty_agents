# Development Guide

> Verified from `pyproject.toml`, `README.md`, `.env.example`, `dashboard/package.json`, `dashboard/vite.config.ts`, and source behavior. Commands listed are those present in repository configuration/docs or directly implied by implemented entry points.

## 1. Prerequisites and environment

### 1.1 Runtime/tooling (observed)

- **Python**: `>=3.11` (required by `pyproject.toml`).
- **Node.js/npm**: Required to run/build the dashboard frontend (Vite/React/TypeScript dependencies declared in `dashboard/package.json`). Exact Node version not pinned in repo (inference: use a current LTS compatible with installed Vite/React toolchain).
- **OS**: Repository contains Windows paths/artifacts in this workspace; code uses cross-platform stdlib/pathlib in most places.

### 1.2 Environment variables

Defined/documented in `.env.example` (no secrets committed):

| Variable | Purpose (as documented) | Default/example behavior |
|---|---|---|
| `PERPLEXITY_API_KEY` | Optional provider token placeholder | Empty by default |
| `GOOGLE_API_KEY` | Optional provider token placeholder | Empty by default |
| `OPENAI_API_KEY` | Optional provider token placeholder | Empty by default |
| `TOGETHER_API_KEY` | Optional provider token placeholder | Empty by default |
| `BUGBOUNTY_WORKSPACE` | Default workspace path hint | `./workspace` |
| `BUGBOUNTY_APPROVAL_MODE` | Approval mode setting hint | `deny` |
| `BUGBOUNTY_DRY_RUN` | Dry-run setting hint | `true` |
| `BUGBOUNTY_MAX_REQUESTS_PER_MINUTE` | Rate setting hint | `10` |
| `BUGBOUNTY_MODEL_TIMEOUT_SECONDS` | Model timeout hint | `30` |

**Important**: Runtime modules do not read these variables directly (no `os.getenv`/dotenv loading observed in `bugbounty/` source). Treat them as configuration placeholders/documentation unless external tooling loads them.

### 1.3 Configuration files

| File | Purpose | Notes |
|---|---|---|
| `pyproject.toml` | Python package, dependencies, CLI script, pytest config | `pythonpath = ["."]`, `testpaths = ["tests"]` |
| `.env.example` | Environment template | Copy to `.env` if needed; `.env` is gitignored |
| `examples/engagement.yaml` | Sample assessment config | Safe local example with `dry_run: true` |
| `dashboard/vite.config.ts`, `dashboard/tsconfig*.json` | Frontend build/dev configuration | Vite + React plugin; TypeScript project references |

### 1.4 Secrets management

- **No secrets should be committed**. `.gitignore` excludes `.env`, `.env.local`, logs, and workspace artifacts.
- **Redaction implemented**: HTTP client, importers, and evidence store sanitize/redact sensitive headers/values/tokens in many paths (see `DATA_FLOW.md`), but operators must still avoid pasting or storing real secrets unnecessarily.

## 2. Local development setup

### 2.1 Python backend/CLI

```bash
python -m venv .venv
# Activate venv (platform-specific)
pip install -e .
```

Verified from `README.md` and `pyproject.toml` (editable install supported; package name `bugbounty`).

### 2.2 Frontend dashboard

```bash
cd dashboard
npm install
npm run dev
```

Scripts from `dashboard/package.json`:
- `dev`: `vite`
- `build`: `tsc -b && vite build`
- `preview`: `vite preview`

Frontend expects dashboard API at `http://127.0.0.1:8765` (hardcoded in `dashboard/src/App.tsx`).

### 2.3 Run dashboard API (backend)

```bash
bugbounty dashboard --host 127.0.0.1 --port 8765
```

Starts the local HTTP API used by the SPA and by direct API clients.

## 3. Local execution workflows

### 3.1 Initialize and inspect workspace

```bash
bugbounty init --workspace ./workspace
bugbounty status --workspace ./workspace
bugbounty report --workspace ./workspace
```

### 3.2 Discover endpoints

```bash
bugbounty discover --target https://authorized-api.test --workspace ./workspace --dry-run
bugbounty discover --target https://authorized-api.test --openapi-file ./openapi.json
bugbounty recon --target https://authorized-api.test
```

### 3.3 Run assessment

```bash
# Target-based (CLI helper builds GET-only engagement)
bugbounty assess --target https://authorized-api.test --workspace ./workspace --dry-run

# Config-driven (recommended for explicit cases/settings)
bugbounty assess --config ./examples/engagement.yaml
```

### 3.4 Dashboard workflow (passive import)

1. Start backend: `bugbounty dashboard`
2. Start frontend: `cd dashboard && npm run dev`
3. In UI: paste program rules, upload H1 scope `.csv` and Burp `.json`, validate, then run assessment (dry-run toggle available in UI).

## 4. Build, test, and validation commands

| Purpose | Command | Source |
|---|---|---|
| Run tests | `python -m pytest -q tests` | `README.md`, `pyproject.toml` (`testpaths = ["tests"]`) |
| Run specific test | `python -m pytest -q tests/test_assessment_engine.py` | `README.md` example |
| Frontend dev server | `npm run dev` (in `dashboard/`) | `dashboard/package.json` |
| Frontend production build | `npm run build` (in `dashboard/`) | `dashboard/package.json` |
| Frontend preview build | `npm run preview` (in `dashboard/`) | `dashboard/package.json` |

No backend packaging/release scripts beyond setuptools config were found in-repo.

## 5. Deployment and runtime considerations

- **Dashboard API**: stdlib `ThreadingHTTPServer`, no TLS/auth built in; binds to configurable host/port (default localhost). Treat as local development/tooling service.
- **Frontend**: Vite SPA; `dashboard/dist/` contains build artifacts but backend does not serve them statically. Production/static hosting integration is **not implemented** in repo.
- **Persistence**: File-based outputs in workspace directories; ensure write permissions and avoid committing sensitive assessment artifacts.
- **Concurrency/state**: Dashboard API keeps mutable in-memory state in a class-level handler attribute; suitable for single-user/local sessions, not designed as multi-tenant service (inference from implementation).

## 6. Safe development practices (repo-aligned)

- Use **explicitly authorized targets only** and prefer `dry_run` when exploring.
- Keep `allowed_hosts/schemes/methods`, request budgets, and timeouts constrained in `Engagement`/config.
- Review imported Burp/H1/program inputs for sensitive data before sharing artifacts.
- Do not assume `.env.example` values are auto-loaded by the application.
