# Repository Structure

> **Verified against workspace snapshot**: `C:\Users\harikrishhhh\OneDrive\Attachments\Desktop\bugbounty` (no git history beyond initial commit; documentation reflects files present in the working tree).  
> **Scope**: Primary architecture focuses on source and configuration. Dependency caches/build outputs (`.venv/`, `.venv-1/`, `dashboard/node_modules/`, `dashboard/dist/`, `**/__pycache__/`, `.pytest_cache/`, `bugbounty.egg-info/`) are excluded from the primary tree and summarized separately.

## 1. Primary directory tree (source & configuration)

```text
.
├─ .env.example                     # Example environment variables (no secrets)
├─ .gitignore                       # Git ignore rules
├─ CLAUDE.md                        # Project entry point for AI/dev tooling (this documentation set)
├─ README.md                        # Project overview and quick start
├─ pyproject.toml                   # Python package/build config, dependencies, CLI entry point
├─ bugbounty/                       # Core Python package (CLI, assessment engine, API, domain logic)
│  ├─ __init__.py                   # Package exports and version
│  ├─ agents.py                     # Lightweight agent specs/registry and signal-based router
│  ├─ assessment.py                 # Assessment engine orchestration and result model
│  ├─ checks.py                     # Security check implementations and default check set
│  ├─ cli.py                        # `bugbounty` CLI argument parsing and command handlers
│  ├─ config.py                     # ScopeConfig and SecurityAppConfig dataclasses
│  ├─ config_loader.py              # YAML/JSON assessment config loading and validation
│  ├─ dashboard_api.py              # Local passive-import/assessment HTTP API server
│  ├─ discovery.py                  # Endpoint discovery and OpenAPI normalization
│  ├─ engagement.py                 # Engagement model, auth identities, authorization/test cases
│  ├─ evidence.py                   # Evidence model and persistence
│  ├─ findings.py                   # Finding model, store, dedupe, severity helper
│  ├─ http_client.py                # Bounded, scope-checked HTTP client with redaction
│  ├─ importers.py                  # HackerOne scope and Burp import/parsing, normalization, scoping
│  ├─ orchestration.py              # Minimal mission/context dispatch abstraction
│  ├─ policy.py                      # Program policy (Markdown) parsing/model
│  ├─ reports.py                    # JSON/Markdown/HTML report generation
│  ├─ safety.py                     # SafetyPolicy and target/method authorization decisions
│  └─ specialists.py                # Rich specialist catalog, registry, and ranking/router
├─ dashboard/                       # React + TypeScript + Vite frontend (local operator UI)
│  ├─ index.html                    # Vite HTML entry
│  ├─ package.json                  # Frontend dependencies and scripts
│  ├─ package-lock.json             # npm lockfile
│  ├─ tsconfig.json                 # TypeScript project references
│  ├─ tsconfig.app.json             # App TypeScript config
│  ├─ tsconfig.node.json            # Node/Vite config TypeScript config
│  ├─ vite.config.ts                # Vite config (React plugin)
│  └─ src/
│     ├─ App.tsx                    # Main UI: import/validate/run workflow, views, API calls
│     ├─ main.tsx                   # React bootstrap
│     ├─ styles.css                 # UI styling
│     └─ vite-env.d.ts              # Vite type declarations
├─ docs/
│  ├─ architecture.md               # Existing (pre-existing) architecture notes
│  └─ architecture/                 # Generated detailed architecture documentation (this set)
│     ├─ API_REFERENCE.md
│     ├─ COMPONENT_INTERACTIONS.md
│     ├─ DATA_FLOW.md
│     ├─ DEVELOPMENT_GUIDE.md
│     ├─ FUTURE_ROADMAP.md
│     ├─ REPOSITORY_STRUCTURE.md
│     ├─ SECURITY_ENGINE.md
│     ├─ SYSTEM_ARCHITECTURE.md
│     └─ TESTING_GUIDE.md
├─ examples/
│  ├─ burp-history.xml              # Example Burp XML history export
│  ├─ engagement.yaml               # Example YAML assessment configuration
│  └─ hackerone-scope.tsv           # Example HackerOne scope file (TSV/CSV-like)
└─ tests/
   ├─ __init__.py
   ├─ fixtures/
   │  ├─ __init__.py
   │  └─ vulnerable_api.py          # Local intentionally vulnerable API fixture for tests
   ├─ test_additional_coverage.py
   ├─ test_agent_routing.py
   ├─ test_assessment_engine.py
   ├─ test_authorized_checks.py
   ├─ test_burp_scope_configuration.py
   ├─ test_cli.py
   ├─ test_cli_config_assessment.py
   ├─ test_config_loader.py
   ├─ test_dashboard_api.py
   ├─ test_engagement_validation.py
   ├─ test_extended_boundaries.py
   ├─ test_http_and_discovery.py
   ├─ test_importers.py
   ├─ test_program_and_burp_json.py
   ├─ test_rei_actual_scope_intersection.py
   ├─ test_robustness.py
   ├─ test_scope_enforcement.py
   ├─ test_scope_only_http_regression.py
   └─ test_specialists.py
```

## 2. Important directories and files (detailed)

| Path | Purpose | Responsibility | Key dependencies | Consumers | Active | Status |
|---|---|---|---|---|---|---|
| `pyproject.toml` | Python project definition | Declares package metadata, runtime deps (`pydantic`, `typer`, `python-dotenv`, `rich`, `PyYAML`), console script `bugbounty`, pytest config | setuptools build backend | `pip install -e .`, `python -m pytest`, CLI entry point | Yes | Implemented |
| `.env.example` | Environment template | Documents optional provider keys and `BUGBOUNTY_*` settings; no secrets | None | Developers/operators copying to `.env` | Yes | Implemented (template) |
| `.gitignore` | VCS hygiene | Ignores caches, venvs, `.env`, logs, `audit.jsonl`, `workspace/`, etc. | git | git workflows | Yes | Implemented |
| `README.md` | User/developer overview | Quick start, capabilities, layout summary, verification/demo commands; includes a historical layout entry (`research.py`) not present in package | N/A | Humans/agents | Yes | Implemented (contains minor historical drift vs actual files) |
| `bugbounty/__init__.py` | Public package surface | Exposes core classes/functions and `__version__ = "0.1.0"` | `agents`, `assessment`, `config`, `engagement`, `findings`, `http_client`, `safety` | Importers of `bugbounty` package | Yes | Implemented |
| `bugbounty/cli.py` | CLI entry point | Parses commands (`init`, `status`, `recon`, `discover`, `assess`, `report`, `dashboard`) and dispatches to engine/import/report/dashboard APIs | `argparse`, `assessment`, `config_loader`, `discovery`, `engagement`, `http_client`, `reports`, `dashboard_api` | `bugbounty` console script / `python -m bugbounty.cli` | Yes | Implemented |
| `bugbounty/config_loader.py` | Config ingestion | Loads YAML/JSON assessment config, validates schema/fields, constructs `Engagement` and discovery options; defines `ConfigurationError` | `json`, `yaml` (PyYAML), `engagement` models | CLI `assess --config` | Yes | Implemented |
| `bugbounty/config.py` | Generic config models | `ScopeConfig` (domain/url containment, allowed methods) and `SecurityAppConfig` (workspace/approval/dry-run defaults) | `urllib.parse` | `engagement.Engagement.scope()`, `safety`, `orchestration` | Yes | Implemented (some fields not consumed by assessment engine) |
| `bugbounty/engagement.py` | Assessment engagement model | Defines `Engagement`, `AuthIdentity`, and case/probe/flow/SSRF dataclasses; validation and `from_target` helper | `config.ScopeConfig`, `uuid`, `urllib.parse` | `AssessmentEngine`, `HttpClient`, checks, CLI, dashboard | Yes | Implemented |
| `bugbounty/safety.py` | Safety guardrails | `SafetyPolicy` authorizes targets (scheme/scope) and methods; returns `SafetyDecision` | `config.ScopeConfig`, `urllib.parse` | `HttpClient`, `discovery.ApiDiscovery`, `orchestration.Mission` | Yes | Implemented |
| `bugbounty/http_client.py` | Controlled HTTP I/O | Scope/method/budget/rate/timeout enforcement, dry-run behavior, auth header/query injection, redirect handling, response capture, secret redaction | `urllib.request`, `engagement`, `safety` | `AssessmentEngine`, `ApiDiscovery`, checks | Yes | Implemented |
| `bugbounty/discovery.py` | Endpoint discovery | Discovers endpoints from OpenAPI file, endpoint list, single endpoint, or common doc paths; normalizes to `Endpoint`; OpenAPI/Swagger validation helpers | `HttpClient`, `Engagement`, `json`, `urllib.parse` | `AssessmentEngine`, CLI `discover/recon`, import inventory conversion | Yes | Implemented |
| `bugbounty/importers.py` | External data import & scope intersection | Parses HackerOne scope (CSV/TSV/JSON/YAML), Burp XML/JSON traffic and Burp scope config; redaction; URL normalization; scope matching; inventory building and conversion to `Endpoint`s | `csv/json/xml/re/yaml`, `discovery.Endpoint` (lazy import) | `dashboard_api`, tests | Yes | Implemented |
| `bugbounty/policy.py` | Program policy parsing | Extracts deterministic policy signals from pasted Markdown (`ProgramPolicy`) | `re`, `dataclasses` | `dashboard_api` | Yes | Implemented (heuristic extraction) |
| `bugbounty/checks.py` | Security checks | Defines `SecurityCheck`/`CheckContext`/`CheckResult`; implements API1–API10-related checks and `default_checks()` registry | `discovery`, `evidence`, `findings`, `engagement`, `http_client`, `json` | `AssessmentEngine`, dashboard check selection | Yes | Implemented (coverage varies by prerequisites) |
| `bugbounty/evidence.py` | Evidence persistence | `Evidence`/`EvidenceStore` with sanitization and JSON write | `json`, `uuid`, `datetime`, `pathlib` | `AssessmentEngine`, checks, dashboard/report context | Yes | Implemented |
| `bugbounty/findings.py` | Findings model/store | `Finding`/`FindingStore` with validation, dedupe/correlation, JSON write, deterministic severity helper | `hashlib`, `json`, `pathlib` | Checks, `AssessmentEngine`, reports/dashboard | Yes | Implemented |
| `bugbounty/assessment.py` | Assessment engine | Coordinates discovery/imported inventory, passive Burp evidence import, per-endpoint request + check execution, audit log, and workspace artifact writes | `checks`, `discovery`, `engagement`, `evidence`, `findings`, `http_client`, `importers` | CLI `assess`, `dashboard_api` | Yes | Implemented |
| `bugbounty/reports.py` | Reporting | Builds report data and writes `report.json`, `report.md`, `report.html` | `json`, `html`, `collections.Counter` | CLI, dashboard, assessment consumers | Yes | Implemented |
| `bugbounty/dashboard_api.py` | Local backend API | `ThreadingHTTPServer` + handler exposing import/validate/assessment/report endpoints; in-memory `DashboardState`; serves CORS for localhost Vite dev server | stdlib `http.server`, `importers`, `policy`, `assessment`, `reports`, `checks` | `dashboard/src/App.tsx` (HTTP), CLI `dashboard` | Yes | Implemented (stateful in-process, single handler state class attribute) |
| `bugbounty/agents.py` | Simple agent routing | `AgentSpec`, `AgentRegistry`, heuristic `route_agent`, `DEFAULT_AGENT_REGISTRY` | stdlib | `orchestration`, package exports, tests/routing consumers | Yes | Implemented (lightweight) |
| `bugbounty/specialists.py` | Specialist catalog/ranking | Rich `Specialist` model, `SpecialistRegistry`, scoring/ranking and `route_specialist`, `DEFAULT_SPECIALIST_REGISTRY` | stdlib dataclasses/typing | Package users/tests (not wired into assessment engine) | Yes | Implemented (catalog/routing utility, not integrated into runtime flow) |
| `bugbounty/orchestration.py` | Mission abstraction | Minimal `Mission`/`MissionContext` dispatching via `agents.route_agent` and `SafetyPolicy` | `agents`, `config`, `safety` | Package users/tests (not used by CLI/assessment) | Yes | Implemented (minimal) |
| `dashboard/src/App.tsx` | Frontend UI | Multi-tab UI for engagement validation, scope/traffic/endpoints/findings/evidence/reports; calls dashboard API at `http://127.0.0.1:8765` | React, browser `fetch`/`FormData` | Browser users via Vite dev/build | Yes | Implemented |
| `dashboard/src/main.tsx` | Frontend bootstrap | Mounts React app and imports styles | React/ReactDOM | Browser runtime | Yes | Implemented |
| `dashboard/src/styles.css` | Frontend styling | Visual theme/layout/components | CSS | `main.tsx` | Yes | Implemented |
| `dashboard/vite.config.ts` | Frontend build config | Vite + React plugin | `vite`, `@vitejs/plugin-react` | `npm run dev/build` | Yes | Implemented |
| `docs/architecture.md` | Existing architecture notes | Historical/summary architecture and working assessment flow | N/A | Developers | Yes | Implemented (pre-existing; partially high-level/historical) |
| `examples/engagement.yaml` | Sample config | Authorized local/dry-run assessment config example | `config_loader` schema | Users running `assess --config` | Yes | Implemented (example) |
| `examples/burp-history.xml`, `examples/hackerone-scope.tsv` | Sample import inputs | Example Burp and scope data formats | `importers` | Manual testing/examples | Yes | Implemented (sample data) |
| `tests/fixtures/vulnerable_api.py` | Test fixture | Local vulnerable API behavior for integration-style assessment tests | stdlib HTTP server/framework used in fixture (see file) | Assessment/integration tests | Yes | Implemented |
| `tests/test_*.py` | Automated tests | Unit/integration/regression coverage for routing, CLI, config, importers, scope, checks, dashboard API, engine, specialists, robustness, boundaries | `pytest`, package modules, fixtures | `python -m pytest` | Yes | Implemented |

## 3. Generated/runtime artifacts and non-primary directories

| Path | Purpose | Active | Status | Notes |
|---|---|---|---|---|
| `.venv/`, `.venv-1/` | Local Python virtual environments | Local-only | Generated | Excluded from primary architecture; contain installed packages and editable install metadata. |
| `dashboard/node_modules/` | Frontend dependencies | Local-only | Generated | Excluded from primary architecture; large dependency tree for Vite/React/TypeScript. |
| `dashboard/dist/` | Frontend build output | Local-only | Generated artifact | Contains built `index.html` and assets (e.g. `assets/index-*.js/css`); not wired to backend static serving. |
| `bugbounty.egg-info/`, `**/__pycache__/`, `.pytest_cache/` | Packaging/test/runtime caches | Local-only | Generated | Ignored by `.gitignore` patterns in part; present in workspace. |
| `assessment-output/`, `cli-assessment/`, `cli-assessment-final/`, `dashboard-assessment-e2e/`, `dashboard-scope-only-validation/`, `deep-dive/`, `demo-assessment/`, `demo-workspace/`, `final-assessment/`, `live-rei-scope-validation/`, `live-scope-only-validation/`, `tmp-debug/` | Assessment/workspace output directories | Data artifacts | Generated/runtime outputs | Contain run artifacts such as `evidence.json`, `findings.json`, `audit.jsonl`, `report.json/.md/.html` in some folders (observed in `assessment-output`, `cli-assessment`, `demo-assessment`). Treat as evidence of prior runs, not source modules. |
| `repo1/`, `repo2/` | Local folders present in workspace | Unknown from code usage | Present, purpose not evidenced in source | No imports/references found in core package/dashboard during audit; document as present but not part of active runtime architecture. |

## 4. Notes and verified observations

- **CLI script name**: `pyproject.toml` defines console script `bugbounty = "bugbounty.cli:main"` (verified).
- **README layout drift**: `README.md` lists `research.py` under `bugbounty/`; file is **not present** in `bugbounty/` (verified). No code references to a `research` module were observed in core package.
- **Dependency declaration drift**: `pyproject.toml` lists `pydantic` as a runtime dependency, but no `pydantic` imports were observed in `bugbounty/` or `dashboard/` source (verified by inspection). Treat as declared but not evidenced in use.
- **Two routing systems coexist**: `bugbounty/agents.py` (simple) and `bugbounty/specialists.py` (richer catalog/scoring). Only `agents.py` is wired into `orchestration.py`; neither is used by the assessment engine/CLI execution path (verified).
- **Dashboard frontend API base URL**: hardcoded to `http://127.0.0.1:8765` in `dashboard/src/App.tsx` (verified).
