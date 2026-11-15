# System Architecture

> **Documentation basis**: Verified from source in `bugbounty/`, `dashboard/`, `examples/`, `tests/`, `pyproject.toml`, `README.md`, and existing `docs/architecture.md`.  
> **Rule**: Only implemented/verified components are diagrammed as current architecture. Proposed components are listed separately in `FUTURE_ROADMAP.md` and not merged into current diagrams.

## 1. Current high-level architecture

The repository implements a **local, scope-bounded API security assessment platform** with two primary user interfaces:
- **CLI** (`bugbounty.cli`) for workspace init/status, discovery, assessment (target/config), report path listing, and starting the dashboard API.
- **Dashboard**: a Python stdlib HTTP API (`bugbounty.dashboard_api`) plus a React/Vite SPA (`dashboard/`) for passive import, validation, scoped assessment execution, and report viewing.

Core runtime capabilities are centered on **engagement modeling**, **safety/scope enforcement**, **HTTP discovery and controlled requests**, **passive import normalization (HackerOne/Burp)**, **check execution/evidence/findings**, and **report generation**.

### 1.1 Component inventory (implemented)

| Layer | Component(s) | Primary files | Status |
|---|---|---|---|
| Frontend | React SPA (import/validate/run/results UI) | `dashboard/src/App.tsx`, `main.tsx`, `styles.css`, `index.html`, `vite.config.ts` | Implemented |
| Backend API (local) | Dashboard HTTP server/state | `bugbounty/dashboard_api.py` | Implemented |
| CLI | Command parsing and dispatch | `bugbounty/cli.py` | Implemented |
| Configuration | YAML/JSON assessment config loader; config models | `bugbounty/config_loader.py`, `config.py`, `engagement.py` | Implemented |
| Assessment engine | Orchestration of discovery/import, checks, artifacts | `bugbounty/assessment.py` | Implemented |
| Security checks | API1–API10-related checks and registry | `bugbounty/checks.py` | Implemented (prerequisite-dependent) |
| Scope/policy/safety | Engagement scope, safety decisions, program policy parsing | `bugbounty/engagement.py`, `safety.py`, `policy.py` | Implemented |
| Discovery | OpenAPI/manual/doc endpoint discovery | `bugbounty/discovery.py` | Implemented |
| HTTP client | Bounded/redacting request execution | `bugbounty/http_client.py` | Implemented |
| Importers | HackerOne/Burp parsing, redaction, scope intersection, inventory | `bugbounty/importers.py` | Implemented |
| Evidence & findings | Models, stores, dedupe, persistence | `bugbounty/evidence.py`, `findings.py` | Implemented |
| Reporting | JSON/Markdown/HTML report generation | `bugbounty/reports.py` | Implemented |
| Routing/orchestration utilities | Simple agent router and mission abstraction; specialist catalog/ranking | `bugbounty/agents.py`, `orchestration.py`, `specialists.py` | Implemented (utilities; not central to assessment execution) |
| Persistence | File-based workspace artifacts | Engine/report/dashboard writes to filesystem | Implemented (no DB) |

### 1.2 External integrations (as implemented)

- **No external SaaS integrations are invoked by runtime code**. Optional provider keys are documented in `.env.example`/`README.md`, but no provider client usage is present in `bugbounty/` source (verified).
- **Local file imports**: HackerOne scope files, Burp exports (JSON/XML), OpenAPI/spec files, program policy Markdown (dashboard paste or import endpoint).
- **Network targets**: User-authorized HTTP(S) targets accessed via `urllib` in `HttpClient` under scope/budget/dry-run controls.

## 2. Communication patterns

- **CLI → in-process modules**: `bugbounty.cli` directly instantiates/calls `AssessmentEngine`, `ApiDiscovery`, `HttpClient`, `Engagement`, `load_assessment_config`, `write_reports`, `serve_dashboard`.
- **Dashboard SPA → Dashboard API**: `dashboard/src/App.tsx` uses `fetch` to `http://127.0.0.1:8765` (JSON and multipart form-data). CORS allows origins `http://localhost:5173` and `http://127.0.0.1:5173`.
- **Dashboard API → core engine**: `DashboardState` parses/imports inputs, builds in-scope inventory/endpoints, constructs `Engagement`, selects checks (disables API4 if policy indicates DoS prohibited), runs `AssessmentEngine`, writes reports, and augments report context.
- **Assessment engine → subsystems**: engine uses `ApiDiscovery`/imported inventory + `HttpClient` + `checks` + `EvidenceStore`/`FindingStore`; writes `evidence.json`, `findings.json`, `audit.jsonl` to `engagement.workspace`.
- **Statefulness**: CLI runs are process-local. Dashboard API maintains **in-memory state** in `DashboardHandler.state` (`DashboardState`) shared across requests in the same server process.

## 3. Mermaid diagrams (current implementation)

### 3.1 High-level system architecture

```mermaid
flowchart TB
  subgraph UI[User Interfaces]
    CLI[CLI\nbugbounty.cli]
    FE[Dashboard SPA\n dashboard/src/App.tsx ]
  end

  subgraph API[Local Backend API]
    DAPI[dashboard_api.DashboardState / Handler\nThreadingHTTPServer]
  end

  subgraph Core[Core Assessment Platform - bugbounty package]
    CFG[config_loader / config / engagement]
    SAFE[safety.SafetyPolicy]
    IMP[importers + policy]
    DISC[discovery.ApiDiscovery]
    HTTP[http_client.HttpClient]
    ENG[assessment.AssessmentEngine]
    CHK[checks.default_checks / SecurityCheck]
    EV[evidence.EvidenceStore]
    FN[findings.FindingStore]
    REP[reports.write_reports]
  end

  subgraph FS[Filesystem / Artifacts]
    WS[Workspace outputs\nevidence.json findings.json audit.jsonl\nreport.json/.md/.html]
    IN[Input files\nOpenAPI, Burp XML/JSON, H1 scope CSV/TSV/JSON/YAML, policy Markdown]
  end

  CLI --> CFG
  CLI --> DISC
  CLI --> HTTP
  CLI --> ENG
  CLI --> REP
  CLI --> DAPI

  FE -->|HTTP JSON/multipart :8765| DAPI
  DAPI --> IMP
  DAPI --> CFG
  DAPI --> SAFE
  DAPI --> ENG
  DAPI --> REP

  CFG --> SAFE
  ENG --> DISC
  ENG --> HTTP
  ENG --> CHK
  ENG --> EV
  ENG --> FN
  CHK --> HTTP
  CHK --> EV
  CHK --> FN
  DISC --> HTTP
  HTTP --> SAFE

  IN --> CLI
  IN --> DAPI
  ENG --> WS
  REP --> WS
  DAPI --> WS
```

### 3.2 Frontend-to-backend communication

```mermaid
sequenceDiagram
  autonumber
  participant U as User (Browser)
  participant FE as Dashboard SPA (App.tsx)
  participant BE as Dashboard API (dashboard_api.py:8765)
  participant ST as DashboardState (in-memory)

  U->>FE: Paste program rules + select scope CSV + Burp JSON
  FE->>BE: POST /engagement/validate (multipart/form-data)
  BE->>ST: validate_engagement(...)
  ST-->>BE: validation summary + intersection
  BE-->>FE: 200 JSON

  U->>FE: Start assessment (dry-run toggle)
  FE->>BE: POST /assessment/run (JSON)
  BE->>ST: run_assessment(require_validation=True)
  ST-->>BE: report_data + policy/intersection context
  BE-->>FE: 200 JSON

  FE->>BE: GET /findings, /evidence, /endpoints, /burp/traffic, /scope, /program
  BE->>ST: read current state/results
  BE-->>FE: 200 JSON

  FE->>BE: GET /reports/json|markdown|html
  BE-->>FE: 200 text/json/html (from workspace files)
```

### 3.3 Assessment execution flow

```mermaid
flowchart TD
  A[Start assessment] --> B{Input source}
  B -->|CLI assess --config| C[config_loader.load_assessment_config]
  B -->|CLI assess --target| D[Engagement.from_target/_engagement]
  B -->|Dashboard /assessment/run| E[DashboardState builds Engagement\nfrom in-scope inventory]

  C --> F[AssessmentEngine.run]
  D --> F
  E --> F

  F --> G{endpoint_inventory provided?}
  G -->|Yes| H[Filter inventory by SafetyPolicy target/method]
  G -->|No| I[ApiDiscovery.discover\nopenapi/file/list/endpoint/docs/target]
  H --> J[Endpoints list]
  I --> J

  F --> K[Import passive Burp exchanges as observed evidence\ncheck_id=burp-import]
  J --> L[For each endpoint: HttpClient.request]
  L --> M[For each SecurityCheck: execute]
  M --> N[Collect CheckResult + audit record]
  M --> O[Add findings to FindingStore]
  N --> P[Append result]
  O --> P
  P --> Q{More checks/endpoints?}
  Q -->|Yes| M
  Q -->|No| R[Write evidence.json, findings.json, audit.jsonl]
  R --> S[Return AssessmentResult]
  S --> T[write_reports -> report.json/.md/.html]
```

### 3.4 Scope validation flow (dashboard engagement validation)

```mermaid
flowchart TD
  A[POST /engagement/validate multipart] --> B{Required fields/files present?}
  B -->|No| X[400 ValueError]
  B -->|Yes| C[Parse program rules\npolicy.parse_program_markdown]
  C --> D[Parse HackerOne scope CSV\nimporters.parse_hackerone_scope]
  D --> E[Parse Burp JSON document\nimporters.parse_burp_json_document]
  E --> F[Build inventory\nbuild_inventory(exchanges, h1_scope, burp_scope)]
  F --> G[Compute intersection summary\nDashboardState.intersection_summary]
  G --> H[Set validation_complete=true\nstore context/state]
  H --> I[Return valid + program/scope/burp/intersection]
```

### 3.5 Security check execution

```mermaid
flowchart LR
  EP[Endpoint + initial response] --> CTX[CheckContext\nEngagement, HttpClient, EvidenceStore, FindingStore]
  CTX --> C1[api8-security-misconfiguration]
  CTX --> C2[api9-improper-inventory]
  CTX --> C3[api7-ssrf-indicator/verification]
  CTX --> C4[api2-broken-authentication]
  CTX --> C5[api1-bola-api5-function]
  CTX --> C6[api3-property-authorization]
  CTX --> C7[api4-resource-consumption]
  CTX --> C8[api6-sensitive-business-flow]
  CTX --> C9[api10-unsafe-consumption]

  C1 --> R[CheckResult]
  C2 --> R
  C3 --> R
  C4 --> R
  C5 --> R
  C6 --> R
  C7 --> R
  C8 --> R
  C9 --> R

  R -->|evidence| EV[EvidenceStore]
  R -->|findings| FN[FindingStore]
  R --> AUD[audit.jsonl record in AssessmentEngine]
```

### 3.6 Evidence and reporting flow

```mermaid
flowchart TD
  subgraph Sources
    IM[Imported Burp exchanges]
    CK[SecurityCheck executions]
  end

  IM -->|AssessmentEngine passive import| E1[EvidenceStore.add\ncheck_id=burp-import]
  CK -->|check artifacts| E2[EvidenceStore.add]
  CK -->|Finding objects| F1[FindingStore.add/dedupe]

  E1 --> EF[evidence.json]
  E2 --> EF
  F1 --> FF[findings.json]
  CK --> AL[audit.jsonl]

  EF --> RD[reports.report_data]
  FF --> RD
  AL --> RD
  RD --> RJ[report.json]
  RD --> RM[report.md]
  RD --> RH[report.html]

  DAPI[dashboard_api] -->|optional augmentation| RJ
  DAPI -->|optional augmentation| RM
  DAPI -->|optional augmentation| RH
```

### 3.7 Data model and relationships (implemented structures)

```mermaid
erDiagram
  ENGAGEMENT ||--o{ AUTH_IDENTITY : has
  ENGAGEMENT ||--o{ OBJECT_AUTHZ_CASE : has
  ENGAGEMENT ||--o{ FUNCTION_AUTHZ_CASE : has
  ENGAGEMENT ||--o{ PROPERTY_AUTHZ_CASE : has
  ENGAGEMENT ||--o{ RESOURCE_PROBE : has
  ENGAGEMENT ||--o{ BUSINESS_FLOW : has
  ENGAGEMENT ||--o{ SSRF_CASE : has
  BUSINESS_FLOW ||--o{ BUSINESS_FLOW_STEP : contains

  ASSESSMENT_RESULT ||--|| ENGAGEMENT : for
  ASSESSMENT_RESULT ||--o{ ENDPOINT : includes
  ASSESSMENT_RESULT ||--o{ CHECK_RESULT : produces
  ASSESSMENT_RESULT ||--|| EVIDENCE_STORE : contains
  ASSESSMENT_RESULT ||--|| FINDING_STORE : contains
  CHECK_RESULT ||--o{ EVIDENCE : references
  CHECK_RESULT ||--o{ FINDING : emits
  FINDING ||--o{ EVIDENCE : cites_by_id

  IMPORTED_SCOPE ||--o{ SCOPE_ASSET : contains
  BURP_EXCHANGE ||--|| BURP_REQUEST : has
  BURP_EXCHANGE ||--o| BURP_RESPONSE : has
  ENDPOINT_INVENTORY }o--|| IMPORTED_SCOPE : matched_against

  EVIDENCE_STORE ||--o{ EVIDENCE : stores
  FINDING_STORE ||--o{ FINDING : stores
```

> **Note**: There is no relational database schema in the repository. The diagram represents in-memory/dataclass and serialized JSON relationships.

## 4. Architectural constraints observed

- **Local-first execution**: Dashboard server binds to host/port provided to CLI (default `127.0.0.1:8765`); frontend expects same host/port hardcoded.
- **Safety-first defaults in config examples**: `examples/engagement.yaml` sets `dry_run: true`; CLI `assess --target` defaults to dry-run in `_engagement` construction path (verified).
- **Passive import principle**: Burp observations are imported as evidence without replay (`AssessmentEngine.run` adds `burp-import` evidence with observation "Sanitized Burp observation imported without replay").
- **File-based artifacts**: Evidence/findings/audit/reports are written under the engagement/workspace directory; no database layer is implemented.
- **Partial integration of agent/specialist subsystems**: `agents.py`/`orchestration.py` and `specialists.py` provide routing/catalog capabilities but are not invoked by the assessment engine or CLI assessment flow (verified).
