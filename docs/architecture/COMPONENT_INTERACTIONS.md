# Component Interactions

> Verified from source code. Describes **actual runtime interactions** implemented in the repository.

## 1. CLI interactions

### 1.1 Command dispatch (`bugbounty/cli.py`)

| Command | Implemented behavior | Interacts with |
|---|---|---|
| `init` | Creates workspace directory and writes `engagement.json` with `{workspace, status:"initialized"}` | `pathlib`, filesystem |
| `status` | Prints JSON with workspace existence and `report.*` filenames in workspace | `pathlib`, filesystem |
| `report` | Prints expected paths for `report.json`, `report.md`, `report.html` under workspace | `pathlib` |
| `dashboard` | Starts local dashboard API server (blocking) | `dashboard_api.serve_dashboard` |
| `discover` | Builds `Engagement` via `_engagement(args)`, runs `ApiDiscovery(...).discover(openapi_file=...)`, prints endpoint JSON | `engagement.Engagement`, `http_client.HttpClient`, `discovery.ApiDiscovery` |
| `recon` | Forces `dry_run=True`, `timeout=5.0`, `max_requests=10`, discovers from target/common doc behavior, prints endpoints JSON | `engagement`, `http_client`, `discovery` |
| `assess` | Loads config (`--config`) or builds target engagement (`--target`), runs `AssessmentEngine(...).run(...)`, writes reports, prints summary and report paths | `config_loader.load_assessment_config`, `assessment.AssessmentEngine`, `reports.write_reports` |

**Error handling**: `assess` catches `ConfigurationError`, `ValueError`, `OSError` and returns exit code `2` with `Configuration error: ...` (verified).

### 1.2 Engagement construction in CLI

`_engagement(args)` creates a GET-only, HTTP/HTTPS-allowed engagement using `Engagement.from_target(...)` with:
- `allowed_methods=["GET"]`
- `maximum_requests` default 50
- `timeout` default 5.0
- `dry_run` from args (default false in argparse, but command paths set it explicitly in some cases)
- `workspace` from args

This path is used by `discover`, `recon`, and `assess --target` (not by `assess --config`).

## 2. Dashboard frontend ↔ backend interactions

### 2.1 Frontend API client (`dashboard/src/App.tsx`)

- **Base URL**: constant `API = "http://127.0.0.1:8765"` (hardcoded).
- **Request helper**: `api(path, options)` performs `fetch`, parses JSON, throws on non-OK using `payload.message || payload.error || "Request failed"`.
- **Validation flow**: `POST /engagement/validate` with `FormData` fields `program_rules`, `scope_file`, `burp_file`.
- **Assessment run**: `POST /assessment/run` with JSON `{ target_url?: string, dry_run: boolean }` (requires prior validation state in UI and backend).
- **Data refresh/views**: `GET /program`, `/scope`, `/burp/traffic`, `/burp`, `/endpoints`, `/findings`, `/evidence`, `/evidence/{id}`.
- **Reports**: opens/links to `GET /reports/json|markdown|html`.

### 2.2 Backend request handling (`bugbounty/dashboard_api.py`)

- **Server**: `ThreadingHTTPServer` via `serve_dashboard(host, port)`; handler `DashboardHandler` uses class-level shared `state = DashboardState()`.
- **CORS**: Allows origins `http://localhost:5173` and `http://127.0.0.1:5173`; methods `GET, POST, OPTIONS`; header `Content-Type`.
- **POST endpoints**:
  - `/engagement/validate`: multipart parser; validates required text/file fields and extensions (`.csv` scope, `.json` Burp); updates state.
  - `/program/import`, `/scope/import`, `/burp/import`: JSON body `{filename, content}`; imports into state.
  - `/assessment/run`: JSON body; calls `state.run_assessment(..., require_validation=True)`.
- **GET endpoints**: serve in-memory state (`scope`, `program`, `burp`, `burp/traffic`, `endpoints`, `findings`, `evidence`) and report files from `state.report_paths`.
- **Errors**: most handler exceptions are caught and returned as `400` JSON `{error: <ExceptionName>, message: <str>}`.

## 3. Dashboard backend ↔ core engine interactions

### 3.1 Validation (`DashboardState.validate_engagement`)
1. Validates presence and file extensions.
2. Parses program Markdown via `parse_program_markdown`.
3. Parses HackerOne scope via `parse_hackerone_scope` from a temporary file.
4. Parses Burp JSON document via `parse_burp_json_document` (returns Burp scope config + exchanges).
5. Builds normalized inventory via `build_inventory(exchanges, scope, burp_scope)`.
6. Stores `EngagementContext` and marks `validation_complete=True`.
7. Returns summary including policy, scope assets/metadata, Burp counts/rules, and intersection metrics.

### 3.2 Assessment (`DashboardState.run_assessment`)
1. Requires validation if `require_validation=True`.
2. Requires imported HackerOne scope; derives in-scope endpoints from inventory (`inventory_to_endpoints`).
3. Computes target URL (payload override, else first in-scope endpoint, else fallback from eligible scoped assets).
4. Computes allowed hosts from in-scope inventory hosts or eligible H1 assets intersecting Burp scope host boundary.
5. Builds `Engagement` (methods from in-scope inventory or default `GET`; dry-run/max requests/timeout/workspace from payload/defaults) and validates it.
6. Selects checks from `default_checks()` and disables API4 checks if `program.dos_prohibited` is true; appends policy warnings (no Burp traffic warning if exchanges empty).
7. Runs `AssessmentEngine(engagement, checks=...).run(endpoint_inventory=in_scope, imported_exchanges=exchanges)`.
8. Writes reports via `write_reports` and augments report files with program/policy context (`_add_report_context`).
9. Returns `report_data` merged with `program`, `policy_warnings`, and `intersection`.

## 4. Assessment engine interactions (`bugbounty/assessment.py`)

1. **Initialization**: stores `Engagement`, creates `HttpClient(engagement)` (which installs `SafetyPolicy` from engagement scope), and resolves check list.
2. **Discovery/import selection**:
   - If `endpoint_inventory` provided: filters items by `client.safety_policy.check(url, method).allowed`.
   - Else: calls `ApiDiscovery(...).discover(...)`.
   - Discovery exceptions (`OSError`, `ValueError`, `TypeError`) produce an error audit record and empty endpoint list.
3. **Passive Burp evidence import**: for each `imported_exchanges` item, adds an `Evidence` artifact (`check_id="burp-import"`, verification `observed`) capturing sanitized request/response metadata.
4. **Check execution loop**:
   - For each endpoint: performs `client.request(endpoint.method, endpoint.url)` once (baseline response passed to checks).
   - For each check: executes `check.execute(endpoint, response, context)`; exceptions are converted to `CheckResult(..., status="ERROR")`.
   - Appends audit log entry per check execution and adds returned findings to `FindingStore`.
5. **Persistence**: ensures workspace exists, writes `evidence.json`, `findings.json`, and `audit.jsonl`.
6. **Result**: returns `AssessmentResult` with endpoints, check results, stores, timestamps, audit log.

## 5. Discovery and HTTP interactions

### 5.1 `ApiDiscovery` (`bugbounty/discovery.py`)
- **File-based OpenAPI**: loads JSON file and normalizes paths/operations to `Endpoint`s.
- **Manual/list**: normalizes provided URL(s) to GET endpoints and filters by safety/allowed methods.
- **Documentation probing**: iterates candidate paths (`COMMON_DOC_PATHS` or provided), fetches with `HttpClient.request("GET", ...)`, parses JSON OpenAPI/Swagger (`paths` object), and returns normalized endpoints; falls back to manual target endpoint if none found.
- **Filtering**: `_allowed` requires `safety_policy.authorize_target` and method in `engagement.allowed_methods`.
- **OpenAPI normalization**: supports Swagger 2.0 and OpenAPI 3.x (string starts with `3.`), extracts parameters, request schema, responses, auth requirement, tags/operation metadata.

### 5.2 `HttpClient` (`bugbounty/http_client.py`)
- **Pre-flight enforcement**: scheme allowlist, `SafetyPolicy.check`, engagement allowed methods, max request budget, dry-run short-circuit.
- **Rate limiting**: sleeps based on `request_rate_limit` and last request time.
- **Auth application**: identity lookup injects custom headers, bearer/basic/api-key header, and api-key query parameter when configured.
- **Execution**: `urllib.request` opener with optional redirect handler (`_NoRedirectHandler` when `follow_redirects=False`).
- **Capture/redaction**: truncates body to `max_response_bytes`, redacts secret header names and known secret values in URL/body; returns `HttpResponse` with timing/error metadata.

## 6. Security check interactions (`bugbounty/checks.py`)

- Checks receive `(endpoint, baseline_response, CheckContext)` and may perform additional `context.client.request(...)` calls depending on configuration (e.g. auth/property/resource/flow/SSRF/authorization cases).
- Checks record evidence via `context.evidence.add(...)` and emit `Finding` objects in `CheckResult.findings`.
- `AssessmentEngine` is responsible for appending findings to `FindingStore` and writing audit entries; checks do not write files directly.
- `default_checks()` returns the ordered list of 9 check definitions currently wired into the engine.

## 7. Importer and policy interactions (`bugbounty/importers.py`, `policy.py`)

- **HackerOne scope**: parsed from CSV/TSV/JSON/YAML into `ImportedScope`/`ScopeAsset` records; asset normalization/classification and eligibility parsing performed.
- **Burp data**: XML and JSON traffic/history parsed into `BurpExchange` records with redaction/sanitization; Burp JSON documents may also provide `BurpScopeConfiguration` include/exclude rules.
- **Inventory/scoping**: `build_inventory` groups exchanges by method+redacted URL, computes HackerOne match and optional Burp technical scope match, and emits `EndpointInventory` records; `inventory_to_endpoints` converts in-scope items to discovery `Endpoint`s.
- **Program policy**: `parse_program_markdown` heuristically extracts policy signals and manual-attention items for dashboard policy warnings/check gating.

## 8. Reporting interactions (`bugbounty/reports.py`, `dashboard_api.py`)

- `write_reports(result)` writes `report.json`, `report.md`, `report.html` into `result.engagement.workspace`.
- `report_data(result)` aggregates engagement/timeline/endpoints/checks/findings/evidence/audit and derived summaries.
- Dashboard may post-process generated JSON/Markdown/HTML to inject program policy and warning context (`DashboardState._add_report_context`).

## 9. Utility subsystems (implemented but not in main assessment path)

- **`agents.py` + `orchestration.py`**: `Mission.dispatch()` routes via `route_agent` against an injected `AgentRegistry`; `Mission.is_authorized()` delegates to `SafetyPolicy`. Not used by CLI or `AssessmentEngine`.
- **`specialists.py`**: Provides richer normalized specialist catalog and ranking (`DEFAULT_SPECIALIST_REGISTRY`, `ranked_specialists`, `route_specialist`) for signal/target-based prioritization. Not invoked by CLI/dashboard/engine runtime flow.
