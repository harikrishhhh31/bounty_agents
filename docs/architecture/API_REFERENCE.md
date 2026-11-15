# API and CLI Reference

> Documents **implemented** interfaces only, verified from `bugbounty/cli.py`, `bugbounty/dashboard_api.py`, and related modules. No undocumented routes/commands are invented.

## 1. CLI reference

Entry point: `bugbounty = "bugbounty.cli:main"` (`pyproject.toml`). Can also be invoked as `python -m bugbounty.cli`.

### 1.1 Global behavior
- Parser prog: `bugbounty`
- Unknown/no command: prints help and exits `0`.
- `assess` configuration/runtime load errors (`ConfigurationError`, `ValueError`, `OSError`) return exit code `2` with `Configuration error: <message>`.

### 1.2 Commands

| Command | Syntax | Required parameters | Optional parameters | Implemented behavior | Output / side effects | Failure modes |
|---|---|---|---|---|---|---|
| `init` | `bugbounty init [--workspace PATH]` | None | `--workspace` (default `.`) | Creates workspace dir and writes `engagement.json` (`{"workspace": ..., "status": "initialized"}`) | Prints `Initialized workspace: <path>` | Filesystem errors may raise (not specially handled) |
| `status` | `bugbounty status [--workspace PATH]` | None | `--workspace` (default `.`) | Reports workspace existence and `report.*` filenames | Prints JSON `{workspace, exists, reports[]}` | None special |
| `recon` | `bugbounty recon --target URL [--workspace PATH]` | `--target` | `--workspace` (default `.`) | Forces dry-run/timeout/max_requests, builds engagement, runs discovery | Prints JSON array of discovered endpoints | Discovery/HTTP/scope constraints reflected in results/errors depending on call path |
| `discover` | `bugbounty discover --target URL [--workspace PATH] [--openapi-file PATH] [--dry-run]` | `--target` | `--workspace`, `--openapi-file`, `--dry-run` | Builds engagement and runs `ApiDiscovery.discover` | Prints JSON array of endpoints | OpenAPI load/validation errors may propagate as exceptions in underlying modules |
| `assess` | `bugbounty assess (--target URL \| --config PATH) [options]` | `--target` or `--config` | `--workspace` (default `./workspace`), `--openapi-file`, `--dry-run`, `--max-requests` (50), `--timeout` (5.0) | Runs assessment from config or target engagement and writes reports | Prints summary line and report file paths; creates workspace artifacts and reports | Returns `2` on config/value/OS errors; requires `--target` if `--config` omitted |
| `report` | `bugbounty report [--workspace PATH]` | None | `--workspace` (default `./workspace`) | Prints expected report paths only (does not regenerate) | Prints paths for `report.json`, `report.md`, `report.html` | None special |
| `dashboard` | `bugbounty dashboard [--host HOST] [--port PORT]` | None | `--host` (default `127.0.0.1`), `--port` (default `8765`) | Starts local dashboard API server (blocking) | Prints listening URL then serves forever | Port bind/permission errors propagate |

### 1.3 CLI notes

- `assess --config` ignores `--target/--openapi-file/--dry-run/--max-requests/--timeout` values for engagement construction because it uses the loaded config; discovery options come from config `discovery` (verified by code path).
- `recon`/`discover`/`assess --target` use CLI helper defaults (GET-only, http/https schemes, host derived from target URL).

## 2. Dashboard HTTP API reference

Server: `bugbounty.dashboard_api.serve_dashboard` (`ThreadingHTTPServer`, handler `DashboardHandler`).  
Default base URL: `http://127.0.0.1:8765`.  
CORS: allows `http://localhost:5173` and `http://127.0.0.1:5173` origins.

### 2.1 Common behavior

- **Content types**: JSON endpoints accept/return `application/json` (except validation multipart and report text responses).
- **Error responses**: On handled exceptions, returns status `400` with JSON body:
  ```json
  { "error": "<ExceptionClassName>", "message": "<string>" }
  ```
- **Not found**: `404` JSON `{ "error": "not found" }` (or specific resource messages for missing evidence/report).
- **State model**: Single in-memory `DashboardState` attached to handler class; shared across requests in process.

### 2.2 Endpoints

| Method | Path | Purpose | Request schema | Response schema | Validation / constraints | Auth | Source |
|---|---|---|---|---|---|---|---|
| `OPTIONS` | any | CORS preflight | none | empty body, `204` | n/a | None | `DashboardHandler.do_OPTIONS` |
| `POST` | `/engagement/validate` | Validate/import program rules, H1 scope, Burp JSON and compute intersection | `multipart/form-data` fields: `program_rules` (text), `scope_file` (file, `.csv`), `burp_file` (file, `.json`) | `200` JSON: `{ valid, program, scope{assets,metadata}, burp{requests,format,scope_configuration,include_rules,exclude_rules}, intersection{...} }` | All three inputs required; scope must be `.csv`; burp must be `.json`; body size limit 50 MB; empty program/scope/burp rejected | None | `do_POST`, `validate_engagement`, `_read_multipart` |
| `POST` | `/program/import` | Import program policy markdown | JSON `{ filename?: string, content?: string }` | `200` JSON `ProgramPolicy.as_dict()` | `content` parsed as markdown text | None | `import_program` |
| `POST` | `/scope/import` | Import HackerOne scope file content | JSON `{ filename?: string, content?: string }` | `200` JSON `{ assets: [...], metadata: {...} }` | Parsed via `parse_hackerone_scope`; temp file used; rebuilds inventory if Burp exchanges already loaded | None | `import_scope` |
| `POST` | `/burp/import` | Import Burp traffic export content | JSON `{ filename?: string, content?: string }` | `200` JSON `{ requests: number, inventory: [...], format: string }` | `.json` parsed with `parse_burp_json`; other extensions parsed with `parse_burp_xml`; rebuilds inventory if scope loaded | None | `import_burp` |
| `POST` | `/assessment/run` | Run assessment against validated in-scope inventory | JSON `{ target_url?: string, dry_run?: boolean, maximum_requests?: number, timeout?: number, workspace?: string }` | `200` JSON `report_data(result)` merged with `program`, `policy_warnings`, `intersection` | Requires prior `/engagement/validate` (`require_validation=True`); requires imported scope and non-empty effective scope; may reject if no in-scope HTTP endpoints available | None | `run_assessment` |
| `GET` | `/scope` | Retrieve imported scope assets | none | `200` JSON `{ assets: [...] }` (empty if none) | n/a | None | `do_GET` |
| `GET` | `/program` | Retrieve imported/validated program policy | none | `200` JSON `ProgramPolicy.as_dict()` or `{ "program": null }` | n/a | None | `do_GET` |
| `GET` | `/burp/traffic` | Retrieve parsed traffic view | none | `200` JSON `{ traffic: [...] }` where each item includes id/timestamp/method/host/path/url/status/content_type/scope_status | Scope status computed against H1 scope if loaded | None | `do_GET`, `_exchange_view` |
| `GET` | `/burp` | Retrieve Burp import summary | none | `200` JSON `{ format, requests, intersection }` | n/a | None | `do_GET` |
| `GET` | `/endpoints` | Retrieve normalized endpoint inventory | none | `200` JSON `{ endpoints: [...] }` (`EndpointInventory.as_dict()` items) | n/a | None | `do_GET` |
| `GET` | `/findings` | Retrieve assessment findings | none | `200` JSON `{ findings: [...] }` or empty array if no result | n/a | None | `do_GET` |
| `GET` | `/evidence` | Retrieve evidence ledger | none | `200` JSON `{ evidence: [...] }` or empty array if no result | n/a | None | `do_GET` |
| `GET` | `/evidence/{evidence_id}` | Retrieve one evidence artifact | path parameter: `evidence_id` | `200` JSON evidence object, or `404` JSON `{ "error": "evidence not found" }` | n/a | None | `do_GET` |
| `GET` | `/reports/{kind}` | Retrieve generated report file | `kind` in `json|markdown|html` (by path suffix) | `200` body with content type `application/json`, `text/markdown`, or `text/html`; `404` JSON `{ "error": "report not found" }` if unavailable | Reads from `state.report_paths[kind]` | None | `do_GET` |

### 2.3 API caveats and implementation notes

- **`/engagement/validate` vs generic imports**: Validation endpoint only accepts H1 scope `.csv` and Burp `.json` and stores both Burp scope config and exchanges; `/scope/import` and `/burp/import` accept broader formats supported by `importers` (`json/yaml/csv/tsv` for scope parsing path, `json/xml` for Burp import path).
- **Assessment gating**: `/assessment/run` enforces prior validation in state (`validation_complete`) and requires H1 scope plus effective in-scope hosts intersecting Burp scope (per implementation logic).
- **Security controls**: No authentication/authorization implemented on dashboard API routes; intended for local use (inferred from localhost defaults/CORS, but not enforced by auth middleware).
- **Report serving**: Serves files written to workspace; content may include dashboard-injected policy context.

## 3. File-based interfaces

| Interface | Location/format | Producer | Consumer |
|---|---|---|---|
| Assessment config | YAML/JSON file (see `config_loader` schema) | User/operator | CLI `assess --config` |
| OpenAPI spec | JSON file (`openapi` 3.x or `swagger` 2.0) | User/system | `ApiDiscovery.from_openapi/discover` |
| HackerOne scope | CSV/TSV/JSON/YAML (`parse_hackerone_scope`) | User/export | Dashboard imports, `importers` |
| Burp export | XML (`parse_burp_xml`), JSON traffic/history or scope+history document (`parse_burp_json(_document)`) | Burp/user | Dashboard imports, assessment passive evidence |
| Program policy | Markdown text (pasted/uploaded content) | User | Dashboard policy parsing/gating |
| Workspace artifacts | `evidence.json`, `findings.json`, `audit.jsonl`, `report.*` | Assessment engine/reports/dashboard augmentation | Users, dashboard report endpoints, CLI report path listing |
