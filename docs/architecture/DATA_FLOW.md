# Data Flow and Data Contracts

> Verified from implemented dataclasses/models, serializers, and file outputs in `bugbounty/` and `dashboard/`.

## 1. Core data contracts

### 1.1 Configuration and engagement models

| Model | Source | Key fields (verified) | Serialization / format |
|---|---|---|---|
| `ScopeConfig` | `bugbounty/config.py` | `domains`, `urls`, `allowed_methods`, `max_requests_per_minute`, `notes` | In-memory dataclass; containment logic via `contains(target)` |
| `SecurityAppConfig` | `bugbounty/config.py` | `workspace`, `max_requests_per_minute`, `approval_mode`, `dry_run`, `max_parallel_agents`, `audit_log_path`, `evidence_path`, `model_timeout_seconds`, `default_risk_threshold`, `scope` | In-memory dataclass with validation in `__post_init__` |
| `AuthIdentity` | `bugbounty/engagement.py` | `name`, `bearer_token`, `api_key_header`, `api_key_query`, `basic_username`, `basic_password`, `custom_headers` | In-memory dataclass; `__repr__` redacts credentials |
| `ObjectAuthorizationCase`, `FunctionAuthorizationCase`, `PropertyAuthorizationCase`, `ResourceProbe`, `BusinessFlowStep`, `BusinessFlow`, `SsrfCase` | `bugbounty/engagement.py` | Case/probe/flow parameters as defined in dataclasses | In-memory dataclasses; loaded/validated from config by `config_loader` |
| `Engagement` | `bugbounty/engagement.py` | `target_url`, `allowed_hosts/schemes/methods`, `identities`, `request_rate_limit`, `timeout`, `maximum_requests`, `dry_run`, `workspace`, `engagement_id`, `user_agent`, `max_response_bytes`, `follow_redirects`, case/probe lists | In-memory dataclass; `scope()` returns `ScopeConfig`; `validate()` enforces constraints |
| `LoadedAssessmentConfig` | `bugbounty/config_loader.py` | `engagement: Engagement`, `discovery: dict[str, Any]` | In-memory result of YAML/JSON config parsing |

**Assessment config file contract (`load_assessment_config`)**:
- **Format**: `.json` parsed with `json.loads`; `.yaml/.yml` parsed with `yaml.safe_load`.
- **Required**: `target_url` (or `target`) string, `allowed_hosts` non-empty string list.
- **Optional validated fields**: `allowed_schemes`, `allowed_methods`, `identities`, `request_rate_limit`, `timeout`, `maximum_requests`, `dry_run`, `workspace`, `user_agent`, `max_response_bytes`, `follow_redirects`, authorization/property/resource/flow/SSRF case arrays.
- **Discovery object**: optional `discovery` dict; recognized keys copied: `openapi_file`, `endpoint_list`, `endpoint`, `documentation_paths` (with `endpoint_list` type validation).

### 1.2 Discovery and endpoint records

| Model | Source | Key fields | Serialization |
|---|---|---|---|
| `Endpoint` | `bugbounty/discovery.py` | `method`, `url`, `path`, `parameters`, `headers`, `request_body_schema`, `response_information`, `authentication_required`, `source`, `confidence`, `api_version`, `deprecated`, `operation_id`, `tags` | `as_dict()` via `dataclasses.asdict`; included in assessment/report outputs |
| `COMMON_DOC_PATHS` | `bugbounty/discovery.py` | `/openapi.json`, `/swagger.json`, `/api-docs`, `/v1/openapi.json`, `/docs/openapi.json` | Constant tuple |

### 1.3 HTTP request/response records

| Model | Source | Key fields | Notes |
|---|---|---|---|
| `HttpResponse` | `bugbounty/http_client.py` | `request_id`, `evidence_artifact_id`, `url`, `status_code`, `headers`, `body`, `body_size`, `elapsed_ms`, `error`, `dry_run` | `body_sha256` property; bodies/URLs/headers redacted by client before return; used by checks/engine |

### 1.4 Import and inventory contracts

| Model | Source | Key fields | Serialization |
|---|---|---|---|
| `ScopeAsset` | `bugbounty/importers.py` | `identifier`, `normalized_identifier`, `asset_type`, `eligible`, `max_severity`, `source_metadata`; property `supported` | `asdict` in dashboard responses |
| `ImportedScope` | `bugbounty/importers.py` | `assets`, `source`, `metadata` | In-memory container |
| `BurpRequest`, `BurpResponse`, `BurpExchange` | `bugbounty/importers.py` | Parsed/sanitized request-response observations with metadata | In-memory; selected fields surfaced in dashboard traffic view |
| `BurpScopeRule`, `BurpScopeConfiguration` | `bugbounty/importers.py` | Include/exclude rules (`host/protocol/port/path/enabled/raw`) | In-memory; summary counts returned by dashboard validation |
| `EndpointInventory` | `bugbounty/importers.py` | `method`, `url`, `host`, `path`, `source`, `scope_status`, `asset_type`, `api_version`, `operation_id`, `authentication`, `observation_count`, `methods`, `status_codes`, `content_types`, `first_seen`, `last_seen`, `reason` | `as_dict()`; primary normalized inventory contract for dashboard/assessment handoff |

### 1.5 Program policy contract

| Model | Source | Key fields | Serialization |
|---|---|---|---|
| `ProgramPolicy` | `bugbounty/policy.py` | `program_name`, booleans/tuples for account/DoS/social/poc/disclosure/reporting signals, `prohibited_testing_categories`, `manual_attention`, `raw_markdown_reference`, `raw_markdown` | `as_dict()` (includes raw markdown) |

### 1.6 Assessment, checks, evidence, findings

| Model | Source | Key fields | Serialization |
|---|---|---|---|
| `CheckResult` | `bugbounty/checks.py` | `check_id`, `category`, `status`, `reason`, `evidence`, `findings`, `confidence`, `endpoint`, `method`, `applicable`, `executed`, `verified`, `severity`, `evidence_ids`, `remediation` | Included in report data/check summaries |
| `AssessmentResult` | `bugbounty/assessment.py` | `engagement`, `endpoints`, `check_results`, `evidence` (`EvidenceStore`), `findings` (`FindingStore`), `started_at`, `finished_at`, `audit_log` | Aggregated by `reports.report_data` and persisted artifacts |
| `Evidence` | `bugbounty/evidence.py` | `evidence_id`, `timestamp`, `check_id`, `endpoint`, `request_metadata`, `response_metadata`, `observation`, `expected_behavior`, `actual_behavior`, `verification_status` | `as_dict()`; written to `evidence.json` as array |
| `Finding` | `bugbounty/findings.py` | `title`, `category`, `endpoint`, `severity`, `confidence`, `status`, `description`, `impact`, `evidence_ids`, `reproduction_summary`, `remediation`, `references`, `affected_endpoints`, `finding_id`, `method`, `identity`, `context`, `expected_behavior`, `observed_behavior`, `timestamp` | `as_dict()`; written to `findings.json` as array; status constrained to `candidate|verified|rejected|not_verified` |

## 2. Persisted artifacts and schemas (observed/implemented)

### 2.1 Workspace and report artifacts

| Artifact | Producer | Format | Content (verified) |
|---|---|---|---|
| `evidence.json` | `AssessmentEngine.run` (`EvidenceStore.write`) | JSON array | Serialized `Evidence` records (sanitized metadata) |
| `findings.json` | `AssessmentEngine.run` (`FindingStore.write_json`) | JSON array | Serialized `Finding` records |
| `audit.jsonl` | `AssessmentEngine.run` | JSON Lines | One JSON object per check/discovery event with timestamp, check/category, endpoint/method, status/executed/verified/reason |
| `report.json` | `reports.write_json_report` (+ dashboard augmentation) | JSON object | `report_data` output: `engagement`, `timeline`, `endpoints`, `checks`, `checks_executed/not_run/not_applicable`, `findings`, `verified_findings`, `potential_findings`, `informational_observations`, `severity_summary`, `evidence`, `limitations`, `audit_log`; dashboard may add `program`, `policy_warnings`, `intersection` |
| `report.md` | `reports.write_markdown_report` (+ dashboard augmentation) | Markdown text | Human-readable sections for summary/scope/endpoints/checks/findings/evidence/limitations; dashboard may prepend policy section |
| `report.html` | `reports.write_html_report` (+ dashboard augmentation) | HTML document | Summary table/lists for findings/evidence/not-run checks; dashboard may inject policy block before `</body>` |

### 2.2 Other observed files

| Artifact | Producer/context | Notes |
|---|---|---|
| `engagement.json` | CLI `init` | `{ "workspace": "<path>", "status": "initialized" }` (verified) |

## 3. Data transformations between stages

1. **Config file → Engagement + discovery options**
   - `config_loader.load_assessment_config` parses YAML/JSON, validates, constructs typed case/probe/identity objects, validates `Engagement`, extracts discovery keys.

2. **OpenAPI/spec/documentation → Endpoint list**
   - `ApiDiscovery.from_openapi`/`discover` normalizes operations/paths into `Endpoint` records with metadata and confidence/source; filters by safety and allowed methods.

3. **HackerOne scope file → ImportedScope**
   - `importers.parse_hackerone_scope` parses CSV/TSV/JSON/YAML rows into `ScopeAsset` entries with normalized identifiers/types/eligibility.

4. **Burp exports → Burp exchanges/scope config**
   - `parse_burp_xml` / `parse_burp_json` / `parse_burp_json_document` decode/parse HTTP messages and sanitize secrets, producing `BurpExchange` tuples and optional `BurpScopeConfiguration`.

5. **Burp exchanges + scopes → EndpointInventory → Endpoints**
   - `build_inventory` groups observations, computes HackerOne and Burp scope matches, aggregates methods/status/content-types/timestamps.
   - `inventory_to_endpoints` converts **IN_SCOPE** inventory items to `discovery.Endpoint` objects for assessment.

6. **Program Markdown → ProgramPolicy**
   - `parse_program_markdown` extracts deterministic/heuristic signals, prohibited categories, and manual-attention items.

7. **Execution/check results → Evidence/Findings/Audit/Reports**
   - Passive imports and checks create `Evidence`; checks emit `Finding`s; engine records per-check audit entries.
   - `reports.report_data` transforms `AssessmentResult` into a structured report object consumed by JSON/MD/HTML writers and dashboard responses.

## 4. Redaction and data handling

- **HTTP client redaction** (`bugbounty/http_client.py`): redacts sensitive header names (`authorization`, cookies, api keys, etc.) and replaces known identity secrets in URLs/bodies with `[REDACTED]`.
- **Import redaction** (`bugbounty/importers.py`): redacts sensitive headers/query parameters/body fields and bearer tokens in parsed Burp data and URLs.
- **Evidence sanitization** (`bugbounty/evidence.py`): recursively redacts keys containing tokens such as `authorization`, `token`, `secret`, `password`, `api-key`, `cookie`.
- **Dashboard uploads**: request body size limits enforced for JSON and multipart endpoints (10 MB / 50 MB respectively in handler).

## 5. Data flow limitations/inferences

- **No database**: All persistence is file-based in workspace/output directories (verified).
- **Dashboard state is ephemeral**: `DashboardState` is in-memory per server process/class handler state; no persistent session store implemented (verified).
- **Report augmentation mutates files**: Dashboard rewrites generated report files to append policy context (verified).
- **Schema evolution not versioned**: No explicit schema version fields observed in serialized artifacts beyond engagement/config content (inference from code).
