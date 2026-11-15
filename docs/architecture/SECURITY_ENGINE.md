# Security Engine Architecture

> Documents the **implemented** API security checks and execution model in `bugbounty/checks.py`, as invoked by `bugbounty/assessment.py` and configurable via `bugbounty/engagement.py` / `bugbounty/dashboard_api.py`.

## 1. Execution model

### 1.1 Check framework (`bugbounty/checks.py`)

- **`SecurityCheck`**: `id`, `category`, `description`, `execute(endpoint, baseline_response, context) -> CheckResult`, `passive` flag.
- **`CheckContext`**: provides `engagement` (`Engagement`), `client` (`HttpClient`), `evidence` (`EvidenceStore`), `findings` (`FindingStore`).
- **`CheckResult`**: captures `status` (`PASS|FAIL|NOT_RUN|NOT_APPLICABLE|ERROR` used in implementation), applicability/execution/verification flags, confidence/severity, endpoint/method, evidence/findings, reason/remediation.

### 1.2 Engine integration (`bugbounty/assessment.py`)

- Builds endpoint list from discovery or filtered imported inventory.
- For each endpoint, performs one baseline `HttpClient.request(endpoint.method, endpoint.url)` and passes the response to every check.
- Checks may perform additional bounded requests via `context.client` when explicit cases/probes/flows are configured.
- Exceptions in a check are converted to `CheckResult(..., status="ERROR", reason=<ExceptionName>)` so assessment continues.
- Engine records per-check audit entries and adds emitted findings to `FindingStore`.
- Passive Burp observations (when provided) are stored as `burp-import` evidence before check execution.

### 1.3 Dashboard check selection (`bugbounty/dashboard_api.py`)

- Starts from `default_checks()`.
- If parsed program policy indicates `dos_prohibited`, removes checks with `category == "API4"` and adds a policy warning.
- Adds warnings when no Burp observations are supplied (traffic-dependent checks not run).

## 2. Default check registry

`default_checks()` returns the following checks in order:

| Check ID | Category | Description | Passive flag |
|---|---|---|---|
| `api8-security-misconfiguration` | `API8` | Passive security configuration review | `True` |
| `api9-improper-inventory` | `API9` | API inventory source review | `True` |
| `api7-ssrf-indicator` | `API7` | Safe SSRF sink identification | `True` |
| `api2-broken-authentication` | `API2` | Authentication prerequisite assessment | `True` |
| `api1-bola-api5-function` | `API1/API5` | Differential authorization prerequisite assessment | `True` |
| `api3-property-authorization` | `API3` | Property-level authorization assessment | `True` |
| `api4-resource-consumption` | `API4` | Conservative resource consumption assessment | `True` |
| `api6-sensitive-business-flow` | `API6` | Sensitive business flow assessment | `True` |
| `api10-unsafe-consumption` | `API10` | Unsafe consumption assessment | `True` |

> Note: "Passive flag" is metadata on `SecurityCheck`; several checks can perform additional active requests when explicit configuration cases exist.

## 3. OWASP API Top 10 check mapping (implemented behavior)

### 3.1 API1 - Broken Object Level Authorization (BOLA)

- **Vulnerability target**: Cross-identity access to another user's/object owner's resource.
- **Implementation**: Implemented within `check_authorization` (`check_id` emitted as `api1-bola` on matched object case). Requires `>=2` engagement identities and a matching `ObjectAuthorizationCase`.
- **How it works**: For a matching case, requests owner object as owner, other identity's own object, and owner object as other identity; compares success states. Emits verified finding if owner and other-own-object succeed and cross-identity access to owner object succeeds.
- **Invocation**: Runs as part of `api1-bola-api5-function` for each endpoint/baseline response.
- **Evidence recorded**: Comparative request/response metadata (statuses, identities/object IDs in request metadata extras) via `_evidence`.
- **Result classification**: `FAIL` + `verified` finding on confirmed cross-access; `PASS` with evidence when comparison does not demonstrate issue; `NOT_RUN` when prerequisites/cases absent.
- **Tests**: `tests/test_authorized_checks.py`, `tests/test_assessment_engine.py` (engine integration paths), and related config/engagement tests (verify in test suite).
- **Missing/limits**: Only runs for explicitly configured object cases/endpoints; no automatic object ID discovery or ownership inference.

### 3.2 API2 - Broken Authentication

- **Vulnerability target**: Protected endpoints accessible anonymously or with invalid/expired/malformed credentials.
- **Implementation**: `check_authentication` (`api2-broken-authentication`).
- **How it works**: Requires configured identities and `endpoint.authentication_required`. If baseline response is successful, records anonymous access finding. Additionally tests identities named `invalid`, `expired`, or `malformed` and flags success as verified failure.
- **Invocation**: Default check on every endpoint.
- **Evidence recorded**: Baseline and invalid-identity request/response evidence artifacts.
- **Result classification**: `FAIL` + verified findings on successful anonymous/invalid access; `PASS` when no failure evidence produced; `NOT_RUN` if no identities; `NOT_APPLICABLE` if endpoint not declared protected.
- **Tests**: `tests/test_authorized_checks.py`, `tests/test_assessment_engine.py`.
- **Missing/limits**: Relies on spec/auth metadata and specially named identities; does not acquire or fuzz credentials.

### 3.3 API3 - Broken Object Property Level Authorization (BOPLA)

- **Vulnerability target**: Excessive protected property exposure and unauthorized protected property writes.
- **Implementation**: `check_property_authorization` (`api3-property-authorization`).
- **How it works**: Requires matching `PropertyAuthorizationCase`. Fetches configured response as specified identity, parses JSON, checks for configured protected properties in response. If `write_endpoint` configured, sends bounded JSON write probe for protected properties and evaluates acceptance.
- **Invocation**: Default check; active only when matching cases exist.
- **Evidence recorded**: Read and optional write probe evidence with identity/method context.
- **Result classification**: `FAIL` with verified findings on exposed properties or accepted protected writes; `PASS` if no issues; `NOT_RUN` without configured cases; `NOT_APPLICABLE`/`ERROR` for non-JSON or unsuccessful read as implemented.
- **Tests**: `tests/test_authorized_checks.py`, `tests/test_extended_boundaries.py` (where applicable).
- **Missing/limits**: Explicit property/case configuration required; no schema inference for sensitive fields.

### 3.4 API4 - Unrestricted Resource Consumption

- **Vulnerability target**: Missing/weak limits on repeated or parameterized resource usage.
- **Implementation**: `check_resource_consumption` (`api4-resource-consumption`).
- **How it works**: Requires matching `ResourceProbe`. Sends bounded repeated requests (1–5 configured) with optional safe limit query parameter. Treats budget exhaustion as `ERROR`. If all responses successful and query parameter used, emits candidate finding indicating boundary accepted repeated configured requests.
- **Invocation**: Default check unless removed by dashboard policy gate when `dos_prohibited`.
- **Evidence recorded**: Aggregated response statuses for bounded probe sequence.
- **Result classification**: `FAIL` candidate finding under implemented heuristic; `PASS` otherwise when probe executed; `NOT_RUN` without probe; `ERROR` on request budget exhaustion.
- **Tests**: `tests/test_authorized_checks.py`, `tests/test_scope_only_http_regression.py` and policy-gating behavior in dashboard tests where covered.
- **Missing/limits**: Conservative, heuristic-only; does not perform high-volume or destructive stress testing.

### 3.5 API5 - Broken Function Level Authorization (BFLA)

- **Vulnerability target**: Lower-privilege identity invoking privileged function/endpoint.
- **Implementation**: Implemented within `check_authorization` (`check_id` emitted as `api5-function-authorization` on matched function case). Requires matching `FunctionAuthorizationCase` and `>=2` identities.
- **How it works**: Compares allowed vs denied identity responses for configured function endpoint/method; verified finding if allowed succeeds and denied also succeeds.
- **Invocation**: Part of `api1-bola-api5-function` check.
- **Evidence recorded**: Comparative evidence with allowed/denied identities and statuses.
- **Result classification**: `FAIL` + verified finding on confirmed unauthorized function access; `PASS` with evidence when denied access not demonstrated; `NOT_RUN` when prerequisites/cases absent.
- **Tests**: `tests/test_authorized_checks.py`.
- **Missing/limits**: Explicit case configuration required; no automatic role/function discovery.

### 3.6 API6 - Unrestricted Access to Sensitive Business Flows

- **Vulnerability target**: Replay/abuse of sensitive workflow steps.
- **Implementation**: `check_business_flow` (`api6-sensitive-business-flow`).
- **How it works**: Requires matching `BusinessFlow` with configured steps. Executes steps in order; if any step fails, returns `ERROR`. If `replay_step` configured, replays that step and evaluates success as verified replay issue.
- **Invocation**: Default check; active only for matching configured flows.
- **Evidence recorded**: Replay attempt evidence when applicable.
- **Result classification**: `FAIL` + verified finding when replay succeeds; `PASS` when replay rejected; `ERROR` if configured flow cannot complete; `NOT_RUN` without configured flow.
- **Tests**: `tests/test_authorized_checks.py`, `tests/test_extended_boundaries.py` (coverage dependent).
- **Missing/limits**: Fully configuration-driven; no automatic workflow inference or stateful business logic modeling.

### 3.7 API7 - Server Side Request Forgery (SSRF)

- **Vulnerability target**: Server-side fetch of attacker-controlled/unsafe URLs via URL-like parameters.
- **Implementation**: `check_ssrf_indicator` (`api7-ssrf-indicator`, may emit `api7-ssrf-verification`).
- **How it works**: Detects URL-like parameter names (`url`, `uri`, `callback`, `webhook`, `redirect`, `next`, `image_url`, `resource`) from endpoint parameter metadata. Always records potential sink observation/candidate finding when candidates exist. If a matching `SsrfCase` provides `verification_url` and `callback_token`, performs a controlled request with that parameter and marks verified if token observed in response.
- **Invocation**: Default check.
- **Evidence recorded**: Sink observation evidence and optional verification evidence.
- **Result classification**: `FAIL` candidate for indicator-only; `FAIL` verified when controlled verification token observed; `NOT_APPLICABLE` when no URL-like parameter discovered.
- **Tests**: `tests/test_assessment_engine.py`, `tests/test_authorized_checks.py` and SSRF-related cases.
- **Missing/limits**: No out-of-band callback infrastructure; verification limited to explicitly configured local/controlled URL+token scenarios.

### 3.8 API8 - Security Misconfiguration

- **Vulnerability target**: Insecure transport/configuration and unsafe response/security header posture.
- **Implementation**: `check_security_misconfiguration` (`api8-security-misconfiguration`).
- **How it works**: Uses baseline response (not run in dry-run). Flags HTTP scheme as verified finding, wildcard CORS (`Access-Control-Allow-Origin: *`) as verified finding, and records observation for missing `X-Content-Type-Options` / `Content-Security-Policy` headers.
- **Invocation**: Default check.
- **Evidence recorded**: Observations/findings tied to response/header state.
- **Result classification**: `FAIL` when verified misconfig findings emitted; `PASS` otherwise when executed; `NOT_RUN` in dry-run/unexecuted baseline.
- **Tests**: `tests/test_assessment_engine.py`, `tests/test_additional_coverage.py`.
- **Missing/limits**: Passive/header-level heuristics only; not a comprehensive configuration benchmark.

### 3.9 API9 - Improper Inventory Management

- **Vulnerability target**: Deprecated/undocumented/unmanaged API exposure.
- **Implementation**: `check_inventory` (`api9-improper-inventory`).
- **How it works**: Flags deprecated endpoints from spec metadata as candidate finding. Flags endpoints discovered from direct target/non-authoritative documentation probes as candidate inventory-review findings. Returns not applicable for supplied OpenAPI inventory endpoints.
- **Invocation**: Default check.
- **Evidence recorded**: Inventory/source/deprecation observations.
- **Result classification**: `FAIL` candidate in flagged cases; `NOT_APPLICABLE` for supplied inventory endpoints.
- **Tests**: `tests/test_assessment_engine.py`, discovery/import-related tests.
- **Missing/limits**: Heuristic/source-based; does not compare against external authoritative inventories.

### 3.10 API10 - Unsafe Consumption of APIs

- **Vulnerability target**: Unsafe handling/assumptions about upstream API responses/content types.
- **Implementation**: `check_unsafe_consumption` (`api10-unsafe-consumption`).
- **How it works**: Static/observational review requiring `endpoint.response_information` (response contract). If baseline response content type is `text/html`, emits candidate finding for unexpected upstream content type.
- **Invocation**: Default check.
- **Evidence recorded**: Content-type observation when mismatch heuristic triggers.
- **Result classification**: `FAIL` candidate on detected mismatch; `PASS` when no issue observed; `NOT_RUN` when no response contract supplied.
- **Tests**: `tests/test_authorized_checks.py`/engine or additional coverage tests where applicable.
- **Missing/limits**: Narrow heuristic; does not perform deep schema validation or downstream parser safety testing.

## 4. Evidence, findings, and reporting semantics

- **Evidence-first artifacts**: Checks attach evidence objects/IDs; `AssessmentEngine` persists all evidence to `evidence.json`.
- **Finding statuses**: `Finding` enforces statuses `candidate`, `verified`, `rejected`, `not_verified`; `FindingStore.add` deduplicates by `(category,title)` key and merges evidence/endpoints/confidence/status.
- **Auditability**: `audit.jsonl` records per-check status/execution/verification/reason for each endpoint-check pair.
- **Report interpretation**: Reports separate checks executed/not run/not applicable and findings by verification/potential status (per `reports.report_data`).

## 5. Safety boundaries in check execution

- All network activity performed by checks goes through `HttpClient`, which enforces scheme/scope/method allowlists, request budgets, rate limiting, timeouts, redirect policy, and dry-run behavior.
- Configuration-driven checks (`Object/Function/Property/Resource/Flow/SSRF` cases) only activate when explicit cases/probes are provided.
- Dashboard can disable API4 based on parsed program policy (`dos_prohibited`).
