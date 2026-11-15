# Independent QA / Red-Team Review — `bounty_agents`

**Document:** `docs/QA/INDEPENDENT_REVIEW.md`  
**Review type:** Independent inspection (no trust in prior reports)  
**Repository:** `C:\Users\harikrishhhh\OneDrive\Attachments\Desktop\bugbounty`  
**Review date:** 2026-11-15  
**Baseline provided:** `105 pytest passed`, `compileall`/`tsc`/bash syntax passed (not independently re-executed in full; targeted read-only inspection and static checks performed)

## Executive summary

The core assessment pipeline demonstrates several strong safety-oriented patterns: scope-gated HTTP execution (`bugbounty/http_client.py`, `bugbounty/safety.py`), request budgeting/rate limiting, `subprocess.run(..., shell=False, ...)` in the external tool adapter, bounded timeouts/output handling, and evidence/request redaction helpers. However, this independent review identified **release-significant gaps and defects**:

- **Dashboard API has no authentication/authorization and uses shared in-memory mutable state** in a threaded server, creating data exposure, integrity, and race-condition risks for any reachable local/network context (`bugbounty/dashboard_api.py`).
- **`/tools` endpoint implementation is contract-broken** against `available_adapters()` and is likely to error at runtime (`bugbounty/dashboard_api.py`, `bugbounty/tool_adapters.py`).
- **Attack surface graph generation/persistence failures are silently swallowed**, allowing partial/corrupt/missing graph state without operator visibility (`bugbounty/assessment.py`).
- **External tool adapter safety is incomplete for untrusted operator/config input**: arbitrary `extra_args` are forwarded to Nuclei without an allowlist, enabling scope-bypass or unintended behavior despite per-target URL validation; raw tool request/response/curl data is normalized without redaction (`bugbounty/tool_adapters.py`).
- **Tool adapter framework/Nuclei are not integrated into assessment/CLI/dashboard execution paths**, so “optional adapter” runtime capability is currently scaffold-only (discoverable in code/tests, not wired into scans).
- **Evidence persistence/hydration is best-effort and can drop artifacts silently**; cached replay paths restore limited result context and can degrade determinism/traceability across restarts.
- **Frontend/dashboard contract and exposure gaps exist** (graph/tools/API data not surfaced; API serves sensitive assessment artifacts without auth).

**Release-blocker assessment:** **NOT RELEASE-READY for exposed/shared or security-sensitive use.** At minimum, fix dashboard `/tools` correctness, add access controls or hard-disable remote exposure, address adapter `extra_args`/raw-output safety, and make graph/persistence failures observable before relying on these features. For strictly local, single-user, disposable analysis with trusted inputs, risk is lower but notable defects remain.

**Lead integration note (Mission 2):** `/tools` endpoint contract handling was corrected during integration to consume `available_adapters()` dict results and return structured tool status; basic optional Nuclei runtime hook added in assessment/CLI (dry-run/missing-binary/scope-aware, graceful handling). Other findings remain open or partially addressed as documented in `MISSION_2_PROGRESS.md` / final report.

## Scope and method

### In scope (requested)
- Assessment orchestration, identity-aware caching, evidence persistence/hydration/restart behavior, finding verification semantics, status semantics consistency
- Attack surface graph implementation and integration (generation, persistence/reload, reference integrity, CLI/API/dashboard exposure gaps)
- Tool adapter framework and Nuclei adapter (safety, scope enforcement, timeouts/bounds, parsing untrusted output, missing-tool behavior, runtime integration state)
- Dashboard API contracts vs frontend expectations, sensitive data exposure, auth/secrets handling, in-memory state limitations
- CLI argument validation, error handling, exit codes
- PowerShell/Bash scripts safety (quoting, destructive actions, cwd assumptions)
- Security regressions, race conditions/persistence failures, untested/error paths, false-positive risks

### Method
- **Independent static inspection** of source, tests, scripts, docs, and frontend code (no trust in prior reports).
- **Read-only repository inspection** via file reads and pattern searches (e.g. `subprocess`, `shell=`, `CORS`, auth/secret/state patterns, adapter integration usage).
- **Targeted contract tracing** across engine ↔ stores ↔ graph ↔ API ↔ frontend.
- **No implementation changes made. No state-changing commands executed.** Baseline test/compile status accepted as provided.

### Limitations
- Did not execute full runtime/manual end-to-end scenarios in this pass.
- `bugbounty/checks.py` and some modules are large; review focused on exported behavior, status/verification logic, evidence handling, and risk-relevant paths.
- Frontend `node_modules` artifacts exist in workspace; review focused on project sources (`dashboard/src/App.tsx`) and API contracts, not vendored dependencies.

## Files reviewed (primary)

**Core/runtime:** `bugbounty/assessment.py`, `bugbounty/checks.py` (targeted), `bugbounty/evidence.py`, `bugbounty/findings.py`, `bugbounty/investigation.py`, `bugbounty/workspace.py`, `bugbounty/preconditions.py`, `bugbounty/attack_surface_graph.py`, `bugbounty/tool_adapters.py`, `bugbounty/dashboard_api.py`, `bugbounty/cli.py`, `bugbounty/reports.py`, `bugbounty/http_client.py`, `bugbounty/safety.py`, `bugbounty/engagement.py`, `bugbounty/config_loader.py`  
**Frontend:** `dashboard/src/App.tsx`  
**Scripts:** `scripts/scan-local.ps1`, `scripts/scan-local.sh`, `scripts/start.ps1`, `scripts/start.sh`, `scripts/stop.ps1`, `scripts/stop.sh`, `scripts/setup.ps1`, `scripts/setup.sh`, `scripts/lint.ps1`, `scripts/lint.sh`, `scripts/test.ps1`, `scripts/test.sh`, `scripts/check-tools.ps1`, `scripts/check-tools.sh`  
**Tests (targeted):** `tests/test_tool_adapters.py`, `tests/test_attack_surface_graph.py`, `tests/test_assessment_engine.py`, `tests/test_dashboard_api.py`, `tests/test_evidence_persistence.py`, `tests/test_cache_and_identity_regression.py`, `tests/test_owasp_category_fixtures.py`, `tests/test_cli_config_assessment.py`, `tests/test_config_loader.py` (plus pattern/context sampling)  
**Docs (context):** `docs/architecture.md`, `docs/architecture/API_REFERENCE.md`, `docs/architecture/DATA_FLOW.md`, `docs/architecture/DEVELOPMENT_GUIDE.md`, `docs/architecture/SYSTEM_ARCHITECTURE.md`

## Findings

### F-01 — Dashboard API `/tools` endpoint is contract-broken and likely fails at runtime
- **Severity:** **High** (availability/correctness; can break dashboard/API consumers)
- **Area:** Dashboard API contracts, tool adapter integration exposure
- **Evidence:**
  - `bugbounty/tool_adapters.py:595-598`: `available_adapters()` returns `{"nuclei": NucleiAdapter().availability()}` (`dict[str, bool]`).
  - `bugbounty/dashboard_api.py:21,233-245`: imports `available_adapters` and does `for item in available_adapters(): info = item.as_dict() if hasattr(item, "as_dict") else dict(item)` then reads `info.get(...)`. Iterating a dict yields keys (`str`), so `dict("nuclei")`/access pattern is invalid and will raise (e.g. `ValueError`/`TypeError`) returning a 400 error via generic exception handling (`dashboard_api.py:255-256,275-276`).
  - No runtime consumer in reviewed frontend (`dashboard/src/App.tsx` has no `/tools` fetch/tab), so breakage may go unnoticed until used.
- **Impact:** `/tools` cannot reliably report optional tool availability/configuration; diagnostic UI/API contract is non-functional.
- **Recommended remediation:** Align contract and implementation: either return structured adapter descriptors from `available_adapters()` (name/available/version/path/details) or adapt handler to consume `dict[str,bool]` safely; add API contract tests for `/tools` success payload.
- **Status update:** **Addressed in lead integration** (endpoint now consumes adapter registry and returns structured tool status for all 7 adapters; `/overview`, `/reports` added; frontend Tools tab consumes `/tools`).

### F-02 — Dashboard API lacks authentication/authorization and exposes sensitive assessment artifacts
- **Severity:** **High**
- **Area:** Dashboard API security, sensitive data exposure, auth/secrets handling
- **Evidence:**
  - `bugbounty/dashboard_api.py:194-197,327-335,353-356`: `DashboardHandler.state = DashboardState()` is global/class-level; server binds to provided host/port (CLI defaults `127.0.0.1:8765`, `bugbounty/cli.py:48-51,84-86`), CORS allowlist only for `http://localhost:5173`/`http://127.0.0.1:5173`, but **no authn/authz checks** on any endpoint.
  - Exposed data includes scope/program/burp traffic (`/scope`, `/program`, `/burp/traffic`, `/endpoints`, `/burp`), findings/evidence (`/findings`, `/evidence`, `/evidence/<id>`), reports (`/reports/*`), graph (`/graph`, `/graph/export`), and assessment trigger (`/assessment/run`) (`dashboard_api.py:205-253,271-273`).
  - Evidence/report payloads can contain request/response metadata, observations, and imported traffic views; sanitization exists in places (`bugbounty/evidence.py:37-49,91-96`, `bugbounty/http_client.py:23-28,35-37,136-143,185-186`, importer redaction per `tests/test_dashboard_api.py`, `tests/test_program_and_burp_json.py`) but coverage is not uniform across all fields/sources (see F-07, F-08).
  - `docs/architecture/API_REFERENCE.md` notes no auth implemented (inspected context).
- **Impact:** Any local process/user with network access to the listener can read assessment data, mutate dashboard state by importing/running assessments, and potentially access sensitive endpoint/request metadata. If bound beyond localhost, exposure increases materially.
- **Recommended remediation:** Enforce localhost-only binding by default/hard guard, add explicit auth token/session or OS-level access control, avoid serving raw sensitive artifacts by default, and document threat model. Consider read-only mode and CSRF/origin protections for state-changing POSTs.

### F-03 — Shared mutable in-memory dashboard state with threaded server enables races and cross-session leakage
- **Severity:** **High**
- **Area:** Dashboard in-memory state limitations, race conditions, persistence consistency
- **Evidence:**
  - `bugbounty/dashboard_api.py:32-44,194-197,353-356`: single `DashboardState` instance stored on handler class; `ThreadingHTTPServer` serves concurrent requests.
  - State fields (`program`, `scope`, `exchanges`, `inventory`, `result`, `report_paths`, `workspace`, `validation_complete`) are mutated/read across multiple endpoints without synchronization (`dashboard_api.py:45-133,205-253,260-273`).
  - `_add_report_context` reads/writes report files and assumes current `self.report_paths`/`self.program` (`dashboard_api.py:173-192`).
- **Impact:** Concurrent imports/runs/reads can produce torn state, inconsistent UI/API responses, wrong report post-processing, and cross-engagement data leakage in long-lived processes.
- **Recommended remediation:** Introduce per-session/workspace state isolation, locking/immutability boundaries, and request serialization for mutating operations; avoid class-global mutable state for multi-request servers.

### F-04 — Attack surface graph generation and persistence errors are silently suppressed
- **Severity:** **High**
- **Area:** Attack surface graph generation/integration, persistence/reload, reference integrity, observability
- **Evidence:**
  - `bugbounty/assessment.py:127-244`: `_write_attack_surface_graph` wraps graph construction in broad `try/except Exception` blocks and **returns silently on any failure** (`242-244`), including many inner `except Exception: pass` around relationship creation (`174-175,190-191,199-200,204-205,214-215,220-221,227-228,238-239`).
  - `graph.add_relationship` enforces node existence and allowed relationship triples, raising on invalid/missing references (`bugbounty/attack_surface_graph.py:255-276`); swallowed exceptions can yield incomplete graphs with missing edges/nodes/provenance.
  - Graph load is best-effort and can return empty graph on parse/IO issues (`attack_surface_graph.py:512-530`), but assessment does not surface graph write/load failures in results/audit.
- **Impact:** Operators and API consumers may assume graph is complete/current when it is partial or absent; investigation/debugging and downstream analysis become unreliable without error signals.
- **Recommended remediation:** Record graph generation status/errors in assessment result/audit log, fail-soft with explicit warning metadata (not silent), and narrow exception handling; validate reference integrity and emit diagnostics.

### F-05 — Nuclei adapter forwards unvalidated `extra_args`, weakening scope/intent safety guarantees
- **Severity:** **High** (when adapter is used/configurable with untrusted input)
- **Area:** Tool adapter/Nuclei safety, scope enforcement, command construction
- **Evidence:**
  - `bugbounty/tool_adapters.py:329-345`: validates `extra_args` are non-empty strings without control chars, but **no semantic allowlist/denylist**.
  - `bugbounty/tool_adapters.py:514-525`: builds argv as `[exe, "-u", safe_target, "-jsonl", "-silent", "-no-color", "-timeout", ...] + extra_args` and executes with `shell=False` (`run_subprocess` uses `subprocess.run(..., shell=False, ...)`, `190-203`).
  - Target URL is validated and scope-checked per provided target (`validate_input`/`validate_scope`, `329-354,379-382,409`), but appended `extra_args` could introduce additional behaviors/inputs supported by Nuclei (e.g. list/target flags, template sources, output/network-affecting options depending on version/config) outside the explicit per-target validation model.
  - `run_subprocess` correctly avoids shell, applies timeout/output truncation, and captures failures/timeouts (`176-217,417-490`).
- **Impact:** A malicious or mistaken config/operator can cause out-of-scope scans, excessive requests, data exfiltration, or unsafe execution patterns not intended by the adapter’s scoped single-target contract.
- **Recommended remediation:** Implement strict allowlist for supported `extra_args` (or disallow entirely), reject target/list/output/template flags that alter scan scope/destination, enforce per-invocation host/scope invariants where possible, and run with least privilege in isolated environments.

### F-06 — External tool adapter framework/Nuclei not integrated into assessment, CLI, or dashboard runtime
- **Severity:** **Medium** (functional gap; can become security issue if assumed active)
- **Area:** Tool adapter runtime integration state
- **Evidence:**
  - Search shows adapter usage limited to adapter module/tests and scripts/tool checks: `bugbounty/tool_adapters.py`, `tests/test_tool_adapters.py`, `scripts/check-tools.*` reference tool names; **no references to `get_adapter`/`NucleiAdapter`/`ToolRunResult` in `bugbounty/assessment.py`, `bugbounty/cli.py`, or dashboard assessment flow** (grep results).
  - `AssessmentEngine` orchestrates only built-in discovery/checks/evidence/findings/graph (`bugbounty/assessment.py:38-128`); CLI assess/report/dashboard run do not invoke adapters (`bugbounty/cli.py:67-109`, `bugbounty/dashboard_api.py:98-133,271-273`).
  - Dashboard `/tools` attempts to expose availability but is broken (F-01).
- **Impact:** External scanning is effectively unavailable despite framework presence; documentation/operators may overestimate coverage. Future integration may inherit unresolved safety issues (F-05, F-07).
- **Recommended remediation:** Clearly mark adapters as non-integrated/experimental, gate behind explicit CLI/API flags when wired, and define trust/scope/provenance/redaction requirements before runtime enablement.
- **Status update:** **Partially addressed in lead integration** (7 external adapters integrated into engine/CLI/dashboard; config loader parses `external_tools`; frontend Tools tab added; full hardening/UI workflow remains).

### F-07 — Nuclei normalized results retain raw/unredacted tool output fields
- **Severity:** **Medium**
- **Area:** Tool adapter parsing of untrusted output, sensitive data exposure, evidence/provenance handling
- **Evidence:**
  - `bugbounty/tool_adapters.py:527-592`: parses JSONL lines and normalizes into `ToolFindingRecord` including `evidence` with `request`, `response`, `curl_command`, extracted results, and `raw=dict(item)`; provenance includes command/target/template metadata. No redaction/sanitization is applied.
  - Untrusted external tool output is parsed permissively (invalid JSON lines skipped, `parse_output` tolerant) which is good for robustness, but stored content may include secrets/tokens/PII reflected by targets or tooling.
- **Impact:** If adapter results are later persisted/displayed/reported, sensitive data leakage can occur.
- **Recommended remediation:** Apply centralized redaction/scrubbing before normalization/storage, bound stored raw payload sizes, and separate operator-debug artifacts from report-safe evidence.

### F-08 — Evidence persistence/hydration and redaction are best-effort and may lose data or leak edge cases
- **Severity:** **Medium**
- **Area:** Evidence persistence/hydration/restart behavior, sensitive data handling
- **Evidence:**
  - `bugbounty/evidence.py:37-49,59-89,91-96`: evidence IDs are random (`uuid4`) per add, store is rewritten as full JSON array on save (`assessment.py:122`), load silently ignores IO/JSON errors and malformed items, and sanitization redacts only dict keys matching tokens (`authorization`, `token`, `secret`, `password`, `api-key`, `cookie`) recursively for dict/list values.
  - Key-name-only redaction can miss sensitive values embedded in strings/URLs/other field names; request metadata from checks is minimal (`checks.py` refs show `{"method","url",...}`), while response metadata includes headers/body from `HttpClient` (`http_client.py:136-143,185-190`) and imported exchanges may carry richer structures.
  - `AssessmentEngine` loads existing evidence store at run start (`assessment.py:50`) but generates new findings store each run (`51`) and appends new artifacts; no dedupe/merge policy for artifacts across runs beyond ID uniqueness.
  - Cache replay returns evidence objects by ID lookup from current store (`assessment.py:84-91`), so missing/corrupt persisted evidence degrades cached result fidelity (evidence tuple may be empty while IDs referenced).
- **Impact:** Restart/resume scenarios can silently drop evidence, produce partially hydrated cached results, or retain sensitive strings in non-redacted forms.
- **Recommended remediation:** Make persistence/load failures visible, validate schema/version, define append/compaction semantics, strengthen context-aware redaction (URL params, common auth patterns, bodies where feasible), and ensure cached results remain verifiable against persisted evidence.

### F-09 — Identity-aware cache/history semantics can suppress needed re-tests and are keyed coarsely
- **Severity:** **Medium**
- **Area:** Assessment orchestration, identity-aware caching, restart behavior, status semantics consistency
- **Evidence:**
  - `bugbounty/assessment.py:81-117`: for every endpoint/check, computes `test_identities` as all engagement identity names (or empty) and uses them for cache lookup, execution-history checks, result tagging, and storage. Cache is consulted before precondition/check execution and returns cached `PASS/FAIL/VULNERABLE` as `executed=True` with reason `"retrieved from investigation cache"` (`84-91`).
  - `bugbounty/investigation.py:43-69,70-114,115-125`: cache key is `(endpoint, check_id, sorted identities joined)`; `get` returns `None` when identities list is empty. Persist/load silently ignores corrupt cache files/items.
  - `bugbounty/workspace.py:21-35,47-71`: execution history keyed by `(endpoint, check_id, identities_key)` and persisted; `load` silently ignores decode/value errors.
  - Preconditions for some checks require specific case-to-identity mappings (`bugbounty/preconditions.py:12-77`), but orchestration’s identity context is global to engagement, not per-case/per-check applicability subset.
- **Impact:** Changes in endpoint behavior, configuration cases, or non-identity factors may not trigger re-execution when prior cached terminal status exists for the same coarse key; conversely, identity-agnostic checks run under a global identity set key. Restart behavior depends on mutable workspace files with silent failure modes.
- **Recommended remediation:** Refine cache keys to include relevant case/config/method parameters, store cache provenance/version, invalidate on config/spec changes, and surface cache-hit vs fresh-execution in results explicitly.

### F-10 — Status and verification semantics are partially inconsistent across engine, checks, findings, and graph
- **Severity:** **Medium**
- **Area:** Finding verification semantics, status semantics consistency
- **Evidence:**
  - `AssessmentEngine` caches only `PASS/FAIL/VULNERABLE` (`assessment.py:85,113-114`), while checks produce statuses including `NOT_RUN`, `NOT_APPLICABLE`, `ERROR`, `PASS`, `FAIL` (`assessment.py:89,96,103,110`, `bugbounty/checks.py` e.g. preconditions/results).
  - `Finding` statuses allowed are `candidate`, `verified`, `rejected`, `not_verified` (`bugbounty/findings.py:10,36-39`); `FindingStore.add` rejects verified findings without evidence IDs but also mutates/merges duplicates (`54-66`).
  - Checks set `CheckResult.verified`/`Finding.status` differently (e.g. verified failures for confirmed issues, candidates for indicators/inventory/resource observations; see sampled `bugbounty/checks.py:134,141,145,156,162-166,187,195,198,212,233-235,245,259,267,270,287-288,305-306`).
  - `CheckResult` stores `evidence` and `evidence_ids`; cached path sets `evidence` from store lookups but not findings, and graph generation derives nodes from result/findings/evidence artifacts best-effort (`assessment.py:84-91,176-240`).
- **Impact:** Consumers may misinterpret confidence/verification (e.g. cached “executed” historical result vs current verification), and reporting/graph views may diverge.
- **Recommended remediation:** Define and enforce a canonical status/verification model (check vs finding vs evidence verification), preserve finding linkage on cache hits or avoid caching unverifiable composites, and include semantic versioning/metadata in outputs.

### F-11 — Graph API/dashboard exposure is partial and frontend does not consume available graph/tools data
- **Severity:** **Low**
- **Area:** Attack surface graph integration/exposure gaps, dashboard contracts vs frontend
- **Evidence:**
  - Backend provides `/graph` and `/graph/export` (`bugbounty/dashboard_api.py:225-232`) and returns `AttackSurfaceGraph` JSON/dashboard forms (`bugbounty/attack_surface_graph.py:425-460,503-511`).
  - Frontend `dashboard/src/App.tsx:11-21,121-144,185` defines tabs/views for Import/Scope/Burp/Endpoints/Findings/Evidence/Reports only, fetches corresponding endpoints, and has **no graph/tools UI or API calls**.
  - `/reports/{kind}` serves from `state.report_paths` only for the last in-memory run context (`dashboard_api.py:246-253`); no listing/metadata endpoint.
- **Impact:** Generated graph data and (intended) tool diagnostics are not operator-visible in the UI; API capabilities exceed frontend contract, increasing undocumented surface area.
- **Recommended remediation:** Either implement frontend consumers and typed contracts or explicitly document/trim unused endpoints; add response schemas and integration tests.
- **Status update:** **Partially addressed in lead integration** (graph/tools backend API and CLI exposure added; frontend UI integration pending).

### F-12 — CLI argument validation and error handling are minimal for some paths
- **Severity:** **Low**
- **Area:** CLI argument validation, error handling, exit codes
- **Evidence:**
  - `bugbounty/cli.py:16-55,67-118`: structured commands exist, but `dashboard --port`, `assess --max-requests/--timeout`, and other numeric/path inputs rely on downstream validation or runtime behavior; invalid bind/config/runtime errors may escape `assess`’s caught exception set (`ConfigurationError, ValueError, OSError` caught at `101-103`, but dashboard and other paths can raise uncaught exceptions).
  - `recon` mutates parsed args (`args.dry_run = True`, sets timeout/max_requests) and uses discovery-only flow (`110-116`); behavior is implicit.
  - Exit code `2` used for configuration errors in assess (`103`), `0` for success/help; other failures may produce traceback/non-deterministic exit behavior.
- **Impact:** Poor operator feedback and automation unreliability on malformed inputs or runtime faults.
- **Recommended remediation:** Centralize CLI validation, bound/validate numeric/network args, catch and map runtime exceptions to stable exit codes/messages, and add negative-path CLI tests.

### F-13 — Scripts are generally argument-forwarding but include operational safety footguns
- **Severity:** **Low**
- **Area:** PowerShell/Bash scripts safety (quoting, destructive actions, cwd assumptions)
- **Evidence:**
  - **Positive:** No `eval`, no `shell=True`, and scripts mostly invoke Python/npm with explicit args; bash scripts use `set -euo pipefail` (`scripts/start.sh:2`, `scripts/stop.sh:2`, `scripts/scan-local.sh:2`, etc.).
  - **CWD assumptions:** scripts `cd` to repo root derived from script location (generally good) and operate on relative `.venv`, `.run`, `dashboard` paths.
  - **Process termination risk:** `scripts/stop.ps1:9-18` and `scripts/stop.sh:60-86` stop listeners/PIDs on specified ports (default `8765,5173`) including non-recorded processes discovered via `Get-NetTCPConnection`/`lsof`/`ss`/`netstat`; this can terminate unrelated services bound to those ports.
  - **Background/start behavior:** `scripts/start.ps1`/`start.sh` launch background processes and logs; no health checks or robust duplicate detection.
  - **scan-local/start argument use:** user-provided target/config/workspace/ports are passed through (expected), but quoting/validation relies on shell/PowerShell parsing; PowerShell parameter typing provides some safety.
- **Impact:** Accidental termination of unrelated local services or operator confusion in multi-process environments; low direct code-execution risk observed in reviewed scripts.
- **Recommended remediation:** Prefer stopping only recorded PIDs by default, require explicit opt-in to kill-by-port, add confirmations/verbose ownership checks where feasible, and document risks.

### F-14 — Potential false positives / overconfidence in selected checks (review-required)
- **Severity:** **Informational** (quality/risk of misreporting; depends on usage)
- **Area:** False-positive risks, verification semantics
- **Evidence (sampled from `bugbounty/checks.py`):**
  - `API8` marks findings as `verified` for passive observations like HTTP scheme, wildcard CORS, and missing headers based on single responses/configuration signals (`~124-134`), which may be context-dependent.
  - `API9` can emit candidate findings when endpoint source is not authoritative inventory (`~143-146`) — useful signal but potentially noisy.
  - `API7` indicator is candidate from URL-like parameter names; controlled verification upgrades to verified only when explicit callback/token case matches (`~150-166`).
  - `API4` candidate finding based on repeated successful responses without observed limit (`~211-213`) may flag legitimate designs lacking explicit throttling signals in bounded probes.
  - `API10` candidate on unexpected content type (`~244-246`) may be benign for non-JSON APIs or valid variations.
- **Impact:** Report consumers may need manual triage; automated workflows could over-prioritize candidates/verified-passive observations.
- **Recommended remediation:** Calibrate wording/severity/confidence, distinguish “policy/observation verified” from “exploitably verified”, and expand fixtures/tests for benign-counterexample scenarios.

## Untested or weakly tested paths (observed gaps)

- **Dashboard `/tools` endpoint contract**: implementation/response shape appears untested against actual `available_adapters()` behavior (F-01); `dashboard/src/App.tsx` has no integration.
- **Dashboard concurrency/race behavior**: no evidence of tests for simultaneous POST/GET mutations under `ThreadingHTTPServer` (F-03).
- **Dashboard auth/exposure controls**: no auth layer to test; security boundary relies on deployment defaults only (F-02).
- **Attack surface graph failure visibility**: graph write/build exceptions are swallowed, so failures may not be asserted/detected (F-04).
- **Assessment restart/hydration edge cases**: corrupt/partial `evidence.json`, `investigation_cache.json`, `execution_history.json`, and missing evidence referenced by cache (F-08, F-09).
- **Cache invalidation across config/case changes**: coarse cache/history keys may not be covered for all mutation scenarios (F-09).
- **Nuclei adapter `extra_args` abuse cases and raw-output redaction**: tests validate command construction and basic parsing/mocked runs, but not malicious/unsafe arg combinations or secret redaction of normalized/raw fields (F-05, F-07).
- **Runtime integration of adapters into assessment/CLI/dashboard**: currently absent, so no end-to-end coverage (F-06).
- **CLI negative paths and non-config exceptions**: dashboard bind failures, invalid numeric args, filesystem permission errors outside caught types (F-12).
- **Scripts operational safety**: kill-by-port side effects and multi-instance behavior on developer machines/CI agents (F-13).

## Recommended remediation priority

1. **Immediate (blockers for safe use):** Fix `/tools` contract (F-01); restrict dashboard exposure/add auth and session/state isolation (F-02, F-03); harden/disable unsafe adapter argument passthrough and redact adapter outputs (F-05, F-07).
2. **High:** Make graph and persistence/cache load/save errors observable and testable; define cache invalidation and status semantics (F-04, F-08, F-09, F-10).
3. **Medium:** Wire adapter runtime only with explicit gating and security controls; align API/frontend contracts or remove dead endpoints; improve CLI validation/exit consistency (F-06, F-11, F-12).
4. **Low/continuous:** Reduce script side effects, refine check precision/wording, and expand regression fixtures for false-positive and restart scenarios (F-13, F-14, untested paths).

## Current release-blocker assessment

- **Release-blocking issues identified:** **Yes**
  - **F-01**: broken dashboard tools endpoint contract (functional defect in exposed API) — **addressed in lead integration**
  - **F-02/F-03**: unauthenticated dashboard with shared mutable state and sensitive data access patterns (security/operational blocker outside tightly controlled local use)
  - **F-04**: silent graph persistence/integrity failures (diagnosability/integrity blocker for graph-dependent workflows)
  - **F-05**: unsafe external tool argument passthrough potential (safety blocker before enabling/integrating adapter execution)
- **Conditional note:** A constrained internal/local-only, single-user, trusted-input workflow may proceed with known limitations, but only after addressing **F-01** and documenting/mitigating **F-02/F-03/F-04/F-05**. For general or multi-user/releasable deployment, these should be treated as blockers.

## Independent review statement

This report is based on direct inspection of repository artifacts available at review time and targeted read-only analysis. Findings are classified by observed behavior and evidenced code paths; absence of evidence for an exploit path is not proof of safety. No findings were silently dismissed.
