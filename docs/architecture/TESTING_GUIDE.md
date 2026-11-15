# Testing Guide

> Verified from `pyproject.toml`, `README.md`, `tests/`, and implemented modules. Test contents are mapped by filename and module responsibilities; this guide does not claim per-test assertions beyond what can be inferred from names and inspected fixtures.

## 1. Test framework and configuration

- **Framework**: `pytest` (configured in `pyproject.toml`).
- **Pytest config** (`[tool.pytest.ini_options]`):
  - `pythonpath = ["."]`
  - `testpaths = ["tests"]`
- **Primary command**: `python -m pytest -q tests` (from `README.md`).

## 2. Test directory structure

```text
tests/
├─ __init__.py
├─ fixtures/
│  ├─ __init__.py
│  └─ vulnerable_api.py                 # Local intentionally vulnerable API fixture
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

`__pycache__` files present in `tests/` and `tests/fixtures/` are runtime artifacts, not source tests.

## 3. Testing strategy (as evidenced)

### 3.1 Unit-level and module-focused tests
- **Routing/specialists**: `test_agent_routing.py`, `test_specialists.py` target `bugbounty.agents` and `bugbounty.specialists` behavior.
- **Configuration**: `test_config_loader.py`, `test_engagement_validation.py` cover config parsing/validation and engagement constraints.
- **Import/parsing/scope logic**: `test_importers.py`, `test_burp_scope_configuration.py`, `test_program_and_burp_json.py`, `test_rei_actual_scope_intersection.py` cover HackerOne/Burp/program parsing and scope intersection rules.
- **Safety/scope enforcement**: `test_scope_enforcement.py`, `test_extended_boundaries.py`, `test_scope_only_http_regression.py`.
- **HTTP/discovery**: `test_http_and_discovery.py`.

### 3.2 Integration and workflow tests
- **Assessment engine**: `test_assessment_engine.py` (documented in README as local demo using vulnerable fixture).
- **Authorized/check-specific scenarios**: `test_authorized_checks.py`.
- **CLI workflows**: `test_cli.py`, `test_cli_config_assessment.py`.
- **Dashboard API workflows**: `test_dashboard_api.py`.

### 3.3 Robustness and regression coverage
- **Robustness/error handling**: `test_robustness.py`.
- **Additional coverage/regressions**: `test_additional_coverage.py`, `test_scope_only_http_regression.py`.

### 3.4 Frontend validation
- **Automated frontend tests**: None found in repository (`dashboard/package.json` has no test script; no frontend test files observed under `dashboard/src`).
- **Build/type validation available**: `npm run build` in `dashboard/` runs `tsc -b && vite build` (compile/build validation).

## 4. Fixtures and test data

| Fixture/Data | Path | Purpose | Used by |
|---|---|---|---|
| Vulnerable API fixture | `tests/fixtures/vulnerable_api.py` | Provides a local intentionally vulnerable API target for safe assessment execution in tests | Assessment/integration tests (notably `test_assessment_engine.py`, per README) |
| Example import/config files | `examples/burp-history.xml`, `examples/hackerone-scope.tsv`, `examples/engagement.yaml` | Sample inputs/formats for manual or automated scenarios | Developers/tests/examples (availability verified) |

## 5. Component-to-test mapping (high level)

| Component / area | Primary source files | Related tests (by name/module intent) |
|---|---|---|
| CLI parsing and commands | `bugbounty/cli.py` | `test_cli.py`, `test_cli_config_assessment.py` |
| Config loading and validation | `bugbounty/config_loader.py`, `engagement.py`, `config.py` | `test_config_loader.py`, `test_engagement_validation.py` |
| Safety and scope enforcement | `bugbounty/safety.py`, `engagement.py`, `http_client.py` | `test_scope_enforcement.py`, `test_extended_boundaries.py`, `test_scope_only_http_regression.py` |
| HTTP client and discovery | `bugbounty/http_client.py`, `discovery.py` | `test_http_and_discovery.py`, `test_assessment_engine.py` |
| Importers and scope intersection | `bugbounty/importers.py`, `policy.py` | `test_importers.py`, `test_burp_scope_configuration.py`, `test_program_and_burp_json.py`, `test_rei_actual_scope_intersection.py` |
| Assessment engine orchestration | `bugbounty/assessment.py` | `test_assessment_engine.py`, `test_robustness.py`, `test_additional_coverage.py` |
| Security checks (API1–API10 behaviors) | `bugbounty/checks.py` | `test_authorized_checks.py`, `test_assessment_engine.py`, `test_scope_only_http_regression.py`, `test_additional_coverage.py` |
| Evidence/findings/reporting outputs | `bugbounty/evidence.py`, `findings.py`, `reports.py` | `test_assessment_engine.py`, `test_additional_coverage.py` (and assertions in related integration tests) |
| Dashboard API/state/workflow | `bugbounty/dashboard_api.py` | `test_dashboard_api.py`, `test_program_and_burp_json.py`, `test_rei_actual_scope_intersection.py` |
| Agent and specialist routing utilities | `bugbounty/agents.py`, `specialists.py`, `orchestration.py` | `test_agent_routing.py`, `test_specialists.py` |

## 6. How to run and extend tests

### 6.1 Run all tests
```bash
python -m pytest -q tests
```

### 6.2 Run targeted suites
```bash
python -m pytest -q tests/test_assessment_engine.py
python -m pytest -q tests/test_dashboard_api.py
python -m pytest -q tests/test_importers.py
```

### 6.3 Extension guidelines (aligned with repo patterns)
- Place new tests under `tests/` (discovered by pytest config).
- Reuse `tests/fixtures/vulnerable_api.py` or add fixtures under `tests/fixtures/` for local, authorized test targets.
- Prefer deterministic local inputs (files/fixtures) over external network dependencies to preserve safety and reproducibility.
- When adding checks/import formats/endpoints, include corresponding unit/regression tests and update `API_REFERENCE.md` / `SECURITY_ENGINE.md` / `DATA_FLOW.md` as needed.

## 7. Known testing gaps (observed)

- **Frontend automated tests**: no JS/TS test framework or test cases present in `dashboard/`.
- **End-to-end browser automation in repo**: not evidenced; dashboard validation is backend/API-focused based on available tests.
- **External integration tests**: not applicable/evidenced (no external provider integrations implemented).
