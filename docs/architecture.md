# Unified architecture

## Backbone decision

SecBrain provides the stronger operational backbone because it already includes:

- workflow phases and orchestration
- CLI execution
- approval and audit patterns
- verification-first data model
- scoped model and tool abstraction

Bug-Bounty-Agents contributes the more complete specialist portfolio. Instead of using the agent prompts as-is, the platform extracts their functional categories and converts them into a registry-based system with a common contract.

## Unified control plane

```text
CLI
  -> Config + Scope Loader
  -> Safety Policy + Authorization Guard
  -> Mission Orchestrator
     -> Agent Router
        -> Recon / Web / API / GraphQL / SSRF / Reporting specialists
     -> Research Layer
     -> Evidence Store
     -> Verification Engine
     -> Reporting Engine
     -> Audit and Metrics
```

## Agent contract

Every agent should expose:

- name
- kind
- risk level
- tags
- prerequisites
- evidence requirements
- verification requirements

This keeps the system comparable to the upstream SecBrain control plane while preserving the specialist breadth of Repository 1.

## Safety requirements

- no active action outside authorized scope
- explicit approval for high-risk operations
- rate-limit aware tool access
- audit trail for actions and decisions
- dry-run default for untrusted execution

## Evidence-first rule

Hypotheses are not vulnerabilities. Evidence and verification are required before a finding is emitted.

## Working assessment flow

```text
Engagement
   -> SafetyPolicy
   -> ApiDiscovery (OpenAPI, docs, file, endpoint, target)
   -> HttpClient (scope, auth, rate, timeout, budget, dry-run)
   -> SecurityCheck modules
   -> EvidenceStore
   -> FindingStore (verification + duplicate correlation)
   -> JSON / Markdown / HTML reports
```

The executable assessment layer covers passive API8 security misconfiguration, API9 inventory metadata, configured API1 BOLA, API2 authentication boundaries, API3 protected-property exposure, API4 bounded resource probes, API5 role comparisons, API6 configured flow replay, API7 sink detection with optional localhost verification, and conservative API10 response-contract review. The identity and case-driven checks return `NOT_RUN` when their explicit prerequisites are absent. The engine never treats specialist selection or a suspicious parameter as proof of a vulnerability.
