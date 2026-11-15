from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Iterable

from .attack_surface_graph import AttackSurfaceGraph
from .checks import CheckContext, CheckResult, SecurityCheck, default_checks
from .discovery import ApiDiscovery, Endpoint
from .engagement import Engagement
from .evidence import EvidenceStore
from .findings import Finding, FindingStore
from .http_client import HttpClient
from .importers import BurpExchange, EndpointInventory
from .investigation import InvestigationMemory
from .normalization import classify_findings
from .preconditions import PRECONDITION_CHECKS
from .workspace import ExecutionHistory


@dataclass(slots=True)
class AssessmentResult:
    engagement: Engagement
    endpoints: list[Endpoint] = field(default_factory=list)
    check_results: list[CheckResult] = field(default_factory=list)
    evidence: EvidenceStore = field(default_factory=EvidenceStore)
    findings: FindingStore = field(default_factory=FindingStore)
    started_at: str = ""
    finished_at: str = ""
    audit_log: list[dict[str, object]] = field(default_factory=list)
    classification: dict[str, int] = field(default_factory=dict)

    @property
    def checks_not_run(self) -> list[CheckResult]:
        return [item for item in self.check_results if item.status == "NOT_RUN"]


class AssessmentEngine:
    """Run a bounded, evidence-producing API assessment."""

    def __init__(self, engagement: Engagement, checks: Iterable[SecurityCheck] | None = None):
        self.engagement = engagement
        self.client = HttpClient(engagement)
        self.checks = sorted(list(checks or default_checks()), key=lambda c: c.priority)
        self.execution_history = ExecutionHistory.load(engagement.workspace)
        self.investigation_memory = InvestigationMemory.load(engagement.workspace)

    def run(self, *, openapi_file: str | Path | None = None, endpoint_list: Iterable[str] | None = None, endpoint: str | None = None, documentation_paths: Iterable[str] | None = None, endpoint_inventory: Iterable[Endpoint] | None = None, imported_exchanges: Iterable[BurpExchange] | None = None) -> AssessmentResult:
        started = datetime.now(timezone.utc).isoformat()
        evidence = EvidenceStore.load(self.engagement.workspace)
        findings = FindingStore()
        discovery = ApiDiscovery(self.engagement, self.client)
        try:
            if endpoint_inventory is not None:
                endpoints = [item for item in endpoint_inventory if self.client.safety_policy and self.client.safety_policy.check(item.url, method=item.method).allowed]
            else:
                endpoints = discovery.discover(openapi_file=openapi_file, endpoint_list=endpoint_list, endpoint=endpoint, documentation_paths=documentation_paths)
        except (OSError, ValueError, TypeError) as error:
            endpoints = []
            audit_error = {"timestamp": datetime.now(timezone.utc).isoformat(), "check_id": "discovery", "category": "DISCOVERY", "endpoint": self.engagement.target_url, "method": "", "status": "ERROR", "executed": False, "verified": False, "reason": type(error).__name__}
            audit_log = [audit_error]
        else:
            audit_log = []
        if not endpoints and not audit_log:
            audit_log.append({"timestamp": datetime.now(timezone.utc).isoformat(), "check_id": "discovery", "category": "DISCOVERY", "endpoint": self.engagement.target_url, "method": "", "status": "PASS", "executed": False, "verified": False, "reason": "zero endpoints discovered"})
        context = CheckContext(self.engagement, self.client, evidence, findings)
        for exchange in imported_exchanges or ():
            response = exchange.response
            evidence.add(
                check_id="burp-import",
                endpoint=exchange.request.url,
                request_metadata={"method": exchange.request.method, "url": exchange.request.url, "headers": exchange.request.headers, "body": exchange.request.body, "source": exchange.request.source},
                response_metadata={"status_code": response.status if response else None, "headers": response.headers if response else {}, "body": response.body if response else "", "content_type": response.content_type if response else None, "elapsed_ms": response.timing_ms if response else None},
                observation="Sanitized Burp observation imported without replay",
                expected_behavior="Imported traffic remains passive and secrets are redacted",
                actual_behavior=f"Observed {exchange.request.method} {exchange.request.path} from Burp export",
                verification_status="observed",
            )
        results: list[CheckResult] = []
        for item in endpoints:
            response = self.client.request(item.method, item.url)
            test_identities = [id.name for id in self.engagement.identities] if self.engagement.identities else []
            for check in self.checks:
                cached = self.investigation_memory.get(item.url, check.id, identities=test_identities)
                if cached and cached.status in ("PASS", "FAIL", "VULNERABLE"):
                    cached_evidence = tuple(ev for eid in cached.evidence_ids if (ev := evidence.get(eid)) is not None)
                    result = CheckResult(check.id, check.category, cached.status, reason="retrieved from investigation cache", evidence=cached_evidence, executed=True, endpoint=item.url, method=item.method, confidence=cached.confidence, severity=cached.severity, evidence_ids=tuple(cached.evidence_ids), identities=tuple(cached.identities))
                elif self.execution_history.has_executed(item.url, check.id, identities=test_identities) and not (cached is not None and cached.status == "ERROR"):
                    result = CheckResult(check.id, check.category, "NOT_RUN", reason="check already executed for this endpoint and identity context in prior assessment", executed=False, endpoint=item.url, method=item.method, identities=tuple(test_identities))
                else:
                    precondition_checker = PRECONDITION_CHECKS.get(check.id)
                    if precondition_checker:
                        precondition_result = precondition_checker(item, context)
                        if precondition_result:
                            status, reason = precondition_result
                            result = CheckResult(check.id, check.category, status, reason=reason, applicable=(status != "NOT_APPLICABLE"), executed=False, endpoint=item.url, method=item.method, identities=tuple(test_identities))
                        else:
                            try:
                                result = check.execute(item, response, context)
                                if hasattr(result, 'identities') and not result.identities:
                                    result = CheckResult(result.check_id, result.category, result.status, reason=result.reason, evidence=result.evidence, findings=result.findings, confidence=result.confidence, endpoint=result.endpoint, method=result.method, applicable=result.applicable, executed=result.executed, verified=result.verified, severity=result.severity, evidence_ids=result.evidence_ids, remediation=result.remediation, identities=tuple(test_identities))
                            except Exception as error:
                                result = CheckResult(check.id, check.category, "ERROR", reason=type(error).__name__, executed=True, endpoint=item.url, method=item.method, identities=tuple(test_identities))
                    else:
                        try:
                            result = check.execute(item, response, context)
                            if hasattr(result, 'identities') and not result.identities:
                                result = CheckResult(result.check_id, result.category, result.status, reason=result.reason, evidence=result.evidence, findings=result.findings, confidence=result.confidence, endpoint=result.endpoint, method=result.method, applicable=result.applicable, executed=result.executed, verified=result.verified, severity=result.severity, evidence_ids=result.evidence_ids, remediation=result.remediation, identities=tuple(test_identities))
                        except Exception as error:
                            result = CheckResult(check.id, check.category, "ERROR", reason=type(error).__name__, executed=True, endpoint=item.url, method=item.method, identities=tuple(test_identities))
                    if result.executed and result.status in ("PASS", "FAIL", "VULNERABLE"):
                        evidence_ids = list(result.evidence_ids) or [ev.evidence_id for ev in result.evidence]
                        self.investigation_memory.store(item.url, check.id, result.status, identities=test_identities, reason=result.reason, confidence=result.confidence, evidence_ids=evidence_ids, severity=result.severity, timestamp=datetime.now(timezone.utc).isoformat())
                        self.execution_history.record(item.url, check.id, identities=test_identities)
                    elif result.executed and result.status == "ERROR":
                        # Persist the error so it is retried instead of silently masked as NOT_RUN.
                        # Identity-aware errors keep the identity context in execution history; for
                        # identity-less checks the error is not recorded so the check is retried.
                        self.investigation_memory.store(item.url, check.id, result.status, identities=test_identities, reason=result.reason, confidence=result.confidence, evidence_ids=list(result.evidence_ids), severity=result.severity, timestamp=datetime.now(timezone.utc).isoformat())
                        if test_identities:
                            self.execution_history.record(item.url, check.id, identities=test_identities)
                results.append(result)
                audit_log.append({"timestamp": datetime.now(timezone.utc).isoformat(), "check_id": result.check_id, "category": result.category, "endpoint": item.url, "method": item.method, "status": result.status, "executed": result.executed, "verified": result.verified, "reason": result.reason, "identities": test_identities})
                for finding in result.findings:
                    findings.add(finding)
        self._run_external_tools(endpoints, evidence, findings, results, audit_log)
        classification = classify_findings(findings, evidence)
        result = AssessmentResult(self.engagement, endpoints, results, evidence, findings, started, datetime.now(timezone.utc).isoformat(), audit_log, classification=classification.as_dict())
        Path(self.engagement.workspace).mkdir(parents=True, exist_ok=True)
        evidence.write(Path(self.engagement.workspace) / "evidence.json")
        findings.write_json(Path(self.engagement.workspace) / "findings.json")
        (Path(self.engagement.workspace) / "audit.jsonl").write_text("\n".join(json.dumps(item) for item in audit_log) + "\n", encoding="utf-8")
        self.execution_history.save()
        self.investigation_memory.save()
        self._write_attack_surface_graph(result)
        return result

    def _run_external_tools(self, endpoints: list[Endpoint], evidence: EvidenceStore, findings: FindingStore, results: list[CheckResult], audit_log: list[dict[str, object]]) -> None:
        enabled = self.engagement.enabled_external_tools()
        if not enabled:
            return
        try:
            from . import tool_adapters  # noqa: F401  (framework availability check)
        except Exception as error:  # pragma: no cover - defensive import
            for name in enabled:
                self._record_external_outcome(results, audit_log, name, "ERROR", f"tool adapter framework unavailable: {type(error).__name__}", executed=False)
            return
        targets = self._external_targets(endpoints)
        for name, options in enabled.items():
            self._run_single_external_tool(name, options, targets, evidence, findings, results, audit_log)

    @staticmethod
    def _external_targets(endpoints: list[Endpoint]) -> list[str]:
        targets: list[str] = []
        seen: set[str] = set()
        for ep in endpoints:
            if ep.url and ep.url not in seen:
                targets.append(ep.url)
                seen.add(ep.url)
            if len(targets) >= 10:
                break
        return targets

    def _record_external_outcome(self, results: list[CheckResult], audit_log: list[dict[str, object]], name: str, status: str, reason: str, *, executed: bool) -> None:
        check_id = f"external:{name}"
        results.append(CheckResult(check_id, "EXTERNAL", status, reason=reason, executed=executed, applicable=True, endpoint=self.engagement.target_url))
        audit_log.append({"timestamp": datetime.now(timezone.utc).isoformat(), "check_id": check_id, "category": "EXTERNAL", "endpoint": self.engagement.target_url, "method": "", "status": status, "executed": executed, "verified": False, "reason": reason})

    def _run_single_external_tool(self, name: str, options: dict[str, object], targets: list[str], evidence: EvidenceStore, findings: FindingStore, results: list[CheckResult], audit_log: list[dict[str, object]]) -> None:
        from .tool_adapters import AdapterConfig, AdapterError, get_adapter

        if self.engagement.dry_run:
            self._record_external_outcome(results, audit_log, name, "NOT_RUN", "external tool execution skipped in dry-run mode", executed=False)
            return
        try:
            adapter = get_adapter(name)
        except AdapterError as error:
            self._record_external_outcome(results, audit_log, name, "ERROR", f"unknown external tool adapter: {error}", executed=False)
            return
        if not adapter.availability():
            self._record_external_outcome(results, audit_log, name, "NOT_RUN", f"{name} binary not available", executed=False)
            return
        if not targets:
            targets = [self.engagement.target_url]
        try:
            cfg = _build_adapter_config(options, self.engagement.timeout)
            run = adapter.run(targets, config=cfg, scope=self.client.safety_policy)
        except Exception as error:
            self._record_external_outcome(results, audit_log, name, "ERROR", f"{name} integration error: {type(error).__name__}", executed=False)
            return
        if not run.executed and not run.success and run.errors:
            status = "NOT_RUN" if not run.available else "ERROR"
            self._record_external_outcome(results, audit_log, name, status, "; ".join(run.errors)[:300] or f"{name} execution failed", executed=run.executed)
            return
        if run.executed and not run.success and run.errors:
            self._record_external_outcome(results, audit_log, name, "ERROR", "; ".join(run.errors)[:300] or f"{name} execution failed", executed=True)
            return
        from .normalization import observation_from_tool_finding

        check_id = f"external:{name}"
        finding_count = 0
        for item in getattr(run, "findings", []) or []:
            observation = observation_from_tool_finding(item, verification_status="potential")
            endpoint = observation.endpoint or self.engagement.target_url
            ev = evidence.add(
                check_id=check_id,
                endpoint=endpoint,
                request_metadata={"source_tool": observation.source, "source_id": observation.source_id, "provenance": observation.provenance},
                response_metadata={"raw_evidence": observation.evidence},
                observation=observation.description or observation.title or f"{name} observation",
                expected_behavior="External tool observations are not proof; the central engine independently verifies or classifies them",
                actual_behavior=f"{name} reported: {observation.title}",
                verification_status="potential",
            )
            finding = Finding(
                title=observation.title or f"{name} finding",
                category=observation.category or f"external-{name}",
                endpoint=endpoint,
                severity=observation.severity or "info",
                confidence=float(observation.confidence or 0.5),
                status="not_verified",
                description=observation.description or f"Observation reported by the {name} adapter",
                impact="External tool observation; verify manually before treating as a confirmed vulnerability.",
                evidence_ids=[ev.evidence_id],
                reproduction_summary=f"Source: {observation.source or name} ({observation.source_id})",
                remediation="Validate the reported issue within authorized scope and apply vendor/template guidance as appropriate.",
                references=[str(observation.source or name)],
            )
            findings.add(finding)
            finding_count += 1
        reason = f"{name} executed on {len(targets)} target(s), {finding_count} observation(s) awaiting verification"
        self._record_external_outcome(results, audit_log, name, "PASS", reason, executed=True)

    def _write_attack_surface_graph(self, result: AssessmentResult) -> None:
        try:
            from urllib.parse import urlsplit

            graph = AttackSurfaceGraph(self.engagement.workspace)
            prov_base = {"source": "assessment", "engagement_id": self.engagement.engagement_id}
            host_nodes: dict[str, str] = {}
            api_node = graph.add_node("API", {"target": self.engagement.target_url}, label=self.engagement.target_url, attributes={"target_url": self.engagement.target_url}, provenance=prov_base)
            endpoint_nodes: dict[str, str] = {}
            for ep in result.endpoints:
                parsed = urlsplit(ep.url)
                host = parsed.hostname or self.engagement.target_url
                if host not in host_nodes:
                    h = graph.add_node("Host", {"host": host}, label=host, attributes={"host": host}, provenance={**prov_base, "from": "discovery"})
                    graph.add_relationship("HOSTS", h.id, api_node.id, provenance=prov_base)
                    host_nodes[host] = h.id
                en = graph.add_node(
                    "Endpoint",
                    {"method": ep.method, "path": ep.path, "host": host},
                    label=f"{ep.method} {ep.path}",
                    attributes={"url": ep.url, "method": ep.method, "path": ep.path, "host": host, "source": getattr(ep, "source", None)},
                    provenance={**prov_base, "from": "discovery"},
                )
                endpoint_nodes[f"{ep.method}|{ep.url}|{ep.path}"] = en.id
                graph.add_relationship("EXPOSES", api_node.id, en.id, provenance=prov_base)
                graph.add_relationship("EXPOSES", host_nodes[host], en.id, provenance=prov_base)
                method_node = graph.add_node("Method", {"endpoint": en.id, "method": ep.method}, label=ep.method, provenance=prov_base)
                graph.add_relationship("ACCEPTS", en.id, method_node.id, provenance=prov_base)
                for param in getattr(ep, "parameters", []) or []:
                    if isinstance(param, dict):
                        name = str(param.get("name") or param.get("in") or "param")
                    else:
                        name = str(param)
                    pn = graph.add_node("Parameter", {"endpoint": en.id, "name": name, "method": ep.method}, label=name, attributes={"raw": param} if isinstance(param, dict) else {"value": param}, provenance=prov_base)
                    graph.add_relationship("ACCEPTS", en.id, pn.id, provenance=prov_base)
            for identity in getattr(self.engagement, "identities", []) or []:
                ident_name = getattr(identity, "name", str(identity))
                inode = graph.add_node("Identity", {"name": ident_name}, label=ident_name, provenance={**prov_base, "from": "engagement"})
                # relate identity to endpoints assessed in identity-dependent contexts
                for ep in result.endpoints:
                    enid = endpoint_nodes.get(f"{ep.method}|{ep.url}|{ep.path}")
                    if enid:
                        try:
                            graph.add_relationship("ACCESSED_BY", enid, inode.id, provenance=prov_base)
                        except Exception:
                            pass
            for cr in result.check_results:
                # best-effort endpoint match
                ep_id = None
                for k, v in endpoint_nodes.items():
                    _, url, path = k.split("|", 2)
                    if cr.endpoint and (cr.endpoint == url or cr.endpoint.endswith(path) or path in cr.endpoint):
                        ep_id = v
                        break
                if ep_id is None and endpoint_nodes:
                    ep_id = next(iter(endpoint_nodes.values()))
                check_node = graph.add_node("SecurityCheck", {"check_id": cr.check_id, "endpoint": cr.endpoint, "method": cr.method}, label=cr.check_id, attributes={"category": cr.category, "status": cr.status, "reason": cr.reason}, provenance=prov_base)
                if ep_id:
                    try:
                        graph.add_relationship("TESTED_BY", ep_id, check_node.id, provenance=prov_base)
                    except Exception:
                        pass
                for evid in getattr(cr, "evidence", ()) or ():
                    evid_id = getattr(evid, "evidence_id", None)
                    if not evid_id:
                        continue
                    ev_node = graph.add_node("Evidence", {"evidence_id": evid_id}, label=evid_id, attributes={"check_id": getattr(evid, "check_id", cr.check_id), "endpoint": getattr(evid, "endpoint", cr.endpoint)}, provenance=prov_base)
                    try:
                        graph.add_relationship("SUPPORTED_BY", check_node.id, ev_node.id, provenance=prov_base)
                    except Exception:
                        pass
                    if ep_id:
                        try:
                            graph.add_relationship("SUPPORTED_BY", ep_id, ev_node.id, provenance=prov_base)
                        except Exception:
                            pass
            for finding in result.findings.findings:
                f_node = graph.add_node("Finding", {"finding_id": finding.finding_id}, label=finding.title, attributes={"category": finding.category, "severity": finding.severity, "status": finding.status, "endpoint": finding.endpoint}, provenance=prov_base)
                # link to checks/evidence/endpoints best-effort
                for cr in result.check_results:
                    if cr.category == finding.category and (not cr.endpoint or cr.endpoint == finding.endpoint or finding.endpoint in cr.endpoint or cr.endpoint in finding.endpoint):
                        cnode = graph.add_node("SecurityCheck", {"check_id": cr.check_id, "endpoint": cr.endpoint, "method": cr.method}, label=cr.check_id, provenance=prov_base)
                        try:
                            graph.add_relationship("PRODUCED", cnode.id, f_node.id, provenance=prov_base)
                        except Exception:
                            pass
                for eid in getattr(finding, "evidence_ids", []) or []:
                    ev_node = graph.add_node("Evidence", {"evidence_id": eid}, label=str(eid), provenance=prov_base)
                    try:
                        graph.add_relationship("SUPPORTED_BY", f_node.id, ev_node.id, provenance=prov_base)
                    except Exception:
                        pass
                for k, v in endpoint_nodes.items():
                    _, url, path = k.split("|", 2)
                    if finding.endpoint and (finding.endpoint == url or path in finding.endpoint or finding.endpoint in path):
                        try:
                            graph.add_relationship("PRODUCED", v, f_node.id, provenance=prov_base)
                        except Exception:
                            pass
                        break
            # include evidence store artifacts to ensure persisted evidence nodes exist
            for ev in result.evidence.artifacts:
                ev_node = graph.add_node("Evidence", {"evidence_id": ev.evidence_id}, label=ev.evidence_id, attributes={"check_id": ev.check_id, "endpoint": ev.endpoint, "verification_status": ev.verification_status}, provenance=prov_base)
                for k, v in endpoint_nodes.items():
                    _, url, path = k.split("|", 2)
                    if ev.endpoint and (ev.endpoint == url or path in ev.endpoint or ev.endpoint in path):
                        try:
                            graph.add_relationship("SUPPORTED_BY", v, ev_node.id, provenance=prov_base)
                        except Exception:
                            pass
                        break
            graph.save()
        except Exception as error:
            # Graph generation must not break assessment execution, but failures must be observable.
            try:
                result.audit_log.append({
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "check_id": "attack-surface-graph",
                    "category": "GRAPH",
                    "endpoint": self.engagement.target_url,
                    "method": "",
                    "status": "ERROR",
                    "executed": True,
                    "verified": False,
                    "reason": f"graph generation failed: {type(error).__name__}: {error}",
                })
            except Exception:
                pass
            return


def _build_adapter_config(options: dict[str, object] | None, default_timeout: float):
    """Build a validated :class:`AdapterConfig` from untrusted per-tool options.

    Only known fields are forwarded and values are coerced defensively so a bad
    configuration can never crash the assessment run.
    """

    from .tool_adapters import AdapterConfig

    values = dict(options or {})
    kwargs: dict[str, object] = {}
    raw_timeout = values.get("timeout_seconds", values.get("timeout", default_timeout))
    try:
        timeout = float(raw_timeout)
    except (TypeError, ValueError):
        timeout = float(default_timeout)
    kwargs["timeout_seconds"] = min(max(timeout, 1.0), 600.0)
    for key in ("max_output_bytes", "max_findings"):
        if key in values:
            try:
                kwargs[key] = int(values[key])
            except (TypeError, ValueError):
                continue
    if values.get("cwd"):
        kwargs["cwd"] = str(values["cwd"])
    extra = values.get("extra_args")
    if isinstance(extra, (list, tuple)):
        kwargs["extra_args"] = tuple(str(item) for item in extra)
    env = values.get("env")
    if isinstance(env, dict):
        kwargs["env"] = {str(k): str(v) for k, v in env.items()}
    if "allow_network" in values:
        kwargs["allow_network"] = bool(values["allow_network"])
    return AdapterConfig(**kwargs)


__all__ = ["AssessmentEngine", "AssessmentResult"]
