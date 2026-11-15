from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Iterable

from .checks import CheckContext, CheckResult, SecurityCheck, default_checks
from .discovery import ApiDiscovery, Endpoint
from .engagement import Engagement
from .evidence import EvidenceStore
from .findings import Finding, FindingStore
from .http_client import HttpClient
from .importers import BurpExchange, EndpointInventory


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

    @property
    def checks_not_run(self) -> list[CheckResult]:
        return [item for item in self.check_results if item.status == "NOT_RUN"]


class AssessmentEngine:
    """Run a bounded, evidence-producing API assessment."""

    def __init__(self, engagement: Engagement, checks: Iterable[SecurityCheck] | None = None):
        self.engagement = engagement
        self.client = HttpClient(engagement)
        self.checks = list(checks or default_checks())

    def run(self, *, openapi_file: str | Path | None = None, endpoint_list: Iterable[str] | None = None, endpoint: str | None = None, documentation_paths: Iterable[str] | None = None, endpoint_inventory: Iterable[Endpoint] | None = None, imported_exchanges: Iterable[BurpExchange] | None = None) -> AssessmentResult:
        started = datetime.now(timezone.utc).isoformat()
        evidence = EvidenceStore(workspace=self.engagement.workspace)
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
            for check in self.checks:
                try:
                    result = check.execute(item, response, context)
                except Exception as error:  # A single check must not abort an authorized assessment.
                    result = CheckResult(check.id, check.category, "ERROR", reason=type(error).__name__, executed=True, endpoint=item.url, method=item.method)
                results.append(result)
                audit_log.append({"timestamp": datetime.now(timezone.utc).isoformat(), "check_id": result.check_id, "category": result.category, "endpoint": item.url, "method": item.method, "status": result.status, "executed": result.executed, "verified": result.verified, "reason": result.reason})
                for finding in result.findings:
                    findings.add(finding)
        result = AssessmentResult(self.engagement, endpoints, results, evidence, findings, started, datetime.now(timezone.utc).isoformat(), audit_log)
        Path(self.engagement.workspace).mkdir(parents=True, exist_ok=True)
        evidence.write(Path(self.engagement.workspace) / "evidence.json")
        findings.write_json(Path(self.engagement.workspace) / "findings.json")
        (Path(self.engagement.workspace) / "audit.jsonl").write_text("\n".join(json.dumps(item) for item in audit_log) + "\n", encoding="utf-8")
        return result


__all__ = ["AssessmentEngine", "AssessmentResult"]
