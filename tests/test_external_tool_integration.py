"""Integration tests: the central engine owns external-tool execution and classification.

These tests prove three guarantees required of the platform:

* an enabled external tool whose binary is missing is recorded as ``NOT_RUN`` (never a
  silent pass and never a crash);
* an unknown tool name is recorded as ``ERROR``;
* findings produced by an external tool are ingested as *observations* and the engine's
  single classification pass marks them ``not_verified`` (never ``verified``).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from bugbounty.assessment import AssessmentEngine
from bugbounty.discovery import Endpoint
from bugbounty.engagement import Engagement
from bugbounty.tool_adapters import ToolFindingRecord, ToolRunResult


def _endpoint(url: str = "https://api.example.com/users") -> Endpoint:
    return Endpoint(method="GET", url=url, path="/users")


def _engagement(workspace: Path, *, dry_run: bool = False, **kwargs: object) -> Engagement:
    engagement = Engagement(
        target_url="https://api.example.com",
        allowed_hosts=["api.example.com"],
        allowed_methods=["GET"],
        dry_run=dry_run,
        workspace=str(workspace),
        **kwargs,
    )
    engagement.validate()
    return engagement


@pytest.fixture(autouse=True)
def _no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    # The engine always issues one request per endpoint; stub it so external-tool
    # integration can be exercised without any network access.
    monkeypatch.setattr("bugbounty.assessment.HttpClient.request", lambda self, method, url: None)


def test_enabled_tool_with_missing_binary_is_not_run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("bugbounty.tool_adapters.discover_executable", lambda names: None)
    engagement = _engagement(tmp_path, external_tools={"zap": {"enabled": True}})
    result = AssessmentEngine(engagement, checks=[]).run(endpoint_inventory=[_endpoint()])

    external = [item for item in result.check_results if item.check_id == "external:zap"]
    assert len(external) == 1
    assert external[0].status == "NOT_RUN"
    assert external[0].executed is False
    assert external[0].verified is False
    assert "not available" in external[0].reason


def test_dry_run_skips_external_tool_execution(tmp_path: Path) -> None:
    engagement = _engagement(tmp_path, dry_run=True, external_tools={"zap": {"enabled": True}})
    result = AssessmentEngine(engagement, checks=[]).run(endpoint_inventory=[_endpoint()])

    external = [item for item in result.check_results if item.check_id == "external:zap"]
    assert len(external) == 1
    assert external[0].status == "NOT_RUN"
    assert "dry-run" in external[0].reason


def test_unknown_tool_name_is_recorded_as_error(tmp_path: Path) -> None:
    engagement = _engagement(tmp_path, external_tools={"does-not-exist": {"enabled": True}})
    result = AssessmentEngine(engagement, checks=[]).run(endpoint_inventory=[_endpoint()])

    external = [item for item in result.check_results if item.check_id == "external:does-not-exist"]
    assert len(external) == 1
    assert external[0].status == "ERROR"


class _FakeAdapter:
    """Minimal adapter double that yields one observation."""

    name = "zap"

    def availability(self) -> bool:
        return True

    def version(self) -> str:
        return "fake-1.0"

    def run(self, targets, *, config=None, scope=None) -> ToolRunResult:
        finding = ToolFindingRecord(
            source_tool="zap",
            source_id="40012",
            title="Cross Site Scripting (Reflected)",
            category="external-zap",
            endpoint="https://api.example.com/users",
            severity="high",
            confidence=0.7,
            status="candidate",
            description="Reflected XSS reported by ZAP",
            evidence={"uri": "https://api.example.com/users", "evidence": "Authorization: Bearer super-secret-value"},
            provenance={"tool": "zap", "target": "https://api.example.com/users"},
            raw={"alert": "Cross Site Scripting (Reflected)", "request-header": "Authorization: Bearer super-secret-value"},
        )
        return ToolRunResult(tool=self.name, available=True, executed=True, success=True, findings=(finding,), errors=())


def test_external_findings_are_observations_not_proof(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("bugbounty.tool_adapters.get_adapter", lambda name, **kwargs: _FakeAdapter())
    engagement = _engagement(tmp_path, external_tools={"zap": {"enabled": True}})
    result = AssessmentEngine(engagement, checks=[]).run(endpoint_inventory=[_endpoint()])

    external_findings = [item for item in result.findings.findings if item.category == "external-zap"]
    assert len(external_findings) == 1
    finding = external_findings[0]
    assert finding.status == "not_verified"
    assert finding.status != "verified"
    assert finding.evidence_ids, "external observations must carry evidence for the engine to classify"

    # The single central classification pass must count it as unverified, not confirmed.
    assert result.classification.get("unverified", 0) >= 1
    assert result.classification.get("confirmed", 0) == 0

    external_check = [item for item in result.check_results if item.check_id == "external:zap"]
    assert len(external_check) == 1
    assert external_check[0].status == "PASS"
    assert external_check[0].executed is True
    # External tool output is never treated as independently verified.
    assert external_check[0].verified is False

    from bugbounty.reports import report_data

    data = report_data(result)
    assert data["classification"].get("unverified", 0) >= 1
    assert data["classification"].get("confirmed", 0) == 0
