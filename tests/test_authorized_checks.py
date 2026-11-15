from pathlib import Path

from bugbounty.assessment import AssessmentEngine
from bugbounty.engagement import (
    AuthIdentity,
    BusinessFlow,
    BusinessFlowStep,
    Engagement,
    FunctionAuthorizationCase,
    ObjectAuthorizationCase,
    PropertyAuthorizationCase,
    ResourceProbe,
    SsrfCase,
)
from tests.fixtures.vulnerable_api import RunningVulnerableApi


def test_configured_authorization_and_safety_checks_produce_evidence(tmp_path: Path):
    fixture = RunningVulnerableApi()
    try:
        engagement = Engagement.from_target(
            fixture.target,
            allowed_schemes=["http"],
            allowed_methods=["GET", "POST"],
            identities=[
                AuthIdentity("alice", bearer_token="alice-token"),
                AuthIdentity("bob", bearer_token="bob-token"),
                AuthIdentity("admin", bearer_token="admin-token"),
                AuthIdentity("invalid", bearer_token="expired-token"),
            ],
            object_authorization_cases=[ObjectAuthorizationCase("/objects/{id}", "alice", "A", "bob", "B")],
            function_authorization_cases=[FunctionAuthorizationCase("/admin", "admin", "alice")],
            property_authorization_cases=[PropertyAuthorizationCase("/profile", "alice", ("ssn",))],
            resource_probes=[ResourceProbe("/resource", query_parameter="limit", repeat_count=2, safe_limit=10)],
            business_flows=[BusinessFlow("checkout", (BusinessFlowStep("create", "/flow/create"), BusinessFlowStep("confirm", "/flow/confirm"), BusinessFlowStep("execute", "/flow/execute")), replay_step="execute")],
            ssrf_cases=[SsrfCase("/fetch", "url", f"{fixture.target}/callback/test-token", "test-token")],
            maximum_requests=80,
            request_rate_limit=100,
            timeout=2,
            dry_run=False,
            workspace=str(tmp_path),
        )
        result = AssessmentEngine(engagement).run()
        categories = {finding.category for finding in result.findings.findings}

        assert {"API1", "API2", "API3", "API4", "API5", "API6", "API7", "API8"}.issubset(categories)
        assert all(finding.evidence_ids for finding in result.findings.findings)
        assert any(item.check_id == "api1-bola" and item.verified for item in result.check_results)
        assert any(item.check_id == "api5-function-authorization" and item.verified for item in result.check_results)
        assert any(item.check_id == "api6-sensitive-business-flow" and item.status == "FAIL" for item in result.check_results)
        assert all("expired-token" not in str(item.as_dict()) for item in result.evidence.artifacts)
    finally:
        fixture.close()


def test_bola_uses_other_object_id_and_records_both_object_requests(tmp_path: Path):
    fixture = RunningVulnerableApi(enforce_object_ownership=True)
    try:
        engagement = Engagement.from_target(
            fixture.target,
            allowed_schemes=["http"],
            allowed_methods=["GET"],
            identities=[AuthIdentity("alice", bearer_token="alice-token"), AuthIdentity("bob", bearer_token="bob-token")],
            object_authorization_cases=[ObjectAuthorizationCase("/objects/{id}", "alice", "A", "bob", "B")],
            maximum_requests=30,
            request_rate_limit=100,
            timeout=2,
            dry_run=False,
            workspace=str(tmp_path),
        )
        result = AssessmentEngine(engagement).run()

        bola = next(item for item in result.check_results if item.check_id == "api1-bola")
        assert bola.status == "PASS"
        assert not any(finding.category == "API1" for finding in result.findings.findings)
        evidence = next(item for item in result.evidence.artifacts if item.check_id == "api1-bola")
        assert evidence.request_metadata["owner_identity"] == "alice"
        assert evidence.request_metadata["other_identity"] == "bob"
        assert evidence.request_metadata["owner_object_id"] == "A"
        assert evidence.request_metadata["other_object_id"] == "B"
        assert evidence.request_metadata["requested_object_id"] == "A"
        assert "owner succeeds" in evidence.expected_behavior.lower()
        assert "cross_identity" in evidence.actual_behavior.lower()
    finally:
        fixture.close()
