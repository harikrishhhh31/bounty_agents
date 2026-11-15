from pathlib import Path

import pytest

from bugbounty.assessment import AssessmentEngine
from bugbounty.engagement import Engagement, ResourceProbe
from bugbounty.http_client import HttpClient
from tests.fixtures.vulnerable_api import RunningVulnerableApi


def test_scope_violation_does_not_execute_request(tmp_path: Path):
    engagement = Engagement.from_target("http://127.0.0.1", allowed_schemes=["http"], dry_run=False, workspace=str(tmp_path))
    response = HttpClient(engagement).request("GET", "http://127.0.0.2/secret")
    assert response.status_code is None
    assert "scope" in (response.error or "")
    assert HttpClient(engagement).requests_made == 0


def test_malformed_resource_configuration_is_rejected():
    with pytest.raises(ValueError, match="repeat_count"):
        Engagement.from_target("https://example.com", resource_probes=[ResourceProbe("/resource", repeat_count=6)])


def test_identity_dependent_checks_are_not_run_without_identities(tmp_path: Path):
    fixture = RunningVulnerableApi()
    try:
        engagement = Engagement.from_target(fixture.target, allowed_schemes=["http"], allowed_methods=["GET", "POST"], dry_run=False, request_rate_limit=100, workspace=str(tmp_path))
        result = AssessmentEngine(engagement).run()
        not_run = {item.check_id for item in result.check_results if item.status == "NOT_RUN"}
        assert "api1-bola" in not_run
        assert "api5-broken-function-level-authorization" in not_run
        assert any(item.check_id == "api2-broken-authentication" and "identities" in item.reason for item in result.check_results)
        assert (tmp_path / "audit.jsonl").exists()
    finally:
        fixture.close()
