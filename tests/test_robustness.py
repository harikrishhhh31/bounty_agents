from pathlib import Path

from bugbounty.assessment import AssessmentEngine
from bugbounty.engagement import Engagement
from bugbounty.http_client import HttpClient


def test_failed_http_request_is_a_response_not_an_exception(tmp_path: Path):
    engagement = Engagement.from_target("http://127.0.0.1:9", allowed_schemes=["http"], dry_run=False, timeout=0.1, workspace=str(tmp_path))
    response = HttpClient(engagement).request("GET", "http://127.0.0.1:9/unreachable")
    assert response.status_code is None
    assert response.error


def test_dry_run_assessment_reports_checks_not_run(tmp_path: Path):
    engagement = Engagement.from_target("https://example.com", dry_run=True, workspace=str(tmp_path))
    result = AssessmentEngine(engagement).run(endpoint="https://example.com/api")
    assert result.endpoints
    assert result.checks_not_run
    assert (tmp_path / "audit.jsonl").exists()
