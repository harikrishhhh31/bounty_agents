from pathlib import Path

from bugbounty.assessment import AssessmentEngine
from bugbounty.engagement import Engagement
from bugbounty.reports import write_reports
from tests.fixtures.vulnerable_api import RunningVulnerableApi


def test_local_end_to_end_assessment(tmp_path: Path):
    fixture = RunningVulnerableApi()
    try:
        engagement = Engagement.from_target(
            fixture.target,
            allowed_schemes=["http"],
            allowed_methods=["GET"],
            maximum_requests=30,
            request_rate_limit=100,
            timeout=2,
            dry_run=False,
            workspace=str(tmp_path),
        )
        result = AssessmentEngine(engagement).run()
        paths = write_reports(result)

        assert len(result.endpoints) >= 6
        assert {"/objects/{id}", "/admin", "/profile", "/resource", "/fetch"}.issubset({item.path for item in result.endpoints})
        assert result.evidence.artifacts
        assert any(finding.category == "API8" for finding in result.findings.findings)
        assert any(finding.category == "API7" for finding in result.findings.findings)
        assert all(path.exists() for path in paths.values())
        assert (tmp_path / "evidence.json").exists()
        assert (tmp_path / "findings.json").exists()
    finally:
        fixture.close()
