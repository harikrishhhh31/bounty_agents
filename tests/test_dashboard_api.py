import json
from pathlib import Path

from bugbounty.dashboard_api import DashboardState


BURP_XML = """<items>
<item><time>2026-09-15T10:00:00Z</time><host>api.example.com</host><port>443</port><protocol>https</protocol><request>GET /users?token=secret-token HTTP/1.1\nHost: api.example.com\nAuthorization: Bearer bearer-secret\n\n</request><response>HTTP/1.1 200 OK\nContent-Type: application/json\n\n{\"id\":1}</response></item>
<item><time>2026-09-15T10:01:00Z</time><host>outside.example</host><port>443</port><protocol>https</protocol><request>GET /admin HTTP/1.1\nHost: outside.example\n\n</request><response>HTTP/1.1 200 OK\nContent-Type: application/json\n\n{}</response></item>
</items>"""

SCOPE_TSV = "identifier\tasset_type\teligible\napi.example.com\tDomain\ttrue\noutside.example\tDomain\tfalse\n"


def test_dashboard_import_counts_scope_status_and_runs_existing_engine(tmp_path: Path):
    state = DashboardState()
    scope_result = state.import_scope("scope.tsv", SCOPE_TSV)
    burp_result = state.import_burp("history.xml", BURP_XML)

    assert len(scope_result["assets"]) == 2
    assert burp_result["requests"] == 2
    assert {item.scope_status for item in state.inventory} == {"IN_SCOPE", "OUT_OF_SCOPE"}

    result = state.run_assessment({"workspace": str(tmp_path), "dry_run": True})

    assert len(result["endpoints"]) == 1
    assert result["endpoints"][0]["url"] == "https://api.example.com/users?token=%5BREDACTED%5D"
    assert len(result["evidence"]) == 2
    blob = json.dumps(result)
    assert "bearer-secret" not in blob
    assert "secret-token" not in blob
    assert all((tmp_path / name).exists() for name in ("report.json", "report.md", "report.html", "evidence.json", "findings.json", "audit.jsonl"))
