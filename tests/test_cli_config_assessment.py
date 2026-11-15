from pathlib import Path

from bugbounty.cli import main
from tests.fixtures.vulnerable_api import RunningVulnerableApi


def test_cli_assess_config_generates_all_artifacts(tmp_path: Path, capsys):
    fixture = RunningVulnerableApi()
    try:
        config = tmp_path / "engagement.yaml"
        workspace = tmp_path / "assessment"
        config.write_text(
            f"""
target_url: {fixture.target}
allowed_hosts: [127.0.0.1]
allowed_schemes: [http]
allowed_methods: [GET]
request_rate_limit: 100
timeout: 2
maximum_requests: 30
dry_run: false
workspace: {workspace.as_posix()}
discovery:
  documentation_paths: [/openapi.json]
""",
            encoding="utf-8",
        )

        assert main(["assess", "--config", str(config)]) == 0
        output = capsys.readouterr().out
        assert "findings" in output
        assert all((workspace / name).exists() for name in ("report.json", "report.md", "report.html", "evidence.json", "audit.jsonl"))
    finally:
        fixture.close()
