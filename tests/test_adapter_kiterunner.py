from __future__ import annotations

import json

import pytest

from bugbounty.adapters_kiterunner import KiterunnerAdapter
from bugbounty.tool_adapters import (
    AdapterConfig,
    InputValidationError,
    ToolExecution,
)

TARGET = "https://api.allowed.example"

# A realistic mixed fixture: two JSON records plus one Kiterunner-style text
# result line, followed by noise that must be ignored.
KITERUNNER_FIXTURE = "\n".join(
    [
        '{"method":"GET","status":200,"length":512,"url":"https://api.allowed.example/v1/users","content_type":"application/json"}',
        '{"method":"POST","status":403,"length":128,"url":"https://api.allowed.example/v1/admin","content_type":"application/json"}',
        "GET 500 64 https://api.allowed.example/v1/legacy [text/html]",
        "not-a-result-line",
        "",
    ]
)

# Contains a literal ``Authorization: Bearer <secret>`` both in a raw request
# string and in a headers map; neither may leak into normalized findings.
REDACTION_FIXTURE = (
    '{"method":"GET","status":200,"length":42,'
    '"url":"https://api.allowed.example/v1/me","content_type":"application/json",'
    '"request":"GET /v1/me HTTP/1.1\\nAuthorization: Bearer supersecret-token",'
    '"headers":{"Authorization":"Bearer supersecret-token"}}'
)


def test_name_and_availability():
    adapter = KiterunnerAdapter(executable="kr")
    assert adapter.name == "kiterunner"
    assert adapter.availability() is True


def test_validate_input_requires_wordlist():
    adapter = KiterunnerAdapter(executable="kr")
    with pytest.raises(InputValidationError):
        adapter.validate_input([TARGET])

    validated = adapter.validate_input([TARGET], AdapterConfig(extra_args=("-w", "routes.kite")))
    assert validated == (TARGET,)


def test_build_command_flags():
    adapter = KiterunnerAdapter(executable="kr")
    cfg = AdapterConfig(extra_args=("-w", "routes.kite", "-x", "20"))
    cmd = adapter.build_command(TARGET, cfg)

    assert isinstance(cmd, tuple)
    assert cmd[0] == "kr"
    assert cmd[1] == "scan"
    assert TARGET in cmd
    # ``-o`` is a format selector, not a file path.
    assert cmd[cmd.index("-o") + 1] == "json"
    assert "-q" in cmd
    assert "-A" not in cmd
    # The wordlist is emitted exactly once and the extra_args value wins.
    assert cmd.count("-w") == 1
    assert cmd[cmd.index("-w") + 1] == "routes.kite"
    # Other extra args are preserved.
    assert "-x" in cmd and "20" in cmd
    assert all(isinstance(part, str) for part in cmd)


def test_parse_output_fixture_and_malformed():
    adapter = KiterunnerAdapter(executable="kr")
    items = adapter.parse_output(KITERUNNER_FIXTURE)

    assert len(items) >= 2
    urls = {item["url"] for item in items}
    assert "https://api.allowed.example/v1/users" in urls
    assert "https://api.allowed.example/v1/legacy" in urls

    legacy = next(item for item in items if item["url"].endswith("/v1/legacy"))
    assert legacy["method"] == "GET"
    assert legacy["status"] == 500
    assert legacy["length"] == 64
    assert legacy["content_type"] == "text/html"

    # Malformed / empty input must never raise and must yield [].
    assert adapter.parse_output("garbage output\n<<<not-json>>>\n") == []
    assert adapter.parse_output("") == []
    assert adapter.parse_output("{ this is not json") == []


def test_normalize_results_contract():
    adapter = KiterunnerAdapter(executable="kr")
    items = [
        {"method": "GET", "status": 200, "length": 512, "url": f"{TARGET}/v1/users"},
        {"method": "POST", "status": 403, "length": 0, "url": f"{TARGET}/v1/admin"},
        {"method": "GET", "status": 500, "length": 10, "url": f"{TARGET}/v1/legacy"},
    ]
    execution = ToolExecution(
        tool="kiterunner",
        version="kr 1.0.0",
        command=("kr", "scan", TARGET, "-w", "routes.kite", "-o", "json", "-q"),
        cwd=None,
        started_at="2026-01-01T00:00:00Z",
        finished_at="2026-01-01T00:00:01Z",
        duration_ms=1000.0,
        return_code=0,
        timed_out=False,
        stdout_bytes=0,
        stderr_bytes=0,
    )
    findings = adapter.normalize_results(items, target=TARGET, execution=execution)

    assert len(findings) == 3
    for finding in findings:
        assert finding.category == "external-kiterunner"
        assert finding.status == "candidate"
        assert finding.source_tool == "kiterunner"
        assert finding.confidence == 0.5

    assert findings[0].endpoint == f"{TARGET}/v1/users"
    assert findings[0].title == f"Discovered API route: {TARGET}/v1/users"
    assert findings[0].severity == "info"  # 2xx
    assert findings[1].severity == "low"  # 401/403
    assert findings[2].severity == "medium"  # 5xx

    assert findings[0].provenance["tool"] == "kiterunner"
    assert findings[0].provenance["tool_version"] == "kr 1.0.0"
    assert findings[0].provenance["target"] == TARGET
    assert findings[0].provenance["command"][0] == "kr"
    assert findings[0].evidence["status"] == 200


def test_normalize_results_severity_defaults_to_info():
    adapter = KiterunnerAdapter(executable="kr")
    findings = adapter.normalize_results(
        [{"method": "GET", "status": 302, "url": f"{TARGET}/redirect"}],
        target=TARGET,
    )
    assert findings[0].severity == "info"


def test_redaction_does_not_leak_secrets():
    adapter = KiterunnerAdapter(executable="kr")
    items = adapter.parse_output(REDACTION_FIXTURE)
    assert items, "redaction fixture should parse into at least one record"

    findings = adapter.normalize_results(items, target=TARGET)
    dumped = json.dumps([finding.as_dict() for finding in findings])

    assert "supersecret-token" not in dumped
    assert "[REDACTED]" in dumped


def test_output_file_is_none():
    adapter = KiterunnerAdapter(executable="kr")
    cfg = AdapterConfig(extra_args=("-w", "routes.kite"))
    cmd = adapter.build_command(TARGET, cfg)

    # Kiterunner streams results to stdout; ``-o`` selects the format.
    assert adapter.output_file(cmd, cfg) is None
