from __future__ import annotations

import json

from bugbounty.adapters_restler import RestlerAdapter
from bugbounty.tool_adapters import AdapterConfig

# Realistic-ish RESTler fuzz-lean console output with several bug markers plus a
# trailing summary line.
RESTLER_FUZZLEAN_FIXTURE = "\n".join(
    [
        "2026-01-01 12:00:00.001: Starting task FuzzLean.",
        "2026-01-01 12:00:00.100: Starting task Test.",
        "BUG: 500 Internal Server Error at GET /api/users/1 - unexpected response body (checksum: 3f9a2b1c)",
        "2026-01-01 12:00:02.000: bug bucket 'a1b2c3d4-1111-2222-3333-444455556666' created for GET https://allowed.example/api/orders",
        "BUG: unexpected status 500 for POST https://allowed.example/api/login",
        "2026-01-01 12:00:03.000: Testing completed.",
        "2 bug buckets created",
    ]
)

# A bug line that embeds a credential header; redaction must scrub it.
RESTLER_AUTH_FIXTURE = "\n".join(
    [
        "BUG: 500 Internal Server Error at GET https://allowed.example/api/secure - Authorization: Bearer supersecret-token",
        "1 bug buckets created",
    ]
)


def test_restler_name_and_availability():
    adapter = RestlerAdapter(executable="restler")
    assert adapter.name == "restler"
    assert adapter.availability() is True
    assert adapter.resolve_executable() == "restler"


def test_restler_build_command_contains_fuzz_lean():
    adapter = RestlerAdapter(executable="restler")
    cmd = adapter.build_command("https://api.example.com", None)
    assert isinstance(cmd, tuple)
    assert cmd[0] == "restler"
    assert "fuzz-lean" in cmd
    assert "--grammar_file" in cmd
    assert "--dictionary_file" in cmd
    assert "--target_ip" in cmd
    assert "--target_port" in cmd
    assert cmd[cmd.index("--target_ip") + 1] == "api.example.com"
    assert cmd[cmd.index("--target_port") + 1] == "443"

    # Grammar/dictionary supplied via extra_args are honored; other extras appended.
    cmd2 = adapter.build_command(
        "https://api.example.com:8443",
        AdapterConfig(
            extra_args=(
                "--grammar_file",
                "g.py",
                "--dictionary_file",
                "d.json",
                "--no-ssl",
            )
        ),
    )
    assert cmd2[0] == "restler"
    assert "fuzz-lean" in cmd2
    assert cmd2[cmd2.index("--grammar_file") + 1] == "g.py"
    assert cmd2[cmd2.index("--dictionary_file") + 1] == "d.json"
    assert cmd2[cmd2.index("--target_port") + 1] == "8443"
    assert cmd2[-1] == "--no-ssl"
    # Consumed grammar/dictionary flags must not be duplicated.
    assert cmd2.count("--grammar_file") == 1
    assert cmd2.count("--dictionary_file") == 1


def test_restler_parse_output_bug_markers():
    adapter = RestlerAdapter(executable="restler")
    items = adapter.parse_output(RESTLER_FUZZLEAN_FIXTURE)
    assert len(items) >= 2
    assert all(isinstance(item, dict) for item in items)
    assert any(item.get("status_code") == 500 for item in items)


def test_restler_parse_output_malformed_returns_empty():
    adapter = RestlerAdapter(executable="restler")
    assert adapter.parse_output("") == []
    assert adapter.parse_output("random noise\nnothing interesting here") == []
    assert adapter.parse_output("only a summary: Testing completed.") == []
    # Defensive: must never raise, even for non-string input.
    assert adapter.parse_output(None) == []  # type: ignore[arg-type]


def test_restler_normalize_results_fields():
    adapter = RestlerAdapter(executable="restler")
    items = adapter.parse_output(RESTLER_FUZZLEAN_FIXTURE)
    findings = adapter.normalize_results(items, target="https://allowed.example")
    assert findings
    for finding in findings:
        assert finding.category == "external-restler"
        assert finding.status == "candidate"
        assert finding.source_tool == "restler"
        assert finding.confidence == 0.5

    endpoints = {finding.endpoint for finding in findings}
    assert "/api/users/1" in endpoints
    assert "https://allowed.example/api/login" in endpoints

    first = findings[0].as_dict()
    assert first["severity"] == "high"  # 500 Internal Server Error
    assert first["provenance"]["tool"] == "restler"
    assert first["provenance"]["target"] == "https://allowed.example"


def test_restler_redaction_does_not_leak_tokens():
    adapter = RestlerAdapter(executable="restler")
    items = adapter.parse_output(RESTLER_AUTH_FIXTURE)
    findings = adapter.normalize_results(items, target="https://allowed.example")
    assert findings
    blob = json.dumps([finding.as_dict() for finding in findings])
    assert "supersecret-token" not in blob
    assert "[REDACTED]" in blob
