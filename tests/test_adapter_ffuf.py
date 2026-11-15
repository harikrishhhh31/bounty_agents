from __future__ import annotations

import json
import os

import pytest

from bugbounty.adapters_ffuf import FfufAdapter
from bugbounty.tool_adapters import AdapterConfig, InputValidationError, ToolExecution


def _report_fixture() -> dict:
    return {
        "commandline": (
            "ffuf -u https://target.example/FUZZ -w words.txt "
            "-o report.json -of json -s -noninteractive"
        ),
        "time": "2026-01-01T00:00:00Z",
        "results": [
            {
                "input": {
                    "FUZZ": "admin",
                    "Authorization": "Bearer supersecret-token",
                },
                "position": 1,
                "status": 200,
                "length": 1234,
                "words": 100,
                "lines": 20,
                "content-type": "text/html",
                "redirectlocation": "",
                "url": "https://target.example/admin",
                "duration": 51,
            },
            {
                "input": {"FUZZ": "login"},
                "position": 2,
                "status": 403,
                "length": 0,
                "words": 0,
                "lines": 0,
                "content-type": "text/plain",
                "redirectlocation": "",
                "url": "https://target.example/login",
                "duration": 11,
            },
            {
                "input": {"FUZZ": "boom"},
                "position": 3,
                "status": 500,
                "length": 12,
                "words": 2,
                "lines": 1,
                "content-type": "text/html",
                "redirectlocation": "",
                "url": "https://target.example/boom",
                "duration": 13,
            },
        ],
        "config": {"url": "https://target.example/FUZZ"},
    }


def test_name_and_availability():
    adapter = FfufAdapter(executable="ffuf")
    assert adapter.name == "ffuf"
    assert adapter.executable_names == ("ffuf", "ffuf.exe")
    assert adapter.availability() is True


def test_validate_input_requires_wordlist():
    adapter = FfufAdapter(executable="ffuf")
    with pytest.raises(InputValidationError):
        adapter.validate_input(["https://target.example"])
    with pytest.raises(InputValidationError):
        adapter.validate_input(
            ["https://target.example"], AdapterConfig(extra_args=("-mc", "200"))
        )

    validated = adapter.validate_input(
        ["https://target.example"], AdapterConfig(extra_args=("-w", "words.txt"))
    )
    assert validated == ("https://target.example",)


def test_build_command_flags_and_fuzz():
    adapter = FfufAdapter(executable="ffuf")
    cmd = adapter.build_command(
        "https://target.example", AdapterConfig(extra_args=("-w", "words.txt"))
    )
    assert isinstance(cmd, tuple)
    assert all(isinstance(a, str) for a in cmd)
    assert cmd[0] == "ffuf"
    assert "-u" in cmd
    assert any("FUZZ" in a for a in cmd)
    assert cmd[cmd.index("-u") + 1] == "https://target.example/FUZZ"
    assert "-o" in cmd
    report_path = cmd[cmd.index("-o") + 1]
    assert report_path.endswith(".json")
    assert "-of" in cmd and cmd[cmd.index("-of") + 1] == "json"
    assert "-s" in cmd
    assert "-noninteractive" in cmd
    assert cmd[-2:] == ("-w", "words.txt")

    # An explicit FUZZ keyword must not be appended twice.
    explicit = adapter.build_command(
        "https://target.example/FUZZ", AdapterConfig(extra_args=("-w", "words.txt"))
    )
    assert explicit[explicit.index("-u") + 1] == "https://target.example/FUZZ"


def test_parse_output_full_report_and_malformed():
    adapter = FfufAdapter(executable="ffuf")
    payload = json.dumps(_report_fixture())
    items = adapter.parse_output(payload)
    assert len(items) == 3
    assert items[0]["url"] == "https://target.example/admin"
    assert items[1]["status"] == 403

    # Newline-delimited JSON records must also be tolerated.
    ndjson = "\n".join(json.dumps(r) for r in _report_fixture()["results"])
    assert len(adapter.parse_output(ndjson)) == 3

    # Malformed input must never raise and yields an empty list.
    assert adapter.parse_output("not json at all") == []
    assert adapter.parse_output("{ broken json") == []
    assert adapter.parse_output("") == []


def test_normalize_results_fields():
    adapter = FfufAdapter(executable="ffuf")
    items = adapter.parse_output(json.dumps(_report_fixture()))
    findings = adapter.normalize_results(items, target="https://target.example")
    assert len(findings) == 3

    first = findings[0]
    assert first.category == "external-ffuf"
    assert first.status == "candidate"
    assert first.source_tool == "ffuf"
    assert first.endpoint == "https://target.example/admin"
    assert first.severity == "info"
    assert first.confidence == 0.5
    assert first.title == "Discovered path: https://target.example/admin"
    assert first.provenance["tool"] == "ffuf"
    assert first.provenance["target"] == "https://target.example"

    assert findings[1].severity == "low"  # 403
    assert findings[2].severity == "medium"  # 500
    assert findings[2].endpoint == "https://target.example/boom"


def test_normalize_results_with_execution_provenance():
    adapter = FfufAdapter(executable="ffuf")
    items = adapter.parse_output(json.dumps(_report_fixture()))
    execution = ToolExecution(
        tool="ffuf",
        version="ffuf 2.1.0",
        command=("ffuf", "-u", "https://target.example/FUZZ", "-w", "words.txt"),
        cwd=None,
        started_at="2026-01-01T00:00:00Z",
        finished_at="2026-01-01T00:00:01Z",
        duration_ms=1000.0,
        return_code=0,
        timed_out=False,
        stdout_bytes=0,
        stderr_bytes=0,
    )
    findings = adapter.normalize_results(
        items, target="https://target.example", execution=execution
    )
    assert findings[0].provenance["tool_version"] == "ffuf 2.1.0"
    assert findings[0].provenance["command"][0] == "ffuf"


def test_redaction_never_leaks_credentials():
    adapter = FfufAdapter(executable="ffuf")
    fixture = _report_fixture()
    fixture["results"][0]["headers"] = "Authorization: Bearer supersecret-token"
    items = adapter.parse_output(json.dumps(fixture))
    findings = adapter.normalize_results(items, target="https://target.example")

    serialized = json.dumps([f.as_dict() for f in findings])
    assert "supersecret-token" not in serialized
    assert "Bearer supersecret-token" not in serialized
    assert "[REDACTED]" in serialized


def test_output_file_returns_report_path():
    adapter = FfufAdapter(executable="ffuf")
    cfg = AdapterConfig(extra_args=("-w", "words.txt"))
    cmd = adapter.build_command("https://target.example", cfg)
    report_path = adapter.output_file(cmd, cfg)
    assert report_path is not None
    assert report_path.endswith(".json")
    assert report_path == cmd[cmd.index("-o") + 1]
    assert os.path.exists(report_path)
