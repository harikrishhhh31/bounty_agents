from __future__ import annotations

import json
import os

import pytest

from bugbounty.adapters_schemathesis import SchemathesisAdapter
from bugbounty.tool_adapters import AdapterConfig

SCHEMA_URL = "https://api.example.com/openapi.json"

# Realistic Schemathesis v4 JUnit report: two failing operations (one carrying a
# credential in its reproduction command) plus one passing operation.
JUNIT_FIXTURE = """<?xml version="1.0" encoding="UTF-8"?>
<testsuites name="schemathesis" tests="3" failures="2" errors="0">
  <testsuite name="schemathesis" tests="3" failures="2" errors="0" time="1.234">
    <testcase name="GET /bookings" classname="test_api" time="0.512">
      <failure message="Server error: 500" type="ServerError">Server error: 500
Reproduce with: curl -H 'Authorization: Bearer supersecret-token' http://127.0.0.1:8080/bookings</failure>
    </testcase>
    <testcase name="POST /bookings" classname="test_api" time="0.321">
      <failure message="Response violates schema" type="SchemaViolation">Response violates schema</failure>
    </testcase>
    <testcase name="GET /health" classname="test_api" time="0.012"/>
  </testsuite>
</testsuites>
"""

MALFORMED_SAMPLES = (
    "",
    "   ",
    "this is not xml at all",
    "<testsuites><testsuite><testcase></testsuites>",
    '{"junit": "json-not-xml"}',
)


def test_name_and_availability_with_override():
    adapter = SchemathesisAdapter(executable="schemathesis")
    assert adapter.name == "schemathesis"
    assert adapter.availability() is True
    assert adapter.executable_names == ("schemathesis", "st", "schemathesis.exe")


def test_version_command_shape():
    adapter = SchemathesisAdapter(executable="schemathesis")
    assert adapter.version_command("schemathesis") == ("schemathesis", "--version")


def test_build_command_shape_and_config_file():
    adapter = SchemathesisAdapter(executable="schemathesis")
    cmd = adapter.build_command(SCHEMA_URL, AdapterConfig())

    assert isinstance(cmd, tuple)
    assert all(isinstance(part, str) for part in cmd)
    assert cmd[0] == "schemathesis"
    assert SCHEMA_URL in cmd
    assert "run" in cmd
    assert "--report=junit" in cmd

    # Global --config-file must precede the `run` subcommand.
    toml_index = cmd.index("--config-file")
    assert toml_index < cmd.index("run")
    toml_path = cmd[toml_index + 1]
    assert os.path.exists(toml_path)
    toml_text = open(toml_path, encoding="utf-8").read()
    assert "[reports.junit]" in toml_text
    assert "path =" in toml_text


def test_build_command_appends_extra_args_and_validates_target():
    adapter = SchemathesisAdapter(executable="schemathesis")
    cfg = AdapterConfig(extra_args=("--url", "https://api.example.com", "--checks", "all"))
    cmd = adapter.build_command(SCHEMA_URL, cfg)
    assert cmd[-4:] == ("--url", "https://api.example.com", "--checks", "all")

    with pytest.raises(Exception):
        adapter.build_command("not-a-url", AdapterConfig())


def test_parse_output_junit_fixture():
    adapter = SchemathesisAdapter(executable="schemathesis")
    items = adapter.parse_output(JUNIT_FIXTURE)

    assert len(items) == 2
    names = {item["name"] for item in items}
    assert names == {"GET /bookings", "POST /bookings"}
    first = items[0]
    assert first["classname"] == "test_api"
    assert first["failure_message"] == "Server error: 500"
    assert first["failure_type"] == "ServerError"
    assert "Reproduce with" in first["failure_text"]


def test_parse_output_malformed_returns_empty():
    adapter = SchemathesisAdapter(executable="schemathesis")
    for sample in MALFORMED_SAMPLES:
        assert adapter.parse_output(sample) == []
    assert adapter.parse_output(None) == []  # type: ignore[arg-type]


def test_normalize_results_contract():
    adapter = SchemathesisAdapter(executable="schemathesis")
    items = adapter.parse_output(JUNIT_FIXTURE)
    findings = adapter.normalize_results(items, target=SCHEMA_URL)

    assert len(findings) == 2
    for finding in findings:
        record = finding.as_dict()
        assert record["category"] == "external-schemathesis"
        assert record["status"] == "candidate"
        assert record["source_tool"] == "schemathesis"
        assert record["endpoint"] == SCHEMA_URL
        assert record["severity"] == "medium"
        assert record["confidence"] == 0.6
        assert record["provenance"]["tool"] == "schemathesis"
        assert record["provenance"]["target"] == SCHEMA_URL

    titles = {finding.title for finding in findings}
    assert "GET /bookings" in titles
    assert "POST /bookings" in titles


def test_normalize_results_title_fallback():
    adapter = SchemathesisAdapter(executable="schemathesis")
    findings = adapter.normalize_results(
        [{"failure_message": "boom", "failure_type": "ServerError"}],
        target=SCHEMA_URL,
    )
    assert len(findings) == 1
    assert findings[0].title == "Schemathesis property failure"


def test_redaction_never_leaks_token():
    adapter = SchemathesisAdapter(executable="schemathesis")
    items = adapter.parse_output(JUNIT_FIXTURE)
    findings = adapter.normalize_results(items, target=SCHEMA_URL)
    serialized = json.dumps([finding.as_dict() for finding in findings])
    assert "supersecret-token" not in serialized
    assert "Bearer supersecret-token" not in serialized
    assert "[REDACTED]" in serialized


def test_output_file_returns_xml_path_from_generated_toml():
    adapter = SchemathesisAdapter(executable="schemathesis")
    cmd = adapter.build_command(SCHEMA_URL, AdapterConfig())
    path = adapter.output_file(cmd, AdapterConfig())
    assert path is not None
    assert path.endswith(".xml")
    assert "schemathesis-junit.xml" in path


def test_output_file_falls_back_without_toml():
    adapter = SchemathesisAdapter(executable="schemathesis")
    path = adapter.output_file(("schemathesis", "run", SCHEMA_URL), AdapterConfig())
    assert path is not None
    assert path.endswith(".xml")
