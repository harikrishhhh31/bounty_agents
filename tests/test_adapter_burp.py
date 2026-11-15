from __future__ import annotations

import json

from bugbounty.adapters_burp import BurpAdapter
from bugbounty.tool_adapters import AdapterConfig

BURP_XML_FIXTURE = """<?xml version="1.0"?>
<issues burpVersion="2024.1.1" exportTime="2026-01-01T00:00:00Z">
  <issue>
    <serialNumber>1</serialNumber>
    <type>1049088</type>
    <name>SQL injection</name>
    <host>https://shop.example.com</host>
    <path>/product?id=1</path>
    <location>https://shop.example.com/product?id=1</location>
    <severity>High</severity>
    <confidence>Certain</confidence>
    <issueBackground>SQL injection occurs when user input is not sanitized.</issueBackground>
    <remediationDetail>Use parameterized queries.</remediationDetail>
    <issueDetail>The id parameter appears to be vulnerable. Authorization: Bearer supersecret-token</issueDetail>
  </issue>
  <issue>
    <serialNumber>2</serialNumber>
    <type>5242880</type>
    <name>Cleartext submission of password</name>
    <host>https://shop.example.com</host>
    <path>/admin</path>
    <location></location>
    <severity>Low</severity>
    <confidence>Tentative</confidence>
    <issueBackground>Passwords should not be sent over cleartext channels.</issueBackground>
    <remediationDetail>Enforce HTTPS.</remediationDetail>
    <issueDetail>The login form posts credentials without TLS.</issueDetail>
  </issue>
</issues>
"""


def test_name_and_availability():
    adapter = BurpAdapter(executable="burp")
    assert adapter.name == "burp"
    assert adapter.availability() is True
    assert adapter.executable_names == ("burp", "burpsuite", "burp.sh", "burp.bat", "burp.exe")


def test_build_command_contains_target_and_report_output():
    adapter = BurpAdapter(executable="burp")
    cmd = adapter.build_command("https://shop.example.com")
    assert isinstance(cmd, tuple)
    assert cmd[0] == "burp"
    assert cmd[1] == "--headless"
    assert "--target" in cmd
    assert cmd[cmd.index("--target") + 1] == "https://shop.example.com"
    assert "--report-format" in cmd
    assert cmd[cmd.index("--report-format") + 1] == "xml"
    assert "--report-output" in cmd
    report_path = cmd[cmd.index("--report-output") + 1]
    assert report_path.endswith(".xml")


def test_build_command_appends_extra_args():
    adapter = BurpAdapter(executable="burp")
    cmd = adapter.build_command("https://shop.example.com", AdapterConfig(extra_args=("--scope", "shop")))
    assert cmd[-2:] == ("--scope", "shop")


def test_output_file_returns_report_path():
    adapter = BurpAdapter(executable="burp")
    cmd = adapter.build_command("https://shop.example.com")
    path = adapter.output_file(cmd, AdapterConfig())
    assert path is not None
    assert path == cmd[cmd.index("--report-output") + 1]
    assert path.endswith(".xml")
    assert adapter.output_file(("burp", "--headless"), AdapterConfig()) is None


def test_parse_output_two_issue_fixture():
    adapter = BurpAdapter(executable="burp")
    items = adapter.parse_output(BURP_XML_FIXTURE)
    assert len(items) == 2
    first = items[0]
    assert first["name"] == "SQL injection"
    assert first["host"] == "https://shop.example.com"
    assert first["path"] == "/product?id=1"
    assert first["location"] == "https://shop.example.com/product?id=1"
    assert first["severity"] == "High"
    assert first["confidence"] == "Certain"
    assert first["type"] == "1049088"
    assert "supersecret-token" in first["issueDetail"]


def test_parse_output_malformed_xml_returns_empty():
    adapter = BurpAdapter(executable="burp")
    assert adapter.parse_output("<issues><issue><name>broken</name>") == []
    assert adapter.parse_output("not xml at all") == []
    assert adapter.parse_output("") == []


def test_normalize_results_fields():
    adapter = BurpAdapter(executable="burp")
    items = adapter.parse_output(BURP_XML_FIXTURE)
    findings = adapter.normalize_results(items, target="https://shop.example.com")
    assert len(findings) == 2

    first = findings[0].as_dict()
    assert first["category"] == "external-burp"
    assert first["status"] == "candidate"
    assert first["source_tool"] == "burp"
    assert first["endpoint"] == "https://shop.example.com/product?id=1"
    assert first["severity"] == "high"
    assert first["confidence"] == 0.9
    assert first["provenance"]["tool"] == "burp"
    assert first["provenance"]["target"] == "https://shop.example.com"
    assert first["provenance"]["burp_type"] == "1049088"

    second = findings[1].as_dict()
    # Empty <location> falls back to scheme://host+path.
    assert second["endpoint"] == "https://shop.example.com/admin"
    assert second["severity"] == "low"
    assert second["confidence"] == 0.5


def test_redaction_hides_bearer_token():
    adapter = BurpAdapter(executable="burp")
    items = adapter.parse_output(BURP_XML_FIXTURE)
    findings = adapter.normalize_results(items, target="https://shop.example.com")
    dumped = json.dumps([f.as_dict() for f in findings])
    assert "supersecret-token" not in dumped
    assert "[REDACTED]" in dumped
