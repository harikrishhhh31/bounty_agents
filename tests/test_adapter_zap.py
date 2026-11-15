"""Tests for the optional OWASP ZAP external-tool adapter.

All tests are offline: no subprocess is launched and no network access occurs.
``ZapAdapter(executable=...)`` injects a fake executable path so availability
can be asserted without ZAP being installed.
"""

from __future__ import annotations

import json

import pytest

from bugbounty.adapters_zap import ZapAdapter
from bugbounty.tool_adapters import AdapterConfig, InputValidationError

# A realistic ZAP "Traditional JSON Report" fragment. Alert 1 has two instances,
# alert 2 has one, and alert 3 has no instances (flattening fallback).
ZAP_REPORT_FIXTURE = json.dumps(
    {
        "@version": "2.14.0",
        "@generated": "2026-01-01T00:00:00",
        "site": [
            {
                "@name": "https://example.com",
                "@host": "example.com",
                "@port": "443",
                "@ssl": "true",
                "alerts": [
                    {
                        "pluginid": "10038",
                        "alertRef": "10038-1",
                        "alert": "Content Security Policy (CSP) Header Not Set",
                        "name": "Content Security Policy (CSP) Header Not Set",
                        "riskcode": "2",
                        "confidence": "3",
                        "riskdesc": "Medium (High)",
                        "desc": "CSP header missing.",
                        "solution": "Set a CSP header.",
                        "reference": "https://owasp.org/",
                        "cweid": "693",
                        "wascid": "15",
                        "instances": [
                            {
                                "uri": "https://example.com/",
                                "method": "GET",
                                "param": "",
                                "evidence": "",
                                "attack": "",
                                "otherinfo": "",
                            },
                            {
                                "uri": "https://example.com/login",
                                "method": "GET",
                                "param": "",
                                "evidence": "",
                                "attack": "",
                                "otherinfo": "",
                            },
                        ],
                    },
                    {
                        "pluginid": "10021",
                        "alertRef": "10021",
                        "alert": "X-Content-Type-Options Header Missing",
                        "name": "X-Content-Type-Options Header Missing",
                        "riskcode": "1",
                        "confidence": "2",
                        "desc": "Missing nosniff header.",
                        "solution": "Add the header.",
                        "reference": "https://owasp.org/",
                        "cweid": "693",
                        "instances": [
                            {
                                "uri": "https://example.com/assets/app.js",
                                "method": "GET",
                                "param": "",
                                "evidence": "Content-Type: text/javascript",
                                "attack": "",
                                "otherinfo": "",
                            }
                        ],
                    },
                    {
                        "pluginid": "99999",
                        "alertRef": "99999",
                        "alert": "Informational Alert",
                        "name": "Informational Alert",
                        "riskcode": "0",
                        "confidence": "0",
                        "desc": "Just informational.",
                        "solution": "None.",
                        "reference": "",
                        "cweid": "",
                        "instances": [],
                    },
                ],
            }
        ],
    }
)

REDACTION_FIXTURE = json.dumps(
    {
        "site": [
            {
                "@name": "https://example.com",
                "alerts": [
                    {
                        "pluginid": "40012",
                        "alertRef": "40012",
                        "alert": "Cross Site Scripting (Reflected)",
                        "name": "Cross Site Scripting (Reflected)",
                        "riskcode": "3",
                        "confidence": "3",
                        "desc": "Reflected XSS.",
                        "solution": "Encode output.",
                        "reference": "",
                        "cweid": "79",
                        "instances": [
                            {
                                "uri": "https://example.com/search?q=x",
                                "method": "GET",
                                "param": "q",
                                "evidence": "Authorization: Bearer supersecret-token",
                                "attack": "<script>alert(1)</script>",
                                "otherinfo": "",
                            }
                        ],
                    }
                ],
            }
        ]
    }
)


def test_name_and_availability_with_injected_executable():
    adapter = ZapAdapter(executable="zap.sh")
    assert adapter.name == "zap"
    assert adapter.executable_names == ("zap.sh", "zap.bat", "zap", "zap.exe")
    assert adapter.availability() is True


def test_build_command_is_argv_tuple_with_target_and_quickout():
    adapter = ZapAdapter(executable="zap.sh")
    cmd = adapter.build_command("https://example.com/", AdapterConfig())

    assert isinstance(cmd, tuple)
    assert cmd[0] == "zap.sh"
    assert "-cmd" in cmd
    assert "-quickurl" in cmd
    assert "https://example.com/" in cmd
    assert "-quickprogress" in cmd
    assert "-quickout" in cmd

    report_path = cmd[cmd.index("-quickout") + 1]
    assert report_path.endswith(".json")
    # Every element is a discrete string (argv-only, never shell).
    assert all(isinstance(part, str) for part in cmd)


def test_build_command_rejects_invalid_target():
    adapter = ZapAdapter(executable="zap.sh")
    with pytest.raises(InputValidationError):
        adapter.build_command("not-a-url", AdapterConfig())


def test_build_command_appends_extra_args():
    adapter = ZapAdapter(executable="zap.sh")
    cmd = adapter.build_command(
        "https://example.com/", AdapterConfig(extra_args=("-config", "a.b=true"))
    )
    assert cmd[-2:] == ("-config", "a.b=true")


def test_parse_output_flattens_instances():
    adapter = ZapAdapter(executable="zap.sh")
    items = adapter.parse_output(ZAP_REPORT_FIXTURE)

    # 2 + 1 instances + 1 instance-less alert == 4 flattened records.
    assert len(items) == 4
    uris = [item.get("uri") for item in items]
    assert "https://example.com/" in uris
    assert "https://example.com/login" in uris
    assert "https://example.com/assets/app.js" in uris
    # Instance-less alert is still represented.
    assert any(item.get("pluginid") == "99999" for item in items)
    # Alert-level fields are propagated onto every flattened record.
    csp_records = [item for item in items if item.get("pluginid") == "10038"]
    assert len(csp_records) == 2
    assert all(rec["riskcode"] == "2" for rec in csp_records)
    assert all(rec["cweid"] == "693" for rec in csp_records)


@pytest.mark.parametrize(
    "bad_input",
    [
        "",
        "   ",
        "not json at all",
        "{",
        "[]",
        '"a string"',
        "123",
        json.dumps({"site": "not-a-list"}),
        json.dumps({"unexpected": True}),
    ],
)
def test_parse_output_malformed_never_raises(bad_input):
    adapter = ZapAdapter(executable="zap.sh")
    assert adapter.parse_output(bad_input) == []


def test_parse_output_tolerates_bad_entries():
    adapter = ZapAdapter(executable="zap.sh")
    payload = json.dumps(
        {
            "site": [
                {"@name": "https://example.com", "alerts": [None, "junk"]},
                "not-a-site",
                {
                    "@name": "https://example.com",
                    "alerts": [{"pluginid": "1", "alert": "ok", "instances": [None]}],
                },
            ]
        }
    )
    items = adapter.parse_output(payload)
    assert items == [
        {
            "site": "https://example.com",
            "alert": "ok",
            "name": None,
            "riskcode": None,
            "confidence": None,
            "desc": None,
            "solution": None,
            "reference": None,
            "cweid": None,
            "pluginid": "1",
            "alert_ref": None,
        }
    ]


def test_normalize_results_maps_category_status_severity():
    adapter = ZapAdapter(executable="zap.sh")
    items = adapter.parse_output(ZAP_REPORT_FIXTURE)
    findings = adapter.normalize_results(items, target="https://example.com")

    assert len(findings) == 4
    for finding in findings:
        assert finding.category == "external-zap"
        assert finding.status == "candidate"
        assert finding.source_tool == "zap"
        assert isinstance(finding.confidence, float)
        assert 0.0 < finding.confidence <= 1.0

    by_plugin = {}
    for finding in findings:
        by_plugin.setdefault(finding.source_id, []).append(finding)

    csp = by_plugin["10038"]
    assert len(csp) == 2
    assert {f.endpoint for f in csp} == {
        "https://example.com/",
        "https://example.com/login",
    }
    # riskcode 2 -> medium, confidence 3 -> 0.9
    assert all(f.severity == "medium" for f in csp)
    assert all(f.confidence == 0.9 for f in csp)
    assert csp[0].provenance["plugin_id"] == "10038"
    assert csp[0].provenance["cwe_id"] == "693"
    assert csp[0].provenance["tool"] == "zap"
    assert csp[0].provenance["target"] == "https://example.com"

    # riskcode 1 -> low, confidence 2 -> 0.7
    xcto = by_plugin["10021"][0]
    assert xcto.severity == "low"
    assert xcto.confidence == 0.7
    assert xcto.endpoint == "https://example.com/assets/app.js"
    assert xcto.evidence["method"] == "GET"

    # riskcode 0 -> info, confidence 0 -> 0.3
    info = by_plugin["99999"][0]
    assert info.severity == "info"
    assert info.confidence == 0.3


def test_normalize_results_unknown_riskcode_defaults_to_info():
    adapter = ZapAdapter(executable="zap.sh")
    findings = adapter.normalize_results(
        [{"pluginid": "1", "alert": "x", "riskcode": "nonsense", "uri": "https://e/"}],
        target="https://example.com",
    )
    assert findings[0].severity == "info"
    assert findings[0].confidence == 0.5


def test_normalize_results_redacts_credentials():
    adapter = ZapAdapter(executable="zap.sh")
    items = adapter.parse_output(REDACTION_FIXTURE)
    findings = adapter.normalize_results(items, target="https://example.com")

    assert findings
    serialized = json.dumps([f.as_dict() for f in findings])
    assert "supersecret-token" not in serialized
    assert "[REDACTED]" in serialized


def test_output_file_returns_report_path():
    adapter = ZapAdapter(executable="zap.sh")
    cfg = AdapterConfig()
    cmd = adapter.build_command("https://example.com/", cfg)

    report_path = adapter.output_file(cmd, cfg)
    assert report_path is not None
    assert report_path == cmd[cmd.index("-quickout") + 1]
    assert report_path.endswith(".json")

    # Missing flag degrades gracefully to None (never raises).
    assert adapter.output_file(("zap.sh", "-cmd"), cfg) is None
    assert adapter.output_file(("zap.sh", "-quickout"), cfg) is None
