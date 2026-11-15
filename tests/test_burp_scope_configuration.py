import json

import pytest

from bugbounty.dashboard_api import DashboardState
from bugbounty.importers import build_inventory, match_burp_scope, parse_burp_json_document, parse_hackerone_scope


RULES = "# REI\nResearchers must use their own accounts. Do not test third-party services."
SCOPE = "identifier,asset_type,eligible\n*.rei.com,Wildcard,true\nadmin.rei.com,Domain,false\nother.test,Domain,true\n"


def scope_json(include=None, exclude=None):
    return json.dumps({"target": {"scope": {"include": include or [], "exclude": exclude or []}}})


def rule(host, path="/"):
    return {"host": host, "protocol": "https", "port": 443, "path": path, "enabled": True}


def test_burp_scope_include_exclude_and_no_traffic():
    path = __import__("pathlib").Path(__import__("tempfile").mktemp(suffix=".json"))
    path.write_text(scope_json([rule("*.rei.com")], [rule("admin.rei.com")]), encoding="utf-8")
    try:
        configuration, exchanges = parse_burp_json_document(path)
    finally:
        path.unlink(missing_ok=True)
    assert len(configuration.include) == 1
    assert len(configuration.exclude) == 1
    assert exchanges == ()
    assert match_burp_scope("https://api.rei.com/users", configuration)
    assert not match_burp_scope("https://admin.rei.com/users", configuration)


def test_effective_scope_never_expands_hackerone_eligibility(tmp_path):
    scope_path = tmp_path / "scope.csv"
    scope_path.write_text(SCOPE, encoding="utf-8")
    burp_path = tmp_path / "scope.json"
    burp_path.write_text(scope_json([rule("*.rei.com")], [rule("admin.rei.com")]), encoding="utf-8")
    scope = parse_hackerone_scope(scope_path)
    burp_scope, exchanges = parse_burp_json_document(burp_path)
    inventory = build_inventory(exchanges, scope, burp_scope)
    assert inventory == ()
    state = DashboardState()
    result = state.validate_engagement(RULES, "scope.csv", SCOPE, "rei.json", burp_path.read_text(encoding="utf-8"))
    assert result["burp"]["include_rules"] == 1
    assert result["burp"]["exclude_rules"] == 1
    assert result["intersection"]["effective_scope"] == 1
    assert result["intersection"]["burp_observations"] == 0
    assert state.context is not None and state.context.burp_observations == ()


def test_malformed_burp_scope_json_is_rejected(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text(json.dumps({"target": {"scope": {"include": {"host": "*.rei.com"}, "exclude": []}}}), encoding="utf-8")
    with pytest.raises(ValueError, match="include/exclude rules must be arrays"):
        parse_burp_json_document(path)


def test_no_traffic_assessment_generates_no_fabricated_evidence(tmp_path):
    state = DashboardState()
    state.validate_engagement(RULES, "scope.csv", SCOPE, "rei.json", scope_json([rule("*.rei.com")], [rule("admin.rei.com")]))
    result = state.run_assessment({"workspace": str(tmp_path), "dry_run": True}, require_validation=True)
    assert result["endpoints"] == []
    assert result["findings"] == []
    assert result["evidence"] == []
