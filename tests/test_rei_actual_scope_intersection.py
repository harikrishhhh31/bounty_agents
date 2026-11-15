import json

from bugbounty.dashboard_api import DashboardState
from bugbounty.importers import parse_burp_json_document, parse_hackerone_scope


REI_RULES = "# REI\nResearchers must use their own accounts."

# Byte-equivalent structure for the supplied REI scope export and Burp scope export.
REI_SCOPE_CSV = """Asset Identifier,Asset Type,Eligible for Submission,Max Severity
rei.com,URL,Yes,Critical
login.rei.com,URL,Yes,Critical
http://www.rei.com/learn/expert-advice,URL,Yes,High
http://collaboration.rei.com,URL,Yes,High
rei.jobs,Domain,No,
reifund.org,Domain,No,
destinations.rei.com,Domain,No,
partners2.rei.com,Domain,No,
greenvestrentals.rei.com,Domain,No,
reicasting.com,Domain,No,
engineering.rei.com,Domain,No,
test-login.rei.com,Domain,No,
*.rentals.rei.com,Wildcard,No,
wpvip.rei.com,Domain,No,
vpn.rei.com,Domain,No,
desktop.rei.com,Domain,No,
foryourbenefit-rei.com,Domain,No,
rei.gladly.com,Domain,No,
/used,URL,No,
/blog,URL,No,
/rentals,URL,No,
/rei-garage,URL,No,
/lists,URL,No,
cloud.rei.com,OTHER,Yes,
REI Android App,OTHER,Yes,
"""

REI_BURP_SCOPE_JSON = json.dumps({"target": {"scope": {
    "include": [
        {"enabled": True, "protocol": "http", "host": "^rei\\.com$", "port": "80", "file": "^/.*"},
        {"enabled": True, "protocol": "https", "host": "^rei\\.com$", "port": "443", "file": "^/.*"},
        {"enabled": True, "protocol": "http", "host": "^login\\.rei\\.com$", "port": "80", "file": "^/.*"},
        {"enabled": True, "protocol": "https", "host": "^login\\.rei\\.com$", "port": "443", "file": "^/.*"},
        {"enabled": True, "protocol": "http", "host": "^www\\.rei\\.com$", "port": "80", "file": "^/learn/expert-advice.*"},
        {"enabled": True, "protocol": "http", "host": "^collaboration\\.rei\\.com$", "port": "80", "file": "^/.*"},
    ],
    "exclude": [
        {"enabled": True, "protocol": "https", "host": "^login\\.rei\\.com$", "port": "443", "file": "^/admin.*"},
        {"enabled": True, "protocol": "http", "host": "^www\\.rei\\.com$", "port": "80", "file": "^/blog.*"},
    ],
}}})


def test_actual_rei_assets_and_burp_regex_rules_produce_non_empty_effective_scope(tmp_path):
    scope_path = tmp_path / "scopes_for_rei_bbp_at_2026-09-16_05_18_15.csv"
    burp_path = tmp_path / "rei_bbp-2026-09-16.json"
    scope_path.write_text(REI_SCOPE_CSV, encoding="utf-8")
    burp_path.write_text(REI_BURP_SCOPE_JSON, encoding="utf-8")

    scope = parse_hackerone_scope(scope_path)
    burp_scope, observations = parse_burp_json_document(burp_path)

    eligible_web = [asset for asset in scope.assets if asset.eligible and asset.asset_type == "url"]
    assert [(asset.normalized_identifier, asset.asset_type) for asset in eligible_web] == [
        ("rei.com", "url"),
        ("login.rei.com", "url"),
        ("http://www.rei.com/learn/expert-advice", "url"),
        ("http://collaboration.rei.com/", "url"),
    ]
    assert len(burp_scope.include) == 6
    assert burp_scope.include[0].host == "^rei\\.com$"
    assert burp_scope.include[0].path == "^/.*"
    assert observations == ()

    state = DashboardState()
    validation = state.validate_engagement(REI_RULES, scope_path.name, REI_SCOPE_CSV, burp_path.name, REI_BURP_SCOPE_JSON)

    assert validation["intersection"]["effective_scope"] == 4
    assert validation["intersection"]["burp_observations"] == 0
    result = state.run_assessment({"workspace": str(tmp_path / "assessment"), "dry_run": True}, require_validation=True)
    assert result["endpoints"] == []
    assert result["findings"] == []
    assert result["evidence"] == []
    assert any("no Burp HTTP observations" in warning for warning in result["policy_warnings"])

    excluded = {"rei.jobs", "reifund.org", "destinations.rei.com", "partners2.rei.com", "greenvestrentals.rei.com", "reicasting.com", "engineering.rei.com", "test-login.rei.com", "rentals.rei.com", "wpvip.rei.com", "vpn.rei.com", "desktop.rei.com", "foryourbenefit-rei.com", "rei.gladly.com"}
    assert not any(asset.eligible and asset.normalized_identifier in excluded for asset in scope.assets)
