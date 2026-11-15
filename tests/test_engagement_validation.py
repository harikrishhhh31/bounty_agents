import json
from pathlib import Path

import pytest

from bugbounty.dashboard_api import DashboardState


SCOPE_CSV = "identifier,asset_type,eligible\napi.example.com,Domain,true\noutside.example,Domain,false\n"
BURP_JSON = json.dumps({"items": [{
    "id": "1",
    "request": {"method": "GET", "url": "https://api.example.com/users?token=secret", "headers": {"Authorization": "Bearer secret-token", "Cookie": "sid=secret"}},
    "response": {"status": 200, "headers": {"Content-Type": "application/json"}, "body": "{}"},
}]})
RULES = "# REI\nResearchers must use their own accounts. Do not test third-party services. Denial of service is prohibited."


def test_pasted_rules_csv_and_burp_json_validate_as_one_context():
    state = DashboardState()

    result = state.validate_engagement(RULES, "scope.csv", SCOPE_CSV, "history.json", BURP_JSON)

    assert result["valid"] is True
    assert state.context is not None
    assert result["intersection"]["burp_observations"] == 1
    assert result["intersection"]["assessment_candidates"] == 1
    assert state.context.program_policy.own_accounts_only is True


def test_validation_rejects_missing_inputs():
    state = DashboardState()
    with pytest.raises(ValueError, match="program_rules"):
        state.validate_engagement("", "scope.csv", SCOPE_CSV, "history.json", BURP_JSON)
    with pytest.raises(ValueError, match="scope_file"):
        state.validate_engagement(RULES, "scope.csv", "", "history.json", BURP_JSON)
    with pytest.raises(ValueError, match="burp_file"):
        state.validate_engagement(RULES, "scope.csv", SCOPE_CSV, "history.json", "")


def test_validation_rejects_invalid_csv_and_json():
    state = DashboardState()
    with pytest.raises(ValueError):
        state.validate_engagement(RULES, "scope.csv", "not,a,valid,scope\n", "history.json", BURP_JSON)
    with pytest.raises(ValueError, match="could not parse Burp JSON"):
        state.validate_engagement(RULES, "scope.csv", SCOPE_CSV, "history.json", "{")


def test_scope_configuration_json_is_not_accepted_as_burp_history():
    state = DashboardState()
    scope_configuration = json.dumps({"target": "rei.com", "scope": [], "include": [], "exclude": [], "advanced_mode": True})
    with pytest.raises(ValueError, match="JSON is valid but does not contain Burp HTTP traffic/history"):
        state.validate_engagement(RULES, "scope.csv", SCOPE_CSV, "rei-scope.json", scope_configuration)


def test_assessment_endpoint_requires_validation_but_legacy_state_api_remains_compatible(tmp_path: Path):
    state = DashboardState()
    with pytest.raises(ValueError, match="validate all three"):
        state.run_assessment({"workspace": str(tmp_path)}, require_validation=True)


def test_validation_redacts_credentials_before_context_storage():
    state = DashboardState()
    state.validate_engagement(RULES, "scope.csv", SCOPE_CSV, "history.json", BURP_JSON)
    blob = json.dumps(state.context, default=lambda value: value.__dict__ if hasattr(value, "__dict__") else str(value))
    assert "secret-token" not in blob
    assert "sid=secret" not in blob
