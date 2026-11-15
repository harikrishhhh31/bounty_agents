from pathlib import Path

import pytest

from bugbounty.cli import main
from bugbounty.config_loader import ConfigurationError, load_assessment_config


def test_yaml_config_loads_existing_engagement_cases(tmp_path: Path):
    config = tmp_path / "engagement.yaml"
    config.write_text(
        """
target_url: http://127.0.0.1:1234
allowed_hosts: [127.0.0.1]
allowed_schemes: [http]
allowed_methods: [GET, POST]
timeout: 2
request_rate_limit: 50
maximum_requests: 20
dry_run: true
workspace: ./assessment
identities:
  - name: alice
    bearer_token: secret-token
    custom_headers:
      X-Test: enabled
object_authorization_cases:
  - endpoint: /objects/{id}
    owner_identity: alice
    owner_object_id: A
    other_identity: bob
    other_object_id: B
property_authorization_cases:
  - endpoint: /profile
    identity: alice
    protected_properties: [ssn]
resource_probes:
  - endpoint: /resource
    query_parameter: limit
discovery:
  endpoint_list: [http://127.0.0.1:1234/profile]
""",
        encoding="utf-8",
    )

    loaded = load_assessment_config(config)

    assert loaded.engagement.target_url == "http://127.0.0.1:1234"
    assert loaded.engagement.identities[0].name == "alice"
    assert loaded.engagement.object_authorization_cases[0].owner_object_id == "A"
    assert loaded.engagement.property_authorization_cases[0].protected_properties == ("ssn",)
    assert loaded.discovery["endpoint_list"]


def test_json_config_loads_and_preserves_secret_redaction(tmp_path: Path):
    config = tmp_path / "engagement.json"
    config.write_text(
        '{"target_url":"https://example.com","allowed_hosts":["example.com"],"identities":[{"name":"api","bearer_token":"do-not-print"}]}',
        encoding="utf-8",
    )

    loaded = load_assessment_config(config)
    assert loaded.engagement.identities[0].bearer_token == "do-not-print"
    assert "do-not-print" not in str(loaded)


def test_config_validation_rejects_missing_scope(tmp_path: Path):
    config = tmp_path / "bad.yaml"
    config.write_text("target_url: https://example.com\n", encoding="utf-8")

    with pytest.raises(ConfigurationError, match="allowed_hosts"):
        load_assessment_config(config)


def test_config_validation_does_not_print_secret(tmp_path: Path, capsys):
    config = tmp_path / "bad.yaml"
    config.write_text("target_url: https://example.com\nallowed_hosts: [example.com]\nmaximum_requests: nope\nsecret: hidden-token\n", encoding="utf-8")

    assert main(["assess", "--config", str(config)]) == 2
    assert "hidden-token" not in capsys.readouterr().out
