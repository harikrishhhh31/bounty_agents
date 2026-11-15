import json
from pathlib import Path

import pytest

from bugbounty.importers import build_inventory, inventory_to_endpoints, parse_burp_json, parse_hackerone_scope
from bugbounty.policy import parse_program_markdown


def test_program_policy_extracts_deterministic_rules_and_preserves_manual_text():
    markdown = """# Acme Security

Researchers must use their own accounts. Do not test third-party services.
Denial of service and social engineering are prohibited.
Include a proof of concept and reproduction steps in reports.

Reports must not disclose vulnerabilities publicly before coordination.
Anything else requires manual review.
"""

    policy = parse_program_markdown(markdown, source="program.md")

    assert policy.program_name == "Acme Security"
    assert policy.own_accounts_only is True
    assert policy.third_party_restriction is True
    assert policy.dos_prohibited is True
    assert policy.social_engineering_prohibited is True
    assert policy.poc_requirement is True
    assert policy.disclosure_restrictions
    assert "Anything else requires manual review." in policy.manual_attention
    assert policy.raw_markdown_reference == "program.md"


def test_burp_json_parses_structured_history_and_redacts_secrets(tmp_path: Path):
    source = tmp_path / "burp.json"
    source.write_text(json.dumps({
        "items": [{
            "id": "req-1",
            "timestamp": "2026-09-16T10:00:00Z",
            "request": {
                "method": "GET",
                "url": "https://api.example.com/v1/users?token=secret",
                "headers": {"Authorization": "Bearer bearer-secret", "Cookie": "sid=secret"},
                "body": "password=body-secret",
            },
            "response": {"status": 200, "headers": {"Content-Type": "application/json"}, "body": "{\"ok\":true}"},
        }]
    }), encoding="utf-8")

    exchanges = parse_burp_json(source)

    assert len(exchanges) == 1
    exchange = exchanges[0]
    assert exchange.request.method == "GET"
    assert exchange.request.host == "api.example.com"
    assert exchange.response and exchange.response.status == 200
    serialized = json.dumps(exchange, default=lambda value: value.__dict__ if hasattr(value, "__dict__") else str(value))
    assert "secret" not in serialized
    assert "bearer-secret" not in serialized


def test_burp_json_project_metadata_without_traffic_is_rejected(tmp_path: Path):
    source = tmp_path / "project.json"
    source.write_text(json.dumps({"project": {"name": "Acme", "settings": {}}}), encoding="utf-8")

    with pytest.raises(ValueError, match="no HTTP traffic"):
        parse_burp_json(source)


def test_json_inventory_intersects_authoritative_scope(tmp_path: Path):
    scope_path = tmp_path / "scope.csv"
    scope_path.write_text("Asset Identifier,Asset Type,Eligible\n*.example.com,Wildcard,Yes\n", encoding="utf-8")
    burp_path = tmp_path / "burp.json"
    burp_path.write_text(json.dumps({"requests": [
        {"method": "GET", "url": "https://api.example.com/users", "response": {"status": 200}},
        {"method": "GET", "url": "https://third-party.test/users", "response": {"status": 200}},
    ]}), encoding="utf-8")

    scope = parse_hackerone_scope(scope_path)
    inventory = build_inventory(parse_burp_json(burp_path), scope)

    assert {item.scope_status for item in inventory} == {"IN_SCOPE", "OUT_OF_SCOPE"}
    assert len(inventory_to_endpoints(inventory)) == 1
