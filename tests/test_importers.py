import base64
import json
from dataclasses import asdict
from pathlib import Path

import pytest

from bugbounty.assessment import AssessmentEngine
from bugbounty.engagement import Engagement
from bugbounty.importers import build_inventory, inventory_to_endpoints, match_scope, parse_burp_xml, parse_hackerone_scope


def _burp_item(request: str, response: str, *, host: str = "api.example.com") -> str:
    encoded_request = base64.b64encode(request.encode()).decode()
    encoded_response = base64.b64encode(response.encode()).decode()
    return f"""<item><time>2026-09-15T10:00:00Z</time><host>{host}</host><port>443</port><protocol>https</protocol><request base64=\"true\">{encoded_request}</request><response base64=\"true\">{encoded_response}</response></item>"""


def test_hackerone_tsv_normalizes_assets_and_preserves_unsupported_rows(tmp_path: Path):
    source = tmp_path / "scope.tsv"
    source.write_text(
        "identifier\tasset_type\teligible_for_submission\tmax_severity\tinstruction\n"
        "*.example.com\tWILDCARD\ttrue\thigh\tAPI only\n"
        "https://api.example.com/v1\tURL\ttrue\tcritical\tUse GET\n"
        "10.0.0.0/8\tCIDR\tfalse\t\tPrivate\n"
        "mobile-app\tAndroid App\ttrue\tmedium\tPreserve this\n",
        encoding="utf-8",
    )

    scope = parse_hackerone_scope(source)

    assert [asset.normalized_identifier for asset in scope.assets] == ["example.com", "https://api.example.com/v1", "10.0.0.0/8", "mobile-app"]
    assert scope.assets[0].eligible is True
    assert scope.assets[0].max_severity == "high"
    assert scope.assets[-1].supported is False
    assert scope.assets[-1].source_metadata["instruction"] == "Preserve this"


def test_hackerone_csv_and_json_compatibility(tmp_path: Path):
    csv_path = tmp_path / "scope.csv"
    csv_path.write_text("Asset Identifier,Asset Type,Eligible\napi.example.com,Domain,Yes\n", encoding="utf-8")
    json_path = tmp_path / "scope.json"
    json_path.write_text(json.dumps({"assets": [{"identifier": "https://api.example.com", "asset_type": "URL", "eligible": True}]}), encoding="utf-8")

    assert parse_hackerone_scope(csv_path).assets[0].normalized_identifier == "api.example.com"
    assert parse_hackerone_scope(json_path).assets[0].asset_type == "url"


def test_burp_xml_parses_response_methods_query_and_redacts_secrets(tmp_path: Path):
    request = "GET /v1/users?token=query-secret&filter=active HTTP/1.1\r\nHost: api.example.com\r\nAuthorization: Bearer bearer-secret\r\nCookie: session=private\r\n\r\npassword=body-secret"
    response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"token\":\"body-secret\"}"
    source = tmp_path / "burp.xml"
    source.write_text(f"<items>{_burp_item(request, response)}</items>", encoding="utf-8")

    exchanges = parse_burp_xml(source)

    assert len(exchanges) == 1
    parsed = exchanges[0]
    assert parsed.request.method == "GET"
    assert parsed.request.path == "/v1/users"
    assert parsed.request.query_parameters["token"] == ["[REDACTED]"]
    assert parsed.request.headers["Authorization"] == "[REDACTED]"
    assert "bearer-secret" not in json.dumps(asdict(parsed))
    assert "body-secret" not in json.dumps(asdict(parsed))
    assert parsed.response.status == 200
    assert parsed.response.content_type == "application/json"


def test_inventory_deduplicates_requests_and_preserves_scope_status(tmp_path: Path):
    scope_path = tmp_path / "scope.tsv"
    scope_path.write_text("identifier\tasset_type\teligible\n*.example.com\tWildcard\ttrue\n", encoding="utf-8")
    burp_path = tmp_path / "burp.xml"
    request = "GET /users/1?filter=active HTTP/1.1\r\nHost: api.example.com\r\n\r\n"
    response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}"
    burp_path.write_text(f"<items>{_burp_item(request, response)}{_burp_item(request, response)}{_burp_item(request, response, host='outside.example')}</items>", encoding="utf-8")

    scope = parse_hackerone_scope(scope_path)
    inventory = build_inventory(parse_burp_xml(burp_path), scope)

    in_scope = next(item for item in inventory if item.host == "api.example.com")
    out_scope = next(item for item in inventory if item.host == "outside.example")
    assert in_scope.observation_count == 2
    assert in_scope.scope_status == "IN_SCOPE"
    assert out_scope.scope_status == "OUT_OF_SCOPE"
    assert in_scope.status_codes == (200,)


def test_scope_match_preserves_unsupported_status(tmp_path: Path):
    source = tmp_path / "scope.tsv"
    source.write_text("identifier\tasset_type\teligible\nAndroid app\tAndroid App\ttrue\n", encoding="utf-8")
    scope = parse_hackerone_scope(source)

    assert match_scope("https://api.example.com/users", scope)[0] == "OUT_OF_SCOPE"
    assert scope.assets[0].supported is False


def test_native_burp_project_is_rejected(tmp_path: Path):
    source = tmp_path / "project.burp"
    source.write_bytes(b"private project data")

    with pytest.raises(ValueError, match="private/unsupported"):
        parse_burp_xml(source)


def test_malformed_and_oversized_imports_are_rejected(tmp_path: Path):
    malformed = tmp_path / "malformed.xml"
    malformed.write_text("<items><item>", encoding="utf-8")
    with pytest.raises(ValueError, match="could not parse"):
        parse_burp_xml(malformed)

    oversized = tmp_path / "oversized.tsv"
    with oversized.open("w", encoding="utf-8") as handle:
        handle.truncate(50 * 1024 * 1024 + 1)
    with pytest.raises(ValueError, match="50 MB"):
        parse_hackerone_scope(oversized)


def test_only_in_scope_inventory_reaches_existing_assessment_engine(tmp_path: Path):
    scope_path = tmp_path / "scope.tsv"
    scope_path.write_text("identifier\tasset_type\teligible\napi.example.com\tDomain\ttrue\n", encoding="utf-8")
    burp_path = tmp_path / "burp.xml"
    request = "GET /users HTTP/1.1\r\nHost: api.example.com\r\n\r\n"
    response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}"
    burp_path.write_text(f"<items>{_burp_item(request, response)}{_burp_item(request, response, host='outside.example')}</items>", encoding="utf-8")
    scope = parse_hackerone_scope(scope_path)
    exchanges = parse_burp_xml(burp_path)
    inventory = build_inventory(exchanges, scope)

    engagement = Engagement.from_target("https://api.example.com", workspace=str(tmp_path / "assessment"), dry_run=True)
    result = AssessmentEngine(engagement).run(endpoint_inventory=inventory_to_endpoints(inventory), imported_exchanges=exchanges)

    assert len(result.endpoints) == 1
    assert result.endpoints[0].url == "https://api.example.com/users"
    assert len([item for item in result.evidence.artifacts if item.check_id == "burp-import"]) == 2
    evidence_blob = json.dumps([item.as_dict() for item in result.evidence.artifacts])
    assert "outside.example" in evidence_blob
    assert "api.example.com/users" in evidence_blob


def test_existing_safety_policy_filters_direct_inventory_injection(tmp_path: Path):
    scope_path = tmp_path / "scope.tsv"
    scope_path.write_text("identifier\tasset_type\teligible\napi.example.com\tDomain\ttrue\n", encoding="utf-8")
    burp_path = tmp_path / "burp.xml"
    request = "GET /users HTTP/1.1\r\nHost: api.example.com\r\n\r\n"
    response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}"
    burp_path.write_text(f"<items>{_burp_item(request, response)}</items>", encoding="utf-8")
    scope = parse_hackerone_scope(scope_path)
    inventory = build_inventory(parse_burp_xml(burp_path), scope)
    in_scope = inventory_to_endpoints(inventory)
    from bugbounty.discovery import Endpoint

    engagement = Engagement.from_target("https://api.example.com", workspace=str(tmp_path / "assessment"), dry_run=True)
    result = AssessmentEngine(engagement).run(endpoint_inventory=(*in_scope, Endpoint("GET", "https://outside.example/admin", "/admin")))

    assert [item.url for item in result.endpoints] == ["https://api.example.com/users"]
