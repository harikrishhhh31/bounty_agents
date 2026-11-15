import json
from pathlib import Path

from bugbounty.assessment import AssessmentEngine
from bugbounty.discovery import ApiDiscovery
from bugbounty.engagement import AuthIdentity, Engagement, PropertyAuthorizationCase
from bugbounty.http_client import HttpClient
from bugbounty.reports import write_reports
from tests.fixtures.vulnerable_api import RunningVulnerableApi


class DuplicateOperationPath(dict):
    def items(self):
        operation = {"responses": {"200": {"description": "ok"}}}
        return [("get", operation), ("GET", operation)]


def test_zero_endpoint_assessment_writes_result_reports_and_audit(tmp_path: Path):
    spec = tmp_path / "empty-openapi.json"
    spec.write_text(json.dumps({"openapi": "3.0.0", "info": {"version": "1"}, "paths": {}}), encoding="utf-8")
    workspace = tmp_path / "assessment"
    engagement = Engagement.from_target("https://example.com", workspace=str(workspace), dry_run=True)

    result = AssessmentEngine(engagement).run(openapi_file=spec)
    paths = write_reports(result)

    assert result.endpoints == []
    assert result.check_results == []
    assert result.audit_log
    assert result.audit_log[0]["category"] == "DISCOVERY"
    assert result.audit_log[0]["reason"] == "zero endpoints discovered"
    assert all(path.exists() for path in paths.values())
    assert (workspace / "evidence.json").exists()
    assert (workspace / "findings.json").exists()
    assert (workspace / "audit.jsonl").read_text(encoding="utf-8").strip()


def test_authentication_transports_are_applied_and_redacted(tmp_path: Path):
    fixture = RunningVulnerableApi()
    identities = [
        AuthIdentity("bearer", bearer_token="bearer-secret"),
        AuthIdentity("header", api_key_header=("X-API-Key", "header-secret")),
        AuthIdentity("query", api_key_query=("api_key", "query-secret")),
        AuthIdentity("basic", basic_username="basic-user", basic_password="basic-secret"),
        AuthIdentity("custom", custom_headers={"X-Custom-Token": "custom-secret"}),
    ]
    try:
        engagement = Engagement.from_target(fixture.target, allowed_schemes=["http"], identities=identities, dry_run=False, workspace=str(tmp_path))
        client = HttpClient(engagement)
        for identity in identities:
            response = client.request("GET", f"{fixture.target}/auth-matrix", identity=identity.name)
            assert response.status_code == 200
            assert all(secret not in response.body for secret in ("bearer-secret", "header-secret", "query-secret", "basic-secret", "custom-secret"))
            assert all(secret not in response.url for secret in ("bearer-secret", "header-secret", "query-secret", "basic-secret", "custom-secret"))
    finally:
        fixture.close()


def test_api3_write_property_case_executes_configured_write(tmp_path: Path):
    fixture = RunningVulnerableApi()
    try:
        engagement = Engagement.from_target(
            fixture.target,
            allowed_schemes=["http"],
            allowed_methods=["GET", "PATCH"],
            identities=[AuthIdentity("alice", bearer_token="alice-token")],
            property_authorization_cases=[PropertyAuthorizationCase("/profile", "alice", ("ssn",), write_endpoint="/profile", write_method="PATCH")],
            maximum_requests=20,
            request_rate_limit=100,
            dry_run=False,
            workspace=str(tmp_path),
        )
        result = AssessmentEngine(engagement).run()
        api3 = next(item for item in result.check_results if item.check_id == "api3-property-authorization" and item.endpoint.endswith("/profile"))
        assert api3.status == "FAIL"
        assert any("write" in item.check_id for item in result.evidence.artifacts)
        assert all("alice-token" not in str(item.as_dict()) for item in result.evidence.artifacts)
    finally:
        fixture.close()


def test_discovery_supports_openapi3_swagger2_duplicates_inventory_and_deprecation(tmp_path: Path):
    engagement = Engagement.from_target("https://example.com", allowed_methods=["GET", "POST"], workspace=str(tmp_path))
    discovery = ApiDiscovery(engagement, HttpClient(engagement))
    openapi_endpoints = discovery.from_openapi({"openapi": "3.0.0", "info": {"version": "1"}, "paths": {"/items": DuplicateOperationPath(), "/old": {"get": {"deprecated": True, "responses": {"200": {}}}}}})
    swagger_endpoints = discovery.from_openapi({"swagger": "2.0", "info": {"version": "2"}, "schemes": ["https"], "host": "example.com", "basePath": "/v2", "paths": {"/items": {"post": {"parameters": [{"in": "body", "name": "body", "schema": {"type": "object"}}], "responses": {"200": {}}}}}})

    assert {(item.method, item.path) for item in openapi_endpoints} == {("GET", "/items"), ("GET", "/old")}
    assert openapi_endpoints[1].deprecated is True
    assert swagger_endpoints[0].url == "https://example.com/v2/items"
    assert swagger_endpoints[0].request_body_schema == {"type": "object"}


def test_discovery_filters_explicit_inventory_and_compares_supplied_paths(tmp_path: Path):
    engagement = Engagement.from_target("https://example.com", allowed_methods=["GET"], workspace=str(tmp_path))
    discovery = ApiDiscovery(engagement, HttpClient(engagement))
    endpoints = discovery.discover(endpoint_list=["https://example.com/items", "https://outside.example/items"])
    documented = [discovery.from_openapi({"openapi": "3.0.0", "paths": {"/items": {"get": {"responses": {}}}, "/missing": {"get": {"responses": {}}}}})[0]]
    comparison = discovery.compare_inventory(documented, ["https://example.com/items", "https://example.com/extra"])

    assert [item.path for item in endpoints] == ["/items"]
    assert comparison["undocumented"] == ["GET /extra"]
    assert comparison["missing_from_supplied"] == []


def test_api9_deprecated_operation_produces_evidence_backed_finding(tmp_path: Path):
    spec = tmp_path / "deprecated.json"
    spec.write_text(json.dumps({"openapi": "3.0.0", "info": {"version": "1"}, "paths": {"/old": {"get": {"deprecated": True, "responses": {"200": {}}}}}}), encoding="utf-8")
    engagement = Engagement.from_target("https://example.com", workspace=str(tmp_path / "assessment"), dry_run=True)

    result = AssessmentEngine(engagement).run(openapi_file=spec)

    assert any(finding.category == "API9" for finding in result.findings.findings)
    assert any(item.check_id == "api9-improper-inventory" for item in result.evidence.artifacts)


def test_api10_html_contract_produces_evidence_backed_finding(tmp_path: Path):
    fixture = RunningVulnerableApi()
    try:
        engagement = Engagement.from_target(fixture.target, allowed_schemes=["http"], allowed_methods=["GET"], maximum_requests=30, request_rate_limit=100, dry_run=False, workspace=str(tmp_path))
        result = AssessmentEngine(engagement).run()

        assert any(finding.category == "API10" for finding in result.findings.findings)
        assert any(item.check_id == "api10-unsafe-consumption" for item in result.evidence.artifacts)
    finally:
        fixture.close()