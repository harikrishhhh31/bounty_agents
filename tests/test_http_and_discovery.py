from pathlib import Path

from bugbounty.discovery import ApiDiscovery
from bugbounty.engagement import AuthIdentity, Engagement
from bugbounty.http_client import HttpClient, redact_text
from tests.fixtures.vulnerable_api import RunningVulnerableApi


def test_http_client_executes_and_enforces_budget(tmp_path: Path):
    fixture = RunningVulnerableApi()
    try:
        engagement = Engagement.from_target(fixture.target, allowed_schemes=["http"], allowed_methods=["GET"], maximum_requests=1, request_rate_limit=100, dry_run=False, workspace=str(tmp_path))
        client = HttpClient(engagement)
        response = client.request("GET", fixture.target + "/openapi.json")
        assert response.status_code == 200
        assert response.request_id
        assert response.evidence_artifact_id
        exhausted = client.request("GET", fixture.target + "/openapi.json")
        assert exhausted.error == "maximum request budget exhausted"
    finally:
        fixture.close()


def test_dry_run_does_not_make_request():
    engagement = Engagement.from_target("https://example.com", dry_run=True)
    response = HttpClient(engagement).request("GET", "https://example.com/openapi.json")
    assert response.dry_run is True
    assert response.status_code is None


def test_openapi_discovery_normalizes_paths(tmp_path: Path):
    engagement = Engagement.from_target("https://example.com", workspace=str(tmp_path))
    document = {"openapi": "3.0.0", "paths": {"/items": {"get": {"parameters": [{"name": "limit", "in": "query"}], "responses": {"200": {"description": "ok"}}}}}}
    endpoints = ApiDiscovery(engagement, HttpClient(engagement)).from_openapi(document)
    assert endpoints[0].method == "GET"
    assert endpoints[0].path == "/items"
    assert endpoints[0].parameters[0]["name"] == "limit"


def test_credentials_are_not_exposed_in_response_body(tmp_path: Path):
    identity = AuthIdentity(name="tester", bearer_token="super-secret")
    engagement = Engagement.from_target("https://example.com", identities=[identity], workspace=str(tmp_path))
    client = HttpClient(engagement)
    assert redact_text("Authorization: super-secret", client._secrets) == "Authorization: [REDACTED]"
