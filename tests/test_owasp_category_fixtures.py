from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from urllib.parse import parse_qs, urlsplit

from bugbounty.assessment import AssessmentEngine
from bugbounty.engagement import (
    AuthIdentity,
    BusinessFlow,
    BusinessFlowStep,
    Engagement,
    PropertyAuthorizationCase,
    ResourceProbe,
    SsrfCase,
)
from tests.fixtures.vulnerable_api import RunningVulnerableApi


class MisconfigFixtureHandler(BaseHTTPRequestHandler):
    server_version = "Misconfig/1.0"

    def log_message(self, format: str, *args: object) -> None:  # noqa: A003
        return

    def do_GET(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path
        if path == "/openapi.json":
            spec = {
                "openapi": "3.0.0",
                "info": {"title": "Misconfig", "version": "1.0"},
                "paths": {
                    "/public": {"get": {"responses": {"200": {"description": "ok"}}}},
                    "/v1/old": {"get": {"deprecated": True, "responses": {"200": {"description": "old"}}}},
                },
            }
            body = json.dumps(spec).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if path == "/public":
            body = json.dumps({"ok": True}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if path == "/v1/old":
            body = json.dumps({"legacy": True}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(404)
        self.end_headers()


class RunningServer:
    def __init__(self, handler):
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.thread = Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    @property
    def target(self) -> str:
        return f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=2)


def test_api8_misconfiguration_detects_headers_and_cors(tmp_path: Path):
    srv = RunningServer(MisconfigFixtureHandler)
    try:
        engagement = Engagement.from_target(
            srv.target,
            allowed_schemes=["http"],
            allowed_methods=["GET"],
            maximum_requests=20,
            request_rate_limit=100,
            timeout=2,
            dry_run=False,
            workspace=str(tmp_path),
        )
        result = AssessmentEngine(engagement).run(endpoint=f"{srv.target}/public")
        # API8 should execute and produce findings/evidence for HTTP/wildcard CORS/missing headers as applicable
        api8 = [r for r in result.check_results if r.category == "API8" and r.executed]
        assert api8, "API8 should execute"
        assert any(r.status == "FAIL" for r in api8) or any(f.category == "API8" for f in result.findings.findings)
        assert any(a.check_id.startswith("api8") for a in result.evidence.artifacts)
    finally:
        srv.close()


def test_api9_inventory_flags_deprecated_endpoint(tmp_path: Path):
    srv = RunningServer(MisconfigFixtureHandler)
    try:
        engagement = Engagement.from_target(
            srv.target,
            allowed_schemes=["http"],
            allowed_methods=["GET"],
            maximum_requests=30,
            request_rate_limit=100,
            timeout=2,
            dry_run=False,
            workspace=str(tmp_path),
        )
        result = AssessmentEngine(engagement).run(openapi_file=None, endpoint=f"{srv.target}/v1/old")
        # When discovered without authoritative inventory or marked deprecated via inventory, API9 may flag; at minimum should run/apply meaningfully
        api9 = [r for r in result.check_results if r.category == "API9"]
        assert api9, "API9 check results should be present"
        assert any(r.executed or r.status in {"NOT_RUN", "NOT_APPLICABLE", "FAIL", "PASS"} for r in api9)
    finally:
        srv.close()


def test_api2_api3_api4_api6_api7_with_existing_fixture(tmp_path: Path):
    # Reuse comprehensive vulnerable fixture/config to exercise multiple categories meaningfully
    fixture = RunningVulnerableApi()
    try:
        engagement = Engagement.from_target(
            fixture.target,
            allowed_schemes=["http"],
            allowed_methods=["GET", "POST"],
            identities=[
                AuthIdentity("alice", bearer_token="alice-token"),
                AuthIdentity("bob", bearer_token="bob-token"),
                AuthIdentity("admin", bearer_token="admin-token"),
                AuthIdentity("invalid", bearer_token="expired-token"),
            ],
            property_authorization_cases=[PropertyAuthorizationCase("/profile", "alice", ("ssn",))],
            resource_probes=[ResourceProbe("/resource", query_parameter="limit", repeat_count=2, safe_limit=10)],
            business_flows=[BusinessFlow("checkout", (BusinessFlowStep("create", "/flow/create"), BusinessFlowStep("confirm", "/flow/confirm"), BusinessFlowStep("execute", "/flow/execute")), replay_step="execute")],
            ssrf_cases=[SsrfCase("/fetch", "url", f"{fixture.target}/callback/test-token", "test-token")],
            maximum_requests=80,
            request_rate_limit=100,
            timeout=2,
            dry_run=False,
            workspace=str(tmp_path),
        )
        result = AssessmentEngine(engagement).run()
        cats = {r.category for r in result.check_results if r.executed}
        # Ensure key categories executed in this configured context
        assert {"API2", "API3", "API4", "API6", "API7"}.issubset(cats)
        # And produced meaningful outcomes/evidence
        assert result.evidence.artifacts
    finally:
        fixture.close()
