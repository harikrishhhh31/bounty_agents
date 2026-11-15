from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread

from bugbounty.assessment import AssessmentEngine
from bugbounty.engagement import AuthIdentity, Engagement, FunctionAuthorizationCase, ObjectAuthorizationCase


class _BflaFixtureHandler(BaseHTTPRequestHandler):
    server_version = "BflaFixture/1.0"

    def log_message(self, format: str, *args: object) -> None:  # noqa: A003
        return

    def _identity(self) -> str | None:
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            return auth.removeprefix("Bearer ").strip() or None
        return None

    def _send(self, status: int, payload: dict[str, object]) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        path = self.path.split("?", 1)[0]
        ident = self._identity()

        if path == "/admin/reports":
            if ident is None:
                self._send(401, {"error": "authentication required"})
                return
            if getattr(self.server, "protect_bfla", False):
                allowed = ident == "admin-token"
            else:
                # Vulnerable: any authenticated user can access privileged function
                allowed = ident in {"admin-token", "user-token"}
            if allowed:
                self._send(200, {"report": "sensitive-admin-report", "identity": ident})
            else:
                self._send(403, {"error": "forbidden", "identity": ident})
            return

        if path.startswith("/objects/"):
            obj = path.rsplit("/", 1)[-1]
            if ident is None:
                self._send(401, {"error": "authentication required"})
                return
            if getattr(self.server, "protect_bola", False):
                allowed = (ident == "user-token" and obj == "A") or (ident == "admin-token")
            else:
                allowed = ident in {"user-token", "admin-token"}
            if allowed:
                self._send(200, {"id": obj, "owner": "user" if obj == "A" else "other"})
            else:
                self._send(403, {"error": "forbidden"})
            return

        self._send(404, {"error": "not found"})


class RunningBflaFixture:
    def __init__(self, *, protect_bfla: bool, protect_bola: bool = True) -> None:
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), _BflaFixtureHandler)
        self.httpd.protect_bfla = protect_bfla
        self.httpd.protect_bola = protect_bola
        self.thread = Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    @property
    def target(self) -> str:
        host, port = self.httpd.server_address
        return f"http://{host}:{port}"

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=2)


def _identities() -> list[AuthIdentity]:
    return [
        AuthIdentity(name="admin", bearer_token="admin-token"),
        AuthIdentity(name="user", bearer_token="user-token"),
    ]


def test_protected_bfla_not_falsely_flagged(tmp_path: Path):
    """Properly protected function-level authorization must not produce a false positive."""
    fixture = RunningBflaFixture(protect_bfla=True)
    try:
        engagement = Engagement.from_target(
            fixture.target,
            allowed_schemes=["http"],
            allowed_methods=["GET"],
            identities=_identities(),
            function_authorization_cases=[
                FunctionAuthorizationCase(endpoint="/admin/reports", allowed_identity="admin", denied_identity="user")
            ],
            maximum_requests=40,
            request_rate_limit=100,
            timeout=2,
            dry_run=False,
            workspace=str(tmp_path),
        )
        result = AssessmentEngine(engagement).run(endpoint=f"{fixture.target}/admin/reports")

        bfla = [r for r in result.check_results if r.check_id == "api5-broken-function-level-authorization"]
        executed = [r for r in bfla if r.executed]
        assert executed, "API5 must execute for a matching protected function authorization case"
        assert all(r.status == "PASS" for r in executed), (
            f"Protected BFLA must not be flagged: {[(r.status, r.reason, r.verified) for r in executed]}"
        )
        assert all(not r.verified for r in executed), "Protected BFLA must not be marked verified vulnerable"
        assert not any(
            f.category == "API5" and f.status in {"verified", "candidate"}
            for f in result.findings.findings
        ), "No confirmed/probable API5 finding expected for properly protected endpoint"

        # Evidence must show correct authorization outcome: allowed succeeds, denied rejected
        bfla_evidence = [a for a in result.evidence.artifacts if a.check_id == "api5-broken-function-level-authorization"]
        assert bfla_evidence, "Expected API5 evidence for protected authorization comparison"
        assert any(
            "allowed=200" in a.actual_behavior and "denied=403" in a.actual_behavior
            for a in bfla_evidence
        ), f"Expected evidence of correct auth outcome (allowed=200, denied=403), got: {[a.actual_behavior for a in bfla_evidence]}"
        assert any(
            a.request_metadata.get("identity") == "user" or "denied role user" in a.observation.lower()
            for a in bfla_evidence
        )
    finally:
        fixture.close()


def test_vulnerable_bfla_detected_with_evidence(tmp_path: Path):
    """Vulnerable function-level authorization must still be detected with evidence."""
    fixture = RunningBflaFixture(protect_bfla=False)
    try:
        engagement = Engagement.from_target(
            fixture.target,
            allowed_schemes=["http"],
            allowed_methods=["GET"],
            identities=_identities(),
            function_authorization_cases=[
                FunctionAuthorizationCase(endpoint="/admin/reports", allowed_identity="admin", denied_identity="user")
            ],
            maximum_requests=40,
            request_rate_limit=100,
            timeout=2,
            dry_run=False,
            workspace=str(tmp_path),
        )
        result = AssessmentEngine(engagement).run(endpoint=f"{fixture.target}/admin/reports")

        bfla = [r for r in result.check_results if r.check_id == "api5-broken-function-level-authorization" and r.executed]
        assert bfla, "API5 must execute for matching vulnerable function authorization case"
        assert any(r.status == "FAIL" and r.verified for r in bfla), (
            f"Expected verified FAIL for vulnerable BFLA, got: {[(r.status, r.verified, r.reason) for r in bfla]}"
        )
        findings = [f for f in result.findings.findings if f.category == "API5"]
        assert findings, "Expected API5 finding for vulnerable BFLA"
        assert any(f.status == "verified" and f.evidence_ids for f in findings)

        bfla_evidence = [a for a in result.evidence.artifacts if a.check_id == "api5-broken-function-level-authorization"]
        assert bfla_evidence, "Expected API5 evidence artifacts"
        assert any("allowed=200" in a.actual_behavior and "denied=200" in a.actual_behavior for a in bfla_evidence)
    finally:
        fixture.close()


def test_bola_bfla_independence_and_scope_sanity(tmp_path: Path):
    """BOLA and BFLA checks remain independent; scope restrictions prevent out-of-scope execution."""
    # Protected BFLA + vulnerable BOLA in same configured assessment
    fixture = RunningBflaFixture(protect_bfla=True, protect_bola=False)
    try:
        engagement = Engagement.from_target(
            fixture.target,
            allowed_schemes=["http"],
            allowed_methods=["GET"],
            identities=_identities(),
            object_authorization_cases=[
                ObjectAuthorizationCase(endpoint="/objects/{id}", owner_identity="user", owner_object_id="A", other_identity="admin", other_object_id="B")
            ],
            function_authorization_cases=[
                FunctionAuthorizationCase(endpoint="/admin/reports", allowed_identity="admin", denied_identity="user")
            ],
            maximum_requests=80,
            request_rate_limit=100,
            timeout=2,
            dry_run=False,
            workspace=str(tmp_path),
        )
        # Run both endpoints in scope of this assessment target
        result_admin = AssessmentEngine(engagement).run(endpoint=f"{fixture.target}/admin/reports")
        bfla = [r for r in result_admin.check_results if r.check_id == "api5-broken-function-level-authorization" and r.executed]
        assert bfla and all(r.status == "PASS" for r in bfla), "Protected BFLA must remain PASS independently"

        result_obj = AssessmentEngine(engagement).run(endpoint=f"{fixture.target}/objects/{{id}}")
        bola = [r for r in result_obj.check_results if r.check_id == "api1-bola" and r.executed]
        assert any(r.status == "FAIL" for r in bola), "Vulnerable BOLA must still be detectable independently of BFLA result"
    finally:
        fixture.close()

    # Scope/identity isolation sanity: out-of-scope host must not be requested
    scoped = Engagement.from_target(
        "http://127.0.0.1",
        allowed_schemes=["http"],
        allowed_methods=["GET"],
        identities=_identities(),
        function_authorization_cases=[FunctionAuthorizationCase("/admin/reports", "admin", "user")],
        maximum_requests=20,
        request_rate_limit=100,
        timeout=2,
        dry_run=False,
        workspace=str(tmp_path / "scope"),
    )
    from bugbounty.http_client import HttpClient

    response = HttpClient(scoped).request("GET", "http://127.0.0.2/admin/reports", identity="admin")
    assert response.status_code is None
    assert response.error and "scope" in response.error.lower()
    assert HttpClient(scoped).requests_made == 0
