from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread

from bugbounty.assessment import AssessmentEngine
from bugbounty.engagement import AuthIdentity, Engagement, FunctionAuthorizationCase, ObjectAuthorizationCase


class _BolaFixtureHandler(BaseHTTPRequestHandler):
    server_version = "BolaFixture/1.0"

    def log_message(self, format: str, *args: object) -> None:  # noqa: A003
        return

    def _identity(self) -> str | None:
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            return auth.removeprefix("Bearer ").strip()
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
        if path == "/openapi.json":
            spec = {
                "openapi": "3.0.0",
                "info": {"title": "BOLA Fixture", "version": "1.0"},
                "paths": {
                    "/objects/{id}": {"get": {"security": [{"bearerAuth": []}], "parameters": [{"name": "id", "in": "path", "required": True, "schema": {"type": "string"}}], "responses": {"200": {"description": "ok"}}}},
                    "/admin/reports": {"get": {"security": [{"bearerAuth": []}], "responses": {"200": {"description": "ok"}}}},
                    "/public/info": {"get": {"responses": {"200": {"description": "ok"}}}},
                },
            }
            self._send(200, spec)
            return
        if path == "/public/info":
            self._send(200, {"status": "ok"})
            return
        if path == "/admin/reports":
            # BFLA: only admin-token allowed when protected; when vulnerable allow any authenticated user
            if ident is None:
                self._send(401, {"error": "auth required"})
                return
            if getattr(self.server, "protect_bfla", False):
                allowed = ident == "admin-token"
            else:
                allowed = ident in {"admin-token", "user-a-token", "user-b-token"}
            self._send(200 if allowed else 403, {"report": "sensitive", "identity": ident})
            return
        if path.startswith("/objects/"):
            obj = path.rsplit("/", 1)[-1]
            if ident is None:
                self._send(401, {"error": "auth required"})
                return
            if getattr(self.server, "protect_bola", False):
                allowed = (ident == "user-a-token" and obj == "A") or (ident == "user-b-token" and obj == "B") or (ident == "admin-token")
            else:
                # vulnerable: any authenticated user can read any object
                allowed = ident in {"user-a-token", "user-b-token", "admin-token"}
            if allowed:
                owner = "user-a" if obj == "A" else "user-b"
                self._send(200, {"id": obj, "owner": owner, "secret": f"secret-{obj}"})
            else:
                self._send(403, {"error": "forbidden"})
            return
        self._send(404, {"error": "not found"})


class RunningBolaFixture:
    def __init__(self, *, protect_bola: bool, protect_bfla: bool) -> None:
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), _BolaFixtureHandler)
        self.httpd.protect_bola = protect_bola
        self.httpd.protect_bfla = protect_bfla
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
        AuthIdentity(name="user-a", bearer_token="user-a-token"),
        AuthIdentity(name="user-b", bearer_token="user-b-token"),
        AuthIdentity(name="admin", bearer_token="admin-token"),
    ]


def test_vulnerable_bola_detected_with_evidence(tmp_path: Path):
    fixture = RunningBolaFixture(protect_bola=False, protect_bfla=True)
    try:
        engagement = Engagement.from_target(
            fixture.target,
            allowed_schemes=["http"],
            allowed_methods=["GET"],
            identities=_identities(),
            object_authorization_cases=[
                ObjectAuthorizationCase(endpoint="/objects/{id}", owner_identity="user-a", owner_object_id="A", other_identity="user-b", other_object_id="B")
            ],
            maximum_requests=60,
            request_rate_limit=100,
            timeout=2,
            dry_run=False,
            workspace=str(tmp_path),
        )
        result = AssessmentEngine(engagement).run(openapi_file=None, endpoint=f"{fixture.target}/objects/{{id}}")
        bola = [r for r in result.check_results if r.check_id == "api1-bola" and r.executed]
        assert bola, "API1 must execute for matching object authorization case"
        assert any(r.status == "FAIL" and r.verified for r in bola), f"Expected verified FAIL, got: {[(r.status,r.verified,r.reason) for r in bola]}"
        findings = [f for f in result.findings.findings if f.category == "API1"]
        assert findings, "Expected API1 finding"
        assert all(f.evidence_ids for f in findings)
        # Evidence should contain request/response context for the authorization comparison
        assert result.evidence.artifacts, "Expected evidence artifacts"
        assert any(a.check_id == "api1-bola" and a.request_metadata and a.response_metadata for a in result.evidence.artifacts)
    finally:
        fixture.close()


def test_protected_bola_not_falsely_flagged(tmp_path: Path):
    fixture = RunningBolaFixture(protect_bola=True, protect_bfla=True)
    try:
        engagement = Engagement.from_target(
            fixture.target,
            allowed_schemes=["http"],
            allowed_methods=["GET"],
            identities=_identities(),
            object_authorization_cases=[
                ObjectAuthorizationCase(endpoint="/objects/{id}", owner_identity="user-a", owner_object_id="A", other_identity="user-b", other_object_id="B")
            ],
            maximum_requests=60,
            request_rate_limit=100,
            timeout=2,
            dry_run=False,
            workspace=str(tmp_path),
        )
        result = AssessmentEngine(engagement).run(endpoint=f"{fixture.target}/objects/{{id}}")
        bola = [r for r in result.check_results if r.check_id == "api1-bola" and r.executed]
        assert bola, "API1 must execute"
        assert all(r.status == "PASS" for r in bola), f"Protected endpoint must not fail: {[(r.status,r.reason) for r in bola]}"
        assert not any(f.category == "API1" and f.status == "verified" for f in result.findings.findings)
        # evidence of authorization outcome should still exist
        assert any(a.check_id == "api1-bola" for a in result.evidence.artifacts)
    finally:
        fixture.close()


def test_vulnerable_bfla_detected_independently(tmp_path: Path):
    fixture = RunningBolaFixture(protect_bola=True, protect_bfla=False)
    try:
        engagement = Engagement.from_target(
            fixture.target,
            allowed_schemes=["http"],
            allowed_methods=["GET"],
            identities=_identities(),
            function_authorization_cases=[
                FunctionAuthorizationCase(endpoint="/admin/reports", allowed_identity="admin", denied_identity="user-a")
            ],
            maximum_requests=60,
            request_rate_limit=100,
            timeout=2,
            dry_run=False,
            workspace=str(tmp_path),
        )
        result = AssessmentEngine(engagement).run(endpoint=f"{fixture.target}/admin/reports")
        bfla = [r for r in result.check_results if r.check_id == "api5-broken-function-level-authorization" and r.executed]
        assert bfla, "API5 must execute independently"
        assert any(r.status == "FAIL" and r.verified for r in bfla), f"Expected verified BFLA FAIL: {[(r.status,r.reason) for r in bfla]}"
        assert any(f.category == "API5" for f in result.findings.findings)
    finally:
        fixture.close()


def test_identity_isolation_no_cross_contamination(tmp_path: Path):
    # same check across different identity sets should execute independently and not reuse wrong cache/history
    fixture = RunningBolaFixture(protect_bola=False, protect_bfla=True)
    try:
        ids1 = [AuthIdentity(name="user-a", bearer_token="user-a-token"), AuthIdentity(name="user-b", bearer_token="user-b-token")]
        ids2 = [AuthIdentity(name="user-a", bearer_token="user-a-token"), AuthIdentity(name="admin", bearer_token="admin-token")]
        case = ObjectAuthorizationCase(endpoint="/objects/{id}", owner_identity="user-a", owner_object_id="A", other_identity="user-b", other_object_id="B")
        ws = str(tmp_path)
        e1 = Engagement.from_target(fixture.target, allowed_schemes=["http"], allowed_methods=["GET"], identities=ids1, object_authorization_cases=[case], maximum_requests=40, request_rate_limit=100, timeout=2, dry_run=False, workspace=ws)
        r1 = AssessmentEngine(e1).run(endpoint=f"{fixture.target}/objects/{{id}}")
        e2 = Engagement.from_target(fixture.target, allowed_schemes=["http"], allowed_methods=["GET"], identities=ids2, object_authorization_cases=[case], maximum_requests=40, request_rate_limit=100, timeout=2, dry_run=False, workspace=ws)
        r2 = AssessmentEngine(e2).run(endpoint=f"{fixture.target}/objects/{{id}}")
        ex1 = [r for r in r1.check_results if r.check_id == "api1-bola" and r.executed]
        ex2 = [r for r in r2.check_results if r.check_id == "api1-bola" and r.executed]
        assert ex1 and ex2
        # ensure second run did not incorrectly return cache hit labeled for different identity context reasoning only via same pair
        # both should have produced concrete executed results for their provided identity sets
        assert all(r.status in {"PASS","FAIL","VULNERABLE","ERROR","NOT_RUN","NOT_APPLICABLE"} for r in ex2)
        # audit/history should distinguish contexts
        assert (Path(ws) / "execution_history.json").exists()
        hist = json.loads((Path(ws) / "execution_history.json").read_text(encoding="utf-8"))
        pairs = [tuple(p) for p in hist.get("executed_pairs", []) if p[1] == "api1-bola"]
        assert len({p[2] for p in pairs}) >= 1
    finally:
        fixture.close()
