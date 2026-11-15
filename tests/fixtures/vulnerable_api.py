from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from urllib.parse import parse_qs, urlsplit


OPENAPI = {
    "openapi": "3.0.0",
    "info": {"title": "Local Vulnerable API", "version": "1.0"},
    "paths": {
        "/auth-required": {"get": {"responses": {"200": {"description": "protected"}}, "security": [{"bearerAuth": []}]}},
        "/objects/{id}": {"get": {"parameters": [{"name": "id", "in": "path", "required": True}], "responses": {"200": {"description": "object"}}, "security": [{"bearerAuth": []}]}},
        "/admin": {"get": {"responses": {"200": {"description": "admin"}}, "security": [{"bearerAuth": []}]}},
        "/profile": {"get": {"responses": {"200": {"description": "profile"}}, "security": [{"bearerAuth": []}]}},
        "/resource": {"get": {"parameters": [{"name": "limit", "in": "query"}], "responses": {"200": {"description": "paged"}}}},
        "/fetch": {"get": {"parameters": [{"name": "url", "in": "query", "required": True}], "responses": {"200": {"description": "fetch result"}}}},
        "/html-contract": {"get": {"responses": {"200": {"description": "HTML response"}}}},
        "/flow/create": {"post": {"responses": {"200": {"description": "created"}}}},
        "/flow/confirm": {"post": {"responses": {"200": {"description": "confirmed"}}}},
        "/flow/execute": {"post": {"responses": {"200": {"description": "executed"}}}},
    },
}


class VulnerableApiHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        parsed = urlsplit(self.path)
        identity = self.headers.get("Authorization", "").removeprefix("Bearer ")
        if self.path == "/openapi.json":
            self._send(200, OPENAPI, cors=True)
            return
        if parsed.path == "/auth-required":
            self._send(200, {"authenticated": bool(identity)}, cors=True)
            return
        if parsed.path.startswith("/objects/"):
            object_id = parsed.path.rsplit("/", 1)[-1]
            allowed = identity in {"alice-token", "bob-token", "admin-token"}
            if getattr(self.server, "enforce_object_ownership", False):
                allowed = (identity == "alice-token" and object_id == "A") or (identity == "bob-token" and object_id == "B")
            self._send(200 if allowed else 403, {"id": object_id, "owner": "alice" if object_id == "A" else "bob", "value": "fixture"}, cors=True)
            return
        if parsed.path == "/admin":
            self._send(200 if identity in {"admin-token", "alice-token"} else 403, {"admin": identity == "admin-token"}, cors=True)
            return
        if parsed.path == "/profile":
            self._send(200 if identity in {"alice-token", "bob-token", "admin-token"} else 401, {"id": "A", "email": "alice@example.test", "ssn": "000-00-0000", "role": "user"}, cors=True)
            return
        if parsed.path == "/resource":
            limit = int(parse_qs(parsed.query).get("limit", ["1"])[0])
            self._send(200, {"items": min(limit, 10), "limit": limit}, cors=True)
            return
        if parsed.path == "/fetch":
            target = parse_qs(parsed.query).get("url", [""])[0]
            callback_token = target.rsplit("/callback/", 1)[-1] if "/callback/" in target else ""
            self._send(200, {"status": "accepted", "callback_token": callback_token}, cors=True)
            return
        if parsed.path == "/html-contract":
            body = b"<html><body>unexpected upstream content</body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if parsed.path == "/auth-matrix":
            self._send(200, {"authorization": self.headers.get("Authorization", ""), "api_key": self.headers.get("X-API-Key", ""), "query_key": parse_qs(parsed.query).get("api_key", [""])[0], "custom": self.headers.get("X-Custom-Token", "")}, cors=True)
            return
        self._send(404, {"error": "not found"}, cors=True)

    def do_POST(self) -> None:
        if self.path in {"/flow/create", "/flow/confirm", "/flow/execute"}:
            self._send(200, {"step": self.path, "executed": True}, cors=True)
            return
        self._send(404, {"error": "not found"}, cors=True)

    def do_PATCH(self) -> None:
        if self.path == "/profile":
            self._send(200, {"updated": True, "ssn": "000-00-0000"}, cors=True)
            return
        self._send(404, {"error": "not found"}, cors=True)

    def log_message(self, format: str, *args: object) -> None:
        return

    def _send(self, status: int, payload: dict[str, object], *, cors: bool = False) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        if cors:
            self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class RunningVulnerableApi:
    def __init__(self, *, enforce_object_ownership: bool = False) -> None:
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), VulnerableApiHandler)
        self.server.enforce_object_ownership = enforce_object_ownership
        self.thread = Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    @property
    def target(self) -> str:
        return f"http://127.0.0.1:{self.server.server_port}"

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
