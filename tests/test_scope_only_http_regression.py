import json
import threading
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

from bugbounty.dashboard_api import DashboardHandler, DashboardState


def _multipart(fields: dict[str, str], files: dict[str, tuple[str, str, str]]) -> tuple[bytes, str]:
    boundary = "----bugbounty-regression"
    chunks: list[bytes] = []
    for name, value in fields.items():
        chunks.append(f"--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n".encode())
    for name, (filename, value, content_type) in files.items():
        chunks.append(f"--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"; filename=\"{filename}\"\r\nContent-Type: {content_type}\r\n\r\n{value}\r\n".encode())
    chunks.append(f"--{boundary}--\r\n".encode())
    return b"".join(chunks), f"multipart/form-data; boundary={boundary}"


def test_live_http_scope_only_validation_and_assessment_returns_200(tmp_path: Path):
    DashboardHandler.state = DashboardState()
    server = ThreadingHTTPServer(("127.0.0.1", 0), DashboardHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        burp_scope = json.dumps({"target": {"scope": {"include": [{"host": "*.rei.com", "protocol": "https", "port": 443, "path": "/api/*"}], "exclude": [{"host": "admin.rei.com", "protocol": "https", "port": 443, "path": "/api/*"}]}}})
        body, content_type = _multipart(
            {"program_rules": "# REI\nResearchers must use their own accounts."},
            {
                "scope_file": ("rei.csv", "identifier,asset_type,eligible\n*.rei.com,Wildcard,true\n", "text/csv"),
                "burp_file": ("rei_bbp-2026-09-16.json", burp_scope, "application/json"),
            },
        )
        request = urllib.request.Request(f"http://127.0.0.1:{server.server_port}/engagement/validate", data=body, headers={"Content-Type": content_type}, method="POST")
        with urllib.request.urlopen(request) as response:
            validation_status = response.status
            validation = json.loads(response.read())
        assert validation_status == 200
        assert validation["intersection"]["effective_scope"] == 1

        assessment_body = json.dumps({"workspace": str(tmp_path), "dry_run": True}).encode()
        assessment_request = urllib.request.Request(f"http://127.0.0.1:{server.server_port}/assessment/run", data=assessment_body, headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(assessment_request) as response:
            assessment_status = response.status
            result = json.loads(response.read())
        assert assessment_status == 200
        assert "at least one allowed host is required" not in json.dumps(result)
        assert result["endpoints"] == []
        assert result["findings"] == []
        assert result["evidence"] == []
        assert any("no Burp HTTP observations" in item for item in result["policy_warnings"])
    finally:
        server.shutdown()
        thread.join(timeout=2)
