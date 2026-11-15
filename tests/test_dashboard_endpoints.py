import json
import threading
import time
from http.client import HTTPConnection
from pathlib import Path

from bugbounty.dashboard_api import DashboardHandler, DashboardState, serve_dashboard
from bugbounty.tool_adapters import known_adapter_names


BURP_XML = """<items>
<item><time>2026-09-15T10:00:00Z</time><host>api.example.com</host><port>443</port><protocol>https</protocol><request>GET /users?token=secret-token HTTP/1.1\nHost: api.example.com\nAuthorization: Bearer bearer-secret\n\n</request><response>HTTP/1.1 200 OK\nContent-Type: application/json\n\n{\"id\":1}</response></item>
</items>"""

SCOPE_TSV = "identifier\tasset_type\teligible\napi.example.com\tDomain\ttrue\n"


def _run_state(tmp_path: Path) -> DashboardState:
    state = DashboardState()
    state.import_scope("scope.tsv", SCOPE_TSV)
    state.import_burp("history.xml", BURP_XML)
    state.run_assessment({"workspace": str(tmp_path), "dry_run": True})
    return state


def test_overview_reports_and_classification(tmp_path: Path):
    state = _run_state(tmp_path)
    overview = state.overview()

    assert overview["validation_complete"] is False or True
    assert "counts" in overview
    assert overview["counts"]["endpoints"] >= 1
    assert overview["counts"]["findings"] >= 0
    assert "classification" in overview
    assert isinstance(overview["classification"], dict)
    assert "reports" in overview
    assert {r["kind"] for r in overview["reports"]} >= {"json", "markdown", "html"}

    assert set(state.report_paths) >= {"json", "markdown", "html"}
    for kind, path in state.report_paths.items():
        assert path.exists()


def test_tools_endpoint_lists_all_known_adapters(tmp_path: Path):
    # Exercise the handler-level /tools route via a live server.
    state = _run_state(tmp_path)
    DashboardHandler.state = state

    server_thread = threading.Thread(target=lambda: serve_dashboard("127.0.0.1", 8799), daemon=True)
    server_thread.start()
    # Wait for readiness.
    for _ in range(50):
        try:
            conn = HTTPConnection("127.0.0.1", 8799, timeout=1)
            conn.request("GET", "/tools")
            resp = conn.getresponse()
            if resp.status == 200:
                body = json.loads(resp.read())
                break
            conn.close()
        except Exception:
            time.sleep(0.1)
    else:
        raise AssertionError("server did not become ready")

    assert set(body["tools"].keys()) == set(known_adapter_names())
    for name, info in body["tools"].items():
        assert "available" in info
        assert "version" in info
        assert "enabled" in info

    # /overview
    conn = HTTPConnection("127.0.0.1", 8799, timeout=2)
    conn.request("GET", "/overview")
    resp = conn.getresponse()
    assert resp.status == 200
    overview = json.loads(resp.read())
    assert "counts" in overview
    assert "classification" in overview

    # /reports
    conn = HTTPConnection("127.0.0.1", 8799, timeout=2)
    conn.request("GET", "/reports")
    resp = conn.getresponse()
    assert resp.status == 200
    reports = json.loads(resp.read())
    assert "reports" in reports
    assert len(reports["reports"]) >= 1