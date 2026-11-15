from __future__ import annotations

import hmac
import json
import html
import os
import tempfile
from dataclasses import asdict, dataclass
from email.parser import BytesParser
from email.policy import default
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit
from uuid import uuid4

from .assessment import AssessmentEngine, AssessmentResult
from .attack_surface_graph import AttackSurfaceGraph
from .engagement import Engagement
from .importers import BurpExchange, BurpScopeConfiguration, build_inventory, inventory_to_endpoints, match_burp_scope, match_burp_scope_host, match_scope, parse_burp_json, parse_burp_json_document, parse_burp_xml, parse_hackerone_scope
from .policy import ProgramPolicy, parse_program_markdown
from .reports import report_data, write_reports
from .checks import default_checks


def _configured_dashboard_token() -> str | None:
    token = os.getenv("BUGBOUNTY_DASHBOARD_TOKEN")
    if token and token.strip():
        return token.strip()
    token_file = os.getenv("BUGBOUNTY_DASHBOARD_TOKEN_FILE")
    if token_file:
        try:
            value = Path(token_file).read_text(encoding="utf-8").strip()
            return value or None
        except OSError:
            return None
    return None



@dataclass(frozen=True, slots=True)
class EngagementContext:
    program_policy: ProgramPolicy
    hackerone_scope: Any
    burp_scope: BurpScopeConfiguration
    burp_observations: tuple[BurpExchange, ...]


class DashboardState:
    def __init__(self) -> None:
        self.program: ProgramPolicy | None = None
        self.scope = None
        self.exchanges: tuple[BurpExchange, ...] = ()
        self.burp_scope = BurpScopeConfiguration()
        self.inventory = ()
        self.result: AssessmentResult | None = None
        self.report_paths: dict[str, Path] = {}
        self.workspace = Path("./dashboard-output")
        self.context: EngagementContext | None = None
        self.validation_complete = False

    def validate_engagement(self, program_rules: str, scope_filename: str, scope_content: str, burp_filename: str, burp_content: str) -> dict[str, Any]:
        if not program_rules.strip():
            raise ValueError("program_rules is required and cannot be empty")
        if not scope_content.strip():
            raise ValueError("scope_file is required and cannot be empty")
        if not burp_content.strip():
            raise ValueError("burp_file is required and cannot be empty")
        if Path(scope_filename).suffix.lower() != ".csv":
            raise ValueError("scope_file must be a CSV file")
        if Path(burp_filename).suffix.lower() != ".json":
            raise ValueError("burp_file must be a JSON file")
        self.program = parse_program_markdown(program_rules, source="pasted program rules")
        self.scope = self._parse_temporary(scope_filename, scope_content, parse_hackerone_scope)
        self.burp_scope, self.exchanges = self._parse_temporary(burp_filename, burp_content, parse_burp_json_document)
        self.inventory = build_inventory(self.exchanges, self.scope, self.burp_scope)
        self.context = EngagementContext(self.program, self.scope, self.burp_scope, self.exchanges)
        self.result = None
        self.report_paths = {}
        self.validation_complete = True
        summary = self.intersection_summary()
        return {"valid": True, "program": self.program.as_dict(), "scope": {"assets": [asdict(item) for item in self.scope.assets], "metadata": self.scope.metadata}, "burp": {"requests": len(self.exchanges), "format": "json", "scope_configuration": bool(self.burp_scope.rule_count), "include_rules": len(self.burp_scope.include), "exclude_rules": len(self.burp_scope.exclude)}, "intersection": summary}

    def _parse_temporary(self, filename: str, content: str, parser: Any) -> Any:
        path = _temporary_input(filename, content)
        try:
            return parser(path)
        finally:
            path.unlink(missing_ok=True)

    def import_program(self, filename: str, content: str) -> dict[str, Any]:
        self.program = parse_program_markdown(content, source=filename)
        return self.program.as_dict()

    def import_scope(self, filename: str, content: str) -> dict[str, Any]:
        path = _temporary_input(filename, content)
        try:
            self.scope = parse_hackerone_scope(path)
        finally:
            path.unlink(missing_ok=True)
        if self.exchanges:
            self.inventory = build_inventory(self.exchanges, self.scope)
        return {"assets": [asdict(item) for item in self.scope.assets], "metadata": self.scope.metadata}

    def import_burp(self, filename: str, content: str) -> dict[str, Any]:
        path = _temporary_input(filename, content)
        try:
            self.exchanges = parse_burp_json(path) if Path(filename).suffix.lower() == ".json" else parse_burp_xml(path)
        finally:
            path.unlink(missing_ok=True)
        if self.scope is not None:
            self.inventory = build_inventory(self.exchanges, self.scope)
        return {"requests": len(self.exchanges), "inventory": [item.as_dict() for item in self.inventory], "format": Path(filename).suffix.lower().lstrip(".")}

    def run_assessment(self, payload: dict[str, Any], *, require_validation: bool = False) -> dict[str, Any]:
        if require_validation and not self.validation_complete:
            raise ValueError("validate all three engagement inputs before starting assessment")
        if self.scope is None:
            raise ValueError("import HackerOne scope before assessment")
        in_scope = inventory_to_endpoints(self.inventory)
        if not in_scope and self.exchanges:
            raise ValueError("no in-scope HTTP endpoints available for assessment")
        target_url = str(payload.get("target_url") or (in_scope[0].url if in_scope else self._assessment_target()))
        allowed_hosts = sorted({item.host for item in self.inventory if item.scope_status == "IN_SCOPE"})
        if not allowed_hosts and self.scope:
            allowed_hosts = sorted({self._scope_host(asset.normalized_identifier) for asset in self.scope.assets if asset.eligible and asset.supported and self._asset_host_in_burp_scope(asset)})
        if not allowed_hosts:
            raise ValueError("effective scope is empty: no eligible HackerOne host intersects the Burp scope")
        methods = sorted({item.method for item in in_scope})
        if not methods:
            methods = ["GET"]
        external_tools = payload.get("external_tools")
        external_tools = dict(external_tools) if isinstance(external_tools, dict) else {}
        nuclei_options = payload.get("nuclei_options")
        nuclei_options = dict(nuclei_options) if isinstance(nuclei_options, dict) else {}
        engagement = Engagement(
            target_url=target_url,
            allowed_hosts=allowed_hosts,
            allowed_methods=methods,
            dry_run=bool(payload.get("dry_run", True)),
            maximum_requests=int(payload.get("maximum_requests", 50)),
            timeout=float(payload.get("timeout", 5)),
            workspace=str(payload.get("workspace", self.workspace)),
            external_tools=external_tools,
            nuclei_enabled=bool(payload.get("nuclei_enabled", False)),
            nuclei_options=nuclei_options,
        )
        engagement.validate()
        checks = default_checks()
        policy_warnings = list(self.program.manual_attention) if self.program else ["Program Markdown was not imported; manual policy confirmation required"]
        if not self.exchanges:
            policy_warnings.append("Traffic-dependent checks were not run: no Burp HTTP observations supplied")
        if self.program and self.program.dos_prohibited:
            checks = [check for check in checks if check.category != "API4"]
            policy_warnings.append("Denial-of-service testing is prohibited; resource-consumption checks were disabled")
        self.result = AssessmentEngine(engagement, checks=checks).run(endpoint_inventory=in_scope, imported_exchanges=self.exchanges)
        self.report_paths = write_reports(self.result)
        self._add_report_context(policy_warnings)
        self.workspace = Path(engagement.workspace)
        result = report_data(self.result)
        result["program"] = self.program.as_dict() if self.program else None
        result["policy_warnings"] = policy_warnings
        result["intersection"] = self.intersection_summary()
        return result

    def _assessment_target(self) -> str:
        asset = next((item for item in self.scope.assets if item.eligible and item.supported and self._asset_host_in_burp_scope(item)), None) if self.scope else None
        if asset is None and self.scope:
            asset = next((item for item in self.scope.assets if item.eligible and item.supported), None)
        if asset is None:
            return "https://localhost"
        identifier = asset.normalized_identifier
        return identifier if identifier.startswith(("http://", "https://")) else f"https://{identifier}"

    def _asset_in_burp_scope(self, asset: Any) -> bool:
        identifier = asset.normalized_identifier
        url = identifier if identifier.startswith(("http://", "https://")) else f"https://{identifier}"
        return match_burp_scope(url, self.burp_scope)

    def _asset_host_in_burp_scope(self, asset: Any) -> bool:
        identifier = asset.normalized_identifier
        url = identifier if identifier.startswith(("http://", "https://")) else f"https://{identifier}"
        return match_burp_scope_host(url, self.burp_scope)

    @staticmethod
    def _scope_host(identifier: str) -> str:
        return identifier.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0].lstrip("*.")

    def intersection_summary(self) -> dict[str, int]:
        return {
            "scope_assets": len(self.scope.assets) if self.scope else 0,
            "eligible_assets": sum(1 for asset in self.scope.assets if asset.eligible) if self.scope else 0,
            "burp_observations": len(self.exchanges),
            "unique_endpoints": len(self.inventory),
            "in_scope": sum(1 for item in self.inventory if item.scope_status == "IN_SCOPE"),
            "out_of_scope": sum(1 for item in self.inventory if item.scope_status == "OUT_OF_SCOPE"),
            "unsupported": sum(1 for item in self.inventory if item.scope_status == "UNSUPPORTED"),
            "assessment_candidates": sum(1 for item in self.inventory if item.scope_status == "IN_SCOPE"),
            "policy_restricted": 0,
            "burp_include_rules": len(self.burp_scope.include),
            "burp_exclude_rules": len(self.burp_scope.exclude),
            "effective_scope": sum(1 for asset in self.scope.assets if asset.eligible and asset.supported and self._asset_host_in_burp_scope(asset)) if self.scope else 0,
        }

    def overview(self) -> dict[str, Any]:
        """Aggregate dashboard state into a single status payload."""

        result = self.result
        findings = [item.as_dict() for item in result.findings.findings] if result else []
        severity: dict[str, int] = {}
        status: dict[str, int] = {}
        for finding in findings:
            key = str(finding.get("severity") or "info")
            severity[key] = severity.get(key, 0) + 1
            key = str(finding.get("status") or "unknown")
            status[key] = status.get(key, 0) + 1
        checks = list(result.check_results) if result else []
        external_checks = [
            {"check_id": item.check_id, "status": item.status, "reason": item.reason}
            for item in checks
            if item.category == "EXTERNAL"
        ]
        return {
            "engagement": (
                {
                    "engagement_id": result.engagement.engagement_id,
                    "target_url": result.engagement.target_url,
                    "dry_run": result.engagement.dry_run,
                }
                if result
                else None
            ),
            "intersection": self.intersection_summary(),
            "validation_complete": self.validation_complete,
            "counts": {
                "endpoints": len(self.inventory),
                "findings": len(findings),
                "verified_findings": sum(1 for item in findings if item.get("status") == "verified"),
                "unverified_findings": sum(1 for item in findings if item.get("status") == "not_verified"),
                "evidence": len(result.evidence.artifacts) if result else 0,
                "checks": len(checks),
                "checks_executed": sum(1 for item in checks if item.executed),
                "checks_not_run": sum(1 for item in checks if item.status == "NOT_RUN"),
                "checks_error": sum(1 for item in checks if item.status == "ERROR"),
            },
            "severity": severity,
            "finding_status": status,
            "classification": dict(result.classification) if result else {},
            "external_tools": {
                "enabled": sorted(result.engagement.enabled_external_tools()) if result else [],
                "checks": external_checks,
            },
            "reports": [{"kind": kind, "filename": path.name} for kind, path in self.report_paths.items()],
        }

    def _add_report_context(self, warnings: list[str]) -> None:
        if not self.program:
            return
        report = self.report_paths.get("json")
        if report:
            payload = json.loads(report.read_text(encoding="utf-8"))
            payload["program"] = self.program.as_dict()
            payload["policy_warnings"] = warnings
            report.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        markdown = self.report_paths.get("markdown")
        if markdown:
            text = markdown.read_text(encoding="utf-8")
            context = "\n## Program Policy\n\n- Program: " + self.program.program_name + "\n- Prohibited categories: " + (", ".join(self.program.prohibited_testing_categories) or "None deterministically extracted")
            context += "\n- Manual attention: " + ("; ".join(warnings) or "None") + "\n"
            markdown.write_text(context + "\n" + text, encoding="utf-8")
        document = self.report_paths.get("html")
        if document:
            text = document.read_text(encoding="utf-8")
            context = f"<h2>Program Policy</h2><p>{html.escape(self.program.program_name)}</p><p>Manual attention: {html.escape('; '.join(warnings) or 'None')}</p>"
            document.write_text(text.replace("</body>", context + "</body>"), encoding="utf-8")


class DashboardHandler(BaseHTTPRequestHandler):
    state = DashboardState()

    def _is_authorized(self) -> bool:
        expected = _configured_dashboard_token()
        if not expected:
            return True
        provided = self.headers.get("X-Dashboard-Token", "").strip()
        auth = self.headers.get("Authorization", "").strip()
        if auth.lower().startswith("bearer "):
            provided = auth[7:].strip() or provided
        return bool(provided) and hmac.compare_digest(provided, expected)

    def _require_auth(self) -> bool:
        if self._is_authorized():
            return True
        self._json({"error": "unauthorized", "message": "valid dashboard authentication token required"}, status=401)
        return False

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self._cors_headers()
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Dashboard-Token")
        self.end_headers()

    def do_GET(self) -> None:
        try:
            if not self._require_auth():
                return
            parsed = urlsplit(self.path)
            path = parsed.path
            if path == "/scope":
                self._json({"assets": [asdict(item) for item in self.state.scope.assets]} if self.state.scope else {"assets": []})
            elif path == "/program":
                self._json(self.state.program.as_dict() if self.state.program else {"program": None})
            elif path == "/burp/traffic":
                self._json({"traffic": [_exchange_view(item, self.state.scope) for item in self.state.exchanges]})
            elif path == "/burp":
                self._json({"format": self.state.exchanges[0].request.source.rsplit(".", 1)[-1] if self.state.exchanges else None, "requests": len(self.state.exchanges), "intersection": self.state.intersection_summary()})
            elif path == "/endpoints":
                self._json({"endpoints": [item.as_dict() for item in self.state.inventory]})
            elif path == "/overview":
                self._json(self.state.overview())
            elif path == "/findings":
                self._json({"findings": [item.as_dict() for item in self.state.result.findings.findings]} if self.state.result else {"findings": []})
            elif path == "/evidence":
                self._json({"evidence": [item.as_dict() for item in self.state.result.evidence.artifacts]} if self.state.result else {"evidence": []})
            elif path.startswith("/evidence/"):
                evidence_id = path.rsplit("/", 1)[-1]
                item = next((item.as_dict() for item in self.state.result.evidence.artifacts if item.evidence_id == evidence_id), None) if self.state.result else None
                self._json(item or {"error": "evidence not found"}, status=200 if item else 404)
            elif path == "/graph":
                workspace = self.state.result.engagement.workspace if self.state.result else str(self.state.workspace)
                graph = AttackSurfaceGraph.load(workspace)
                self._json({"workspace": str(workspace), "graph": graph.to_dashboard_graph(), "summary": {"nodes": len(graph.nodes), "relationships": len(graph.relationships)}})
            elif path == "/graph/export":
                workspace = self.state.result.engagement.workspace if self.state.result else str(self.state.workspace)
                graph = AttackSurfaceGraph.load(workspace)
                self._json(graph.to_dict())
            elif path == "/tools":
                try:
                    from .tool_adapters import get_adapter, known_adapter_names

                    enabled = set(self.state.result.engagement.enabled_external_tools()) if self.state.result else set()
                    tools = {}
                    for name in known_adapter_names():
                        version = None
                        is_available = False
                        try:
                            adapter = get_adapter(name)
                            is_available = bool(adapter.availability())
                            if is_available:
                                version = adapter.version()
                        except Exception:
                            version = None
                        tools[name] = {"name": name, "available": is_available, "version": version, "enabled": name in enabled}
                    self._json({"tools": tools, "known": list(known_adapter_names())})
                except Exception as error:
                    self._json({"tools": {}, "error": type(error).__name__, "message": str(error)})
            elif path == "/reports":
                self._json({"reports": [{"kind": kind, "filename": path.name} for kind, path in self.state.report_paths.items()]})
            elif path.startswith("/reports/"):
                kind = path.rsplit("/", 1)[-1]
                file_path = self.state.report_paths.get(kind)
                if not file_path:
                    self._json({"error": "report not found"}, status=404)
                else:
                    self._text(file_path.read_text(encoding="utf-8"), content_type={"json": "application/json", "html": "text/html"}.get(kind, "text/markdown"))
            else:
                self._json({"error": "not found"}, status=404)
        except Exception as error:
            self._json({"error": type(error).__name__, "message": str(error)}, status=400)

    def do_POST(self) -> None:
        try:
            if not self._require_auth():
                return
            parsed = urlsplit(self.path)
            path = parsed.path
            if path == "/engagement/validate":
                fields = self._read_multipart()
                self._json(self.state.validate_engagement(fields["program_rules"], fields["scope_file"][0], fields["scope_file"][1], fields["burp_file"][0], fields["burp_file"][1]))
                return
            payload = self._read_json()
            if path == "/program/import":
                self._json(self.state.import_program(str(payload.get("filename", "program.md")), str(payload.get("content", ""))))
            elif path == "/scope/import":
                self._json(self.state.import_scope(str(payload.get("filename", "scope.csv")), str(payload.get("content", ""))))
            elif path == "/burp/import":
                self._json(self.state.import_burp(str(payload.get("filename", "burp.xml")), str(payload.get("content", ""))))
            elif path == "/assessment/run":
                self._json(self.state.run_assessment(payload, require_validation=True))
            else:
                self._json({"error": "not found"}, status=404)
        except Exception as error:
            self._json({"error": type(error).__name__, "message": str(error)}, status=400)

    def _read_json(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        if length > 10_000_000:
            raise ValueError("request body is too large")
        value = json.loads(self.rfile.read(length).decode("utf-8"))
        if not isinstance(value, dict):
            raise ValueError("request body must be an object")
        return value

    def _read_multipart(self) -> dict[str, Any]:
        content_type = self.headers.get("Content-Type", "")
        if not content_type.lower().startswith("multipart/form-data"):
            raise ValueError("engagement validation requires multipart/form-data")
        length = int(self.headers.get("Content-Length", "0"))
        if length > 50 * 1024 * 1024:
            raise ValueError("request body is too large")
        body = self.rfile.read(length)
        message = BytesParser(policy=default).parsebytes((f"Content-Type: {content_type}\r\nMIME-Version: 1.0\r\n\r\n").encode() + body)
        fields: dict[str, Any] = {}
        for part in message.iter_parts():
            name = part.get_param("name", header="content-disposition")
            if not name:
                continue
            value = part.get_payload(decode=True) or b""
            filename = part.get_filename()
            if filename:
                fields[name] = (filename, value.decode("utf-8-sig"))
            else:
                fields[name] = value.decode("utf-8")
        required = {"program_rules", "scope_file", "burp_file"}
        missing = sorted(required - fields.keys())
        if missing:
            raise ValueError(f"missing multipart fields: {', '.join(missing)}")
        if not isinstance(fields["scope_file"], tuple) or not isinstance(fields["burp_file"], tuple):
            raise ValueError("scope_file and burp_file must be uploaded files")
        return fields

    def _json(self, value: Any, *, status: int = 200) -> None:
        self._text(json.dumps(value, indent=2), content_type="application/json", status=status)

    def _text(self, value: str, *, content_type: str, status: int = 200) -> None:
        body = value.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self._cors_headers()
        self.end_headers()
        self.wfile.write(body)

    def _cors_headers(self) -> None:
        origin = self.headers.get("Origin", "")
        if origin in {"http://localhost:5173", "http://127.0.0.1:5173"}:
            self.send_header("Access-Control-Allow-Origin", origin)
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Dashboard-Token")

    def log_message(self, format: str, *args: object) -> None:
        return


def _temporary_input(filename: str, content: str) -> Path:
    suffix = Path(filename).suffix or ".txt"
    handle = tempfile.NamedTemporaryFile(prefix="bugbounty-import-", suffix=suffix, delete=False, mode="w", encoding="utf-8")
    try:
        handle.write(content)
    finally:
        handle.close()
    return Path(handle.name)


def _exchange_view(exchange: BurpExchange, scope: Any) -> dict[str, Any]:
    status = match_scope(exchange.request.url, scope)[0] if scope is not None else "UNKNOWN"
    return {"id": exchange.request.id, "timestamp": exchange.request.timestamp, "method": exchange.request.method, "host": exchange.request.host, "path": exchange.request.path, "url": exchange.request.url, "status": exchange.response.status if exchange.response else None, "content_type": exchange.response.content_type if exchange.response else None, "scope_status": status}


def serve_dashboard(host: str = "127.0.0.1", port: int = 8765) -> None:
    server = ThreadingHTTPServer((host, port), DashboardHandler)
    print(f"Dashboard API listening on http://{host}:{port}")
    server.serve_forever()


__all__ = ["DashboardHandler", "DashboardState", "serve_dashboard"]
