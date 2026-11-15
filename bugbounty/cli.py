from __future__ import annotations

import argparse
import json
from pathlib import Path

from .assessment import AssessmentEngine
from .config_loader import ConfigurationError, load_assessment_config
from .discovery import ApiDiscovery
from .engagement import Engagement
from .http_client import HttpClient
from .reports import write_reports
from .dashboard_api import serve_dashboard


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="bugbounty", description="Unified security research and bug-bounty platform")
    subparsers = parser.add_subparsers(dest="command")

    init_parser = subparsers.add_parser("init", help="initialize a workspace")
    init_parser.add_argument("--workspace", default=".")

    status_parser = subparsers.add_parser("status", help="show workspace state")
    status_parser.add_argument("--workspace", default=".")

    recon_parser = subparsers.add_parser("recon", help="run reconnaissance")
    recon_parser.add_argument("--target", required=True)
    recon_parser.add_argument("--workspace", default=".")

    discover_parser = subparsers.add_parser("discover", help="discover API endpoints")
    discover_parser.add_argument("--target", required=True)
    discover_parser.add_argument("--workspace", default=".")
    discover_parser.add_argument("--openapi-file")
    discover_parser.add_argument("--dry-run", action="store_true")

    assess_parser = subparsers.add_parser("assess", help="run a bounded API security assessment")
    assess_parser.add_argument("--target")
    assess_parser.add_argument("--config", help="YAML or JSON engagement configuration")
    assess_parser.add_argument("--workspace", default="./workspace")
    assess_parser.add_argument("--openapi-file")
    assess_parser.add_argument("--dry-run", action="store_true")
    assess_parser.add_argument("--max-requests", type=int, default=50)
    assess_parser.add_argument("--timeout", type=float, default=5.0)
    assess_parser.add_argument("--nuclei", action="store_true", help="enable optional Nuclei adapter (requires nuclei binary; respects scope and dry-run)")

    report_parser = subparsers.add_parser("report", help="show or regenerate report paths")
    report_parser.add_argument("--workspace", default="./workspace")

    dashboard_parser = subparsers.add_parser("dashboard", help="start the local passive-import dashboard API")
    dashboard_parser.add_argument("--host", default="127.0.0.1")
    dashboard_parser.add_argument("--port", type=int, default=8765)

    graph_parser = subparsers.add_parser("graph", help="inspect or export the attack surface graph")
    graph_parser.add_argument("--workspace", default="./workspace")
    graph_parser.add_argument("--summary", action="store_true", help="print graph node/relationship counts")
    graph_parser.add_argument("--export", help="export graph JSON to a file path")
    graph_parser.add_argument("--endpoint", help="show graph details for an endpoint path or URL fragment")

    tools_parser = subparsers.add_parser("tools", help="show optional external tool adapter status")
    tools_parser.add_argument("--workspace", default=".")

    return parser


def _engagement(args: argparse.Namespace) -> Engagement:
    return Engagement.from_target(
        args.target,
        allowed_schemes=["http", "https"],
        allowed_methods=["GET"],
        maximum_requests=getattr(args, "max_requests", 50),
        timeout=getattr(args, "timeout", 5.0),
        dry_run=getattr(args, "dry_run", False),
        workspace=args.workspace,
        nuclei_enabled=bool(getattr(args, "nuclei", False)),
    )


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "init":
        workspace = Path(args.workspace)
        workspace.mkdir(parents=True, exist_ok=True)
        (workspace / "engagement.json").write_text(json.dumps({"workspace": str(workspace), "status": "initialized"}, indent=2), encoding="utf-8")
        print(f"Initialized workspace: {workspace}")
        return 0
    if args.command == "status":
        workspace = Path(args.workspace)
        print(json.dumps({"workspace": str(workspace), "exists": workspace.exists(), "reports": [item.name for item in workspace.glob("report.*")]}, indent=2))
        return 0
    if args.command == "report":
        workspace = Path(args.workspace)
        for name in ("report.json", "report.md", "report.html"):
            print(workspace / name)
        return 0
    if args.command == "dashboard":
        serve_dashboard(args.host, args.port)
        return 0
    if args.command == "discover":
        engagement = _engagement(args)
        endpoints = ApiDiscovery(engagement, HttpClient(engagement)).discover(openapi_file=args.openapi_file)
        print(json.dumps([item.as_dict() for item in endpoints], indent=2))
        return 0
    if args.command == "assess":
        try:
            if args.config:
                loaded = load_assessment_config(args.config)
                result = AssessmentEngine(loaded.engagement).run(**loaded.discovery)
            else:
                if not args.target:
                    raise ConfigurationError("assess requires --target or --config")
                result = AssessmentEngine(_engagement(args)).run(openapi_file=args.openapi_file)
        except (ConfigurationError, ValueError, OSError) as error:
            print(f"Configuration error: {error}")
            return 2
        paths = write_reports(result)
        print(f"Assessment {result.engagement.engagement_id}: {len(result.endpoints)} endpoints, {len(result.findings.findings)} findings")
        for path in paths.values():
            print(path)
        return 0
    if args.command == "recon":
        args.dry_run = True
        args.timeout = 5.0
        args.max_requests = 10
        engagement = _engagement(args)
        endpoints = ApiDiscovery(engagement, HttpClient(engagement)).discover()
        print(json.dumps([item.as_dict() for item in endpoints], indent=2))
        return 0
    if args.command == "tools":
        try:
            from .tool_adapters import available_adapters, get_adapter
            availability = available_adapters()
            tools = {}
            for name, is_available in availability.items():
                version = None
                try:
                    adapter = get_adapter(name)
                    if is_available and hasattr(adapter, "version"):
                        version = adapter.version()
                except Exception:
                    version = None
                tools[name] = {"name": name, "available": bool(is_available), "version": version}
            print(json.dumps({"tools": tools}, indent=2))
            return 0
        except Exception as error:
            print(f"Tool status error: {error}")
            return 2
    if args.command == "graph":
        try:
            from .attack_surface_graph import AttackSurfaceGraph
            workspace = Path(args.workspace)
            graph = AttackSurfaceGraph.load(workspace)
            if args.export:
                dest = Path(args.export)
                dest.parent.mkdir(parents=True, exist_ok=True)
                graph.export_json(dest)
                print(f"Exported graph: {dest}")
                return 0
            if args.endpoint:
                matches = []
                needle = args.endpoint
                for item in graph.query_endpoints():
                    ep = item["endpoint"]
                    ep_path = str(ep.key.get("path") or ep.attributes.get("path") or "")
                    ep_url = str(ep.attributes.get("url") or "")
                    if needle in ep_path or needle in ep_url or needle == ep.label:
                        findings = [{"id": n.id, "label": n.label, "type": n.type, "attributes": n.attributes} for n in graph.findings_for_endpoint(ep.id)]
                        evidence_links = []
                        for rel in graph.finding_evidence_relationships():
                            if rel["finding"].id in {f["id"] for f in findings}:
                                evidence_links.append({"finding": rel["finding"].id, "evidence": rel["evidence"].id, "evidence_label": rel["evidence"].label})
                        matches.append({"endpoint": ep.as_dict(), "findings": findings, "finding_evidence": evidence_links})
                print(json.dumps({"workspace": str(workspace), "query": needle, "matches": matches}, indent=2))
                return 0
            summary = {
                "workspace": str(workspace),
                "exists": (workspace / "attack_surface_graph.json").exists() if workspace.suffix.lower() != ".json" else workspace.exists(),
                "nodes": len(graph.nodes),
                "relationships": len(graph.relationships),
                "node_types": {},
                "relationship_types": {},
            }
            for node in graph.nodes.values():
                summary["node_types"][node.type] = summary["node_types"].get(node.type, 0) + 1
            for rel in graph.relationships.values():
                summary["relationship_types"][rel.type] = summary["relationship_types"].get(rel.type, 0) + 1
            print(json.dumps(summary, indent=2))
            return 0
        except Exception as error:
            print(f"Graph error: {error}")
            return 2
    build_parser().print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
