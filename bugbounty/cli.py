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

    report_parser = subparsers.add_parser("report", help="show or regenerate report paths")
    report_parser.add_argument("--workspace", default="./workspace")

    dashboard_parser = subparsers.add_parser("dashboard", help="start the local passive-import dashboard API")
    dashboard_parser.add_argument("--host", default="127.0.0.1")
    dashboard_parser.add_argument("--port", type=int, default=8765)

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
    build_parser().print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
