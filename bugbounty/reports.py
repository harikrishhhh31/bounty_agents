from __future__ import annotations

import html
import json
from collections import Counter
from pathlib import Path
from typing import Any

from .assessment import AssessmentResult


def report_data(result: AssessmentResult) -> dict[str, Any]:
    checks = [{"check_id": item.check_id, "category": item.category, "endpoint": item.endpoint, "method": item.method, "status": item.status, "applicable": item.applicable, "executed": item.executed, "verified": item.verified, "confidence": item.confidence, "severity": item.severity, "evidence_ids": list(item.evidence_ids) or [evidence.evidence_id for evidence in item.evidence], "reason": item.reason, "remediation": item.remediation} for item in result.check_results]
    return {
        "engagement": {"id": result.engagement.engagement_id, "target_url": result.engagement.target_url, "allowed_hosts": result.engagement.allowed_hosts, "dry_run": result.engagement.dry_run, "maximum_requests": result.engagement.maximum_requests},
        "timeline": {"started_at": result.started_at, "finished_at": result.finished_at},
        "endpoints": [item.as_dict() for item in result.endpoints],
        "checks": checks,
        "checks_executed": [item for item in checks if item["executed"]],
        "checks_not_run": [item for item in checks if item["status"] == "NOT_RUN"],
        "checks_not_applicable": [item for item in checks if item["status"] == "NOT_APPLICABLE"],
        "findings": [item.as_dict() for item in result.findings.findings],
        "verified_findings": [item.as_dict() for item in result.findings.findings if item.status == "verified"],
        "potential_findings": [item.as_dict() for item in result.findings.findings if item.status in {"candidate", "not_verified"}],
        "informational_observations": [item.as_dict() for item in result.evidence.artifacts if item.verification_status == "observed"],
        "severity_summary": dict(Counter(item.severity for item in result.findings.findings)),
        "classification": dict(result.classification),
        "evidence": [item.as_dict() for item in result.evidence.artifacts],
        "limitations": [item.reason for item in result.checks_not_run],
        "audit_log": result.audit_log,
    }


def write_json_report(result: AssessmentResult, path: str | Path) -> Path:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(report_data(result), indent=2), encoding="utf-8")
    return destination


def write_markdown_report(result: AssessmentResult, path: str | Path) -> Path:
    data = report_data(result)
    classification = data.get("classification") or {}
    classification_line = ", ".join(f"{key}={value}" for key, value in sorted(classification.items())) or "none"
    lines = ["# API Security Assessment", "", "## Executive Summary", f"Target: `{data['engagement']['target_url']}`", f"Findings: {len(data['findings'])}", f"Classification: {classification_line}", "", "## Target / Scope", f"- Engagement: `{data['engagement']['id']}`", f"- Allowed hosts: {', '.join(data['engagement']['allowed_hosts'])}", f"- Dry run: `{data['engagement']['dry_run']}`", "", "## Endpoints Discovered"]
    lines.extend(f"- `{item['method']} {item['url']}` ({item['source']}, confidence {item['confidence']})" for item in data["endpoints"])
    lines.extend(["", "## Checks Not Run"])
    lines.extend(f"- `{item['check_id']}`: {item['reason']}" for item in data["checks_not_run"])
    lines.extend(["", "## Checks Not Applicable"])
    lines.extend(f"- `{item['check_id']}`: {item['reason']}" for item in data["checks_not_applicable"])
    for section, findings in (("Verified Findings", data["verified_findings"]), ("Potential Findings", data["potential_findings"])):
        lines.extend(["", f"## {section}"])
        if findings:
            for finding in findings:
                lines.extend([f"### {finding['severity'].upper()} - {finding['title']}", f"- Category: `{finding['category']}`", f"- Status: **{finding['status']}**", f"- Confidence: {finding['confidence']}", f"- Endpoint: `{finding['method']} {finding['endpoint']}`", f"- Identity: `{finding.get('identity') or 'anonymous/unspecified'}`", f"- Expected: {finding.get('expected_behavior') or finding['description']}", f"- Observed: {finding.get('observed_behavior') or finding['impact']}", f"- Context: {json.dumps(finding.get('context', {}), sort_keys=True)}", f"- Evidence: {', '.join(finding['evidence_ids'])}", f"- Reproduction: {finding['reproduction_summary']}", f"- Remediation: {finding['remediation']}", ""])
        else:
            lines.append("No findings in this section.")
    evidence_lines = [f"- `{item['evidence_id']}`: {item['observation']} ({item['verification_status']})" for item in data["evidence"]]
    limitation_lines = [f"- {item}" for item in data["limitations"]]
    lines.extend(["", "## Informational Observations", *[f"- {item['observation']}" for item in data["informational_observations"]], "", "## Evidence", *evidence_lines, "", "## Limitations", *limitation_lines])
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return destination


def write_html_report(result: AssessmentResult, path: str | Path) -> Path:
    data = report_data(result)
    finding_rows = "".join(f"<tr><td>{html.escape(item['title'])}</td><td>{html.escape(item['category'])}</td><td>{html.escape(item['severity'])}</td><td>{html.escape(item['status'])}</td><td>{item['confidence']}</td></tr>" for item in data["findings"])
    evidence_rows = "".join("<li>{}: {}</li>".format(html.escape(str(item["evidence_id"])), html.escape(str(item["observation"]))) for item in data["evidence"])
    not_run_rows = "".join("<li>{}: {}</li>".format(html.escape(str(item["check_id"])), html.escape(str(item["reason"]))) for item in data["checks_not_run"])
    not_applicable_rows = "".join("<li>{}: {}</li>".format(html.escape(str(item["check_id"])), html.escape(str(item["reason"]))) for item in data["checks_not_applicable"])
    target = html.escape(str(data["engagement"]["target_url"]))
    body = f"<h1>API Security Assessment</h1><p>Target: <code>{target}</code></p><h2>Findings</h2><table><tr><th>Title</th><th>Category</th><th>Severity</th><th>Status</th><th>Confidence</th></tr>{finding_rows}</table><h2>Evidence</h2><ul>{evidence_rows}</ul><h2>Checks Not Run</h2><ul>{not_run_rows}</ul><h2>Checks Not Applicable</h2><ul>{not_applicable_rows}</ul>"
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(f"<!doctype html><html><head><meta charset='utf-8'><title>API Assessment</title><style>body{{font-family:system-ui;max-width:960px;margin:2rem auto}}table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #ccc;padding:.5rem;text-align:left}}</style></head><body>{body}</body></html>", encoding="utf-8")
    return destination


def write_reports(result: AssessmentResult) -> dict[str, Path]:
    workspace = Path(result.engagement.workspace)
    return {"json": write_json_report(result, workspace / "report.json"), "markdown": write_markdown_report(result, workspace / "report.md"), "html": write_html_report(result, workspace / "report.html")}


__all__ = ["report_data", "write_html_report", "write_json_report", "write_markdown_report", "write_reports"]
