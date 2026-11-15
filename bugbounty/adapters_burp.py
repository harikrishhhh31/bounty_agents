"""Optional external adapter for Burp Suite's headless scanner.

Burp Suite has **no universal headless CLI**: the stock desktop product and the
Enterprise/Professional editions expose different interfaces, and many teams run
Burp behind a thin wrapper script. This adapter therefore assumes a
**headless-capable Burp build or wrapper** that accepts the following argv
contract:

    <exe> --headless --target <url> --report-format xml --report-output <file>

The report written to ``--report-output`` is expected to be Burp's **native XML
scanner report** schema, i.e. an ``<issues>`` document whose ``<issue>`` children
carry ``<name>``, ``<host>``, ``<path>``, ``<location>``, ``<severity>``,
``<confidence>``, ``<type>``, ``<issueDetail>``, ``<remediationDetail>`` and
``<issueBackground>`` elements. If a given Burp build uses different flags or a
JSON/HTML report, it must be wrapped to present this contract.

Everything here is argv-only (``shell=False``) and performs no network access of
its own; any scanning is delegated to the external executable.
"""

from __future__ import annotations

import tempfile
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence
from urllib.parse import urlsplit

from .tool_adapters import (
    AdapterConfig,
    BaseSubprocessAdapter,
    InputValidationError,
    ToolExecution,
    ToolFindingRecord,
    redact_command,
    redact_sensitive,
    validate_target_url,
)

_SEVERITY_MAP = {
    "high": "high",
    "medium": "medium",
    "low": "low",
    "information": "info",
    "info": "info",
}

_CONFIDENCE_MAP = {
    "certain": 0.9,
    "firm": 0.7,
    "tentative": 0.5,
}

_DEFAULT_SEVERITY = "info"
_DEFAULT_CONFIDENCE = 0.5
_MAX_EVIDENCE_CHARS = 2000


def _bounded(value: Any, limit: int = _MAX_EVIDENCE_CHARS) -> Any:
    """Clamp evidence strings so persisted records stay small."""

    if isinstance(value, str) and len(value) > limit:
        return value[:limit] + "...<truncated>"
    return value


class BurpAdapter(BaseSubprocessAdapter):
    """Adapter for a headless-capable Burp Suite build/wrapper."""

    name = "burp"
    executable_names = ("burp", "burpsuite", "burp.sh", "burp.bat", "burp.exe")

    def version_command(self, executable: str) -> tuple[str, ...]:
        return (executable, "--version")

    def build_command(self, target: str, config: AdapterConfig | None = None) -> tuple[str, ...]:
        cfg = config or AdapterConfig()
        exe = self.resolve_executable() or self.executable_names[0]
        safe_target = validate_target_url(target)
        report_path = Path(tempfile.gettempdir()) / f"burp-report-{uuid.uuid4().hex}.xml"
        args: list[str] = [
            exe,
            "--headless",
            "--target",
            safe_target,
            "--report-format",
            "xml",
            "--report-output",
            str(report_path),
        ]
        args.extend(str(arg) for arg in cfg.extra_args)
        return tuple(args)

    def output_file(self, command: Sequence[str], config: AdapterConfig) -> str | None:
        parts = list(command)
        try:
            index = parts.index("--report-output")
        except ValueError:
            return None
        if index + 1 < len(parts):
            return parts[index + 1]
        return None

    def parse_output(self, stdout: str, stderr: str = "") -> list[dict[str, Any]]:
        """Parse a Burp native XML scanner report. Never raises; ``[]`` on error."""

        text = (stdout or "").strip()
        if not text:
            return []
        try:
            root = ET.fromstring(text)
        except ET.ParseError:
            return []
        except Exception:
            return []
        try:
            if root.tag == "issue":
                issue_elements = [root]
            else:
                issue_elements = list(root.iter("issue"))
            items: list[dict[str, Any]] = []
            for issue in issue_elements:
                record: dict[str, Any] = {}
                for child in issue:
                    tag = child.tag
                    if not isinstance(tag, str):
                        continue
                    record[tag] = child.text if child.text is not None else ""
                items.append(record)
            return items
        except Exception:
            return []

    @staticmethod
    def _map_severity(value: Any) -> str:
        return _SEVERITY_MAP.get(str(value or "").strip().lower(), _DEFAULT_SEVERITY)

    @staticmethod
    def _map_confidence(value: Any) -> float:
        return _CONFIDENCE_MAP.get(str(value or "").strip().lower(), _DEFAULT_CONFIDENCE)

    @staticmethod
    def _build_endpoint(item: Mapping[str, Any], target: str) -> str:
        location = str(item.get("location") or "").strip()
        if location:
            return location
        host = str(item.get("host") or "").strip()
        path = str(item.get("path") or "").strip()
        if host:
            if "://" in host:
                return f"{host}{path}"
            scheme = urlsplit(target).scheme or "https"
            return f"{scheme}://{host}{path}"
        return target

    def normalize_results(
        self,
        raw_items: Iterable[Mapping[str, Any]],
        *,
        target: str,
        execution: ToolExecution | None = None,
    ) -> tuple[ToolFindingRecord, ...]:
        findings: list[ToolFindingRecord] = []
        tool_version = execution.version if execution else self.version()
        command = redact_command(list(execution.command)) if execution else None

        for item in raw_items:
            name = str(item.get("name") or "Burp issue")
            host = str(item.get("host") or "")
            path = str(item.get("path") or "")
            location = str(item.get("location") or "")
            issue_detail = str(item.get("issueDetail") or "")
            issue_background = str(item.get("issueBackground") or "")
            burp_type = str(item.get("type") or "")

            endpoint = self._build_endpoint(item, target)
            severity = self._map_severity(item.get("severity"))
            confidence = self._map_confidence(item.get("confidence"))

            evidence = redact_sensitive(
                {
                    "location": _bounded(location),
                    "host": _bounded(host),
                    "path": _bounded(path),
                    "issue_detail": _bounded(issue_detail),
                    "issue_background": _bounded(issue_background),
                }
            )
            if not isinstance(evidence, dict):
                evidence = {"redacted": True}

            provenance = {
                "tool": self.name,
                "tool_version": tool_version,
                "target": target,
                "burp_type": burp_type,
                "command": command,
            }

            redacted_raw = redact_sensitive(dict(item))
            if not isinstance(redacted_raw, dict):
                redacted_raw = {"redacted": True}

            findings.append(
                ToolFindingRecord(
                    source_tool=self.name,
                    source_id=burp_type or name,
                    title=redact_sensitive(name, "name") if isinstance(name, str) else "Burp issue",
                    category="external-burp",
                    endpoint=endpoint,
                    severity=severity,
                    confidence=confidence,
                    status="candidate",
                    description=redact_sensitive(issue_detail or name, "issue_detail"),
                    evidence=evidence,
                    provenance=provenance,
                    raw=redacted_raw,
                )
            )
        return tuple(findings)


__all__ = ["BurpAdapter"]
