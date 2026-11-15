"""Optional external adapter for OWASP ZAP (baseline "quick" scan).

This adapter drives the ZAP command line in ``-cmd`` (headless) mode using the
``-quickurl`` convenience scan and asks ZAP to emit a machine-readable
"Traditional JSON Report" via ``-quickout``. The report is read back from disk
by :meth:`BaseSubprocessAdapter.run` through :meth:`ZapAdapter.output_file`.

Design constraints (see ``bugbounty/tool_adapters.py`` for the base contract):

* argv-only subprocess usage -- the base runner never enables ``shell`` and every
  argument here is passed as a discrete list element.
* ``parse_output`` must never raise: malformed JSON or unexpected shapes simply
  yield ``[]`` so an optional external tool can never crash the core scanner.
* every echoed string/argument is passed through the shared redaction helpers so
  credentials that a target or ZAP echoes are never persisted into findings.
"""

from __future__ import annotations

import json
import os
import tempfile
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

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

# ZAP riskcode -> normalized severity. Anything unknown falls back to "info".
_RISKCODE_SEVERITY: dict[int, str] = {
    3: "high",
    2: "medium",
    1: "low",
    0: "info",
}

# ZAP confidence (0..3) -> normalized 0.0..1.0 confidence.
_CONFIDENCE_SCORE: dict[int, float] = {
    0: 0.3,
    1: 0.5,
    2: 0.7,
    3: 0.9,
}

# Instance-level keys copied out of each ZAP alert instance.
_INSTANCE_KEYS = ("uri", "method", "param", "evidence", "attack", "otherinfo")


class ZapAdapter(BaseSubprocessAdapter):
    """Adapter for the OWASP ZAP command line scanner."""

    name = "zap"
    executable_names = ("zap.sh", "zap.bat", "zap", "zap.exe")

    def version_command(self, executable: str) -> tuple[str, ...]:
        return (executable, "-version")

    def build_command(self, target: str, config: AdapterConfig | None = None) -> tuple[str, ...]:
        """Build an argv-only ZAP quick-scan command with a unique report path."""

        cfg = config or AdapterConfig()
        exe = self.resolve_executable() or self.executable_names[0]
        # Validation happens before the value is embedded anywhere in argv.
        safe_target = validate_target_url(target)

        report_dir = tempfile.mkdtemp(prefix="zap-report-")
        report_path = os.path.join(report_dir, "zap-report.json")

        args: list[str] = [
            exe,
            "-cmd",
            "-quickurl",
            safe_target,
            "-quickout",
            report_path,
            "-quickprogress",
        ]
        args.extend(cfg.extra_args)
        return tuple(args)

    def output_file(self, command: Sequence[str], config: AdapterConfig) -> str | None:
        """Return the report path referenced by ``-quickout`` in ``command``."""

        cmd = list(command)
        try:
            idx = cmd.index("-quickout")
        except ValueError:
            return None
        if idx + 1 < len(cmd):
            return cmd[idx + 1]
        return None

    def parse_output(self, stdout: str, stderr: str = "") -> list[dict[str, Any]]:
        """Parse a ZAP Traditional JSON Report; never raises.

        Each alert instance becomes one flat dict. Alerts without instances
        still produce a single dict carrying only alert-level fields.
        """

        if not stdout or not isinstance(stdout, str) or not stdout.strip():
            return []
        try:
            data = json.loads(stdout)
        except (ValueError, TypeError):
            return []
        if not isinstance(data, Mapping):
            return []

        sites = data.get("site")
        if isinstance(sites, Mapping):
            sites = [sites]
        if not isinstance(sites, list):
            return []

        items: list[dict[str, Any]] = []
        for site in sites:
            if not isinstance(site, Mapping):
                continue
            site_name = site.get("@name") or site.get("name") or ""
            alerts = site.get("alerts")
            if isinstance(alerts, Mapping):
                alerts = [alerts]
            if not isinstance(alerts, list):
                continue
            for alert in alerts:
                if not isinstance(alert, Mapping):
                    continue
                base: dict[str, Any] = {
                    "site": site_name,
                    "alert": alert.get("alert"),
                    "name": alert.get("name"),
                    "riskcode": alert.get("riskcode"),
                    "confidence": alert.get("confidence"),
                    "desc": alert.get("desc"),
                    "solution": alert.get("solution"),
                    "reference": alert.get("reference"),
                    "cweid": alert.get("cweid"),
                    "pluginid": alert.get("pluginid"),
                    "alert_ref": alert.get("alertRef") or alert.get("alert_ref"),
                }
                instances = alert.get("instances")
                if isinstance(instances, Mapping):
                    instances = [instances]
                emitted = False
                if isinstance(instances, list) and instances:
                    for instance in instances:
                        if not isinstance(instance, Mapping):
                            continue
                        item = dict(base)
                        for key in _INSTANCE_KEYS:
                            item[key] = instance.get(key)
                        items.append(item)
                        emitted = True
                if not emitted:
                    # No usable instances: still surface the alert itself.
                    items.append(dict(base))
        return items

    def normalize_results(
        self,
        raw_items: Iterable[Mapping[str, Any]],
        *,
        target: str,
        execution: ToolExecution | None = None,
    ) -> tuple[ToolFindingRecord, ...]:
        """Convert flattened ZAP alerts into normalized candidate findings."""

        tool_version = execution.version if execution else self.version()
        redacted_command = redact_command(list(execution.command)) if execution else None
        redacted_target = redact_sensitive(target)

        findings: list[ToolFindingRecord] = []
        for item in raw_items:
            if not isinstance(item, Mapping):
                continue

            plugin_id = (
                item.get("pluginid")
                or item.get("plugin_id")
                or item.get("alert_ref")
                or item.get("alertRef")
                or "unknown"
            )
            plugin_id = str(plugin_id)
            cwe_id = item.get("cweid")

            title = str(item.get("alert") or item.get("name") or "ZAP alert")
            raw_endpoint = item.get("uri") or item.get("url") or target
            endpoint = str(redact_sensitive(str(raw_endpoint)))
            description = str(item.get("desc") or item.get("description") or title)
            severity = self._severity_from_riskcode(item.get("riskcode"))
            confidence = self._confidence_from_code(item.get("confidence"))

            evidence: dict[str, Any] = {
                "uri": redact_sensitive(item.get("uri")),
                "method": redact_sensitive(item.get("method")),
                "param": redact_sensitive(item.get("param")),
                "evidence": redact_sensitive(item.get("evidence")),
                "attack": redact_sensitive(item.get("attack")),
                "cweid": redact_sensitive(cwe_id),
                "pluginid": redact_sensitive(plugin_id),
            }

            provenance: dict[str, Any] = {
                "tool": self.name,
                "tool_version": tool_version,
                "target": redacted_target,
                "plugin_id": plugin_id,
                "cwe_id": cwe_id,
                "command": redacted_command,
            }

            redacted_raw = redact_sensitive(dict(item))
            if not isinstance(redacted_raw, dict):
                redacted_raw = {"redacted": True}

            findings.append(
                ToolFindingRecord(
                    source_tool=self.name,
                    source_id=plugin_id,
                    title=str(redact_sensitive(title)),
                    category="external-zap",
                    endpoint=endpoint,
                    severity=severity,
                    confidence=confidence,
                    status="candidate",
                    description=str(redact_sensitive(description)),
                    evidence=evidence,
                    provenance=provenance,
                    raw=redacted_raw,
                )
            )
        return tuple(findings)

    @staticmethod
    def _severity_from_riskcode(value: Any) -> str:
        try:
            code = int(str(value).strip())
        except (TypeError, ValueError):
            return "info"
        return _RISKCODE_SEVERITY.get(code, "info")

    @staticmethod
    def _confidence_from_code(value: Any) -> float:
        try:
            code = int(str(value).strip())
        except (TypeError, ValueError):
            return 0.5
        return _CONFIDENCE_SCORE.get(code, 0.5)


__all__ = ["ZapAdapter"]
