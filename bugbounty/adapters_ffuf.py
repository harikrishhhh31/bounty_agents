"""Optional adapter for the ``ffuf`` web fuzzer.

This adapter drives ``ffuf`` in a strictly argv-only, non-interactive mode and
converts its machine-readable JSON report into normalized
:class:`~bugbounty.tool_adapters.ToolFindingRecord` objects. It never performs
network access itself; the tool is executed by the shared base runner via
``run_subprocess`` (no shell).
"""

from __future__ import annotations

import json
import os
import tempfile
from typing import Any, Iterable, Mapping, Sequence

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

__all__ = ["FfufAdapter"]


class FfufAdapter(BaseSubprocessAdapter):
    """Adapter for ``ffuf`` directory/content discovery."""

    name = "ffuf"
    executable_names = ("ffuf", "ffuf.exe")

    # -- discovery / version -------------------------------------------------

    def version_command(self, executable: str) -> tuple[str, ...]:
        return (executable, "-V")

    # -- validation ----------------------------------------------------------

    @staticmethod
    def _has_wordlist(extra_args: Sequence[str]) -> bool:
        args = list(extra_args or ())
        for index, arg in enumerate(args):
            if arg == "-w" and index + 1 < len(args) and str(args[index + 1]).strip():
                return True
            if isinstance(arg, str) and arg.startswith("-w=") and arg[3:].strip():
                return True
        return False

    def validate_input(
        self, targets: Sequence[str], config: AdapterConfig | None = None
    ) -> tuple[str, ...]:
        values = super().validate_input(targets, config)
        cfg = config or AdapterConfig()
        if not self._has_wordlist(cfg.extra_args):
            raise InputValidationError(
                "ffuf requires a wordlist via extra_args: -w <path>"
            )
        return values

    # -- command construction ------------------------------------------------

    @staticmethod
    def _new_report_path() -> str:
        """Create a unique temp path for ffuf's JSON report."""

        handle, path = tempfile.mkstemp(prefix="ffuf-report-", suffix=".json")
        os.close(handle)
        return path

    def build_command(
        self, target: str, config: AdapterConfig | None = None
    ) -> tuple[str, ...]:
        cfg = config or AdapterConfig()
        exe = self.resolve_executable() or self.executable_names[0]
        # Validate the caller-supplied target before injecting the FUZZ keyword.
        safe_target = validate_target_url(target)
        if "FUZZ" not in safe_target:
            safe_target = safe_target.rstrip("/") + "/FUZZ"
        report_path = self._new_report_path()
        args: list[str] = [
            exe,
            "-u",
            safe_target,
            "-o",
            report_path,
            "-of",
            "json",
            "-s",
            "-noninteractive",
        ]
        args.extend(cfg.extra_args)
        return tuple(args)

    def output_file(self, command: Sequence[str], config: AdapterConfig) -> str | None:
        args = list(command or ())
        for index, arg in enumerate(args):
            if arg == "-o" and index + 1 < len(args):
                return args[index + 1]
        return None

    # -- output parsing ------------------------------------------------------

    def parse_output(self, stdout: str, stderr: str = "") -> list[dict[str, Any]]:
        """Parse an ffuf JSON report or newline-delimited JSON records.

        Never raises: malformed input yields an empty list.
        """

        try:
            text = stdout or ""
            if not text.strip():
                return []

            # Preferred form: a single JSON document with a "results" list.
            try:
                document = json.loads(text)
            except (json.JSONDecodeError, ValueError, TypeError):
                document = None

            if isinstance(document, dict):
                results = document.get("results")
                if isinstance(results, list):
                    return [item for item in results if isinstance(item, dict)]
                if any(key in document for key in ("url", "status", "input")):
                    return [document]
                return []
            if isinstance(document, list):
                return [item for item in document if isinstance(item, dict)]

            # Fallback: newline-delimited JSON records emitted by `-json`.
            items: list[dict[str, Any]] = []
            for line in text.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except (json.JSONDecodeError, ValueError, TypeError):
                    continue
                if isinstance(obj, dict):
                    items.append(obj)
            return items
        except Exception:  # pragma: no cover - defensive: parsing must never raise.
            return []

    # -- normalization -------------------------------------------------------

    @staticmethod
    def _severity_for_status(status: Any) -> str:
        try:
            code = int(status)
        except (TypeError, ValueError):
            return "info"
        if 200 <= code < 400:
            return "info"
        if code in (401, 403):
            return "low"
        if 500 <= code < 600:
            return "medium"
        return "info"

    def normalize_results(
        self,
        raw_items: Iterable[Mapping[str, Any]],
        *,
        target: str,
        execution: ToolExecution | None = None,
    ) -> tuple[ToolFindingRecord, ...]:
        findings: list[ToolFindingRecord] = []
        for item in raw_items:
            record: dict[str, Any] = dict(item) if isinstance(item, Mapping) else {}
            url = str(record.get("url") or target)
            severity = self._severity_for_status(record.get("status"))
            evidence = redact_sensitive(
                {
                    "status": record.get("status"),
                    "length": record.get("length"),
                    "words": record.get("words"),
                    "lines": record.get("lines"),
                    "content_type": record.get("content-type")
                    or record.get("content_type"),
                    "redirectlocation": record.get("redirectlocation"),
                    "input": record.get("input"),
                }
            )
            if not isinstance(evidence, dict):
                evidence = {"value": evidence}
            provenance = {
                "tool": self.name,
                "tool_version": execution.version if execution else self.version(),
                "target": target,
                "command": redact_command(list(execution.command))
                if execution
                else None,
            }
            redacted_raw = redact_sensitive(record)
            findings.append(
                ToolFindingRecord(
                    source_tool=self.name,
                    source_id=url,
                    title=f"Discovered path: {url}",
                    category="external-ffuf",
                    endpoint=url,
                    severity=severity,
                    confidence=0.5,
                    status="candidate",
                    description=f"ffuf discovered {url} (HTTP {record.get('status')})",
                    evidence=evidence,
                    provenance=provenance,
                    raw=redacted_raw if isinstance(redacted_raw, dict) else {"redacted": True},
                )
            )
        return tuple(findings)
