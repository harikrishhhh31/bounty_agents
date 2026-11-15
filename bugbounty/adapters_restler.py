"""External tool adapter for Microsoft RESTler (stateful REST API fuzzing).

RESTler is a stateful REST API fuzzer. Unlike content scanners that accept a
bare URL, RESTler needs a *compiled grammar* (and usually a dictionary) that
describes the API's request/response surface. This adapter therefore expects the
caller to pass those artefacts through ``AdapterConfig.extra_args``.

Required inputs (via ``AdapterConfig.extra_args``)::

    --grammar_file <path-to-compiled-grammar.py>   # RESTler compiled grammar
    --dictionary_file <path-to-dict.json>          # RESTler dictionary

The engine's target is a URL, so the adapter derives ``--target_ip`` and
``--target_port`` from it (defaulting the port to 443/80 from the scheme) and
passes them to RESTler's ``fuzz-lean`` mode. ``fuzz-lean`` runs a shorter,
less aggressive fuzzing pass than ``fuzz`` and is appropriate for scoped
bug-bounty engagements.

When no grammar/dictionary is supplied the adapter still builds a syntactically
valid command using placeholder paths rooted at ``AdapterConfig.cwd`` (it never
raises from :meth:`RestlerAdapter.build_command`); the resulting run will simply
fail to find the placeholder files, which the engine surfaces as a normal tool
failure.

Only argv-based subprocess execution is used (``shell=False``); no shell is ever
involved.
"""

from __future__ import annotations

import os
import re
from typing import Any, Iterable, Mapping, Sequence
from urllib.parse import urlsplit

from .tool_adapters import (
    AdapterConfig,
    AdapterError,
    BaseSubprocessAdapter,
    InputValidationError,
    ToolExecution,
    ToolFindingRecord,
    redact_command,
    redact_sensitive,
    run_subprocess,
)

_UUID_RE = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)
_CHECKSUM_RE = re.compile(r"checksum\s*[:=]?\s*([A-Za-z0-9._-]+)", re.IGNORECASE)
_BUCKET_RE = re.compile(r"bug\s*bucket\s*[:=]?\s*['\"]?([A-Za-z0-9._-]+)", re.IGNORECASE)
_URL_RE = re.compile(r"https?://[^\s'\"]+", re.IGNORECASE)
_PATH_RE = re.compile(r"\b(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(\S+)")
# Status codes, but not digits that are part of a timestamp/fraction (e.g. ".200").
_STATUS_RE = re.compile(r"(?<![.:\d])\b([1-5][0-9]{2})\b")
_SUMMARY_RE = re.compile(r"(\d+)\s+bug\s+buckets?\s+created", re.IGNORECASE)


class RestlerAdapter(BaseSubprocessAdapter):
    """Adapter for Microsoft RESTler ``fuzz-lean`` mode."""

    name = "restler"
    executable_names = ("restler", "restler.exe", "Restler", "Restler.exe")

    _GRAMMAR_FLAGS = ("--grammar_file", "--grammar-file", "--grammar")
    _DICTIONARY_FLAGS = ("--dictionary_file", "--dictionary-file", "--dict", "--dictionary")

    def version_command(self, executable: str) -> tuple[str, ...]:
        # RESTler has no dedicated --version flag; --help is the closest probe.
        return (executable, "--help")

    def version(self) -> str | None:
        """Return the first non-empty ``--help`` line (RESTler has no --version)."""

        if self._version_checked:
            return self._version_cache
        self._version_checked = True
        exe = self.resolve_executable()
        if not exe:
            self._version_cache = None
            return None
        try:
            _code, out, err, _timed_out, _ = run_subprocess(
                self.version_command(exe), timeout_seconds=5.0, max_output_bytes=20000
            )
        except AdapterError:
            self._version_cache = None
            return None
        text = out or err or ""
        for line in text.splitlines():
            stripped = line.strip()
            if stripped:
                self._version_cache = stripped
                return self._version_cache
        self._version_cache = None
        return None

    @classmethod
    def _split_extra_args(
        cls, extra_args: Sequence[str]
    ) -> tuple[str | None, str | None, tuple[str, ...]]:
        """Extract grammar/dictionary flags from ``extra_args``.

        Returns ``(grammar, dictionary, remaining)`` where ``remaining`` excludes
        the consumed grammar/dictionary flags so they are not duplicated in the
        final argv.
        """

        grammar: str | None = None
        dictionary: str | None = None
        remaining: list[str] = []
        args = list(extra_args)
        index = 0
        while index < len(args):
            arg = args[index]
            key, sep, inline = arg.partition("=")
            lowered = key.lower()
            if lowered in cls._GRAMMAR_FLAGS:
                if sep:
                    grammar = inline
                    index += 1
                elif index + 1 < len(args):
                    grammar = args[index + 1]
                    index += 2
                else:
                    index += 1
            elif lowered in cls._DICTIONARY_FLAGS:
                if sep:
                    dictionary = inline
                    index += 1
                elif index + 1 < len(args):
                    dictionary = args[index + 1]
                    index += 2
                else:
                    index += 1
            else:
                remaining.append(arg)
                index += 1
        return grammar, dictionary, tuple(remaining)

    @staticmethod
    def _target_host_port(target: str) -> tuple[str | None, int | None]:
        try:
            parsed = urlsplit(target)
        except (TypeError, ValueError):
            return None, None
        host = parsed.hostname or None
        try:
            port = parsed.port
        except ValueError:
            port = None
        if port is None:
            if parsed.scheme == "https":
                port = 443
            elif parsed.scheme == "http":
                port = 80
        return host, port

    def build_command(self, target: str, config: AdapterConfig | None = None) -> tuple[str, ...]:
        """Build the RESTler ``fuzz-lean`` argv.

        Required inputs (documented above) come from ``config.extra_args``:
        ``--grammar_file`` and ``--dictionary_file``. Missing values fall back to
        placeholder paths under ``config.cwd`` so this method never raises.
        """

        cfg = config or AdapterConfig()
        exe = self.resolve_executable() or self.executable_names[0]
        grammar, dictionary, remaining = self._split_extra_args(tuple(cfg.extra_args))
        base_dir = cfg.cwd or "."
        if not grammar:
            grammar = os.path.join(base_dir, "restler-grammar", "grammar.py")
        if not dictionary:
            dictionary = os.path.join(base_dir, "restler-grammar", "dict.json")

        args: list[str] = [
            exe,
            "fuzz-lean",
            "--grammar_file",
            grammar,
            "--dictionary_file",
            dictionary,
        ]

        host, port = self._target_host_port(target)
        if host:
            args.extend(["--target_ip", host])
        if port is not None:
            args.extend(["--target_port", str(port)])
        args.extend(remaining)
        return tuple(args)

    def output_file(self, command: Sequence[str], config: AdapterConfig) -> str | None:
        # RESTler reports through stdout plus its own log/bug-bucket directories;
        # parse_output consumes stdout, so there is no single report file to read.
        return None

    @staticmethod
    def _extract_bucket(line: str) -> str | None:
        match = _UUID_RE.search(line)
        if match:
            return match.group(0)
        match = _CHECKSUM_RE.search(line)
        if match:
            return match.group(1)
        match = _BUCKET_RE.search(line)
        if match:
            return match.group(1)
        return None

    @staticmethod
    def _extract_endpoint(line: str) -> str | None:
        match = _URL_RE.search(line)
        if match:
            return match.group(0)
        match = _PATH_RE.search(line)
        if match:
            return match.group(1)
        return None

    @staticmethod
    def _extract_status(line: str) -> int | None:
        codes = [int(m.group(1)) for m in _STATUS_RE.finditer(line)]
        if not codes:
            return None
        if 500 in codes:
            return 500
        for code in codes:
            if 500 <= code < 600:
                return code
        return codes[0]

    @staticmethod
    def _is_bug_line(line: str) -> bool:
        lowered = line.lower()
        if "bug bucket" in lowered or "bugbucket" in lowered:
            return True
        if "checksum" in lowered:
            return True
        if "500 internal server error" in lowered:
            return True
        if "unexpected" in lowered:
            return True
        return bool(re.search(r"\bBUG\b", line))

    @staticmethod
    def _summary(line: str) -> tuple[str, int | None] | None:
        match = _SUMMARY_RE.search(line)
        if match:
            try:
                return "created", int(match.group(1))
            except ValueError:
                return "created", None
        if "testing completed" in line.lower():
            return "completed", None
        return None

    def _bug_item_from_line(self, line: str) -> dict[str, Any]:
        lowered = line.lower()
        bucket = self._extract_bucket(line)
        endpoint = self._extract_endpoint(line)
        status_code = self._extract_status(line)
        if status_code == 500 or "500 internal server error" in lowered:
            severity = "high"
        else:
            severity = "medium"
        return {
            "bucket": bucket,
            "title": f"RESTler bug bucket {bucket}" if bucket else "RESTler bug bucket",
            "endpoint": endpoint,
            "url": endpoint,
            "status_code": status_code,
            "severity": severity,
            "detail": line,
        }

    def parse_output(self, stdout: str, stderr: str = "") -> list[dict[str, Any]]:
        """Parse RESTler ``fuzz-lean`` console output defensively.

        Recognizes explicit bug lines (markers: ``BUG`` / ``bug bucket`` /
        ``checksum`` / ``500 Internal Server Error`` / ``unexpected``) and a
        trailing summary line (``N bug buckets created`` / ``Testing completed``).
        Never raises; returns ``[]`` for empty or unparseable input.
        """

        try:
            text = "\n".join(part for part in (str(stdout or ""), str(stderr or "")) if part)
            items: list[dict[str, Any]] = []
            summary_count: int | None = None
            summary_line: str | None = None
            for raw_line in text.splitlines():
                line = raw_line.strip()
                if not line:
                    continue
                summary = self._summary(line)
                if summary is not None:
                    _kind, count = summary
                    if count is not None:
                        summary_count = max(summary_count or 0, count)
                    summary_line = line
                    continue
                if self._is_bug_line(line):
                    items.append(self._bug_item_from_line(line))
            if not items and summary_count:
                items.append(
                    {
                        "bucket": "summary",
                        "title": f"{summary_count} bug buckets created",
                        "endpoint": None,
                        "url": None,
                        "status_code": None,
                        "severity": "medium",
                        "detail": summary_line or f"{summary_count} bug buckets created",
                    }
                )
            return items
        except Exception:  # Parsing must never raise.
            return []

    def normalize_results(
        self,
        raw_items: Iterable[Mapping[str, Any]],
        *,
        target: str,
        execution: ToolExecution | None = None,
    ) -> tuple[ToolFindingRecord, ...]:
        findings: list[ToolFindingRecord] = []
        for item in raw_items:
            if not isinstance(item, Mapping):
                continue
            redacted = redact_sensitive(dict(item))
            if not isinstance(redacted, dict):
                redacted = {}

            status_value = redacted.get("status_code")
            try:
                status_code = int(status_value) if status_value is not None else None
            except (TypeError, ValueError):
                status_code = None

            if status_code == 500:
                severity = "high"
            elif status_code is not None and 500 <= status_code < 600:
                severity = "medium"
            else:
                severity = str(redacted.get("severity") or "medium").lower()

            bucket = redacted.get("bucket")
            title = str(redacted.get("title") or "RESTler bug bucket")
            endpoint = str(redacted.get("endpoint") or redacted.get("url") or target)
            detail = str(redacted.get("detail") or title)

            evidence = {
                "bucket": bucket,
                "detail": detail,
                "status_code": status_code if status_code is not None else status_value,
            }
            provenance = {
                "tool": self.name,
                "tool_version": execution.version if execution else self.version(),
                "target": target,
                "command": redact_command(list(execution.command)) if execution else None,
            }

            findings.append(
                ToolFindingRecord(
                    source_tool=self.name,
                    source_id=str(bucket or title or "restler-bug"),
                    title=title,
                    category="external-restler",
                    endpoint=endpoint,
                    severity=severity,
                    confidence=0.5,
                    status="candidate",
                    description=detail,
                    evidence=evidence,
                    provenance=provenance,
                    raw=redacted,
                )
            )
        return tuple(findings)


__all__ = ["RestlerAdapter"]
