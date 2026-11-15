"""External tool adapter for Assetnote Kiterunner (``kr``).

Kiterunner is a contextual content-discovery tool that brute-forces API
routes from a compiled ``.kite`` wordlist. This module wraps the ``kr``
binary behind the shared :class:`~bugbounty.tool_adapters.BaseSubprocessAdapter`
contract so the rest of the platform can invoke it as an optional external
scanner without taking a hard dependency on it.

Exact CLI form used by :meth:`KiterunnerAdapter.build_command`::

    kr scan <target> -w <kite> -o json -q [extra_args...]

Flags (matching the real ``kr`` CLI):

* ``scan``   - the Kiterunner sub-command for API route scanning.
* ``<target>`` - a single validated ``http(s)`` URL (``kr`` also accepts host
  files/domains, but the engine feeds URL targets).
* ``-w <kite>`` - the compiled kite wordlist path (required; supplied through
  ``AdapterConfig.extra_args`` as ``("-w", "<path>")``). Only ever emitted once.
* ``-o json`` - select Kiterunner's machine-readable JSON output. ``-o/--output``
  is an output *format* selector (``json|text|pretty``), not a file path.
* ``-q``     - quiet mode (mutes the pretty banner so stdout stays parseable).

Kiterunner writes results to stdout, so :meth:`output_file` returns ``None`` and
:meth:`parse_output` consumes stdout directly. It understands both the JSON
output and the ``pretty``/``text`` result lines such as
``POST    403 [    287,   10,   1] https://host/path <hash>``.

The wordlist path is resolved from ``extra_args``; any other ``extra_args``
(e.g. ``-x 20``) are appended verbatim. Extra arguments are validated by the
base class (non-empty strings, no control characters) and are always passed as
argv entries - a shell is never used.
"""

from __future__ import annotations

import json
import re
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

__all__ = ["KiterunnerAdapter"]

_WORDLIST_ERROR = "kiterunner requires a kite wordlist via extra_args: -w <path>"

# ``<METHOD> <status> <rest>`` where ``rest`` is parsed further. Kept permissive
# (2-10 letters, exactly three status digits) so malformed lines are skipped
# rather than mis-parsed.
_METHOD_STATUS_RE = re.compile(r"^(?P<method>[A-Za-z]{2,10})\s+(?P<status>\d{3})\s+(?P<rest>.+?)\s*$")

# Leading bracketed length list, e.g. ``[ 287, 10, 1]`` (real kiterunner output).
_BRACKET_LENGTHS_RE = re.compile(r"^\[(?P<lens>[^\]]*)\]\s*(?P<tail>.*)$")

# A trailing opaque request hash, e.g. a 40-char sha1, which is not a route field.
_HASH_RE = re.compile(r"^[0-9a-fA-F]{16,}$")

_URL_SCHEMES = ("http://", "https://")


def _first_present(mapping: Mapping[str, Any], keys: Sequence[str]) -> Any:
    for key in keys:
        if key in mapping:
            value = mapping[key]
            if value is not None and value != "":
                return value
    return None


class KiterunnerAdapter(BaseSubprocessAdapter):
    """Adapter for the Kiterunner (``kr``) API route scanner."""

    name = "kiterunner"
    executable_names = ("kr", "kr.exe", "kiterunner", "kiterunner.exe")

    # ------------------------------------------------------------------
    # Version / discovery
    # ------------------------------------------------------------------
    def version_command(self, executable: str) -> tuple[str, ...]:
        return (executable, "--version")

    # ------------------------------------------------------------------
    # Input validation
    # ------------------------------------------------------------------
    @staticmethod
    def _split_wordlist_args(extra_args: Sequence[str]) -> tuple[str | None, list[str]]:
        """Return ``(kite_path, residual_args)`` from ``extra_args``.

        Recognises both ``-w <path>`` and ``-w=<path>``. The ``-w`` token is
        removed from the residual so it is never emitted twice.
        """

        kite: str | None = None
        residual: list[str] = []
        index = 0
        total = len(extra_args)
        while index < total:
            arg = extra_args[index]
            if arg == "-w":
                if index + 1 < total:
                    kite = extra_args[index + 1]
                    index += 2
                    continue
                index += 1
                continue
            if arg.startswith("-w="):
                kite = arg[3:]
                index += 1
                continue
            residual.append(arg)
            index += 1
        return (kite or None), residual

    def validate_input(self, targets: Sequence[str], config: AdapterConfig | None = None) -> tuple[str, ...]:
        values = super().validate_input(targets, config)
        cfg = config or AdapterConfig()
        kite, _ = self._split_wordlist_args(tuple(cfg.extra_args))
        if not kite:
            raise InputValidationError(_WORDLIST_ERROR)
        return values

    # ------------------------------------------------------------------
    # Command construction
    # ------------------------------------------------------------------
    def build_command(self, target: str, config: AdapterConfig | None = None) -> tuple[str, ...]:
        cfg = config or AdapterConfig()
        exe = self.resolve_executable() or self.executable_names[0]
        safe_target = validate_target_url(target)
        kite, residual = self._split_wordlist_args(tuple(cfg.extra_args))
        if not kite:
            raise InputValidationError(_WORDLIST_ERROR)
        args: list[str] = [exe, "scan", safe_target, "-w", kite, "-o", "json", "-q"]
        args.extend(residual)
        return tuple(args)

    # ------------------------------------------------------------------
    # Output handling
    # ------------------------------------------------------------------
    def output_file(self, command: Sequence[str], config: AdapterConfig) -> str | None:
        # Kiterunner writes results to stdout (``-o`` selects the format, not a
        # file path), so there is no report file for the base runner to read.
        return None

    @staticmethod
    def _to_int_or_none(value: Any) -> int | None:
        if value is None or isinstance(value, bool):
            return None
        if isinstance(value, int):
            return value
        text = str(value).strip()
        if not text:
            return None
        try:
            return int(text)
        except ValueError:
            return None

    @classmethod
    def _to_int_or_str(cls, value: Any) -> Any:
        parsed = cls._to_int_or_none(value)
        return parsed if parsed is not None else value

    @classmethod
    def _severity_for_status(cls, status: Any) -> str:
        code = cls._to_int_or_none(status)
        if code is None:
            return "info"
        if 200 <= code <= 299:
            return "info"
        if code in (401, 403):
            return "low"
        if 500 <= code <= 599:
            return "medium"
        return "info"

    @classmethod
    def _coerce_record(cls, obj: Mapping[str, Any]) -> dict[str, Any] | None:
        """Normalize a JSON-ish record into the canonical route shape."""

        if not isinstance(obj, Mapping):
            return None
        method = _first_present(obj, ("method", "Method", "http_method", "verb"))
        status = _first_present(obj, ("status", "StatusCode", "status_code", "statusCode", "code"))
        length = _first_present(obj, ("length", "Length", "content_length", "contentLength", "size", "bytes"))
        url = _first_present(obj, ("url", "URL", "Url", "endpoint", "path", "route", "uri"))
        content_type = _first_present(obj, ("content_type", "content-type", "ContentType", "mime", "mime_type"))
        if url is None and status is None:
            return None
        record: dict[str, Any] = dict(obj)
        if method is not None:
            record["method"] = str(method).upper()
        if status is not None:
            record["status"] = cls._to_int_or_str(status)
        if length is not None:
            record["length"] = cls._to_int_or_none(length)
        if url is not None:
            record["url"] = str(url)
        if content_type is not None:
            record["content_type"] = str(content_type)
        return record

    @classmethod
    def _parse_text_line(cls, line: str) -> dict[str, Any] | None:
        match = _METHOD_STATUS_RE.match(line)
        if not match:
            return None
        method = match.group("method").upper()
        status = cls._to_int_or_str(match.group("status"))
        rest = match.group("rest").strip()
        if not rest:
            return None

        length: Any = None
        bracket = _BRACKET_LENGTHS_RE.match(rest)
        if bracket:
            first_len = re.search(r"\d+", bracket.group("lens"))
            if first_len:
                length = cls._to_int_or_none(first_len.group(0))
            rest = bracket.group("tail").strip()

        url: str | None = None
        content_type: str | None = None
        for token in rest.split():
            if url is None and token.startswith(_URL_SCHEMES):
                url = token
                continue
            if length is None and token.isdigit():
                length = cls._to_int_or_none(token)
                continue
            if token.startswith("[") and token.endswith("]"):
                inner = token.strip("[]")
                first_len = re.search(r"\d+", inner)
                if length is None and first_len:
                    length = cls._to_int_or_none(first_len.group(0))
                elif content_type is None and "/" in inner and not _HASH_RE.match(inner):
                    content_type = inner
                continue
            if content_type is None and "/" in token and not _HASH_RE.match(token):
                content_type = token.strip("[]")
                continue
            # Unknown trailing token (e.g. a request hash): ignore.

        if url is None:
            return None
        record: dict[str, Any] = {"method": method, "status": status, "url": url}
        if length is not None:
            record["length"] = length
        if content_type:
            record["content_type"] = content_type
        return record

    @classmethod
    def _parse_line(cls, line: str) -> dict[str, Any] | None:
        if line[:1] in ("{", "["):
            try:
                obj = json.loads(line)
            except (json.JSONDecodeError, ValueError):
                obj = None
            if isinstance(obj, Mapping):
                record = cls._coerce_record(obj)
                if record is not None:
                    return record
        return cls._parse_text_line(line)

    def parse_output(self, stdout: str, stderr: str = "") -> list[dict[str, Any]]:
        """Parse Kiterunner results from the report file or stdout.

        Supports whole-document JSON (array or object), JSON-lines records, and
        the text result lines ``<METHOD> <status> <length> <url>`` as well as
        real Kiterunner lines such as ``POST 403 [ 287, 10, 1] <url> <hash>``.
        Never raises; unparseable or empty input yields ``[]``.
        """

        items: list[dict[str, Any]] = []
        text = stdout or ""
        stripped = text.strip()
        if not stripped:
            return items

        if stripped[:1] in ("[", "{"):
            try:
                document = json.loads(stripped)
            except (json.JSONDecodeError, ValueError):
                document = None
            if isinstance(document, list):
                for entry in document:
                    if isinstance(entry, Mapping):
                        record = self._coerce_record(entry)
                        if record is not None:
                            items.append(record)
                return items
            if isinstance(document, Mapping):
                record = self._coerce_record(document)
                if record is not None:
                    items.append(record)
                return items

        for raw_line in text.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            try:
                record = self._parse_line(line)
            except Exception:  # Defensive: parsing must never abort a scan.
                record = None
            if record is not None:
                items.append(record)
        return items

    # ------------------------------------------------------------------
    # Normalization
    # ------------------------------------------------------------------
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
            url = str(item.get("url") or item.get("endpoint") or target or "")
            method = item.get("method")
            status = item.get("status")
            length = item.get("length")
            content_type = item.get("content_type")
            severity = self._severity_for_status(status)

            evidence = redact_sensitive(
                {
                    "method": method,
                    "status": status,
                    "length": length,
                    "content_type": content_type,
                }
            )
            if not isinstance(evidence, dict):
                evidence = {"value": evidence}

            provenance = {
                "tool": self.name,
                "tool_version": execution.version if execution else self.version(),
                "target": target,
                "command": redact_command(list(execution.command)) if execution else None,
            }

            raw = redact_sensitive(dict(item))
            if not isinstance(raw, dict):
                raw = {"value": raw}

            method_label = f"{method} " if method else ""
            findings.append(
                ToolFindingRecord(
                    source_tool=self.name,
                    source_id=url or target,
                    title=f"Discovered API route: {url}",
                    category="external-kiterunner",
                    endpoint=url or target,
                    severity=severity,
                    confidence=0.5,
                    status="candidate",
                    description=f"Kiterunner discovered API route {method_label}{url}".strip(),
                    evidence=evidence,
                    provenance=provenance,
                    raw=raw,
                )
            )
        return tuple(findings)
