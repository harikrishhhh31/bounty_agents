"""Optional external tool adapter architecture.

Core scanner must work without external tools. Adapters provide a stable contract for
discovery, safe scoped execution, and normalized result/provenance conversion.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Protocol, Sequence, runtime_checkable
from urllib.parse import urlsplit

try:  # Optional dependency in this codebase.
    from .safety import SafetyPolicy
except Exception:  # pragma: no cover - defensive import for isolated use.
    SafetyPolicy = Any  # type: ignore[assignment,misc]


ScopeValidator = Callable[[str, str], bool]


@dataclass(frozen=True, slots=True)
class AdapterConfig:
    """Configuration for an adapter invocation."""

    timeout_seconds: float = 30.0
    max_output_bytes: int = 1_000_000
    max_findings: int = 500
    cwd: str | None = None
    extra_args: tuple[str, ...] = ()
    env: Mapping[str, str] | None = None
    allow_network: bool = True


@dataclass(frozen=True, slots=True)
class ToolExecution:
    """Provenance for one tool execution."""

    tool: str
    version: str | None
    command: tuple[str, ...]
    cwd: str | None
    started_at: str
    finished_at: str
    duration_ms: float
    return_code: int | None
    timed_out: bool
    stdout_bytes: int
    stderr_bytes: int


@dataclass(frozen=True, slots=True)
class ToolFindingRecord:
    """Normalized findings-like record produced by an external tool."""

    source_tool: str
    source_id: str
    title: str
    category: str
    endpoint: str
    severity: str
    confidence: float
    status: str
    description: str
    evidence: dict[str, Any]
    provenance: dict[str, Any]
    raw: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class ToolRunResult:
    """Structured result from an adapter run."""

    tool: str
    available: bool
    executed: bool
    success: bool
    findings: tuple[ToolFindingRecord, ...] = ()
    errors: tuple[str, ...] = ()
    execution: ToolExecution | None = None
    raw_output: str | None = None

    def as_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["findings"] = [f.as_dict() for f in self.findings]
        return data


class AdapterError(ValueError):
    """Base error for adapter validation/configuration issues."""


class InputValidationError(AdapterError):
    pass


class ScopeValidationError(AdapterError):
    pass


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def is_safe_url_target(target: str) -> bool:
    parsed = urlsplit(target)
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


def validate_target_url(target: str) -> str:
    if not isinstance(target, str) or not target.strip():
        raise InputValidationError("target must be a non-empty URL string")
    value = target.strip()
    if "\x00" in value or any(ch.isspace() for ch in value):
        raise InputValidationError("target URL must not contain whitespace/control characters")
    if not is_safe_url_target(value):
        raise InputValidationError("target must be an http(s) URL with a host")
    return value


def _coerce_scope_validator(scope: SafetyPolicy | ScopeValidator | None) -> ScopeValidator | None:
    if scope is None:
        return None
    if callable(scope) and not hasattr(scope, "check"):
        return scope  # type: ignore[return-value]

    def _validator(target: str, method: str = "GET") -> bool:
        check = getattr(scope, "check", None)
        if callable(check):
            try:
                decision = check(target, method=method)
            except TypeError:
                decision = check(target)
            return bool(getattr(decision, "allowed", decision))
        authorize = getattr(scope, "authorize_target", None)
        if callable(authorize):
            return bool(authorize(target))
        return False

    return _validator


def validate_scope(
    target: str,
    *,
    scope: SafetyPolicy | ScopeValidator | None = None,
    method: str = "GET",
) -> str:
    value = validate_target_url(target)
    validator = _coerce_scope_validator(scope)
    if validator is not None and not validator(value, method):
        raise ScopeValidationError(f"target is outside authorized scope: {value}")
    return value


def discover_executable(names: Sequence[str]) -> str | None:
    for name in names:
        if not name:
            continue
        found = shutil.which(name)
        if found:
            return found
    return None


def run_subprocess(
    args: Sequence[str],
    *,
    timeout_seconds: float,
    cwd: str | None = None,
    env: Mapping[str, str] | None = None,
    max_output_bytes: int = 1_000_000,
) -> tuple[int | None, str, str, bool, float]:
    """Run a command safely without a shell and with timeout/output budgets."""

    if not args or not all(isinstance(a, str) and a for a in args):
        raise InputValidationError("command arguments must be a non-empty sequence of strings")
    started = time.monotonic()
    timed_out = False
    try:
        proc = subprocess.run(
            list(args),
            shell=False,
            cwd=cwd,
            env=dict(env) if env is not None else None,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_seconds if timeout_seconds and timeout_seconds > 0 else None,
        )
        stdout = proc.stdout or ""
        stderr = proc.stderr or ""
        return_code: int | None = proc.returncode
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        stdout = (exc.stdout or "") if isinstance(exc.stdout, str) else (exc.stdout or b"").decode("utf-8", "replace")
        stderr = (exc.stderr or "") if isinstance(exc.stderr, str) else (exc.stderr or b"").decode("utf-8", "replace")
        return_code = None
    except FileNotFoundError as exc:
        raise AdapterError(f"executable not found: {args[0]}") from exc
    except OSError as exc:
        raise AdapterError(f"failed to execute {args[0]}: {exc.__class__.__name__}") from exc
    duration_ms = (time.monotonic() - started) * 1000.0
    if max_output_bytes > 0:
        stdout = stdout.encode("utf-8", "replace")[:max_output_bytes].decode("utf-8", "replace")
        stderr = stderr.encode("utf-8", "replace")[:max_output_bytes].decode("utf-8", "replace")
    return return_code, stdout, stderr, timed_out, duration_ms


def _truncate(s: str | None, limit: int = 4000) -> str | None:
    if s is None:
        return None
    if len(s) <= limit:
        return s
    return s[:limit] + "...<truncated>"


# Shared redaction vocabulary. External tools frequently echo credentials in
# headers, query strings, or their command lines; adapters must never persist
# those values into findings or evidence.
_SENSITIVE_KEY_TOKENS = (
    "authorization",
    "cookie",
    "set-cookie",
    "token",
    "secret",
    "password",
    "api-key",
    "apikey",
    "x-api-key",
    "proxy-authorization",
    "credential",
)
_SENSITIVE_VALUE_MARKERS = (
    "authorization:",
    "cookie:",
    "set-cookie:",
    "x-api-key:",
    "token=",
    "api_key=",
    "apikey=",
    "password=",
)


def redact_sensitive(value: Any, key_hint: str = "") -> Any:
    """Recursively redact credential-like values from tool output.

    Strings under a sensitive key name are replaced wholesale; otherwise common
    ``key=value``/``Header:`` credential markers are scrubbed. Long strings are
    truncated to keep persisted evidence bounded.
    """

    if isinstance(value, dict):
        return {str(k): redact_sensitive(v, str(k)) for k, v in value.items()}
    if isinstance(value, list):
        return [redact_sensitive(v, key_hint) for v in value]
    if isinstance(value, tuple):
        return [redact_sensitive(v, key_hint) for v in value]
    if isinstance(value, str):
        lowered = (key_hint or "").lower()
        if any(token in lowered for token in _SENSITIVE_KEY_TOKENS):
            return "[REDACTED]"
        redacted = value
        for marker in _SENSITIVE_VALUE_MARKERS:
            if marker in redacted.lower():
                redacted = "[REDACTED]"
                break
        return redacted[:4000]
    return value


def redact_command(command: Sequence[str] | None) -> list[str] | None:
    """Redact credential-like fragments from a recorded argv."""

    if command is None:
        return None
    redacted: list[str] = []
    redact_next = False
    for part in command:
        if redact_next:
            redacted.append("[REDACTED]")
            redact_next = False
            continue
        lowered = part.lower()
        # A single argv token can embed a credential, e.g. 'Authorization: Bearer abc'
        # or 'X-Api-Key: abc' (common when a header is passed as one -H argument).
        head, sep, _ = part.partition(":")
        if sep and any(t in head.lower() for t in ("authorization", "cookie", "api-key", "apikey", "x-api-key", "token", "secret", "password", "credential")):
            redacted.append(f"{head}: [REDACTED]")
            continue
        if any(t in lowered for t in ("token", "secret", "password", "authorization", "cookie", "apikey", "api-key")) and "=" not in part:
            redacted.append(part)
            redact_next = True
        elif any(t in lowered for t in ("token=", "secret=", "password=", "authorization=", "cookie=", "apikey=", "api-key=", "api_key=", "credential=")):
            key = part.split("=", 1)[0]
            redacted.append(f"{key}=[REDACTED]")
        else:
            redacted.append(part)
    return redacted


@runtime_checkable
class ToolAdapter(Protocol):
    """Adapter contract for optional external tools."""

    name: str

    def version(self) -> str | None:
        ...

    def availability(self) -> bool:
        ...

    def validate_input(self, targets: Sequence[str], config: AdapterConfig | None = None) -> tuple[str, ...]:
        ...

    def validate_scope(
        self,
        targets: Sequence[str],
        *,
        scope: SafetyPolicy | ScopeValidator | None = None,
        method: str = "GET",
    ) -> tuple[str, ...]:
        ...

    def build_command(self, target: str, config: AdapterConfig | None = None) -> tuple[str, ...]:
        ...

    def parse_output(self, stdout: str, stderr: str = "") -> list[dict[str, Any]]:
        ...

    def normalize_results(
        self,
        raw_items: Iterable[Mapping[str, Any]],
        *,
        target: str,
        execution: ToolExecution | None = None,
    ) -> tuple[ToolFindingRecord, ...]:
        ...

    def run(
        self,
        targets: Sequence[str],
        *,
        config: AdapterConfig | None = None,
        scope: SafetyPolicy | ScopeValidator | None = None,
    ) -> ToolRunResult:
        ...


class BaseSubprocessAdapter:
    """Shared implementation for safe subprocess-based adapters."""

    name: str = "base"
    executable_names: tuple[str, ...] = ()

    def __init__(self, executable: str | None = None):
        self._executable_override = executable
        self._version_cache: str | None = None
        self._version_checked = False

    def resolve_executable(self) -> str | None:
        return self._executable_override or discover_executable(self.executable_names)

    def availability(self) -> bool:
        return self.resolve_executable() is not None

    def version(self) -> str | None:
        if self._version_checked:
            return self._version_cache
        self._version_checked = True
        exe = self.resolve_executable()
        if not exe:
            self._version_cache = None
            return None
        try:
            code, out, err, timed_out, _ = run_subprocess(
                self.version_command(exe), timeout_seconds=5.0, max_output_bytes=20000
            )
        except AdapterError:
            self._version_cache = None
            return None
        if timed_out or code not in (0, None):
            text = (out or err).strip()
        else:
            text = (out or err).strip()
        self._version_cache = (text.splitlines()[0].strip() if text else None) or None
        return self._version_cache

    def version_command(self, executable: str) -> tuple[str, ...]:
        return (executable, "--version")

    def configuration(self, config: AdapterConfig | None = None) -> dict[str, Any]:
        cfg = config or AdapterConfig()
        return {
            "name": self.name,
            "executable": self.resolve_executable(),
            "version": self.version(),
            "available": self.availability(),
            "config": asdict(cfg),
        }

    def validate_input(self, targets: Sequence[str], config: AdapterConfig | None = None) -> tuple[str, ...]:
        if targets is None or isinstance(targets, (str, bytes)):
            raise InputValidationError("targets must be a sequence of target strings")
        values = tuple(validate_target_url(t) for t in targets)
        if not values:
            raise InputValidationError("at least one target is required")
        cfg = config or AdapterConfig()
        if cfg.timeout_seconds <= 0:
            raise InputValidationError("timeout_seconds must be greater than 0")
        if cfg.max_output_bytes <= 0 or cfg.max_findings <= 0:
            raise InputValidationError("resource budgets must be positive")
        for arg in cfg.extra_args:
            if not isinstance(arg, str) or not arg:
                raise InputValidationError("extra_args must contain non-empty strings")
            if "\x00" in arg:
                raise InputValidationError("extra_args must not contain control characters")
        return values

    def validate_scope(
        self,
        targets: Sequence[str],
        *,
        scope: SafetyPolicy | ScopeValidator | None = None,
        method: str = "GET",
    ) -> tuple[str, ...]:
        return tuple(validate_scope(t, scope=scope, method=method) for t in targets)

    def build_command(self, target: str, config: AdapterConfig | None = None) -> tuple[str, ...]:  # pragma: no cover - abstract
        raise NotImplementedError

    def output_file(self, command: Sequence[str], config: AdapterConfig) -> str | None:
        """Optional path a tool writes machine-readable output to.

        Tools that only emit reports to a file (e.g. ZAP ``-J``, ffuf ``-o``)
        override this to return the report path referenced by ``build_command``.
        The base runner reads it after execution and feeds it to ``parse_output``.
        """
        return None

    def _resolve_output_file(self, command: Sequence[str], config: AdapterConfig, stdout: str) -> str:
        try:
            output_path = self.output_file(command, config)
        except Exception:
            output_path = None
        if not output_path:
            return stdout
        try:
            file_text = Path(output_path).read_text(encoding="utf-8", errors="replace")
        except OSError:
            return stdout
        return file_text if file_text.strip() else stdout

    def parse_output(self, stdout: str, stderr: str = "") -> list[dict[str, Any]]:  # pragma: no cover - abstract
        raise NotImplementedError

    def normalize_results(
        self,
        raw_items: Iterable[Mapping[str, Any]],
        *,
        target: str,
        execution: ToolExecution | None = None,
    ) -> tuple[ToolFindingRecord, ...]:  # pragma: no cover - abstract
        raise NotImplementedError

    def run(
        self,
        targets: Sequence[str],
        *,
        config: AdapterConfig | None = None,
        scope: SafetyPolicy | ScopeValidator | None = None,
    ) -> ToolRunResult:
        cfg = config or AdapterConfig()
        try:
            validated = self.validate_input(targets, cfg)
            scoped = self.validate_scope(validated, scope=scope)
        except AdapterError as exc:
            return ToolRunResult(
                tool=self.name,
                available=self.availability(),
                executed=False,
                success=False,
                errors=(str(exc),),
            )

        exe = self.resolve_executable()
        version = self.version()
        if not exe:
            return ToolRunResult(
                tool=self.name,
                available=False,
                executed=False,
                success=False,
                errors=(f"{self.name} binary not found; skipping optional external scan",),
            )

        all_findings: list[ToolFindingRecord] = []
        errors: list[str] = []
        executions: list[ToolExecution] = []
        combined_output: list[str] = []
        overall_success = True
        executed_any = False

        for target in scoped:
            command = self.build_command(target, cfg)
            started_at = _utc_now()
            mono = time.monotonic()
            timed_out = False
            return_code: int | None = None
            stdout = stderr = ""
            try:
                return_code, stdout, stderr, timed_out, duration_ms = run_subprocess(
                    command,
                    timeout_seconds=cfg.timeout_seconds,
                    cwd=cfg.cwd,
                    env=cfg.env,
                    max_output_bytes=cfg.max_output_bytes,
                )
            except AdapterError as exc:
                duration_ms = (time.monotonic() - mono) * 1000.0
                errors.append(str(exc))
                overall_success = False
                executions.append(
                    ToolExecution(
                        tool=self.name,
                        version=version,
                        command=tuple(command),
                        cwd=cfg.cwd,
                        started_at=started_at,
                        finished_at=_utc_now(),
                        duration_ms=duration_ms,
                        return_code=None,
                        timed_out=False,
                        stdout_bytes=0,
                        stderr_bytes=0,
                    )
                )
                continue

            executed_any = True
            finished_at = _utc_now()
            execution = ToolExecution(
                tool=self.name,
                version=version,
                command=tuple(command),
                cwd=cfg.cwd,
                started_at=started_at,
                finished_at=finished_at,
                duration_ms=duration_ms,
                return_code=return_code,
                timed_out=timed_out,
                stdout_bytes=len(stdout.encode("utf-8", "replace")),
                stderr_bytes=len(stderr.encode("utf-8", "replace")),
            )
            executions.append(execution)
            # File-emitting tools (ZAP -J, ffuf -o, ...) write results to disk rather
            # than stdout; resolve that report before parsing so it is not lost.
            effective_stdout = self._resolve_output_file(command, cfg, stdout)
            combined_output.append(effective_stdout)

            if timed_out:
                overall_success = False
                errors.append(f"{self.name} timed out for target {target}")
                continue
            if return_code not in (0, None):
                # Nuclei and similar tools may use non-zero in some modes; parse first, then decide.
                parsed_for_error_check = []
                try:
                    parsed_for_error_check = self.parse_output(effective_stdout, stderr)
                except Exception:
                    parsed_for_error_check = []
                if not parsed_for_error_check:
                    overall_success = False
                    msg = stderr.strip() or effective_stdout.strip() or f"exit code {return_code}"
                    errors.append(f"{self.name} execution failed for {target}: {msg.splitlines()[0]}")
                    continue
            try:
                raw_items = self.parse_output(effective_stdout, stderr)
                findings = list(self.normalize_results(raw_items, target=target, execution=execution))
                if cfg.max_findings and len(all_findings) + len(findings) > cfg.max_findings:
                    remaining = max(cfg.max_findings - len(all_findings), 0)
                    findings = findings[:remaining]
                    errors.append(f"{self.name} finding limit reached ({cfg.max_findings})")
                all_findings.extend(findings)
            except Exception as exc:  # Parsing/normalization must not be treated as successful scan results.
                overall_success = False
                errors.append(f"{self.name} output handling failed for {target}: {exc.__class__.__name__}")

        # success means executions completed without adapter/tool failures; empty findings can still be success.
        success = executed_any and overall_success and not errors
        return ToolRunResult(
            tool=self.name,
            available=True,
            executed=executed_any,
            success=success,
            findings=tuple(all_findings),
            errors=tuple(errors),
            execution=executions[-1] if executions else None,
            raw_output=_truncate("\n".join(part for part in combined_output if part)) if combined_output else None,
        )


class NucleiAdapter(BaseSubprocessAdapter):
    """Optional adapter for ProjectDiscovery Nuclei."""

    name = "nuclei"
    executable_names = ("nuclei", "nuclei.exe")
    _ALLOWED_EXTRA_FLAGS = {
        "-tags", "-exclude-tags", "-severity", "-exclude-severity",
        "-author", "-exclude-id", "-id", "-type",
        "-rate-limit", "-rl", "-concurrency", "-c", "-bulk-size", "-bs",
        "-retries", "-max-host-error", "-no-mhe", "-disable-redirects",
        "-follow-redirects", "-fr", "-max-redirects", "-mr",
        "-timeout", "-passive", "-headless=false",
    }
    _FORBIDDEN_EXTRA_PREFIXES = ("-u", "-target", "-l", "-list", "-t", "-templates", "-template-url", "-w", "-workflows", "-config", "-rc", "-report", "-markdown-export", "-sarif-export", "-json-export", "-jsonl-export", "-o", "-output", "-cloud", "-auth", "-env-vars", "-duc", "-interactsh", "-iserver", "-itoken")
    _SENSITIVE_KEY_TOKENS = ("authorization", "cookie", "set-cookie", "token", "secret", "password", "api-key", "apikey", "x-api-key", "proxy-authorization", "credential")

    def version_command(self, executable: str) -> tuple[str, ...]:
        return (executable, "-version")

    @classmethod
    def _is_allowed_extra_arg(cls, arg: str) -> bool:
        if not isinstance(arg, str) or not arg or "\x00" in arg or any(ch.isspace() for ch in arg):
            return False
        lowered = arg.lower()
        for bad in cls._FORBIDDEN_EXTRA_PREFIXES:
            if lowered == bad or lowered.startswith(bad + "="):
                return False
        if lowered.startswith("-"):
            flag = lowered.split("=", 1)[0]
            return flag in cls._ALLOWED_EXTRA_FLAGS
        # allow value tokens (conservative: simple chars only)
        return all(ch.isalnum() or ch in "._:/,-@" for ch in arg)

    @classmethod
    def _sanitize_extra_args(cls, extra_args: Sequence[str]) -> tuple[str, ...]:
        safe: list[str] = []
        for extra in extra_args:
            if not cls._is_allowed_extra_arg(extra):
                raise InputValidationError(f"unsupported or unsafe nuclei extra arg: {extra}")
            safe.append(extra)
        return tuple(safe)

    @classmethod
    def _redact_value(cls, value: Any, key_hint: str = "") -> Any:
        return redact_sensitive(value, key_hint)

    @classmethod
    def _redacted_command(cls, command: Sequence[str] | None) -> list[str] | None:
        return redact_command(command)

    def validate_input(self, targets: Sequence[str], config: AdapterConfig | None = None) -> tuple[str, ...]:
        values = super().validate_input(targets, config)
        cfg = config or AdapterConfig()
        self._sanitize_extra_args(tuple(cfg.extra_args))
        return values

    def build_command(self, target: str, config: AdapterConfig | None = None) -> tuple[str, ...]:
        cfg = config or AdapterConfig()
        exe = self.resolve_executable() or self.executable_names[0]
        safe_target = validate_target_url(target)
        args: list[str] = [exe, "-u", safe_target, "-jsonl", "-silent", "-no-color"]
        args.extend(["-timeout", str(max(1, int(min(cfg.timeout_seconds, 30))))])
        args.extend(self._sanitize_extra_args(tuple(cfg.extra_args)))
        return tuple(args)

    def parse_output(self, stdout: str, stderr: str = "") -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        for line in (stdout or "").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict):
                items.append(obj)
        return items

    def normalize_results(
        self,
        raw_items: Iterable[Mapping[str, Any]],
        *,
        target: str,
        execution: ToolExecution | None = None,
    ) -> tuple[ToolFindingRecord, ...]:
        findings: list[ToolFindingRecord] = []
        for item in raw_items:
            info = item.get("info") if isinstance(item.get("info"), Mapping) else {}
            template_id = str(item.get("template-id") or item.get("templateID") or item.get("template") or "unknown")
            name = str(info.get("name") or template_id)
            severity = str(info.get("severity") or "info").lower()
            matched = str(item.get("matched-at") or item.get("matched") or item.get("host") or target)
            description = str(info.get("description") or info.get("name") or "Nuclei template matched")
            matcher_name = item.get("matcher-name") or item.get("matcher_name")
            extracted = self._redact_value(item.get("extracted-results") or item.get("extracted_results"), "extracted_results")
            evidence = {
                "matched_at": matched,
                "matcher_name": matcher_name,
                "extracted_results": extracted,
                "type": item.get("type"),
                "request": "[REDACTED]" if item.get("request") is not None else None,
                "response": "[REDACTED]" if item.get("response") is not None else None,
                "curl_command": "[REDACTED]" if (item.get("curl-command") or item.get("curl_command")) is not None else None,
            }
            provenance = {
                "tool": self.name,
                "tool_version": execution.version if execution else self.version(),
                "template_id": template_id,
                "template_path": item.get("template-path") or item.get("template"),
                "target": target,
                "timestamp": item.get("timestamp") or (execution.finished_at if execution else _utc_now()),
                "command": self._redacted_command(list(execution.command) if execution else None),
            }
            redacted_raw = self._redact_value(dict(item))
            if isinstance(redacted_raw, dict):
                for k in ("request", "response", "curl-command", "curl_command"):
                    if k in redacted_raw and redacted_raw[k] is not None:
                        redacted_raw[k] = "[REDACTED]"
            findings.append(
                ToolFindingRecord(
                    source_tool=self.name,
                    source_id=template_id,
                    title=name,
                    category="external-nuclei",
                    endpoint=matched,
                    severity=severity,
                    confidence=0.7 if severity in {"critical", "high", "medium"} else 0.5,
                    status="candidate",
                    description=description,
                    evidence=evidence,
                    provenance=provenance,
                    raw=redacted_raw if isinstance(redacted_raw, dict) else {"redacted": True},
                )
            )
        return tuple(findings)


# Registry of every supported optional external tool. Modules are imported lazily
# so a missing/partially-installed adapter can never break the core scanner or the
# rest of the registry.
_ADAPTER_REGISTRY: dict[str, tuple[str, str]] = {
    "nuclei": (__name__, "NucleiAdapter"),
    "zap": ("bugbounty.adapters_zap", "ZapAdapter"),
    "burp": ("bugbounty.adapters_burp", "BurpAdapter"),
    "schemathesis": ("bugbounty.adapters_schemathesis", "SchemathesisAdapter"),
    "restler": ("bugbounty.adapters_restler", "RestlerAdapter"),
    "ffuf": ("bugbounty.adapters_ffuf", "FfufAdapter"),
    "kiterunner": ("bugbounty.adapters_kiterunner", "KiterunnerAdapter"),
}


def known_adapter_names() -> tuple[str, ...]:
    """Return the names of every registered external tool adapter."""

    return tuple(_ADAPTER_REGISTRY)


def _load_adapter_class(name: str) -> type[Any]:
    key = (name or "").strip().lower()
    if key not in _ADAPTER_REGISTRY:
        raise AdapterError(f"unknown adapter: {name}")
    module_name, class_name = _ADAPTER_REGISTRY[key]
    import importlib

    module = importlib.import_module(module_name)
    adapter_class = getattr(module, class_name)
    return adapter_class  # type: ignore[no-any-return]


def available_adapters() -> dict[str, bool]:
    """Detect availability of known optional adapters.

    An adapter that cannot be imported is reported as unavailable rather than
    raising, so the registry is resilient to partially installed tooling.
    """

    result: dict[str, bool] = {}
    for name in _ADAPTER_REGISTRY:
        try:
            adapter_class = _load_adapter_class(name)
            result[name] = bool(adapter_class().availability())
        except Exception:
            result[name] = False
    return result


def get_adapter(name: str, **kwargs: Any) -> ToolAdapter:
    adapter_class = _load_adapter_class(name)
    return adapter_class(**kwargs)  # type: ignore[no-any-return]


__all__ = [
    "AdapterConfig",
    "AdapterError",
    "BaseSubprocessAdapter",
    "InputValidationError",
    "NucleiAdapter",
    "ScopeValidationError",
    "ToolExecution",
    "ToolFindingRecord",
    "ToolRunResult",
    "available_adapters",
    "discover_executable",
    "get_adapter",
    "is_safe_url_target",
    "known_adapter_names",
    "redact_command",
    "redact_sensitive",
    "run_subprocess",
    "validate_scope",
    "validate_target_url",
]
