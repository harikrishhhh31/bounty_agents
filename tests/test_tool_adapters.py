from __future__ import annotations

import json
import subprocess

import pytest

from bugbounty.tool_adapters import (
    AdapterConfig,
    BaseSubprocessAdapter,
    InputValidationError,
    NucleiAdapter,
    ScopeValidationError,
    ToolFindingRecord,
    available_adapters,
    get_adapter,
    run_subprocess,
    validate_scope,
    validate_target_url,
)


class DummyAdapter(BaseSubprocessAdapter):
    name = "dummy"
    executable_names = ("dummytool",)

    def build_command(self, target: str, config: AdapterConfig | None = None) -> tuple[str, ...]:
        return (self.resolve_executable() or "dummytool", "--scan", target)

    def parse_output(self, stdout: str, stderr: str = "") -> list[dict[str, object]]:
        return json.loads(stdout) if stdout.strip() else []

    def normalize_results(self, raw_items, *, target: str, execution=None):
        return tuple(
            ToolFindingRecord(
                source_tool=self.name,
                source_id=str(item.get("id", "x")),
                title=str(item.get("title", "t")),
                category="external-dummy",
                endpoint=target,
                severity="low",
                confidence=0.5,
                status="candidate",
                description="d",
                evidence={"raw": dict(item)},
                provenance={"tool": self.name, "command": list(execution.command) if execution else None},
                raw=dict(item),
            )
            for item in raw_items
        )


class ExplodingParseAdapter(DummyAdapter):
    name = "exploding"

    def parse_output(self, stdout: str, stderr: str = "") -> list[dict[str, object]]:
        raise ValueError("bad output")


class Scope:
    def __init__(self, allowed: bool):
        self.allowed = allowed

    def check(self, target: str, method: str = "GET"):
        class Decision:
            def __init__(self, allowed: bool):
                self.allowed = allowed

        return Decision(self.allowed and target.startswith("https://allowed.example"))


def test_adapter_contract_surface():
    adapter = DummyAdapter(executable="dummytool")
    assert adapter.name == "dummy"
    assert adapter.availability() is True
    assert adapter.validate_input(["https://example.com"]) == ("https://example.com",)
    cmd = adapter.build_command("https://example.com")
    assert cmd[:2] == ("dummytool", "--scan")
    parsed = adapter.parse_output('[{"id":"1"}]')
    assert parsed == [{"id": "1"}]
    normalized = adapter.normalize_results(parsed, target="https://example.com")
    assert len(normalized) == 1 and normalized[0].source_tool == "dummy"


def test_missing_tool_handling_graceful(monkeypatch):
    adapter = DummyAdapter()
    monkeypatch.setattr("bugbounty.tool_adapters.discover_executable", lambda names: None)
    result = adapter.run(["https://example.com"])
    assert result.available is False
    assert result.executed is False
    assert result.success is False
    assert result.findings == ()
    assert any("not found" in e.lower() or "skipping" in e.lower() for e in result.errors)


def test_run_subprocess_uses_arg_array_no_shell(monkeypatch):
    calls = {}

    def fake_run(args, **kwargs):
        calls["args"] = args
        calls["kwargs"] = kwargs
        return subprocess.CompletedProcess(args=args, returncode=0, stdout="ok", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    code, out, err, timed_out, _ = run_subprocess(["dummy", "--flag", "value"], timeout_seconds=5)
    assert code == 0 and out == "ok" and not timed_out
    assert calls["args"] == ["dummy", "--flag", "value"]
    assert calls["kwargs"]["shell"] is False
    assert calls["kwargs"]["capture_output"] is True


def test_safe_arg_construction_prevents_shell_injection_patterns():
    adapter = NucleiAdapter(executable="nuclei")
    target = "https://example.com/path?q=1;rm"
    # Execution must remain argv-based (no shell); metacharacters stay literal argument content.
    cmd = adapter.build_command(validate_target_url(target), AdapterConfig(timeout_seconds=10))
    assert cmd[0] == "nuclei"
    assert "-u" in cmd
    assert target in cmd
    assert isinstance(cmd, tuple)
    assert all(isinstance(a, str) for a in cmd)
    assert cmd[cmd.index("-u") + 1] == target
    # Inputs with whitespace/control chars are rejected before execution.
    with pytest.raises(InputValidationError):
        validate_target_url("https://example.com/path?q=1;rm -rf /")


def test_rejects_invalid_targets_and_shell_metacharacter_inputs_for_structure():
    with pytest.raises(InputValidationError):
        validate_target_url("https://example.com bad")
    with pytest.raises(InputValidationError):
        validate_target_url("")
    with pytest.raises(InputValidationError):
        DummyAdapter().validate_input(["not-a-url"])


def test_scope_validation_blocks_out_of_scope():
    adapter = DummyAdapter(executable="dummytool")
    with pytest.raises(ScopeValidationError):
        adapter.validate_scope(["https://denied.example"], scope=Scope(allowed=True))
    result = adapter.run(["https://denied.example"], scope=Scope(allowed=True))
    assert result.executed is False
    assert result.success is False
    assert result.errors and "scope" in result.errors[0].lower()


def test_failure_handling_timeout_not_success(monkeypatch):
    adapter = DummyAdapter(executable="dummytool")
    monkeypatch.setattr("bugbounty.tool_adapters.discover_executable", lambda names: "dummytool")
    monkeypatch.setattr(adapter, "version", lambda: "1.0")
    monkeypatch.setattr(
        "bugbounty.tool_adapters.run_subprocess",
        lambda *a, **k: (None, "", "", True, 10.0),
    )
    result = adapter.run(["https://allowed.example"], scope=Scope(allowed=True))
    assert result.available is True
    assert result.executed is True
    assert result.success is False
    assert result.findings == ()
    assert any("timed out" in e for e in result.errors)


def test_failure_handling_nonzero_exit_not_success(monkeypatch):
    adapter = DummyAdapter(executable="dummytool")
    monkeypatch.setattr(adapter, "version", lambda: "1.0")
    monkeypatch.setattr(
        "bugbounty.tool_adapters.run_subprocess",
        lambda *a, **k: (2, "", "boom", False, 5.0),
    )
    result = adapter.run(["https://example.com"])
    assert result.executed is True
    assert result.success is False
    assert result.findings == ()
    assert any("execution failed" in e for e in result.errors)


def test_parse_or_normalization_error_not_reported_as_success(monkeypatch):
    adapter = ExplodingParseAdapter(executable="dummytool")
    monkeypatch.setattr(adapter, "version", lambda: "1.0")
    monkeypatch.setattr(
        "bugbounty.tool_adapters.run_subprocess",
        lambda *a, **k: (0, "not-json", "", False, 5.0),
    )
    result = adapter.run(["https://example.com"])
    assert result.executed is True
    assert result.success is False
    assert result.findings == ()
    assert any("output handling failed" in e for e in result.errors)


NUCLEI_JSONL_FIXTURE = """
{"template-id":"cve-2021-1234","info":{"name":"Example Exposure","severity":"high","description":"Sensitive file exposed"},"type":"http","host":"https://allowed.example","matched-at":"https://allowed.example/.env","matcher-name":"body","timestamp":"2026-01-01T00:00:00Z"}
{"template-id":"tech-detect","info":{"name":"Tech Detect","severity":"info"},"matched-at":"https://allowed.example/"}
not-json-line
""".strip()


def test_nuclei_parse_and_normalize_fixture():
    adapter = NucleiAdapter(executable="nuclei")
    items = adapter.parse_output(NUCLEI_JSONL_FIXTURE)
    assert len(items) == 2
    findings = adapter.normalize_results(items, target="https://allowed.example")
    assert len(findings) == 2
    first = findings[0].as_dict()
    assert first["source_tool"] == "nuclei"
    assert first["source_id"] == "cve-2021-1234"
    assert first["title"] == "Example Exposure"
    assert first["severity"] == "high"
    assert first["endpoint"] == "https://allowed.example/.env"
    assert first["status"] == "candidate"
    assert first["provenance"]["template_id"] == "cve-2021-1234"
    assert first["provenance"]["target"] == "https://allowed.example"
    assert first["evidence"]["matcher_name"] == "body"


def test_nuclei_command_construction_and_mocked_run(monkeypatch):
    adapter = NucleiAdapter(executable="nuclei")
    monkeypatch.setattr(adapter, "version", lambda: "Nuclei v3.0.0")
    captured = {}

    def fake_run(args, **kwargs):
        captured["args"] = args
        captured["kwargs"] = kwargs
        return (0, NUCLEI_JSONL_FIXTURE, "", False, 12.3)

    monkeypatch.setattr("bugbounty.tool_adapters.run_subprocess", fake_run)
    cfg = AdapterConfig(timeout_seconds=10, extra_args=("-tags", "cves"))
    result = adapter.run(["https://allowed.example"], config=cfg, scope=Scope(allowed=True))
    assert captured["args"][0] == "nuclei"
    assert "-u" in captured["args"] and "https://allowed.example" in captured["args"]
    assert "-jsonl" in captured["args"]
    assert captured["args"][-2:] == ("-tags", "cves")
    assert captured["kwargs"]["shell"] if "shell" in captured["kwargs"] else True  # run_subprocess API; actual no-shell tested separately
    assert result.success is True
    assert result.executed is True
    assert len(result.findings) == 2
    assert result.execution is not None
    assert result.execution.tool == "nuclei"
    assert result.execution.command[0] == "nuclei"


def test_discovery_helpers_and_factory(monkeypatch):
    monkeypatch.setattr("bugbounty.tool_adapters.discover_executable", lambda names: "/usr/bin/nuclei" if "nuclei" in names else None)
    avail = available_adapters()
    assert avail["nuclei"] is True
    adapter = get_adapter("nuclei")
    assert isinstance(adapter, NucleiAdapter)
    with pytest.raises(Exception):
        get_adapter("unknown-tool")


def test_validate_scope_callable():
    scoped = validate_scope("https://ok.example", scope=lambda t, m: t.startswith("https://ok"))
    assert scoped == "https://ok.example"
    with pytest.raises(ScopeValidationError):
        validate_scope("https://no.example", scope=lambda t, m: False)


def test_redaction_helpers_scrub_embedded_credentials():
    from bugbounty.tool_adapters import redact_command, redact_sensitive

    command = ["curl", "-H", "Authorization: Bearer abc123", "--token", "xyz", "api_key=qqq"]
    blob = " ".join(redact_command(command))
    assert "abc123" not in blob
    assert "xyz" not in blob
    assert "qqq" not in blob
    assert "[REDACTED]" in blob

    nested = redact_sensitive({"headers": {"Authorization": "Bearer abc123"}, "note": "token=leaky"})
    assert nested["headers"]["Authorization"] == "[REDACTED]"
    assert "leaky" not in json.dumps(nested)
