from __future__ import annotations

import base64
import csv
import fnmatch
import ipaddress
import json
import re
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

try:
    import yaml
except ImportError:  # pragma: no cover - project dependencies include PyYAML
    yaml = None


SENSITIVE_HEADERS = {"authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key", "x-auth-token", "x-access-token"}
SENSITIVE_QUERY_NAMES = {"access_token", "api_key", "apikey", "key", "password", "passwd", "secret", "session", "sessionid", "token"}
SUPPORTED_SCOPE_TYPES = {"domain", "url", "cidr", "wildcard", "wildcard_domain", "ip", "hostname"}
MAX_IMPORT_BYTES = 50 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class ScopeAsset:
    identifier: str
    normalized_identifier: str
    asset_type: str
    eligible: bool
    max_severity: str | None = None
    source_metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def supported(self) -> bool:
        return self.asset_type in SUPPORTED_SCOPE_TYPES


@dataclass(frozen=True, slots=True)
class ImportedScope:
    assets: tuple[ScopeAsset, ...]
    source: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class BurpResponse:
    status: int | None
    headers: dict[str, str]
    body: str
    content_type: str | None
    timing_ms: float | None = None


@dataclass(frozen=True, slots=True)
class BurpRequest:
    id: str
    timestamp: str | None
    method: str
    url: str
    scheme: str
    host: str
    port: int | None
    path: str
    query_parameters: dict[str, list[str]]
    headers: dict[str, str]
    body: str
    source: str


@dataclass(frozen=True, slots=True)
class BurpExchange:
    request: BurpRequest
    response: BurpResponse | None


@dataclass(frozen=True, slots=True)
class BurpScopeRule:
    host: str = "*"
    protocol: str | None = None
    port: int | None = None
    path: str = "/"
    enabled: bool = True
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class BurpScopeConfiguration:
    include: tuple[BurpScopeRule, ...] = ()
    exclude: tuple[BurpScopeRule, ...] = ()
    source: str = ""

    @property
    def rule_count(self) -> int:
        return len(self.include) + len(self.exclude)


@dataclass(frozen=True, slots=True)
class EndpointInventory:
    method: str
    url: str
    host: str
    path: str
    source: str
    scope_status: str
    asset_type: str | None
    api_version: str | None
    operation_id: str | None
    authentication: str | None
    observation_count: int
    methods: tuple[str, ...]
    status_codes: tuple[int, ...]
    content_types: tuple[str, ...]
    first_seen: str | None
    last_seen: str | None
    reason: str

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def parse_hackerone_scope(path: str | Path) -> ImportedScope:
    source = Path(path)
    if not source.exists():
        raise ValueError(f"scope file does not exist: {source}")
    if source.stat().st_size > MAX_IMPORT_BYTES:
        raise ValueError("scope file exceeds the 50 MB import limit")
    raw = source.read_text(encoding="utf-8-sig")
    suffix = source.suffix.lower()
    if suffix == ".json":
        data = json.loads(raw)
        rows = data if isinstance(data, list) else data.get("assets", data.get("scope", [])) if isinstance(data, dict) else []
        if not isinstance(rows, list):
            raise ValueError("scope JSON must contain a list or assets list")
        assets = tuple(_scope_asset(row, index) for index, row in enumerate(rows) if isinstance(row, dict))
        return ImportedScope(assets, str(source), {"format": "json"})
    if suffix in {".yaml", ".yml"}:
        if yaml is None:
            raise ValueError("YAML scope parsing requires PyYAML")
        data = yaml.safe_load(raw)
        rows = data if isinstance(data, list) else data.get("assets", data.get("scope", [])) if isinstance(data, dict) else []
        if not isinstance(rows, list):
            raise ValueError("scope YAML must contain a list or assets list")
        assets = tuple(_scope_asset(row, index) for index, row in enumerate(rows) if isinstance(row, dict))
        return ImportedScope(assets, str(source), {"format": "yaml"})
    first_line = next((line for line in raw.splitlines() if line.strip()), "")
    if "\t" in first_line:
        dialect = csv.excel_tab
    else:
        dialect = csv.Sniffer().sniff(raw[:4096], delimiters=",;") if raw.strip() else csv.excel
    rows = csv.DictReader(StringIO(raw), dialect=dialect)
    headers = {_header(value) for value in (rows.fieldnames or ())}
    if not headers.intersection({"identifier", "asset_identifier", "host", "url", "asset"}):
        raise ValueError("scope CSV is missing an asset identifier column")
    assets = tuple(_scope_asset(row, index) for index, row in enumerate(rows) if any(str(value or "").strip() for value in row.values()))
    return ImportedScope(assets, str(source), {"format": "tsv" if dialect.delimiter == "\t" else "csv", "delimiter": dialect.delimiter})


def _scope_asset(row: dict[str, Any], index: int) -> ScopeAsset:
    normalized = {_header(key): value for key, value in row.items()}
    identifier = _first(normalized, "identifier", "asset_identifier", "host", "url", "asset")
    if not identifier:
        raise ValueError(f"scope row {index + 1} is missing an identifier")
    asset_type = _normalize_asset_type(_first(normalized, "asset_type", "type", "asset_type_name") or "unknown")
    eligible = _parse_bool(_first(normalized, "eligible", "eligible_for_submission", "in_scope", "eligible_for_bounty"), default=False)
    severity = _first(normalized, "max_severity", "maximum_severity", "severity")
    return ScopeAsset(str(identifier).strip(), normalize_scope_identifier(str(identifier)), asset_type, eligible, str(severity).strip() if severity else None, {str(key): value for key, value in row.items()})


def parse_burp_xml(path: str | Path) -> tuple[BurpExchange, ...]:
    source = Path(path)
    if source.suffix.lower() in {".db", ".sqlite", ".sqlite3", ".burp"}:
        raise ValueError("native Burp project databases are private/unsupported; export Proxy history as XML")
    if source.stat().st_size > MAX_IMPORT_BYTES:
        raise ValueError("Burp export exceeds the 50 MB import limit")
    try:
        root = ET.fromstring(source.read_bytes())
    except (OSError, ET.ParseError) as error:
        raise ValueError(f"could not parse Burp XML export: {type(error).__name__}") from error
    if root.tag.lower() not in {"items", "burp", "project"}:
        raise ValueError("unsupported Burp export: expected Burp XML items")
    exchanges: list[BurpExchange] = []
    for index, item in enumerate(root.findall(".//item")):
        request_value = _xml_text(item.find("request"))
        if not request_value:
            continue
        request_raw = _decode_burp_value(request_value, item.find("request"))
        method, target, headers, body = _parse_http_message(request_raw)
        host = _xml_text(item.find("host")) or urlsplit(target).hostname or ""
        protocol = _xml_text(item.find("protocol")) or urlsplit(target).scheme or "https"
        port_value = _xml_text(item.find("port"))
        port = int(port_value) if port_value and port_value.isdigit() else urlsplit(target).port
        url = _normalize_url(target, protocol, host, port)
        parsed = urlsplit(url)
        response_node = item.find("response")
        response = None
        if response_node is not None and _xml_text(response_node):
            response_raw = _decode_burp_value(_xml_text(response_node), response_node)
            status, response_headers, response_body = _parse_http_response(response_raw)
            response = BurpResponse(status, response_headers, response_body, _content_type(response_headers), _float_or_none(_xml_text(item.find("time"))))
        timestamp = _xml_text(item.find("time")) or _xml_text(item.find("timestamp"))
        exchanges.append(BurpExchange(BurpRequest(str(index + 1), timestamp, method, url, parsed.scheme, parsed.hostname or host, parsed.port or port, parsed.path or "/", _query_map(parsed.query), headers, body, str(source)), response))
    return tuple(exchanges)


def parse_burp_json(path: str | Path) -> tuple[BurpExchange, ...]:
    source = Path(path)
    if not source.exists():
        raise ValueError(f"Burp JSON file does not exist: {source}")
    if source.stat().st_size > MAX_IMPORT_BYTES:
        raise ValueError("Burp JSON export exceeds the 50 MB import limit")
    try:
        data = json.loads(source.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"could not parse Burp JSON export: {type(error).__name__}") from error
    rows = _burp_json_rows(data)
    if not rows:
        raise ValueError("JSON is valid but does not contain Burp HTTP traffic/history (no HTTP traffic).")
    exchanges: list[BurpExchange] = []
    errors: list[str] = []
    for index, row in enumerate(rows):
        try:
            exchanges.append(_burp_json_exchange(row, source, index))
        except (TypeError, ValueError, KeyError) as error:
            errors.append(f"row {index + 1}: {type(error).__name__}")
    if not exchanges:
        detail = "; ".join(errors[:3])
        raise ValueError(f"Burp JSON contains no parseable HTTP traffic{': ' + detail if detail else ''}")
    return tuple(exchanges)


def parse_burp_json_document(path: str | Path) -> tuple[BurpScopeConfiguration, tuple[BurpExchange, ...]]:
    source = Path(path)
    if not source.exists():
        raise ValueError(f"Burp JSON file does not exist: {source}")
    try:
        data = json.loads(source.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"could not parse Burp JSON export: {type(error).__name__}") from error
    scope = _burp_scope_configuration(data, source)
    if scope is not None:
        return scope, parse_burp_json(source) if _burp_json_rows(data) else ()
    return BurpScopeConfiguration(source=str(source)), parse_burp_json(source)


def _burp_scope_configuration(data: Any, source: Path) -> BurpScopeConfiguration | None:
    try:
        scope = data["target"]["scope"]
    except (KeyError, TypeError):
        return None
    if not isinstance(scope, dict) or not {"include", "exclude"}.intersection(scope):
        return None
    if any(key in scope and not isinstance(scope[key], list) for key in ("include", "exclude")):
        raise ValueError("Burp scope include/exclude rules must be arrays")
    include = tuple(_burp_scope_rule(item) for item in scope.get("include", ()) if isinstance(item, dict))
    exclude = tuple(_burp_scope_rule(item) for item in scope.get("exclude", ()) if isinstance(item, dict))
    return BurpScopeConfiguration(include, exclude, str(source))


def _burp_scope_rule(item: dict[str, Any]) -> BurpScopeRule:
    host = str(item.get("host", item.get("hostname", item.get("domain", item.get("value", "*")))) or "*").lower()
    protocol = item.get("protocol") or item.get("scheme")
    port_value = item.get("port")
    try:
        port = int(port_value) if port_value not in (None, "", "*") else None
    except (TypeError, ValueError):
        port = None
    path = str(item.get("path", item.get("file", item.get("url_path", "/"))) or "/")
    return BurpScopeRule(host, str(protocol).lower() if protocol else None, port, path, bool(item.get("enabled", True)), dict(item))


def match_burp_scope(url: str, scope: BurpScopeConfiguration) -> bool:
    if not scope.include:
        return not any(_burp_rule_matches(url, rule) for rule in scope.exclude if rule.enabled)
    return any(_burp_rule_matches(url, rule) for rule in scope.include if rule.enabled) and not any(_burp_rule_matches(url, rule) for rule in scope.exclude if rule.enabled)


def match_burp_scope_host(url: str, scope: BurpScopeConfiguration) -> bool:
    """Match only the technical host boundary for safety initialization."""
    if not scope.include:
        return not any(_burp_rule_matches(url, rule, include_path=False) and _burp_rule_covers_all_paths(rule) for rule in scope.exclude if rule.enabled)
    return any(_burp_rule_matches(url, rule, include_path=False) for rule in scope.include if rule.enabled) and not any(_burp_rule_matches(url, rule, include_path=False) and _burp_rule_covers_all_paths(rule) for rule in scope.exclude if rule.enabled)


def _burp_rule_covers_all_paths(rule: BurpScopeRule) -> bool:
    return rule.path in {"", "/", "*", "^/.*", "^.*"}


def _burp_rule_matches(url: str, rule: BurpScopeRule, *, include_path: bool = True) -> bool:
    parsed = urlsplit(url)
    host = (parsed.hostname or "").lower()
    host_matches = _burp_pattern_matches(host, rule.host)
    protocol_matches = not rule.protocol or parsed.scheme.lower() == rule.protocol
    port_matches = rule.port is None or (parsed.port or _default_port(parsed.scheme)) == rule.port
    path_matches = not include_path or _burp_pattern_matches(parsed.path or "/", rule.path, default_all=True)
    return host_matches and protocol_matches and port_matches and path_matches


def _burp_pattern_matches(value: str, pattern: str, *, default_all: bool = False) -> bool:
    if default_all and pattern in {"", "/", "*"}:
        return True
    if pattern.startswith("^") or pattern.endswith("$") or "\\" in pattern:
        try:
            return re.fullmatch(pattern, value) is not None
        except re.error:
            return False
    if pattern.startswith("*."):
        return value == pattern[2:] or fnmatch.fnmatch(value, pattern)
    return value == pattern or fnmatch.fnmatch(value, pattern)


def _burp_json_rows(data: Any) -> list[dict[str, Any]]:
    if isinstance(data, list):
        rows = data
    elif isinstance(data, dict):
        rows = next((data[key] for key in ("items", "entries", "requests", "history") if isinstance(data.get(key), list)), None)
        if rows is None and isinstance(data.get("httpHistory"), list):
            rows = data["httpHistory"]
    else:
        rows = None
    return [row for row in rows or () if isinstance(row, dict)]


def _burp_json_exchange(row: dict[str, Any], source: Path, index: int) -> BurpExchange:
    request_value = row.get("request", row)
    response_value = row.get("response")
    request = _burp_json_request(request_value, row, source, index)
    response = _burp_json_response(response_value) if response_value is not None else None
    return BurpExchange(request, response)


def _burp_json_request(value: Any, row: dict[str, Any], source: Path, index: int) -> BurpRequest:
    if not isinstance(value, dict):
        raise ValueError("request must be an object")
    method = str(value.get("method", row.get("method", ""))).upper().strip()
    url = str(value.get("url", row.get("url", ""))).strip()
    headers = value.get("headers", row.get("headers", {}))
    body = value.get("body", row.get("body", ""))
    if not method or not url:
        raw = value.get("raw") or value.get("message")
        if raw:
            method, url, headers, body = _parse_http_message(str(raw))
        else:
            raise ValueError("request is missing method or URL")
    parsed = urlsplit(url)
    if not parsed.scheme or not parsed.hostname:
        raise ValueError("request URL must be absolute")
    normalized_headers = _json_headers(headers)
    normalized_url = redact_url(url)
    return BurpRequest(str(value.get("id", row.get("id", index + 1))), str(row.get("timestamp", value.get("timestamp", ""))) or None, method, normalized_url, parsed.scheme, parsed.hostname, parsed.port or _default_port(parsed.scheme), parsed.path or "/", _query_map(parsed.query), normalized_headers, _redact_body(str(body or "")), str(source))


def _burp_json_response(value: Any) -> BurpResponse:
    if not isinstance(value, dict):
        raise ValueError("response must be an object")
    headers = _json_headers(value.get("headers", {}))
    status_value = value.get("status", value.get("statusCode"))
    try:
        status = int(status_value) if status_value is not None else None
    except (TypeError, ValueError):
        status = None
    return BurpResponse(status, headers, _redact_body(str(value.get("body", "") or "")), _content_type(headers), _float_or_none(str(value.get("timing_ms", value.get("timingMs", "")) or "")))


def _json_headers(value: Any) -> dict[str, str]:
    if isinstance(value, dict):
        return {str(key): "[REDACTED]" if str(key).lower() in SENSITIVE_HEADERS else _redact_text(str(item)) for key, item in value.items()}
    if isinstance(value, list):
        return _parse_headers(str(item) for item in value)
    return {}


def _decode_burp_value(value: str, node: ET.Element | None) -> str:
    if node is not None and node.attrib.get("base64", "false").lower() == "true":
        return base64.b64decode(value).decode("utf-8", errors="replace")
    return value


def _parse_http_message(raw: str) -> tuple[str, str, dict[str, str], str]:
    head, _, body = raw.partition("\r\n\r\n")
    if not _:
        head, _, body = raw.partition("\n\n")
    lines = head.splitlines()
    if not lines:
        raise ValueError("Burp request is missing request line")
    first = lines[0].split()
    if len(first) < 2:
        raise ValueError("Burp request line is malformed")
    method, target = first[0].upper(), first[1]
    headers = _parse_headers(lines[1:])
    return method, target, headers, _redact_body(body)


def _parse_http_response(raw: str) -> tuple[int | None, dict[str, str], str]:
    head, _, body = raw.partition("\r\n\r\n")
    if not _:
        head, _, body = raw.partition("\n\n")
    lines = head.splitlines()
    status = None
    if lines:
        match = re.search(r"\s(\d{3})(?:\s|$)", lines[0])
        status = int(match.group(1)) if match else None
    return status, _parse_headers(lines[1:]), _redact_body(body)


def _parse_headers(lines: Iterable[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in lines:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        result[key.strip()] = "[REDACTED]" if key.strip().lower() in SENSITIVE_HEADERS else _redact_text(value.strip())
    return result


def _redact_text(value: str) -> str:
    return re.sub(r"(?i)(bearer\s+)[^\s,;]+", r"\1[REDACTED]", value)


def _redact_body(value: str) -> str:
    result = _redact_text(value)
    names = "|".join(sorted(SENSITIVE_QUERY_NAMES | {"password", "passwd", "secret", "session_token"}))
    pattern = rf"[\"']?(?:{names})[\"']?\s*[:=]\s*[\"']?[^,\s\"']+"
    return re.sub(pattern, lambda match: re.sub(r"([:=]\s*[\"']?)[^,\s\"']+$", r"\1[REDACTED]", match.group(0)), result)


def normalize_scope_identifier(identifier: str) -> str:
    value = identifier.strip().lower()
    if "://" in value:
        parsed = urlsplit(value)
        return urlunsplit((parsed.scheme, parsed.netloc, parsed.path.rstrip("/") or "/", "", ""))
    if "/" in value and not value.startswith("/"):
        return value.rstrip("/")
    if value.startswith("*."):
        return value[2:]
    return value.rstrip("/")


def normalize_burp_exchange(exchange: BurpExchange, scope: ImportedScope) -> EndpointInventory:
    request = exchange.request
    match = match_scope(request.url, scope)
    status_codes = (exchange.response.status,) if exchange.response and exchange.response.status is not None else ()
    content_types = (exchange.response.content_type,) if exchange.response and exchange.response.content_type else ()
    return EndpointInventory(request.method, redact_url(request.url), request.host, request.path, "burp", match[0], match[1], None, None, _auth_metadata(request.headers), 1, (request.method,), tuple(status_codes), tuple(content_types), request.timestamp, request.timestamp, match[2])


def build_inventory(exchanges: Iterable[BurpExchange], scope: ImportedScope, burp_scope: BurpScopeConfiguration | None = None) -> tuple[EndpointInventory, ...]:
    grouped: dict[tuple[str, str], list[BurpExchange]] = {}
    for exchange in exchanges:
        key = (exchange.request.method, redact_url(exchange.request.url))
        grouped.setdefault(key, []).append(exchange)
    result: list[EndpointInventory] = []
    for group in grouped.values():
        first = normalize_burp_exchange(group[0], scope)
        if burp_scope is not None and first.scope_status == "IN_SCOPE" and not match_burp_scope(first.url, burp_scope):
            first = EndpointInventory(first.method, first.url, first.host, first.path, first.source, "OUT_OF_SCOPE", first.asset_type, first.api_version, first.operation_id, first.authentication, first.observation_count, first.methods, first.status_codes, first.content_types, first.first_seen, first.last_seen, "excluded by Burp technical scope")
        statuses = sorted({exchange.response.status for exchange in group if exchange.response and exchange.response.status is not None})
        content_types = sorted({exchange.response.content_type for exchange in group if exchange.response and exchange.response.content_type})
        methods = sorted({exchange.request.method for exchange in group})
        timestamps = [exchange.request.timestamp for exchange in group if exchange.request.timestamp]
        result.append(EndpointInventory(first.method, first.url, first.host, first.path, first.source, first.scope_status, first.asset_type, first.api_version, first.operation_id, first.authentication, len(group), tuple(methods), tuple(statuses), tuple(content_types), min(timestamps) if timestamps else None, max(timestamps) if timestamps else None, first.reason))
    return tuple(result)


def inventory_to_endpoints(inventory: Iterable[EndpointInventory]) -> tuple[Any, ...]:
    from .discovery import Endpoint

    return tuple(
        Endpoint(method=item.method, url=item.url, path=item.path, source="burp", confidence=1.0, authentication_required=bool(item.authentication))
        for item in inventory
        if item.scope_status == "IN_SCOPE"
    )


def match_scope(url: str, scope: ImportedScope) -> tuple[str, str | None, str]:
    parsed = urlsplit(url)
    host = (parsed.hostname or "").lower()
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    for asset in scope.assets:
        if not asset.eligible:
            continue
        if not asset.supported:
            continue
        target = asset.normalized_identifier
        if asset.asset_type in {"cidr"} and address:
            try:
                if address in ipaddress.ip_network(target, strict=False):
                    return "IN_SCOPE", asset.asset_type, "matched eligible CIDR"
            except ValueError:
                pass
        elif asset.asset_type in {"domain", "hostname", "wildcard", "wildcard_domain"}:
            pattern = target if target.startswith("*.") else f"*.{target}"
            if host == target or fnmatch.fnmatch(host, pattern):
                return "IN_SCOPE", asset.asset_type, "matched eligible domain"
        elif asset.asset_type == "url" and _url_in_scope(url, target):
            return "IN_SCOPE", asset.asset_type, "matched eligible URL"
        elif asset.asset_type == "ip" and host == target:
            return "IN_SCOPE", asset.asset_type, "matched eligible IP"
    if any(not asset.supported and (asset.normalized_identifier in host or host in asset.normalized_identifier) for asset in scope.assets):
        return "UNSUPPORTED", None, "scope asset type is preserved but unsupported for HTTP endpoint matching"
    return "OUT_OF_SCOPE", None, "no eligible HackerOne asset matched"


def _url_in_scope(url: str, target: str) -> bool:
    parsed = urlsplit(target)
    observed = urlsplit(url)
    return (observed.scheme, observed.hostname, observed.port or _default_port(observed.scheme), observed.path.rstrip("/") or "/") == (parsed.scheme, parsed.hostname, parsed.port or _default_port(parsed.scheme), parsed.path.rstrip("/") or "/")


def redact_url(url: str) -> str:
    parsed = urlsplit(url)
    query = [(key, "[REDACTED]" if key.lower() in SENSITIVE_QUERY_NAMES else _redact_text(value)) for key, value in parse_qsl(parsed.query, keep_blank_values=True)]
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", urlencode(query), ""))


def _query_map(query: str) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for key, value in parse_qsl(query, keep_blank_values=True):
        result.setdefault(key, []).append("[REDACTED]" if key.lower() in SENSITIVE_QUERY_NAMES else _redact_text(value))
    return result


def _auth_metadata(headers: dict[str, str]) -> str | None:
    names = [key.lower() for key in headers]
    return "configured-auth-header-observed" if any(key in SENSITIVE_HEADERS for key in names) else None


def _normalize_url(target: str, scheme: str, host: str, port: int | None) -> str:
    parsed = urlsplit(target)
    if parsed.scheme:
        return redact_url(target)
    netloc = host if not port or (scheme == "https" and port == 443) or (scheme == "http" and port == 80) else f"{host}:{port}"
    return redact_url(urlunsplit((scheme, netloc, parsed.path or "/", parsed.query, "")))


def _content_type(headers: dict[str, str]) -> str | None:
    return next((value for key, value in headers.items() if key.lower() == "content-type"), None)


def _xml_text(node: ET.Element | None) -> str:
    return (node.text or "").strip() if node is not None and node.text else ""


def _header(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", value.strip().lower()).strip("_")


def _first(row: dict[str, Any], *keys: str) -> Any:
    return next((row[key] for key in keys if key in row and str(row[key] or "").strip()), None)


def _normalize_asset_type(value: str) -> str:
    value = re.sub(r"[^a-z0-9]+", "_", value.strip().lower())
    return {"domain_name": "domain", "wildcard_domain_name": "wildcard_domain", "ip_address": "ip"}.get(value, value)


def _parse_bool(value: Any, *, default: bool) -> bool:
    if value is None or not str(value).strip():
        return default
    return str(value).strip().lower() in {"true", "yes", "y", "1", "in_scope", "eligible"}


def _float_or_none(value: str) -> float | None:
    try:
        return float(value) if value else None
    except ValueError:
        return None


def _default_port(scheme: str) -> int:
    return 443 if scheme == "https" else 80


__all__ = ["BurpExchange", "BurpRequest", "BurpResponse", "BurpScopeConfiguration", "BurpScopeRule", "EndpointInventory", "ImportedScope", "ScopeAsset", "build_inventory", "inventory_to_endpoints", "match_burp_scope", "match_burp_scope_host", "match_scope", "normalize_burp_exchange", "normalize_scope_identifier", "parse_burp_json", "parse_burp_json_document", "parse_burp_xml", "parse_hackerone_scope", "redact_url"]
