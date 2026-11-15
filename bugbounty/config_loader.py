from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from .engagement import (
    AuthIdentity,
    BusinessFlow,
    BusinessFlowStep,
    Engagement,
    FunctionAuthorizationCase,
    ObjectAuthorizationCase,
    PropertyAuthorizationCase,
    ResourceProbe,
    SsrfCase,
)


@dataclass(frozen=True, slots=True)
class LoadedAssessmentConfig:
    engagement: Engagement
    discovery: dict[str, Any]


class ConfigurationError(ValueError):
    """Raised when an engagement configuration cannot be safely loaded."""


def load_assessment_config(path: str | Path) -> LoadedAssessmentConfig:
    """Load and validate a YAML or JSON engagement configuration."""
    source = Path(path)
    if not source.exists():
        raise ConfigurationError(f"configuration file does not exist: {source}")
    try:
        raw = json.loads(source.read_text(encoding="utf-8")) if source.suffix.lower() == ".json" else yaml.safe_load(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, yaml.YAMLError) as error:
        raise ConfigurationError(f"could not parse configuration: {type(error).__name__}") from error
    if not isinstance(raw, dict):
        raise ConfigurationError("configuration root must be an object")

    target_url = raw.get("target_url") or raw.get("target")
    if not isinstance(target_url, str) or not target_url.strip():
        raise ConfigurationError("target_url is required")
    allowed_hosts = raw.get("allowed_hosts")
    if not isinstance(allowed_hosts, list) or not allowed_hosts or not all(isinstance(item, str) and item.strip() for item in allowed_hosts):
        raise ConfigurationError("allowed_hosts must be a non-empty list of host names")

    identities = [_identity(item) for item in _list(raw, "identities")]
    engagement = Engagement(
        target_url=target_url,
        allowed_hosts=[item.strip() for item in allowed_hosts],
        allowed_schemes=_strings(raw, "allowed_schemes", ["https"]),
        allowed_methods=[item.upper() for item in _strings(raw, "allowed_methods", ["GET"])],
        identities=identities,
        request_rate_limit=_number(raw, "request_rate_limit", 2.0),
        timeout=_number(raw, "timeout", 5.0),
        maximum_requests=_integer(raw, "maximum_requests", 50),
        dry_run=bool(raw.get("dry_run", True)),
        workspace=str(raw.get("workspace", ".")),
        user_agent=str(raw.get("user_agent", "bugbounty-local-assessment/0.1")),
        max_response_bytes=_integer(raw, "max_response_bytes", 1_000_000),
        follow_redirects=bool(raw.get("follow_redirects", False)),
        object_authorization_cases=[ObjectAuthorizationCase(**_case(item, ObjectAuthorizationCase)) for item in _list(raw, "object_authorization_cases")],
        function_authorization_cases=[FunctionAuthorizationCase(**_case(item, FunctionAuthorizationCase)) for item in _list(raw, "function_authorization_cases")],
        property_authorization_cases=[_property_case(item) for item in _list(raw, "property_authorization_cases")],
        resource_probes=[ResourceProbe(**_case(item, ResourceProbe)) for item in _list(raw, "resource_probes")],
        business_flows=[_flow(item) for item in _list(raw, "business_flows")],
        ssrf_cases=[SsrfCase(**_case(item, SsrfCase)) for item in _list(raw, "ssrf_cases")],
    )
    try:
        engagement.validate()
    except (TypeError, ValueError) as error:
        raise ConfigurationError(f"invalid engagement configuration: {error}") from error

    discovery_raw = raw.get("discovery", {})
    if not isinstance(discovery_raw, dict):
        raise ConfigurationError("discovery must be an object")
    discovery = {key: discovery_raw[key] for key in ("openapi_file", "endpoint_list", "endpoint", "documentation_paths") if key in discovery_raw}
    if "endpoint_list" in discovery and not isinstance(discovery["endpoint_list"], list):
        raise ConfigurationError("discovery.endpoint_list must be a list")
    return LoadedAssessmentConfig(engagement, discovery)


def _list(raw: dict[str, Any], key: str) -> list[dict[str, Any]]:
    value = raw.get(key, [])
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise ConfigurationError(f"{key} must be a list of objects")
    return value


def _strings(raw: dict[str, Any], key: str, default: list[str]) -> list[str]:
    value = raw.get(key, default)
    if not isinstance(value, list) or not all(isinstance(item, str) and item.strip() for item in value):
        raise ConfigurationError(f"{key} must be a list of non-empty strings")
    return value


def _number(raw: dict[str, Any], key: str, default: float) -> float:
    value = raw.get(key, default)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ConfigurationError(f"{key} must be numeric")
    return float(value)


def _integer(raw: dict[str, Any], key: str, default: int) -> int:
    value = raw.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigurationError(f"{key} must be an integer")
    return value


def _identity(item: dict[str, Any]) -> AuthIdentity:
    if not isinstance(item.get("name"), str) or not item["name"].strip():
        raise ConfigurationError("each identity requires a non-empty name")
    header = item.get("api_key_header")
    query = item.get("api_key_query")
    return AuthIdentity(
        name=item["name"],
        bearer_token=item.get("bearer_token"),
        api_key_header=_pair(header, "api_key_header"),
        api_key_query=_pair(query, "api_key_query"),
        basic_username=item.get("basic_username"),
        basic_password=item.get("basic_password"),
        custom_headers=item.get("custom_headers", {}),
    )


def _pair(value: Any, key: str) -> tuple[str, str] | None:
    if value is None:
        return None
    if isinstance(value, dict) and isinstance(value.get("name"), str) and isinstance(value.get("value"), str):
        return value["name"], value["value"]
    raise ConfigurationError(f"{key} must contain name and value")


def _case(item: dict[str, Any], expected: type[Any]) -> dict[str, Any]:
    fields = set(expected.__dataclass_fields__)
    unknown = set(item) - fields
    if unknown:
        raise ConfigurationError(f"unsupported fields for {expected.__name__}: {', '.join(sorted(unknown))}")
    return item


def _property_case(item: dict[str, Any]) -> PropertyAuthorizationCase:
    values = _case(item, PropertyAuthorizationCase)
    properties = values.get("protected_properties")
    if not isinstance(properties, (list, tuple)) or not all(isinstance(value, str) for value in properties):
        raise ConfigurationError("property_authorization_cases.protected_properties must be a list of strings")
    values["protected_properties"] = tuple(properties)
    return PropertyAuthorizationCase(**values)


def _flow(item: dict[str, Any]) -> BusinessFlow:
    name = item.get("name")
    steps = item.get("steps")
    if not isinstance(name, str) or not name.strip() or not isinstance(steps, list) or not steps:
        raise ConfigurationError("each business flow requires a name and non-empty steps")
    normalized = []
    for step in steps:
        if not isinstance(step, dict):
            raise ConfigurationError("business flow steps must be objects")
        normalized.append(BusinessFlowStep(**_case(step, BusinessFlowStep)))
    return BusinessFlow(name=name, steps=tuple(normalized), replay_step=item.get("replay_step"))


__all__ = ["ConfigurationError", "LoadedAssessmentConfig", "load_assessment_config"]
