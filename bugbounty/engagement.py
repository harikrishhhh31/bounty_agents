from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping
from uuid import uuid4

from .config import ScopeConfig


@dataclass(frozen=True, slots=True, repr=False)
class AuthIdentity:
    """Explicitly supplied credentials for one assessment identity."""

    name: str
    bearer_token: str | None = None
    api_key_header: tuple[str, str] | None = None
    api_key_query: tuple[str, str] | None = None
    basic_username: str | None = None
    basic_password: str | None = None
    custom_headers: Mapping[str, str] = field(default_factory=dict)

    def __repr__(self) -> str:
        return f"AuthIdentity(name={self.name!r}, credentials='[REDACTED]')"


@dataclass(frozen=True, slots=True)
class ObjectAuthorizationCase:
    endpoint: str
    owner_identity: str
    owner_object_id: str
    other_identity: str
    other_object_id: str
    method: str = "GET"


@dataclass(frozen=True, slots=True)
class FunctionAuthorizationCase:
    endpoint: str
    allowed_identity: str
    denied_identity: str
    method: str = "GET"


@dataclass(frozen=True, slots=True)
class PropertyAuthorizationCase:
    endpoint: str
    identity: str
    protected_properties: tuple[str, ...]
    method: str = "GET"
    write_endpoint: str | None = None
    write_method: str = "PATCH"


@dataclass(frozen=True, slots=True)
class ResourceProbe:
    endpoint: str
    method: str = "GET"
    repeat_count: int = 2
    query_parameter: str | None = None
    safe_limit: int = 10
    max_payload_bytes: int = 2048

    def validate(self) -> None:
        if self.repeat_count < 1 or self.repeat_count > 5:
            raise ValueError("repeat_count must be between 1 and 5")
        if self.safe_limit < 1 or self.safe_limit > 100:
            raise ValueError("safe_limit must be between 1 and 100")
        if self.max_payload_bytes < 1 or self.max_payload_bytes > 16_384:
            raise ValueError("max_payload_bytes must be between 1 and 16384")


@dataclass(frozen=True, slots=True)
class BusinessFlowStep:
    name: str
    endpoint: str
    method: str = "POST"
    identity: str | None = None


@dataclass(frozen=True, slots=True)
class BusinessFlow:
    name: str
    steps: tuple[BusinessFlowStep, ...]
    replay_step: str | None = None


@dataclass(frozen=True, slots=True)
class SsrfCase:
    endpoint: str
    parameter: str
    verification_url: str | None = None
    callback_token: str | None = None


@dataclass(slots=True)
class Engagement:
    """Authorized target and bounded execution settings for one assessment."""

    target_url: str
    allowed_hosts: list[str]
    allowed_schemes: list[str] = field(default_factory=lambda: ["https"])
    allowed_methods: list[str] = field(default_factory=lambda: ["GET"])
    identities: list[AuthIdentity] = field(default_factory=list)
    request_rate_limit: float = 2.0
    timeout: float = 5.0
    maximum_requests: int = 50
    dry_run: bool = True
    workspace: str = "."
    engagement_id: str = field(default_factory=lambda: uuid4().hex)
    user_agent: str = "bugbounty-local-assessment/0.1"
    max_response_bytes: int = 1_000_000
    follow_redirects: bool = False
    object_authorization_cases: list[ObjectAuthorizationCase] = field(default_factory=list)
    function_authorization_cases: list[FunctionAuthorizationCase] = field(default_factory=list)
    property_authorization_cases: list[PropertyAuthorizationCase] = field(default_factory=list)
    resource_probes: list[ResourceProbe] = field(default_factory=list)
    business_flows: list[BusinessFlow] = field(default_factory=list)
    ssrf_cases: list[SsrfCase] = field(default_factory=list)

    def scope(self) -> ScopeConfig:
        return ScopeConfig(
            domains=list(self.allowed_hosts),
            urls=[self.target_url],
            allowed_methods=[method.upper() for method in self.allowed_methods],
        )

    def validate(self) -> None:
        if not self.target_url:
            raise ValueError("target_url is required")
        if not self.allowed_hosts:
            raise ValueError("at least one allowed host is required")
        if not self.allowed_schemes:
            raise ValueError("at least one allowed scheme is required")
        if self.request_rate_limit <= 0 or self.timeout <= 0:
            raise ValueError("request_rate_limit and timeout must be positive")
        if self.maximum_requests <= 0:
            raise ValueError("maximum_requests must be positive")
        if self.max_response_bytes <= 0:
            raise ValueError("max_response_bytes must be positive")
        for probe in self.resource_probes:
            probe.validate()

    @classmethod
    def from_target(cls, target_url: str, **kwargs: object) -> "Engagement":
        from urllib.parse import urlparse

        parsed = urlparse(target_url)
        if not parsed.hostname:
            raise ValueError("target_url must include a hostname")
        engagement = cls(target_url=target_url, allowed_hosts=[parsed.hostname], **kwargs)
        engagement.validate()
        return engagement


__all__ = [
    "AuthIdentity",
    "BusinessFlow",
    "BusinessFlowStep",
    "Engagement",
    "FunctionAuthorizationCase",
    "ObjectAuthorizationCase",
    "PropertyAuthorizationCase",
    "ResourceProbe",
    "SsrfCase",
]
