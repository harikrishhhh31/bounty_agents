from __future__ import annotations

import base64
import hashlib
import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from http.client import HTTPResponse
from typing import Mapping
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener, urlopen
from uuid import uuid4

from .engagement import AuthIdentity, Engagement
from .safety import SafetyPolicy


SECRET_NAMES = {"authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key"}


def redact_headers(headers: Mapping[str, str]) -> dict[str, str]:
    return {key: "[REDACTED]" if key.lower() in SECRET_NAMES else value for key, value in headers.items()}


def redact_text(value: str, secrets: list[str] | None = None) -> str:
    result = value
    for secret in secrets or []:
        if secret:
            result = result.replace(secret, "[REDACTED]")
    return result


@dataclass(frozen=True, slots=True)
class HttpResponse:
    request_id: str
    evidence_artifact_id: str
    url: str
    status_code: int | None
    headers: dict[str, str]
    body: str
    body_size: int
    elapsed_ms: float
    error: str | None = None
    dry_run: bool = False

    @property
    def body_sha256(self) -> str:
        return hashlib.sha256(self.body.encode("utf-8", errors="replace")).hexdigest()


@dataclass(slots=True)
class HttpClient:
    """Bounded HTTP client. Every request is checked against the engagement scope."""

    engagement: Engagement
    safety_policy: SafetyPolicy | None = None
    _requests_made: int = 0
    _last_request_at: float = 0.0
    _secrets: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.engagement.validate()
        if self.safety_policy is None:
            self.safety_policy = SafetyPolicy(scope=self.engagement.scope())
        for identity in self.engagement.identities:
            self._secrets.extend(_identity_secrets(identity))

    @property
    def requests_made(self) -> int:
        return self._requests_made

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        body: bytes | str | None = None,
        identity: str | None = None,
        params: Mapping[str, str] | None = None,
    ) -> HttpResponse:
        method = method.upper()
        if params:
            parsed = urlsplit(url)
            query = urlencode({**dict(__import__("urllib.parse", fromlist=["parse_qsl"]).parse_qsl(parsed.query)), **params})
            url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, parsed.fragment))

        parsed_url = urlsplit(url)
        if parsed_url.scheme.lower() not in {item.lower() for item in self.engagement.allowed_schemes}:
            decision = None
            decision_reason = f"scheme {parsed_url.scheme} is not allowed"
        else:
            decision = self.safety_policy.check(url, method=method) if self.safety_policy else None
            decision_reason = decision.reason if decision else "no safety policy configured"
        request_id = uuid4().hex
        evidence_id = f"evidence-{request_id}"
        started = time.monotonic()
        if decision is None or not decision.allowed:
            return HttpResponse(request_id, evidence_id, url, None, {}, "", 0, 0.0, error=decision_reason)
        if method not in {item.upper() for item in self.engagement.allowed_methods}:
            return HttpResponse(request_id, evidence_id, url, None, {}, "", 0, 0.0, error=f"method {method} is not allowed")
        if self._requests_made >= self.engagement.maximum_requests:
            return HttpResponse(request_id, evidence_id, url, None, {}, "", 0, 0.0, error="maximum request budget exhausted")
        if self.engagement.dry_run:
            return HttpResponse(request_id, evidence_id, url, None, {}, "", 0, 0.0, dry_run=True)

        wait_for = (1.0 / self.engagement.request_rate_limit) - (time.monotonic() - self._last_request_at)
        if wait_for > 0:
            time.sleep(wait_for)
        request_headers = {"User-Agent": self.engagement.user_agent, **dict(headers or {})}
        request_headers.update(self._auth_headers(identity))
        if identity:
            selected_identity = next((item for item in self.engagement.identities if item.name == identity), None)
            if selected_identity and selected_identity.api_key_query:
                query = dict(__import__("urllib.parse", fromlist=["parse_qsl"]).parse_qsl(parsed_url.query))
                query[selected_identity.api_key_query[0]] = selected_identity.api_key_query[1]
                url = urlunsplit((parsed_url.scheme, parsed_url.netloc, parsed_url.path, urlencode(query), parsed_url.fragment))
        payload = body.encode("utf-8") if isinstance(body, str) else body
        request = Request(url, data=payload, headers=request_headers, method=method)
        try:
            opener = build_opener() if self.engagement.follow_redirects else build_opener(_NoRedirectHandler())
            with opener.open(request, timeout=self.engagement.timeout) as response:
                captured = _capture_response(response, self.engagement.max_response_bytes)
        except HTTPError as error:
            captured = _capture_response(error, self.engagement.max_response_bytes)
        except (URLError, TimeoutError, OSError) as error:
            captured = HttpResponse(request_id, evidence_id, url, None, {}, "", 0, 0.0, error=type(error).__name__)
        self._requests_made += 1
        self._last_request_at = time.monotonic()
        elapsed = (time.monotonic() - started) * 1000
        return HttpResponse(
            request_id=request_id,
            evidence_artifact_id=evidence_id,
            url=redact_text(url, self._secrets),
            status_code=captured.status_code,
            headers=captured.headers,
            body=redact_text(captured.body, self._secrets),
            body_size=captured.body_size,
            elapsed_ms=elapsed,
            error=captured.error,
        )

    def _auth_headers(self, identity_name: str | None) -> dict[str, str]:
        if not identity_name:
            return {}
        identity = next((item for item in self.engagement.identities if item.name == identity_name), None)
        if identity is None:
            raise ValueError(f"unknown identity: {identity_name}")
        headers = dict(identity.custom_headers)
        if identity.bearer_token:
            headers["Authorization"] = f"Bearer {identity.bearer_token}"
        if identity.api_key_header:
            headers[identity.api_key_header[0]] = identity.api_key_header[1]
        if identity.basic_username is not None and identity.basic_password is not None:
            encoded = base64.b64encode(f"{identity.basic_username}:{identity.basic_password}".encode()).decode()
            headers["Authorization"] = f"Basic {encoded}"
        return headers


def _identity_secrets(identity: AuthIdentity) -> list[str]:
    values = [identity.bearer_token, identity.basic_password]
    if identity.api_key_header:
        values.append(identity.api_key_header[1])
    if identity.api_key_query:
        values.append(identity.api_key_query[1])
    values.extend(identity.custom_headers.values())
    return [value for value in values if value]


def _capture_response(response: HTTPResponse, max_bytes: int) -> HttpResponse:
    request_id = uuid4().hex
    evidence_id = f"evidence-{request_id}"
    raw_body = response.read(max_bytes + 1)
    truncated = len(raw_body) > max_bytes
    raw_body = raw_body[:max_bytes]
    body = raw_body.decode(response.headers.get_content_charset() or "utf-8", errors="replace")
    if truncated:
        body += "\n[TRUNCATED]"
    return HttpResponse(
        request_id=request_id,
        evidence_artifact_id=evidence_id,
        url=response.geturl(),
        status_code=response.status,
        headers=redact_headers(dict(response.headers.items())),
        body=body,
        body_size=len(raw_body),
        elapsed_ms=0.0,
    )


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


__all__ = ["HttpClient", "HttpResponse", "redact_headers", "redact_text"]
