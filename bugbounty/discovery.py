from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urljoin, urlsplit

from .engagement import Engagement
from .http_client import HttpClient, HttpResponse


@dataclass(frozen=True, slots=True)
class Endpoint:
    method: str
    url: str
    path: str
    parameters: list[dict[str, Any]] = field(default_factory=list)
    headers: list[str] = field(default_factory=list)
    request_body_schema: dict[str, Any] | None = None
    response_information: dict[str, Any] = field(default_factory=dict)
    authentication_required: bool = False
    source: str = "manual"
    confidence: float = 1.0
    api_version: str | None = None
    deprecated: bool = False
    operation_id: str | None = None
    tags: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


COMMON_DOC_PATHS = ("/openapi.json", "/swagger.json", "/api-docs", "/v1/openapi.json", "/docs/openapi.json")


class ApiDiscovery:
    """Discover bounded API descriptions and normalize them into Endpoint objects."""

    def __init__(self, engagement: Engagement, client: HttpClient):
        self.engagement = engagement
        self.client = client

    def discover(
        self,
        *,
        openapi_file: str | Path | None = None,
        endpoint_list: Iterable[str] | None = None,
        endpoint: str | None = None,
        documentation_paths: Iterable[str] | None = None,
    ) -> list[Endpoint]:
        if openapi_file:
            return self.from_openapi(_load_document(openapi_file), source=f"file:{openapi_file}")
        if endpoint_list:
            return [item for item in (self._manual_endpoint(value) for value in endpoint_list) if self._allowed(item)]
        if endpoint:
            item = self._manual_endpoint(endpoint)
            return [item] if self._allowed(item) else []

        paths = list(documentation_paths or COMMON_DOC_PATHS)
        for path in paths:
            response = self.client.request("GET", urljoin(self.engagement.target_url.rstrip("/") + "/", path.lstrip("/")))
            if response.status_code and 200 <= response.status_code < 300:
                try:
                    document = json.loads(response.body)
                except json.JSONDecodeError:
                    continue
                if isinstance(document, dict) and isinstance(document.get("paths"), dict):
                    return self.from_openapi(document, source=f"url:{path}")
        return [self._manual_endpoint(self.engagement.target_url, source="target")]

    def from_openapi(self, document: dict[str, Any], *, source: str = "openapi") -> list[Endpoint]:
        _validate_document(document)
        is_swagger = document.get("swagger") == "2.0"
        base_url = self._base_url(document)
        version = str(document.get("info", {}).get("version")) if document.get("info", {}).get("version") else None
        endpoints: list[Endpoint] = []
        for path, item in (document.get("paths") or {}).items():
            if not isinstance(item, dict):
                continue
            for method, operation in item.items():
                method = method.upper()
                if method not in {"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"} or not isinstance(operation, dict):
                    continue
                parameters = list(item.get("parameters") or []) + list(operation.get("parameters") or [])
                responses = operation.get("responses") or {}
                endpoints.append(
                    Endpoint(
                        method=method,
                        url=urljoin(base_url.rstrip("/") + "/", str(path).lstrip("/")),
                        path=str(path),
                        parameters=parameters,
                        headers=[str(p.get("name")) for p in parameters if p.get("in") == "header"],
                        request_body_schema=_request_body(operation, document, is_swagger),
                        response_information=responses if isinstance(responses, dict) else {},
                        authentication_required=bool(operation.get("security", document.get("security") or document.get("securityDefinitions"))),
                        source=source,
                        confidence=0.98,
                        api_version=version,
                        deprecated=bool(operation.get("deprecated", False)),
                        operation_id=operation.get("operationId"),
                        tags=[str(tag) for tag in operation.get("tags", []) if isinstance(tag, str)],
                    )
                )
        unique: dict[tuple[str, str], Endpoint] = {}
        for endpoint in endpoints:
            unique.setdefault((endpoint.method, endpoint.path), endpoint)
        return [item for item in unique.values() if self._allowed(item)]

    def _allowed(self, endpoint: Endpoint) -> bool:
        return self.client.safety_policy.authorize_target(endpoint.url) and endpoint.method.upper() in {item.upper() for item in self.engagement.allowed_methods}

    def _base_url(self, document: dict[str, Any]) -> str:
        if document.get("swagger") == "2.0":
            scheme = (document.get("schemes") or [urlsplit(self.engagement.target_url).scheme])[0]
            host = document.get("host") or urlsplit(self.engagement.target_url).netloc
            base_path = document.get("basePath", "")
            return f"{scheme}://{host}{base_path}"
        servers = document.get("servers") or []
        if servers and isinstance(servers[0], dict) and servers[0].get("url"):
            return urljoin(self.engagement.target_url, str(servers[0]["url"]))
        return self.engagement.target_url

    def compare_inventory(self, documented: Iterable[Endpoint], supplied: Iterable[str]) -> dict[str, list[str]]:
        documented_keys = {f"{item.method.upper()} {item.path}" for item in documented}
        supplied_keys = {f"GET {urlsplit(item).path or '/'}" for item in supplied}
        return {"documented": sorted(documented_keys), "supplied": sorted(supplied_keys), "undocumented": sorted(supplied_keys - documented_keys), "missing_from_supplied": sorted(documented_keys - supplied_keys)}

    def _manual_endpoint(self, value: str, source: str = "manual") -> Endpoint:
        parsed = urlsplit(value)
        path = parsed.path or "/"
        return Endpoint(method="GET", url=value, path=path, source=source, confidence=0.75)


__all__ = ["ApiDiscovery", "Endpoint", "COMMON_DOC_PATHS"]


def _load_document(path: str | Path) -> dict[str, Any]:
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"could not load OpenAPI document: {type(error).__name__}") from error
    if not isinstance(value, dict):
        raise ValueError("OpenAPI document root must be an object")
    return value


def _validate_document(document: dict[str, Any]) -> None:
    if document.get("openapi") and not str(document["openapi"]).startswith("3."):
        raise ValueError("only OpenAPI 3.x documents are supported")
    if document.get("swagger") and document.get("swagger") != "2.0":
        raise ValueError("only Swagger 2.0 documents are supported")
    if not document.get("openapi") and not document.get("swagger"):
        raise ValueError("document must declare openapi or swagger version")
    if not isinstance(document.get("paths"), dict):
        raise ValueError("OpenAPI document paths must be an object")


def _request_body(operation: dict[str, Any], document: dict[str, Any], is_swagger: bool) -> dict[str, Any] | None:
    if not is_swagger:
        return (operation.get("requestBody") or {}).get("content", {}).get("application/json", {}).get("schema")
    body = next((item for item in operation.get("parameters", []) if isinstance(item, dict) and item.get("in") == "body"), None)
    return body.get("schema") if body else None
