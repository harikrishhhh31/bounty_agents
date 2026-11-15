from __future__ import annotations

from dataclasses import dataclass, field
import json
from typing import Callable
from urllib.parse import urljoin, urlsplit, urlunsplit

from .discovery import Endpoint
from .evidence import Evidence, EvidenceStore
from .engagement import Engagement
from .findings import Finding, FindingStore, deterministic_severity
from .http_client import HttpClient, HttpResponse


@dataclass(frozen=True, slots=True)
class CheckResult:
    """Result from executing a security check.

    Status values:
    - PASS: Executed successfully; no vulnerability detected.
    - VULNERABLE: Executed successfully; vulnerability evidence found.
    - FAIL: Executed successfully; unexpected failure (may indicate auth/access issues).
    - NOT_RUN: Preconditions not met; test did not execute.
    - NOT_APPLICABLE: Check does not apply to this endpoint category.
    - ERROR: Execution failed due to exception.

    For identity-dependent checks (API1-5), the identities field tracks which
    authentication contexts were used for this check execution.
    """
    check_id: str
    category: str
    status: str
    reason: str = ""
    evidence: tuple[Evidence, ...] = ()
    findings: tuple[Finding, ...] = ()
    confidence: float = 0.0
    endpoint: str = ""
    method: str = ""
    applicable: bool = True
    executed: bool = False
    verified: bool = False
    severity: str = ""
    evidence_ids: tuple[str, ...] = ()
    remediation: str = ""
    identities: tuple[str, ...] = ()


@dataclass(slots=True)
class SecurityCheck:
    id: str
    category: str
    description: str
    execute: Callable[[Endpoint, HttpResponse | None, "CheckContext"], CheckResult]
    passive: bool = True
    priority: int = 10


@dataclass(slots=True)
class CheckContext:
    engagement: Engagement
    client: HttpClient
    evidence: EvidenceStore
    findings: FindingStore


def _response_meta(response: HttpResponse | None) -> dict[str, object]:
    if response is None:
        return {}
    return {"status_code": response.status_code, "headers": response.headers, "body_size": response.body_size, "elapsed_ms": round(response.elapsed_ms, 2), "body_sha256": response.body_sha256, "error": response.error}


def _request_meta(endpoint: Endpoint) -> dict[str, object]:
    return {"method": endpoint.method, "url": endpoint.url, "source": endpoint.source}


def _not_run(check_id: str, category: str, reason: str) -> CheckResult:
    return CheckResult(check_id, category, "NOT_RUN", reason=reason, applicable=True, executed=False)


def _not_applicable(check_id: str, category: str, reason: str) -> CheckResult:
    return CheckResult(check_id, category, "NOT_APPLICABLE", reason=reason, applicable=False, executed=False)


def _url(base: str, configured: str) -> str:
    if configured.startswith(("http://", "https://")):
        return configured
    parsed = urlsplit(base)
    origin = urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))
    return urljoin(origin.rstrip("/") + "/", configured.lstrip("/"))


def _is_success(response: HttpResponse | None) -> bool:
    return bool(response and response.status_code is not None and 200 <= response.status_code < 300)


_AUTHORITATIVE_INVENTORY_HINTS = ("openapi", "swagger", "api-docs", "api_docs", "/docs", "docs/", "spec")


def _is_authoritative_inventory_source(source: str) -> bool:
    """Return True when an endpoint came from a supplied or discovered API inventory.

    Endpoints parsed from a real OpenAPI/Swagger document (``file:`` uploads or
    ``url:`` spec probes such as ``/swagger.json`` and ``/api-docs``) are authoritative
    inventory and must not be reported as undocumented. Only direct target guesses or
    documentation probes that are not parsed specifications warrant review.
    """
    value = (source or "").lower()
    if value.startswith("file:"):
        return True
    if value.startswith("url:"):
        return any(hint in value for hint in _AUTHORITATIVE_INVENTORY_HINTS)
    return False


def _evidence(context: CheckContext, check_id: str, endpoint: str, observation: str, expected: str, actual: str, responses: list[HttpResponse | None], *, method: str = "UNKNOWN", identity: str | None = None, object_id: str | None = None, request_metadata_extra: dict[str, object] | None = None, verified: bool = False) -> Evidence:
    """Record an evidence artifact.

    ``verified`` must only be True when the observed responses independently confirm
    a vulnerability. Merely receiving an HTTP response is an *observation*, not proof,
    so the default status is ``observed`` (or ``unavailable`` when no response arrived).
    """
    response = next((item for item in reversed(responses) if item is not None), None)
    request_metadata: dict[str, object] = {"method": method, "url": endpoint}
    if identity:
        request_metadata["identity"] = identity
    if object_id:
        request_metadata["object_id"] = object_id
    request_metadata.update(request_metadata_extra or {})
    got_response = bool(response and response.status_code is not None)
    if verified and got_response:
        verification_status = "verified"
    elif got_response:
        verification_status = "observed"
    else:
        verification_status = "unavailable"
    return context.evidence.add(
        check_id=check_id,
        endpoint=endpoint,
        request_metadata=request_metadata,
        response_metadata=_response_meta(response),
        observation=observation,
        expected_behavior=expected,
        actual_behavior=actual,
        verification_status=verification_status,
    )


def check_security_misconfiguration(endpoint: Endpoint, response: HttpResponse | None, context: CheckContext) -> CheckResult:
    if response is None or response.dry_run:
        return _not_run("api8-security-misconfiguration", "API8", "request was not executed because dry-run mode is enabled")
    evidence: list[Evidence] = []
    findings: list[Finding] = []
    headers = {key.lower(): value for key, value in response.headers.items()}
    missing = [name for name in ("x-content-type-options", "content-security-policy") if name not in headers]
    if endpoint.url.startswith("http://"):
        artifact = context.evidence.add(check_id="api8-security-misconfiguration", endpoint=endpoint.url, request_metadata=_request_meta(endpoint), response_metadata=_response_meta(response), observation="Endpoint is served over HTTP", expected_behavior="Sensitive API traffic uses HTTPS", actual_behavior="HTTP endpoint is reachable", verification_status="observed")
        evidence.append(artifact)
        findings.append(Finding(title="Insecure HTTP endpoint", category="API8", endpoint=endpoint.url, severity="medium", confidence=0.99, status="verified", description="The assessed endpoint is configured with HTTP rather than HTTPS.", impact="Traffic may be exposed to interception or modification.", evidence_ids=[artifact.evidence_id], reproduction_summary=f"GET {endpoint.url}", remediation="Serve the API exclusively over HTTPS and redirect HTTP safely.", references=["OWASP API8"]))
    if "*" in headers.get("access-control-allow-origin", ""):
        artifact = context.evidence.add(check_id="api8-security-misconfiguration", endpoint=endpoint.url, request_metadata=_request_meta(endpoint), response_metadata=_response_meta(response), observation="CORS allows every origin", expected_behavior="CORS is restricted to trusted origins", actual_behavior=headers.get("access-control-allow-origin", ""), verification_status="observed")
        evidence.append(artifact)
        findings.append(Finding(title="Overly permissive CORS", category="API8", endpoint=endpoint.url, severity="medium", confidence=0.95, status="verified", description="The endpoint advertises a wildcard CORS origin.", impact="Browser-based callers from arbitrary origins may access responses depending on credentials and content.", evidence_ids=[artifact.evidence_id], reproduction_summary=f"GET {endpoint.url} and inspect Access-Control-Allow-Origin", remediation="Restrict CORS origins and credential behavior to the intended clients.", references=["OWASP API8"]))
    if missing:
        artifact = context.evidence.add(check_id="api8-security-misconfiguration", endpoint=endpoint.url, request_metadata=_request_meta(endpoint), response_metadata=_response_meta(response), observation=f"Missing passive response headers: {', '.join(missing)}", expected_behavior="Security-relevant response headers are configured where applicable", actual_behavior="One or more headers were absent", verification_status="observed")
        evidence.append(artifact)
    return CheckResult("api8-security-misconfiguration", "API8", "FAIL" if findings else "PASS", evidence=tuple(evidence), findings=tuple(findings), confidence=0.95 if findings else 0.7, executed=True, verified=bool(findings), endpoint=endpoint.url, method=endpoint.method)


def check_inventory(endpoint: Endpoint, response: HttpResponse | None, context: CheckContext) -> CheckResult:
    if endpoint.deprecated:
        artifact = context.evidence.add(check_id="api9-improper-inventory", endpoint=endpoint.url, request_metadata=_request_meta(endpoint), response_metadata=_response_meta(response), observation="Endpoint is marked deprecated in the supplied API specification", expected_behavior="Deprecated API operations are retired or isolated from active inventory", actual_behavior="Deprecated operation remains discoverable", verification_status="observed")
        finding = Finding(title="Deprecated API operation remains exposed", category="API9", endpoint=endpoint.url, severity="low", confidence=0.9, status="candidate", description="The API inventory marks this operation deprecated while it remains exposed to the assessment.", impact="Deprecated operations can retain outdated controls and unexpected attack surface.", evidence_ids=[artifact.evidence_id], reproduction_summary=f"Discovered deprecated {endpoint.method} {endpoint.path}", remediation="Retire deprecated operations or document their remaining support and controls.", references=["OWASP API9"])
        return CheckResult("api9-improper-inventory", "API9", "FAIL", evidence=(artifact,), findings=(finding,), confidence=0.9, executed=True, endpoint=endpoint.url, method=endpoint.method)
    if endpoint.source == "target" or (endpoint.source.startswith("url:") and not _is_authoritative_inventory_source(endpoint.source)):
        artifact = context.evidence.add(check_id="api9-improper-inventory", endpoint=endpoint.url, request_metadata=_request_meta(endpoint), response_metadata=_response_meta(response), observation="Endpoint was discovered without an authoritative supplied inventory", expected_behavior="API inventory is explicit and maintained", actual_behavior=f"Endpoint source: {endpoint.source}", verification_status="potential")
        finding = Finding(title="API endpoint inventory requires review", category="API9", endpoint=endpoint.url, severity="low", confidence=0.65, status="candidate", description="An API endpoint was assessed from a direct target or documentation probe rather than a supplied inventory.", impact="Undocumented or unmanaged endpoints can remain exposed.", evidence_ids=[artifact.evidence_id], reproduction_summary=f"Discovered {endpoint.method} {endpoint.url}", remediation="Maintain an authoritative API inventory and retire undocumented versions.", references=["OWASP API9"])
        return CheckResult("api9-improper-inventory", "API9", "FAIL", evidence=(artifact,), findings=(finding,), confidence=0.65, executed=True, endpoint=endpoint.url, method=endpoint.method)
    return _not_applicable("api9-improper-inventory", "API9", "endpoint came from supplied OpenAPI inventory")


def check_ssrf_indicator(endpoint: Endpoint, response: HttpResponse | None, context: CheckContext) -> CheckResult:
    candidates = [str(parameter.get("name")) for parameter in endpoint.parameters if isinstance(parameter, dict) and str(parameter.get("name", "")).lower() in {"url", "uri", "callback", "webhook", "redirect", "next", "image_url", "resource"}]
    if not candidates:
        return _not_applicable("api7-ssrf-indicator", "API7", "no URL-like parameter was discovered")
    configured = [case for case in context.engagement.ssrf_cases if case.endpoint in endpoint.path or case.endpoint in endpoint.url]
    observation = f"Potential server-side URL sink parameter(s): {', '.join(candidates)}"
    artifact = context.evidence.add(check_id="api7-ssrf-indicator", endpoint=endpoint.url, request_metadata=_request_meta(endpoint), response_metadata=_response_meta(response), observation=observation, expected_behavior="URL/resource parameters are validated and constrained", actual_behavior="URL-like input surface was discovered", verification_status="potential")
    findings = [Finding(title="Potential SSRF sink", category="API7", endpoint=endpoint.url, severity="medium", confidence=0.6, status="candidate", description="A URL-like parameter may cause the server to fetch a remote resource.", impact="If insufficiently constrained, server-side requests could reach internal services.", evidence_ids=[artifact.evidence_id], reproduction_summary=f"Review parameter(s): {', '.join(candidates)}", remediation="Use allowlists, block private address ranges, validate schemes, and avoid server-side fetching where unnecessary.", references=["OWASP API7"])]
    if configured and configured[0].verification_url and configured[0].callback_token:
        case = configured[0]
        verification = context.client.request(endpoint.method, endpoint.url, params={case.parameter: case.verification_url})
        if case.callback_token in verification.body:
            verified_artifact = _evidence(context, "api7-ssrf-verification", endpoint.url, "Controlled local callback token was returned by the configured fixture", "Only the explicitly configured local verification path is used", f"callback token observed: {case.callback_token}", [verification], verified=True)
            findings[0].status = "verified"
            findings[0].confidence = 0.98
            findings[0].evidence_ids.append(verified_artifact.evidence_id)
            return CheckResult("api7-ssrf-verification", "API7", "FAIL", evidence=(artifact, verified_artifact), findings=tuple(findings), confidence=0.98, executed=True, verified=True, endpoint=endpoint.url, method=endpoint.method)
    return CheckResult("api7-ssrf-indicator", "API7", "FAIL", evidence=(artifact,), findings=tuple(findings), confidence=0.6, executed=True, endpoint=endpoint.url, method=endpoint.method)


def check_property_authorization(endpoint: Endpoint, response: HttpResponse | None, context: CheckContext) -> CheckResult:
    cases = [case for case in context.engagement.property_authorization_cases if case.endpoint in endpoint.path or case.endpoint in endpoint.url]
    if not cases:
        return _not_run("api3-property-authorization", "API3", "no protected properties were explicitly configured")
    configured_response = context.client.request(endpoint.method, endpoint.url, identity=cases[0].identity)
    if configured_response is None or not _is_success(configured_response):
        return CheckResult("api3-property-authorization", "API3", "ERROR", reason="property response was not successfully retrieved", executed=True, endpoint=endpoint.url, method=endpoint.method)
    try:
        payload = json.loads(configured_response.body)
    except json.JSONDecodeError:
        return _not_applicable("api3-property-authorization", "API3", "response was not JSON")
    case = cases[0]
    evidence: list[Evidence] = []
    findings: list[Finding] = []
    leaked = [name for name in case.protected_properties if isinstance(payload, dict) and name in payload]
    if leaked:
        artifact = _evidence(context, "api3-property-authorization", endpoint.url, f"Protected response properties exposed: {', '.join(leaked)}", "Protected properties are omitted or minimized for the configured identity", f"properties present: {', '.join(leaked)}", [configured_response], method=endpoint.method, identity=case.identity, verified=True)
        evidence.append(artifact)
        findings.append(Finding(title="Excessive property exposure", category="API3", endpoint=endpoint.url, severity="medium", confidence=0.96, status="verified", description="The response contains properties explicitly designated as protected in the engagement configuration.", impact="Sensitive object properties may be disclosed to an unauthorized client.", evidence_ids=[artifact.evidence_id], reproduction_summary=f"GET {endpoint.url} as {case.identity}", remediation="Use response schemas and field-level authorization to omit protected properties.", references=["OWASP API3"]))
    if case.write_endpoint:
        write_url = _url(endpoint.url, case.write_endpoint)
        write_body = json.dumps({name: "__bugbounty_write_probe__" for name in case.protected_properties})
        write_response = context.client.request(case.write_method, write_url, identity=case.identity, body=write_body, headers={"Content-Type": "application/json"})
        write_ok = _is_success(write_response)
        write_artifact = _evidence(context, "api3-property-write-authorization", write_url, "Attempted a bounded write of configured protected properties", "Protected properties cannot be modified by the configured identity", f"write status={write_response.status_code}", [write_response], method=case.write_method, identity=case.identity, verified=write_ok)
        evidence.append(write_artifact)
        if write_ok:
            findings.append(Finding(title="Protected property write accepted", category="API3", endpoint=write_url, severity="medium", confidence=0.9, status="verified", description="A configured write endpoint accepted a bounded write containing protected properties.", impact="Clients may modify properties that should be protected by field-level authorization.", evidence_ids=[write_artifact.evidence_id], reproduction_summary=f"{case.write_method} {write_url} as {case.identity}", remediation="Reject unauthorized protected-property updates and enforce field-level write authorization.", references=["OWASP API3"]))
    if not findings:
        return CheckResult("api3-property-authorization", "API3", "PASS", evidence=tuple(evidence), executed=True, endpoint=endpoint.url, method=endpoint.method)
    return CheckResult("api3-property-authorization", "API3", "FAIL", evidence=tuple(evidence), findings=tuple(findings), confidence=max(item.confidence for item in findings), executed=True, verified=any(item.status == "verified" for item in findings), endpoint=endpoint.url, method=endpoint.method)


def check_resource_consumption(endpoint: Endpoint, response: HttpResponse | None, context: CheckContext) -> CheckResult:
    probes = [probe for probe in context.engagement.resource_probes if probe.endpoint in endpoint.path or probe.endpoint in endpoint.url]
    if not probes:
        return _not_run("api4-resource-consumption", "API4", "no bounded resource probe was explicitly configured")
    probe = probes[0]
    responses = [context.client.request(probe.method, endpoint.url, params={probe.query_parameter: str(probe.safe_limit)} if probe.query_parameter else None) for _ in range(probe.repeat_count)]
    if any(item.error == "maximum request budget exhausted" for item in responses):
        return CheckResult("api4-resource-consumption", "API4", "ERROR", reason="request budget exhausted during bounded probe", executed=True, endpoint=endpoint.url, method=probe.method)
    artifact = _evidence(context, "api4-resource-consumption", endpoint.url, f"Completed {len(responses)} bounded request(s) with limit {probe.safe_limit}", "Configured resource boundaries reject unsafe values without service degradation", ", ".join(str(item.status_code) for item in responses), responses, method=probe.method)
    if all(_is_success(item) for item in responses) and probe.query_parameter:
        finding = Finding(title="Resource boundary accepts repeated configured requests", category="API4", endpoint=endpoint.url, severity="low", confidence=0.7, status="candidate", description="A bounded, configuration-driven resource probe received successful responses without an observable limit response.", impact="Missing resource controls may allow higher-cost requests than intended.", evidence_ids=[artifact.evidence_id], reproduction_summary=f"Repeated {probe.method} requests with {probe.query_parameter}={probe.safe_limit}", remediation="Apply endpoint-specific pagination, rate, and cost controls; validate maximum limits server-side.", references=["OWASP API4"])
        return CheckResult("api4-resource-consumption", "API4", "FAIL", evidence=(artifact,), findings=(finding,), confidence=0.7, executed=True, endpoint=endpoint.url, method=probe.method)
    return CheckResult("api4-resource-consumption", "API4", "PASS", evidence=(artifact,), executed=True, endpoint=endpoint.url, method=probe.method)


def check_business_flow(endpoint: Endpoint, response: HttpResponse | None, context: CheckContext) -> CheckResult:
    flows = [flow for flow in context.engagement.business_flows if any(step.endpoint in endpoint.path or step.endpoint in endpoint.url for step in flow.steps)]
    if not flows:
        return _not_run("api6-sensitive-business-flow", "API6", "no explicit business flow was configured")
    flow = flows[0]
    responses: list[HttpResponse] = []
    for step in flow.steps:
        responses.append(context.client.request(step.method, _url(endpoint.url, step.endpoint), identity=step.identity))
    failed = next((item for item in responses if not _is_success(item)), None)
    if failed:
        return CheckResult("api6-sensitive-business-flow", "API6", "ERROR", reason=f"configured flow step failed with status {failed.status_code}", executed=True, endpoint=endpoint.url)
    if flow.replay_step:
        replay = next((step for step in flow.steps if step.name == flow.replay_step), None)
        if replay:
            replay_response = context.client.request(replay.method, _url(endpoint.url, replay.endpoint), identity=replay.identity)
            replay_ok = _is_success(replay_response)
            artifact = _evidence(context, "api6-sensitive-business-flow", endpoint.url, f"Replayed configured flow step {flow.replay_step}", "Sensitive flow steps reject unauthorized or duplicate replay", f"replay status={replay_response.status_code}", [replay_response], method=replay.method, identity=replay.identity, verified=replay_ok)
            if replay_ok:
                finding = Finding(title="Sensitive business flow can be replayed", category="API6", endpoint=endpoint.url, severity="medium", confidence=0.9, status="verified", description="An explicitly configured flow step succeeded when replayed.", impact="Duplicate execution may cause repeated side effects in a sensitive workflow.", evidence_ids=[artifact.evidence_id], reproduction_summary=f"Replay flow {flow.name}, step {flow.replay_step}", remediation="Use idempotency keys, state transitions, and replay protection for sensitive actions.", references=["OWASP API6"])
                return CheckResult("api6-sensitive-business-flow", "API6", "FAIL", evidence=(artifact,), findings=(finding,), confidence=0.9, executed=True, verified=True, endpoint=endpoint.url)
            return CheckResult("api6-sensitive-business-flow", "API6", "PASS", evidence=(artifact,), executed=True, endpoint=endpoint.url)
    return CheckResult("api6-sensitive-business-flow", "API6", "PASS", executed=True, endpoint=endpoint.url)


def check_unsafe_consumption(endpoint: Endpoint, response: HttpResponse | None, context: CheckContext) -> CheckResult:
    if not endpoint.response_information:
        return _not_run("api10-unsafe-consumption", "API10", "no response contract was supplied for static consumption review")
    if response and response.headers.get("Content-Type", "").lower().startswith("text/html"):
        artifact = _evidence(context, "api10-unsafe-consumption", endpoint.url, "Endpoint response content type is HTML while the API contract is present", "Consumers validate content type against the declared API contract", response.headers.get("Content-Type", ""), [response])
        finding = Finding(title="Unexpected upstream content type", category="API10", endpoint=endpoint.url, severity="low", confidence=0.75, status="candidate", description="The observed response content type differs from the expected API-style content.", impact="Unsafe consumers may parse untrusted upstream content under incorrect assumptions.", evidence_ids=[artifact.evidence_id], reproduction_summary=f"GET {endpoint.url} and inspect Content-Type", remediation="Validate upstream content types and schemas before processing responses.", references=["OWASP API10"])
        return CheckResult("api10-unsafe-consumption", "API10", "FAIL", evidence=(artifact,), findings=(finding,), confidence=0.75, executed=True, endpoint=endpoint.url)
    return CheckResult("api10-unsafe-consumption", "API10", "PASS", executed=True, endpoint=endpoint.url)


def check_authentication(endpoint: Endpoint, response: HttpResponse | None, context: CheckContext) -> CheckResult:
    if not context.engagement.identities:
        return _not_run("api2-broken-authentication", "API2", "no explicitly supplied identities; credential acquisition is unsupported")
    if not endpoint.authentication_required:
        return _not_applicable("api2-broken-authentication", "API2", "endpoint does not declare authentication")
    evidence: list[Evidence] = []
    findings: list[Finding] = []
    if _is_success(response):
        artifact = _evidence(context, "api2-broken-authentication", endpoint.url, "Protected endpoint returned success without an identity", "Authentication is required before protected data is returned", f"anonymous status={response.status_code}", [response], method=endpoint.method, identity="anonymous", verified=True)
        evidence.append(artifact)
        findings.append(Finding(title="Protected endpoint accessible anonymously", category="API2", endpoint=endpoint.url, severity="high", confidence=0.98, status="verified", description="An endpoint declared protected by the API specification returned a successful response without credentials.", impact="Unauthenticated callers may access protected API functionality or data.", evidence_ids=[artifact.evidence_id], reproduction_summary=f"GET {endpoint.url} without credentials", remediation="Enforce authentication at the API boundary and return an appropriate unauthorized response.", references=["OWASP API2"]))
    for identity in context.engagement.identities:
        if identity.name.lower() not in {"invalid", "expired", "malformed"}:
            continue
        invalid_response = context.client.request(endpoint.method, endpoint.url, identity=identity.name)
        if _is_success(invalid_response):
            artifact = _evidence(context, "api2-broken-authentication", endpoint.url, f"Invalid credential identity {identity.name} was accepted", "Invalid, expired, or malformed credentials are rejected", f"{identity.name} status={invalid_response.status_code}", [invalid_response], method=endpoint.method, identity=identity.name, verified=True)
            evidence.append(artifact)
            findings.append(Finding(title="Invalid authentication accepted", category="API2", endpoint=endpoint.url, severity="high", confidence=0.97, status="verified", description="An explicitly configured invalid credential identity received a successful response.", impact="Attackers may bypass authentication checks with invalid credentials.", evidence_ids=[artifact.evidence_id], reproduction_summary=f"GET {endpoint.url} as {identity.name}", remediation="Validate credential format, signature, expiry, issuer, and audience before authorizing requests.", references=["OWASP API2"]))
    if not evidence:
        return CheckResult("api2-broken-authentication", "API2", "PASS", reason="anonymous and configured invalid-credential checks did not produce a failure", executed=True, endpoint=endpoint.url, method=endpoint.method)
    return CheckResult("api2-broken-authentication", "API2", "FAIL", evidence=tuple(evidence), findings=tuple(findings), confidence=max(item.confidence for item in findings), executed=True, verified=True, endpoint=endpoint.url, method=endpoint.method)


def check_authorization_bola(endpoint: Endpoint, response: HttpResponse | None, context: CheckContext) -> CheckResult:
    """Check for broken object-level authorization (OWASP API1)."""
    if len(context.engagement.identities) < 2:
        return _not_run("api1-bola", "API1", "at least two explicitly supplied identities are required for differential authorization testing")
    for case in context.engagement.object_authorization_cases:
        if case.endpoint not in endpoint.path and case.endpoint not in endpoint.url:
            continue
        owner_url = _url(endpoint.url, case.endpoint).replace("{id}", case.owner_object_id)
        other_url = _url(endpoint.url, case.endpoint).replace("{id}", case.other_object_id)
        owner_response = context.client.request(case.method, owner_url, identity=case.owner_identity)
        other_response = context.client.request(case.method, other_url, identity=case.other_identity)
        cross_response = context.client.request(case.method, owner_url, identity=case.other_identity)
        # BOLA is confirmed when the non-owner identity can access the owner's object.
        # Requiring the owner baseline to also succeed caused false negatives when the
        # baseline was denied but the cross-identity access still succeeded.
        bola_confirmed = _is_success(cross_response) and case.owner_object_id != case.other_object_id
        artifact = _evidence(context, "api1-bola", owner_url, f"Compared owner identity {case.owner_identity} on object {case.owner_object_id} with other identity {case.other_identity} on object {case.other_object_id}, then requested the owner object cross-identity", "Owner succeeds on the owner object, the other identity succeeds on its own object, and the cross-identity request for the owner object is denied", f"owner={owner_response.status_code}, other_own_object={other_response.status_code}, cross_identity_owner_object={cross_response.status_code}", [owner_response, other_response, cross_response], method=case.method, identity=case.other_identity, object_id=case.owner_object_id, request_metadata_extra={"owner_identity": case.owner_identity, "other_identity": case.other_identity, "owner_object_id": case.owner_object_id, "other_object_id": case.other_object_id, "requested_object_id": case.owner_object_id}, verified=bola_confirmed)
        if bola_confirmed:
            finding = Finding(title="Broken object level authorization", category="API1", endpoint=owner_url, severity="high", confidence=0.99, status="verified", description="An explicitly configured non-owner identity accessed an object owned by another identity.", impact="Users may read or modify objects outside their authorization boundary.", evidence_ids=[artifact.evidence_id], reproduction_summary=f"{case.other_identity} requested object {case.owner_object_id}", remediation="Enforce object ownership or authorization checks on every object access.", references=["OWASP API1"])
            return CheckResult("api1-bola", "API1", "FAIL", evidence=(artifact,), findings=(finding,), confidence=0.99, executed=True, verified=True, endpoint=owner_url, method=case.method)
        return CheckResult("api1-bola", "API1", "PASS", evidence=(artifact,), executed=True, endpoint=owner_url, method=case.method)
    return _not_run("api1-bola", "API1", "no explicit object authorization case matched this endpoint")


def check_authorization_function(endpoint: Endpoint, response: HttpResponse | None, context: CheckContext) -> CheckResult:
    """Check for broken function-level authorization (OWASP API5)."""
    if len(context.engagement.identities) < 2:
        return _not_run("api5-broken-function-level-authorization", "API5", "at least two explicitly supplied identities are required for differential authorization testing")
    for case in context.engagement.function_authorization_cases:
        if case.endpoint not in endpoint.path and case.endpoint not in endpoint.url:
            continue
        url = _url(endpoint.url, case.endpoint)
        allowed_response = context.client.request(case.method, url, identity=case.allowed_identity)
        denied_response = context.client.request(case.method, url, identity=case.denied_identity)
        # BFLA is confirmed when the lower-privilege identity is accepted by a function
        # reserved for another role. Requiring the allowed baseline to succeed hid the
        # vulnerability whenever that baseline was denied.
        bfla_confirmed = _is_success(denied_response) and case.denied_identity != case.allowed_identity
        artifact = _evidence(context, "api5-broken-function-level-authorization", url, f"Compared allowed role {case.allowed_identity} with denied role {case.denied_identity}", "Allowed role succeeds and denied role is rejected", f"allowed={allowed_response.status_code}, denied={denied_response.status_code}", [allowed_response, denied_response], method=case.method, identity=case.denied_identity, verified=bfla_confirmed)
        if bfla_confirmed:
            finding = Finding(title="Broken function level authorization", category="API5", endpoint=url, severity="high", confidence=0.99, status="verified", description="An explicitly configured lower-privilege identity accessed a function reserved for another role.", impact="Users may invoke privileged operations without the required role.", evidence_ids=[artifact.evidence_id], reproduction_summary=f"{case.denied_identity} requested {url}", remediation="Enforce role or permission checks on the function endpoint.", references=["OWASP API5"])
            return CheckResult("api5-broken-function-level-authorization", "API5", "FAIL", evidence=(artifact,), findings=(finding,), confidence=0.99, executed=True, verified=True, endpoint=url, method=case.method)
        return CheckResult("api5-broken-function-level-authorization", "API5", "PASS", evidence=(artifact,), executed=True, endpoint=url, method=case.method)
    return _not_run("api5-broken-function-level-authorization", "API5", "no explicit function authorization case matched this endpoint")


def check_unsupported(endpoint: Endpoint, response: HttpResponse | None, context: CheckContext, *, check_id: str, category: str, reason: str) -> CheckResult:
    return _not_run(check_id, category, reason)


def default_checks() -> list[SecurityCheck]:
    return [
        SecurityCheck("api1-bola", "API1", "Broken object-level authorization assessment", check_authorization_bola, priority=1),
        SecurityCheck("api5-broken-function-level-authorization", "API5", "Broken function-level authorization assessment", check_authorization_function, priority=2),
        SecurityCheck("api2-broken-authentication", "API2", "Authentication prerequisite assessment", check_authentication, priority=3),
        SecurityCheck("api3-property-authorization", "API3", "Property-level authorization assessment", check_property_authorization, priority=4),
        SecurityCheck("api7-ssrf-indicator", "API7", "Safe SSRF sink identification", check_ssrf_indicator, priority=5),
        SecurityCheck("api8-security-misconfiguration", "API8", "Passive security configuration review", check_security_misconfiguration, priority=6),
        SecurityCheck("api9-improper-inventory", "API9", "API inventory source review", check_inventory, priority=7),
        SecurityCheck("api10-unsafe-consumption", "API10", "Unsafe consumption assessment", check_unsafe_consumption, priority=8),
        SecurityCheck("api4-resource-consumption", "API4", "Conservative resource consumption assessment", check_resource_consumption, priority=9),
        SecurityCheck("api6-sensitive-business-flow", "API6", "Sensitive business flow assessment", check_business_flow, priority=10),
    ]


__all__ = ["CheckContext", "CheckResult", "SecurityCheck", "default_checks"]
