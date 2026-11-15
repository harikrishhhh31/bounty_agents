from __future__ import annotations

from typing import Callable

from .checks import CheckContext
from .discovery import Endpoint


PreconditionChecker = Callable[[Endpoint, CheckContext], tuple[str, str] | None]


def check_api1_preconditions(endpoint: Endpoint, context: CheckContext) -> tuple[str, str] | None:
    if len(context.engagement.identities) < 2:
        return ("NOT_RUN", "at least two explicitly supplied identities are required for differential authorization testing")
    cases = context.engagement.object_authorization_cases
    if not any(case.endpoint in endpoint.path or case.endpoint in endpoint.url for case in cases):
        return ("NOT_RUN", "no explicit object authorization case matched this endpoint")
    return None


def check_api5_preconditions(endpoint: Endpoint, context: CheckContext) -> tuple[str, str] | None:
    if len(context.engagement.identities) < 2:
        return ("NOT_RUN", "at least two explicitly supplied identities are required for differential function authorization testing")
    cases = context.engagement.function_authorization_cases
    if not any(case.endpoint in endpoint.path or case.endpoint in endpoint.url for case in cases):
        return ("NOT_RUN", "no explicit function authorization case matched this endpoint")
    return None


def check_api2_preconditions(endpoint: Endpoint, context: CheckContext) -> tuple[str, str] | None:
    if not context.engagement.identities:
        return ("NOT_RUN", "no explicitly supplied identities; credential acquisition is unsupported")
    if not endpoint.authentication_required:
        return ("NOT_APPLICABLE", "endpoint does not declare authentication")
    return None


def check_api3_preconditions(endpoint: Endpoint, context: CheckContext) -> tuple[str, str] | None:
    cases = [case for case in context.engagement.property_authorization_cases if case.endpoint in endpoint.path or case.endpoint in endpoint.url]
    if not cases:
        return ("NOT_RUN", "no protected properties were explicitly configured")
    return None


def check_api4_preconditions(endpoint: Endpoint, context: CheckContext) -> tuple[str, str] | None:
    probes = [probe for probe in context.engagement.resource_probes if probe.endpoint in endpoint.path or probe.endpoint in endpoint.url]
    if not probes:
        return ("NOT_RUN", "no bounded resource probe was explicitly configured")
    return None


def check_api6_preconditions(endpoint: Endpoint, context: CheckContext) -> tuple[str, str] | None:
    flows = [flow for flow in context.engagement.business_flows if any(step.endpoint in endpoint.path or step.endpoint in endpoint.url for step in flow.steps)]
    if not flows:
        return ("NOT_RUN", "no explicit business flow was configured")
    return None


def check_api7_preconditions(endpoint: Endpoint, context: CheckContext) -> tuple[str, str] | None:
    candidates = [str(parameter.get("name")) for parameter in endpoint.parameters if isinstance(parameter, dict) and str(parameter.get("name", "")).lower() in {"url", "uri", "callback", "webhook", "redirect", "next", "image_url", "resource"}]
    if not candidates:
        return ("NOT_APPLICABLE", "no URL-like parameter was discovered")
    return None


def check_api8_preconditions(endpoint: Endpoint, context: CheckContext) -> tuple[str, str] | None:
    return None


def check_api9_preconditions(endpoint: Endpoint, context: CheckContext) -> tuple[str, str] | None:
    return None


def check_api10_preconditions(endpoint: Endpoint, context: CheckContext) -> tuple[str, str] | None:
    if not endpoint.response_information:
        return ("NOT_RUN", "no response contract was supplied for static consumption review")
    return None


PRECONDITION_CHECKS: dict[str, PreconditionChecker] = {
    "api1-bola": check_api1_preconditions,
    "api2-broken-authentication": check_api2_preconditions,
    "api3-property-authorization": check_api3_preconditions,
    "api4-resource-consumption": check_api4_preconditions,
    "api5-broken-function-level-authorization": check_api5_preconditions,
    "api6-sensitive-business-flow": check_api6_preconditions,
    "api7-ssrf-indicator": check_api7_preconditions,
    "api8-security-misconfiguration": check_api8_preconditions,
    "api9-improper-inventory": check_api9_preconditions,
    "api10-unsafe-consumption": check_api10_preconditions,
}


__all__ = ["PreconditionChecker", "PRECONDITION_CHECKS"]
