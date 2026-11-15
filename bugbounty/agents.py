from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable


@dataclass(frozen=True)
class AgentSpec:
    name: str
    kind: str
    risk: str = "safe"
    tags: set[str] = field(default_factory=set)
    description: str = ""


class AgentRegistry:
    """Registry for the platform's specialist agents."""

    def __init__(self):
        self._agents: list[AgentSpec] = []

    def register(self, agent: AgentSpec) -> None:
        self._agents.append(agent)

    def get(self, name: str) -> AgentSpec | None:
        for agent in self._agents:
            if agent.name == name:
                return agent
        return None

    def all(self) -> list[AgentSpec]:
        return list(self._agents)


def _normalize_signals(signals: Iterable[str]) -> set[str]:
    return {str(item).lower().strip() for item in signals if str(item).strip()}


def route_agent(registry: AgentRegistry, context: dict[str, Any]) -> AgentSpec:
    """Route a mission or observation to the most relevant specialist.

    This combines the repo1 specialist catalog with the dynamic routing ethos of
    the SecBrain control plane.
    """
    if not registry.all():
        raise ValueError("registry is empty")

    target = str(context.get("target", "")).lower()
    signals = _normalize_signals(context.get("signals", []))
    if "graphql" in signals or "/graphql" in target or "graphql" in target:
        for agent in registry.all():
            if "graphql" in agent.tags or agent.kind == "graphql":
                return agent

    if "ssrf" in signals or "ssrf" in target:
        for agent in registry.all():
            if "ssrf" in agent.tags or agent.kind == "ssrf":
                return agent

    if "auth" in signals or "authorization" in signals or "idor" in signals:
        for agent in registry.all():
            if any(tag in {"auth", "authorization", "idor", "api"} for tag in agent.tags):
                return agent

    best: tuple[int, AgentSpec] | None = None
    for agent in registry.all():
        score = 0
        agent_tags = agent.tags
        for signal in signals:
            if signal in agent_tags:
                score += 3
            if signal == agent.kind:
                score += 2
        if target and any(token in target for token in agent.kind.split("-")):
            score += 1
        if best is None or score > best[0]:
            best = (score, agent)

    if not best:
        return registry.all()[0]
    return best[1]


DEFAULT_AGENT_REGISTRY = AgentRegistry()
for agent in [
    AgentSpec(
        name="web-specialist",
        kind="web",
        risk="active",
        tags={"web", "http", "application"},
        description="Web application testing and vulnerability hunting",
    ),
    AgentSpec(
        name="graphql-specialist",
        kind="graphql",
        risk="active",
        tags={"graphql", "api", "authorization"},
        description="GraphQL schema, authz, and query abuse analysis",
    ),
    AgentSpec(
        name="ssrf-specialist",
        kind="ssrf",
        risk="active",
        tags={"ssrf", "http", "cloud"},
        description="SSRF and metadata endpoint exploitation",
    ),
    AgentSpec(
        name="api-specialist",
        kind="api",
        risk="active",
        tags={"api", "auth", "authorization", "business-logic"},
        description="API testing, authn/authz, and business-logic review",
    ),
    AgentSpec(
        name="recon-specialist",
        kind="recon",
        risk="safe",
        tags={"recon", "intel", "subdomain", "osint"},
        description="Reconnaissance and asset discovery",
    ),
    AgentSpec(
        name="reporting-specialist",
        kind="report",
        risk="safe",
        tags={"report", "evidence", "triage"},
        description="Structured reporting and evidence packaging",
    ),
]:
    DEFAULT_AGENT_REGISTRY.register(agent)

__all__ = ["AgentSpec", "AgentRegistry", "DEFAULT_AGENT_REGISTRY", "route_agent"]
