from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .agents import AgentRegistry, AgentSpec, route_agent
from .config import ScopeConfig
from .safety import SafetyPolicy


@dataclass
class MissionContext:
    target: str
    scope: ScopeConfig
    signals: list[str] = field(default_factory=list)
    findings: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class Mission:
    context: MissionContext
    policy: SafetyPolicy
    router: AgentRegistry | None = None

    def dispatch(self) -> list[AgentSpec] | AgentSpec:
        if self.router is None:
            return []
        return route_agent(self.router, {"target": self.context.target, "signals": self.context.signals})

    def is_authorized(self) -> bool:
        return self.policy.authorize_target(self.context.target)


__all__ = ["Mission", "MissionContext", "route_agent"]
