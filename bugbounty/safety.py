from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse

from .config import ScopeConfig


@dataclass(frozen=True)
class SafetyDecision:
    allowed: bool
    reason: str
    target: str


class SafetyPolicy:
    """Guard rails for all active testing."""

    def __init__(self, scope: ScopeConfig | None = None):
        self.scope = scope or ScopeConfig(domains=[], urls=[])

    def authorize_target(self, target: str) -> bool:
        if not target:
            return False
        parsed = urlparse(target)
        if parsed.scheme not in {"http", "https"}:
            return False
        return self.scope.contains(target)

    def check(self, target: str, method: str = "GET", risk: str = "low") -> SafetyDecision:
        if not self.authorize_target(target):
            return SafetyDecision(False, "target is outside authorized scope", target)
        if method.upper() not in {m.upper() for m in self.scope.allowed_methods}:
            return SafetyDecision(False, f"method {method.upper()} is not allowed by scope", target)
        if risk.lower() in {"high", "critical"} and self.scope.notes:
            return SafetyDecision(False, "high-risk action requires explicit approval", target)
        return SafetyDecision(True, "authorized within scope", target)
