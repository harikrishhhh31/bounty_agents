from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlparse


@dataclass
class ScopeConfig:
    """Boundary definition for a testing mission."""

    domains: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    allowed_methods: list[str] = field(
        default_factory=lambda: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
    )
    max_requests_per_minute: int = 10
    notes: str = ""

    def contains(self, target: str) -> bool:
        if not target:
            return False
        parsed = urlparse(target)
        hostname = (parsed.netloc or parsed.path or "").split(":", 1)[0].lower()
        if not hostname:
            return False
        domain_matches = any(hostname == d.lower() or hostname.endswith(f".{d.lower()}") for d in self.domains)
        url_matches = any(target.startswith(url.rstrip("/").lower()) for url in self.urls)
        return domain_matches or url_matches


@dataclass
class SecurityAppConfig:
    """Shared runtime configuration for the unified platform."""

    workspace: str = "."
    max_requests_per_minute: int = 10
    approval_mode: str = "deny"
    dry_run: bool = True
    max_parallel_agents: int = 3
    audit_log_path: str = "audit.jsonl"
    evidence_path: str = "evidence"
    model_timeout_seconds: int = 30
    default_risk_threshold: str = "medium"
    scope: ScopeConfig = field(default_factory=ScopeConfig)

    def __post_init__(self) -> None:
        allowed = {"deny", "ask", "auto"}
        if self.approval_mode not in allowed:
            raise ValueError("approval_mode must be one of: deny, ask, auto")
        if self.max_requests_per_minute <= 0:
            raise ValueError("max_requests_per_minute must be positive")
