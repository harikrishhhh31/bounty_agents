from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Literal

RiskLevel = Literal["safe", "active", "intrusive"]


@dataclass(frozen=True, slots=True)
class Specialist:
    """Normalized specialist definition converted from Bug-Bounty-Agents source docs."""

    id: str
    name: str
    description: str
    domains: list[str]
    tags: list[str]
    signals: list[str]
    capabilities: list[str]
    risk_level: RiskLevel
    source: str
    source_reference: str
    priority: int = 50

    def __post_init__(self) -> None:
        if not self.id or not self.id.strip():
            raise ValueError("specialist id cannot be empty")
        if not self.name or not self.name.strip():
            raise ValueError("specialist name cannot be empty")
        if not self.description or not self.description.strip():
            raise ValueError("specialist description cannot be empty")
        if not self.source or not self.source.strip():
            raise ValueError("specialist source cannot be empty")
        if not self.source_reference or not self.source_reference.strip():
            raise ValueError("specialist source_reference cannot be empty")
        if self.risk_level not in {"safe", "active", "intrusive"}:
            raise ValueError("risk_level must be 'safe', 'active', or 'intrusive'")
        if not 0 <= self.priority <= 100:
            raise ValueError("priority must be between 0 and 100")

        object.__setattr__(self, "domains", [str(v).strip().lower() for v in self.domains if str(v).strip()])
        object.__setattr__(self, "tags", [str(v).strip().lower() for v in self.tags if str(v).strip()])
        object.__setattr__(self, "signals", [str(v).strip().lower() for v in self.signals if str(v).strip()])
        object.__setattr__(self, "capabilities", [str(v).strip().lower() for v in self.capabilities if str(v).strip()])

        if not self.domains:
            raise ValueError(f"specialist {self.id} must include at least one domain")


@dataclass(frozen=True, slots=True)
class RankedSpecialist:
    specialist: Specialist
    score: int
    reasons: list[str] = field(default_factory=list)

    @property
    def id(self) -> str:
        return self.specialist.id

    @property
    def name(self) -> str:
        return self.specialist.name


class SpecialistRegistry:
    """Central registry for normalized security specialists."""

    def __init__(self, specialists: Iterable[Specialist] | None = None) -> None:
        self._specialists: dict[str, Specialist] = {}
        if specialists:
            for specialist in specialists:
                self.register(specialist)

    def register(self, specialist: Specialist) -> Specialist:
        self.validate(specialist)
        if specialist.id in self._specialists:
            raise ValueError(f"duplicate specialist id: {specialist.id}")
        self._specialists[specialist.id] = specialist
        return specialist

    def get(self, specialist_id: str) -> Specialist | None:
        return self._specialists.get(specialist_id.strip())

    def list(self) -> list[Specialist]:
        return list(self._specialists.values())

    def find_by_domain(self, domain: str) -> list[Specialist]:
        lookup = domain.strip().lower()
        return [s for s in self.list() if lookup in {item.lower() for item in s.domains}]

    def find_by_signal(self, signal: str) -> list[Specialist]:
        lookup = signal.strip().lower()
        return [s for s in self.list() if lookup in {item.lower() for item in s.signals}]

    def search(self, query: str) -> list[Specialist]:
        if not query or not query.strip():
            return []
        needle = query.strip().lower()
        matches: list[Specialist] = []
        for specialist in self.list():
            haystack = " ".join(
                [
                    specialist.id,
                    specialist.name,
                    specialist.description,
                    " ".join(specialist.domains),
                    " ".join(specialist.tags),
                    " ".join(specialist.signals),
                    " ".join(specialist.capabilities),
                ]
            ).lower()
            if needle in haystack:
                matches.append(specialist)
        return matches

    def validate(self, specialist: Specialist | None = None) -> bool:
        if specialist is None:
            for item in self.list():
                self.validate(item)
            return True

        if not isinstance(specialist, Specialist):
            raise TypeError("specialist must be of type Specialist")
        if not specialist.id or not specialist.name or not specialist.description:
            raise ValueError(f"malformed specialist definition: {specialist}")
        if specialist.source_reference == "":
            raise ValueError(f"specialist {specialist.id} is missing source_reference")
        return True


def _normalize_tokens(values: Iterable[str] | None) -> set[str]:
    if values is None:
        return set()
    return {str(v).strip().lower() for v in values if str(v).strip()}


def ranked_specialists(
    registry: SpecialistRegistry,
    *,
    target: str = "",
    observations: Iterable[str] | None = None,
    domain_hints: Iterable[str] | None = None,
    technology: str | None = None,
) -> list[RankedSpecialist]:
    """Score specialists using observable signals and target characteristics."""
    target_text = (target or "").lower()
    observed = _normalize_tokens(observations)
    domains = _normalize_tokens(domain_hints)
    if technology:
        domains.add(str(technology).lower())

    scored: list[RankedSpecialist] = []
    for specialist in registry.list():
        score = 0
        reasons: list[str] = []

        if specialist.priority:
            score += int(specialist.priority // 10)

        # Domain + target overlap
        overlap = set(specialist.domains) & (domains | set(specialist.domains))
        if overlap:
            score += 30
            reasons.append(f"domain match: {', '.join(sorted(overlap))}")

        if "graphql" in target_text or "graphql" in observed:
            if "graphql" in specialist.domains or "graphql" in specialist.tags or "graphql" in specialist.signals:
                score += 45
                reasons.append("target or observations indicate GraphQL usage")

        if "ssrf" in target_text or "ssrf" in observed:
            if "ssrf" in specialist.domains or "ssrf" in specialist.tags or "ssrf" in specialist.signals:
                score += 45
                reasons.append("observable SSRF signal")

        if any(token in observed for token in {"auth", "authorization", "idor", "jwt", "oauth", "session"}):
            if any(token in specialist.tags or token in specialist.signals for token in {"auth", "authorization", "api", "jwt", "oauth"}):
                score += 35
                reasons.append("identity or authorization signal")

        if any(token in observed for token in {"xss", "sql", "injection", "command", "file", "path"}):
            if any(token in specialist.tags or token in specialist.signals for token in {"xss", "injection", "file", "path", "web"}):
                score += 28
                reasons.append("injection or web attack signal")

        if any(token in observed for token in {"workflow", "payment", "checkout", "price", "logic"}):
            if any(token in specialist.tags or token in specialist.signals for token in {"business-logic", "logic", "workflow", "payment"}):
                score += 33
                reasons.append("application workflow or business-logic signal")

        if any(token in observed for token in {"recon", "subdomain", "osint", "intel", "host", "asset"}):
            if any(token in specialist.tags or token in specialist.signals for token in {"recon", "intel", "osint", "asset"}):
                score += 25
                reasons.append("reconnaissance intake signal")

        if any(token in observed for token in {"cloud", "metadata", "aws", "azure", "gcp"}):
            if any(token in specialist.tags or token in specialist.signals for token in {"cloud", "metadata"}):
                score += 30
                reasons.append("cloud or metadata signal")

        # Target character hints
        if "/graphql" in target_text and ("graphql" in specialist.domains or "graphql" in specialist.tags):
            score += 45
            reasons.append("GraphQL endpoint detected")
        if "/api/" in target_text and ("api" in specialist.domains or "api" in specialist.tags):
            score += 30
            reasons.append("API endpoint detected")
        if "webhook" in target_text and ("ssrf" in specialist.domains or "ssrf" in specialist.tags):
            score += 30
            reasons.append("webhook or fetch sink detected")

        # Observed signal matching
        matched_signals = set(specialist.signals) & observed
        if matched_signals:
            score += len(matched_signals) * 12
            reasons.append(f"signal match: {', '.join(sorted(matched_signals))}")

        if not reasons and score <= 0:
            continue

        scored.append(RankedSpecialist(specialist=specialist, score=score, reasons=reasons))

    return sorted(scored, key=lambda item: (-item.score, -item.specialist.priority, item.specialist.name))


def route_specialist(
    registry: SpecialistRegistry,
    *,
    target: str = "",
    observations: Iterable[str] | None = None,
    domain_hints: Iterable[str] | None = None,
    technology: str | None = None,
) -> list[RankedSpecialist]:
    """Return ranked specialists without asserting a vulnerability exists."""
    return ranked_specialists(
        registry,
        target=target,
        observations=observations,
        domain_hints=domain_hints,
        technology=technology,
    )


def _make_default_specialists() -> list[Specialist]:
    return [
        Specialist(
            id="recon-advisor",
            name="Recon Advisor",
            description="Surface enumeration and asset discovery",
            domains=["reconnaissance", "recon"],
            tags=["recon", "intel", "asset", "subdomain"],
            signals=["recon", "subdomain", "asset", "intel"],
            capabilities=["surface-enumeration", "asset-discovery", "technology-fingerprinting"],
            risk_level="safe",
            source="Bug-Bounty-Agents",
            source_reference="recon-advisor.md",
            priority=86,
        ),
        Specialist(
            id="osint-collector",
            name="OSINT Collector",
            description="Open-source intelligence gathering",
            domains=["reconnaissance", "intel"],
            tags=["intel", "osint", "whois", "dns"],
            signals=["osint", "subdomain", "whois", "dns"],
            capabilities=["dns-enumeration", "identity-collection", "infrastructure-osint"],
            risk_level="safe",
            source="Bug-Bounty-Agents",
            source_reference="osint-collector.md",
            priority=82,
        ),
        Specialist(
            id="web-hunter",
            name="Web Hunter",
            description="Web application vulnerability hunting and parameter testing",
            domains=["web", "injection", "xss", "csrf"],
            tags=["web", "http", "xss", "injection", "directory"],
            signals=["web", "xss", "sql", "command", "injection", "directory"],
            capabilities=["content-discovery", "parameter-fuzzing", "sql-injection-testing", "xss-testing", "command-injection-testing"],
            risk_level="active",
            source="Bug-Bounty-Agents",
            source_reference="web-hunter.md",
            priority=92,
        ),
        Specialist(
            id="api-security",
            name="API Security",
            description="REST and GraphQL API testing with OWASP API Top 10 guidance",
            domains=["api", "authentication", "authorization", "business-logic"],
            tags=["api", "auth", "authorization", "jwt", "oauth"],
            signals=["api", "authorization", "idor", "jwt", "oauth", "session"],
            capabilities=["api-discovery", "jwt-analysis", "oauth-testing", "authorization-testing", "rate-limit-bypass-analysis"],
            risk_level="active",
            source="Bug-Bounty-Agents",
            source_reference="api-security.md",
            priority=94,
        ),
        Specialist(
            id="graphql-hunter",
            name="GraphQL Hunter",
            description="GraphQL schema mapping, introspection, authz, and complexity attacks",
            domains=["graphql", "api", "authorization"],
            tags=["graphql", "api", "authorization", "schema"],
            signals=["graphql", "authorization", "introspection", "depth", "batching"],
            capabilities=["schema-mapping", "introspection-analysis", "depth-testing", "authority-review", "mutation-safety-review"],
            risk_level="active",
            source="Bug-Bounty-Agents",
            source_reference="graphql-hunter.md",
            priority=95,
        ),
        Specialist(
            id="bizlogic-hunter",
            name="Business Logic Hunter",
            description="Workflow and business-rule abuse detection",
            domains=["business-logic", "authorization", "workflow"],
            tags=["logic", "payment", "checkout", "workflow"],
            signals=["workflow", "payment", "price", "logic", "checkout"],
            capabilities=["price-manipulation-review", "workflow-bypass-analysis", "race-condition-review", "authorization-boundary-review"],
            risk_level="active",
            source="Bug-Bounty-Agents",
            source_reference="bizlogic-hunter.md",
            priority=90,
        ),
        Specialist(
            id="ssrf-hunter",
            name="SSRF Hunter",
            description="Server-side request forgery discovery with metadata and internal probes",
            domains=["ssrf", "cloud", "infrastructure"],
            tags=["ssrf", "cloud", "metadata", "webhook"],
            signals=["ssrf", "metadata", "url-fetch", "cloud", "webhook"],
            capabilities=["sink-identification", "callback-analysis", "filter-bypass-review", "cloud-metadata-testing"],
            risk_level="active",
            source="Bug-Bounty-Agents",
            source_reference="ssrf-hunter.md",
            priority=93,
        ),
        Specialist(
            id="jwt-cracker",
            name="JWT Cracker",
            description="JWT and OIDC token analysis and misconfiguration review",
            domains=["authentication", "api"],
            tags=["jwt", "oauth", "oidc", "token"],
            signals=["jwt", "token", "oauth", "oidc", "authorization"],
            capabilities=["jwt-signature-analysis", "oidc-review", "token-claim-manipulation"],
            risk_level="active",
            source="Bug-Bounty-Agents",
            source_reference="jwt-cracker.md",
            priority=78,
        ),
        Specialist(
            id="vuln-scanner",
            name="Vulnerability Scanner",
            description="Automated scanning orchestration and triage",
            domains=["reconnaissance", "web"],
            tags=["scan", "triage", "fuzz", "discovery"],
            signals=["scan", "discovery", "fuzz", "web"],
            capabilities=["scan-orchestration", "finding-triage", "output-normalization"],
            risk_level="intrusive",
            source="Bug-Bounty-Agents",
            source_reference="vuln-scanner.md",
            priority=74,
        ),
        Specialist(
            id="cloud-security",
            name="Cloud Security",
            description="Cloud misconfiguration and metadata abuse review",
            domains=["cloud", "infrastructure"],
            tags=["cloud", "aws", "azure", "gcp", "metadata"],
            signals=["cloud", "aws", "azure", "gcp", "metadata"],
            capabilities=["misconfiguration-review", "identity-review", "cloud-metadata-abuse-review"],
            risk_level="active",
            source="Bug-Bounty-Agents",
            source_reference="cloud-security.md",
            priority=80,
        ),
        Specialist(
            id="container-escape",
            name="Container Escape",
            description="Container and Kubernetes breakout assessment",
            domains=["infrastructure", "cloud"],
            tags=["container", "kubernetes", "escape", "infra"],
            signals=["container", "kubernetes", "privilege", "escape"],
            capabilities=["container-review", "kubernetes-hardening-review", "privilege-escalation-path-analysis"],
            risk_level="intrusive",
            source="Bug-Bounty-Agents",
            source_reference="container-escape.md",
            priority=76,
        ),
        Specialist(
            id="cicd-redteam",
            name="CI/CD Red Team",
            description="Pipeline and supply-chain security review",
            domains=["infrastructure", "cloud"],
            tags=["cicd", "pipeline", "supply-chain"],
            signals=["ci", "cd", "pipeline", "github", "gitlab"],
            capabilities=["pipeline-review", "supply-chain-risk-analysis", "workflow-hardening"],
            risk_level="intrusive",
            source="Bug-Bounty-Agents",
            source_reference="cicd-redteam.md",
            priority=75,
        ),
        Specialist(
            id="mobile-pentester",
            name="Mobile Pentester",
            description="Application testing and traffic interception for mobile apps",
            domains=["mobile", "api", "authentication"],
            tags=["mobile", "ios", "android", "api"],
            signals=["mobile", "android", "ios", "traffic"],
            capabilities=["static-analysis", "dynamic-analysis", "traffic-interception", "storage-review"],
            risk_level="active",
            source="Bug-Bounty-Agents",
            source_reference="mobile-pentester.md",
            priority=72,
        ),
        Specialist(
            id="exploit-chainer",
            name="Exploit Chainer",
            description="Combine findings into multi-step exploit paths and attack chains",
            domains=["exploit", "reconnaissance", "business-logic"],
            tags=["exploit", "attack-chain", "path"],
            signals=["exploit", "chain", "impact", "correlation"],
            capabilities=["attack-chain-construction", "impact-analysis", "exploit-correlation"],
            risk_level="active",
            source="Bug-Bounty-Agents",
            source_reference="exploit-chainer.md",
            priority=77,
        ),
        Specialist(
            id="poc-validator",
            name="PoC Validator",
            description="Verify, stabilize, and minimize proof-of-concept output",
            domains=["validation", "exploit", "reporting"],
            tags=["validation", "poc", "verification"],
            signals=["verification", "proof", "evidence", "repro"],
            capabilities=["evidence-validation", "proof-minimization", "verification-planning"],
            risk_level="active",
            source="Bug-Bounty-Agents",
            source_reference="poc-validator.md",
            priority=84,
        ),
        Specialist(
            id="report-generator",
            name="Report Generator",
            description="Bug-bounty report drafting and evidence packaging",
            domains=["reporting"],
            tags=["report", "evidence", "triage"],
            signals=["report", "evidence", "triage"],
            capabilities=["report-drafting", "severity-rationale", "evidence-packaging"],
            risk_level="safe",
            source="Bug-Bounty-Agents",
            source_reference="report-generator.md",
            priority=88,
        ),
        Specialist(
            id="engagement-planner",
            name="Engagement Planner",
            description="Scope, rules-of-engagement, and test-plan authoring",
            domains=["reconnaissance", "planning"],
            tags=["scope", "planning", "engagement"],
            signals=["scope", "engagement", "plan"],
            capabilities=["scope-validation", "test-plan-authoring", "roe-planning"],
            risk_level="safe",
            source="Bug-Bounty-Agents",
            source_reference="engagement-planner.md",
            priority=80,
        ),
    ]


DEFAULT_SPECIALIST_REGISTRY = SpecialistRegistry(_make_default_specialists())

__all__ = [
    "RankedSpecialist",
    "RiskLevel",
    "Specialist",
    "SpecialistRegistry",
    "DEFAULT_SPECIALIST_REGISTRY",
    "ranked_specialists",
    "route_specialist",
]
