from bugbounty.config import ScopeConfig
from bugbounty.orchestration import Mission, MissionContext
from bugbounty.safety import SafetyPolicy
from bugbounty.specialists import (
    Specialist,
    SpecialistRegistry,
    ranked_specialists,
    route_specialist,
)


def test_registry_registration():
    registry = SpecialistRegistry()
    specialist = Specialist(
        id="web-hunter",
        name="Web Hunter",
        description="Web app testing",
        domains=["web"],
        tags=["http", "web"],
        signals=["web", "xss", "injection"],
        capabilities=["web-testing", "parameter-fuzzing"],
        risk_level="active",
        source="Bug-Bounty-Agents",
        source_reference="web-hunter.md",
        priority=90,
    )
    registry.register(specialist)
    assert registry.get("web-hunter") == specialist


def test_duplicate_specialist_rejection():
    registry = SpecialistRegistry()
    specialist = Specialist(
        id="api-security",
        name="API Security",
        description="API testing",
        domains=["api"],
        tags=["api"],
        signals=["api", "auth"],
        capabilities=["api-testing"],
        risk_level="active",
        source="Bug-Bounty-Agents",
        source_reference="api-security.md",
        priority=85,
    )
    registry.register(specialist)

    try:
        registry.register(specialist)
        assert False, "duplicate specialist registration should fail"
    except ValueError:
        pass


def test_specialist_lookup():
    registry = SpecialistRegistry()
    registry.register(
        Specialist(
            id="graphql-hunter",
            name="GraphQL Hunter",
            description="GraphQL testing",
            domains=["graphql"],
            tags=["graphql", "api"],
            signals=["graphql", "authorization"],
            capabilities=["schema-mapping"],
            risk_level="active",
            source="Bug-Bounty-Agents",
            source_reference="graphql-hunter.md",
            priority=95,
        )
    )

    result = registry.get("graphql-hunter")
    assert result is not None
    assert result.name == "GraphQL Hunter"


def test_domain_lookup():
    registry = SpecialistRegistry()
    registry.register(
        Specialist(
            id="ssrf-hunter",
            name="SSRF Hunter",
            description="SSRF testing",
            domains=["ssrf"],
            tags=["ssrf", "cloud"],
            signals=["ssrf", "cloud", "metadata"],
            capabilities=["callback-testing"],
            risk_level="active",
            source="Bug-Bounty-Agents",
            source_reference="ssrf-hunter.md",
            priority=92,
        )
    )

    matches = registry.find_by_domain("ssrf")
    assert any(item.id == "ssrf-hunter" for item in matches)


def test_signal_based_routing():
    registry = SpecialistRegistry()
    registry.register(
        Specialist(
            id="graphql-hunter",
            name="GraphQL Hunter",
            description="GraphQL testing",
            domains=["graphql"],
            tags=["graphql", "api"],
            signals=["graphql", "authorization"],
            capabilities=["schema-mapping"],
            risk_level="active",
            source="Bug-Bounty-Agents",
            source_reference="graphql-hunter.md",
            priority=95,
        )
    )
    registry.register(
        Specialist(
            id="web-hunter",
            name="Web Hunter",
            description="Web app testing",
            domains=["web"],
            tags=["web", "http"],
            signals=["web", "xss"],
            capabilities=["parameter-fuzzing"],
            risk_level="active",
            source="Bug-Bounty-Agents",
            source_reference="web-hunter.md",
            priority=50,
        )
    )

    candidates = route_specialist(registry, target="https://example.com/graphql", observations=["graphql", "authorization"])
    assert candidates[0].id == "graphql-hunter"


def test_ranked_routing():
    registry = SpecialistRegistry()
    registry.register(
        Specialist(
            id="api-security",
            name="API Security",
            description="API dedicates",
            domains=["api"],
            tags=["api", "auth"],
            signals=["api", "authorization", "id-or"],
            capabilities=["id-or-testing"],
            risk_level="active",
            source="Bug-Bounty-Agents",
            source_reference="api-security.md",
            priority=90,
        )
    )
    registry.register(
        Specialist(
            id="bizlogic-hunter",
            name="Business Logic",
            description="Workflow testing",
            domains=["business-logic"],
            tags=["logic", "checkout"],
            signals=["price", "workflow", "payment"],
            capabilities=["workflow-analysis"],
            risk_level="active",
            source="Bug-Bounty-Agents",
            source_reference="bizlogic-hunter.md",
            priority=88,
        )
    )

    ranked = ranked_specialists(
        registry,
        target="https://example.com/api/checkout",
        observations=["authorization", "payment", "workflow"],
    )
    assert ranked[0].id == "api-security"
    assert ranked[0].reasons


def test_routing_explanations():
    registry = SpecialistRegistry()
    registry.register(
        Specialist(
            id="ssrf-hunter",
            name="SSRF Hunter",
            description="SSRF testing",
            domains=["ssrf"],
            tags=["ssrf", "cloud"],
            signals=["ssrf", "metadata", "url-fetch"],
            capabilities=["callback-testing"],
            risk_level="active",
            source="Bug-Bounty-Agents",
            source_reference="ssrf-hunter.md",
            priority=93,
        )
    )

    ranked = ranked_specialists(
        registry,
        target="https://example.com/api/webhook",
        observations=["ssrf", "url-fetch"],
        domain_hints=["ssrf"],
    )
    assert ranked[0].reasons
    assert any("ssrf" in reason.lower() for reason in ranked[0].reasons)


def test_malformed_specialist_validation():
    registry = SpecialistRegistry()
    try:
        registry.register(
            Specialist(
                id="",
                name="",
                description="",
                domains=[],
                tags=[],
                signals=[],
                capabilities=[],
                risk_level="active",
                source="Bug-Bounty-Agents",
                source_reference="missing.md",
            )
        )
        assert False, "malformed specialist should fail validation"
    except ValueError:
        pass


def test_provenance_preservation():
    specialist = Specialist(
        id="report-generator",
        name="Report Generator",
        description="Evidence packaging",
        domains=["reporting"],
        tags=["report"],
        signals=["evidence", "report"],
        capabilities=["reporting"],
        risk_level="safe",
        source="Bug-Bounty-Agents",
        source_reference="report-generator.md",
        priority=70,
    )

    assert specialist.source == "Bug-Bounty-Agents"
    assert specialist.source_reference == "report-generator.md"


def test_safety_boundary_separation():
    scope = ScopeConfig(domains=["example.com"])
    policy = SafetyPolicy(scope=scope)
    mission = Mission(
        MissionContext(target="https://evil.example.net/login", scope=scope, signals=["web"]),
        policy,
    )

    assert mission.is_authorized() is False
    assert mission.dispatch() == []
