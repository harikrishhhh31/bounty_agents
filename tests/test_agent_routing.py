from bugbounty.agents import AgentRegistry, AgentSpec
from bugbounty.orchestration import route_agent


def test_routing_prefers_graphql_specialist_for_graphql_endpoints():
    registry = AgentRegistry()
    registry.register(
        AgentSpec(
            name="graphql-specialist",
            kind="graphql",
            risk="active",
            tags={"graphql", "api"},
        )
    )
    registry.register(
        AgentSpec(
            name="web-specialist",
            kind="web",
            risk="active",
            tags={"web"},
        )
    )

    result = route_agent(registry, {"target": "https://example.com/graphql", "signals": ["graphql", "api"]})
    assert result.name == "graphql-specialist"


def test_routing_uses_ssrf_specialist_for_ssrf_hints():
    registry = AgentRegistry()
    registry.register(AgentSpec(name="ssrf-specialist", kind="ssrf", risk="active", tags={"ssrf"}))
    registry.register(AgentSpec(name="web-specialist", kind="web", risk="active", tags={"web"}))

    result = route_agent(registry, {"target": "https://example.com", "signals": ["ssrf"]})
    assert result.name == "ssrf-specialist"
