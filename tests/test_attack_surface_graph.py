from __future__ import annotations

import json
from pathlib import Path

import pytest

from bugbounty.attack_surface_graph import (
    ALLOWED_RELATIONSHIPS,
    NODE_TYPES,
    RELATIONSHIP_TYPES,
    AttackSurfaceGraph,
)


def build_basic_graph(tmp_path: Path) -> AttackSurfaceGraph:
    graph = AttackSurfaceGraph(tmp_path)
    host = graph.add_node("Host", {"host": "api.example.com"}, label="api.example.com", provenance={"source": "scope"})
    api = graph.add_node("API", {"name": "billing"}, provenance={"source": "openapi"})
    endpoint = graph.add_node("Endpoint", {"path": "/v1/invoices", "host": "api.example.com"}, provenance={"source": "discovery"})
    method = graph.add_node("Method", {"method": "GET"}, provenance={"source": "discovery"})
    param = graph.add_node("Parameter", {"name": "id", "in": "query"}, provenance={"source": "schema"})
    req = graph.add_node("RequestSchema", {"name": "InvoiceRequest"}, provenance={"source": "schema"})
    resp = graph.add_node("ResponseSchema", {"name": "InvoiceResponse"}, provenance={"source": "schema"})
    auth = graph.add_node("AuthenticationMechanism", {"scheme": "bearer"}, provenance={"source": "config"})
    identity = graph.add_node("Identity", {"name": "user-a"}, provenance={"source": "auth"})
    resource = graph.add_node("Resource", {"resource_id": "invoice:123"}, provenance={"source": "app"})
    check = graph.add_node("SecurityCheck", {"check_id": "bola"}, provenance={"source": "engine"})
    finding = graph.add_node("Finding", {"finding_id": "F-1", "title": "BOLA"}, provenance={"source": "finding"})
    evidence = graph.add_node("Evidence", {"evidence_id": "E-1"}, provenance={"source": "evidence"})

    graph.add_relationship("HOSTS", host.id, api.id)
    graph.add_relationship("EXPOSES", api.id, endpoint.id)
    graph.add_relationship("ACCEPTS", endpoint.id, method.id)
    graph.add_relationship("ACCEPTS", method.id, param.id)
    graph.add_relationship("ACCEPTS", endpoint.id, req.id)
    graph.add_relationship("RETURNS", endpoint.id, resp.id)
    graph.add_relationship("AUTHENTICATES_WITH", endpoint.id, auth.id)
    graph.add_relationship("ACCESSED_BY", endpoint.id, identity.id)
    graph.add_relationship("OWNS", identity.id, resource.id)
    graph.add_relationship("TESTED_BY", endpoint.id, check.id)
    graph.add_relationship("PRODUCED", check.id, finding.id)
    graph.add_relationship("SUPPORTED_BY", finding.id, evidence.id)
    return graph


def test_node_types_and_relationship_types_cover_requirements() -> None:
    required_nodes = {
        "Host", "API", "Endpoint", "Method", "Parameter", "RequestSchema", "ResponseSchema",
        "AuthenticationMechanism", "Identity", "Resource", "SecurityCheck", "Finding", "Evidence",
    }
    required_rels = {
        "HOSTS", "EXPOSES", "ACCEPTS", "RETURNS", "AUTHENTICATES_WITH", "ACCESSED_BY",
        "OWNS", "TESTED_BY", "PRODUCED", "SUPPORTED_BY", "RELATED_TO",
    }
    assert required_nodes.issubset(NODE_TYPES)
    assert required_rels.issubset(RELATIONSHIP_TYPES)


def test_node_creation_updates_and_stable_ids(tmp_path: Path) -> None:
    graph = AttackSurfaceGraph(tmp_path)
    n1 = graph.add_node("Endpoint", {"path": "/a"}, label="/a", attributes={"methods": ["GET"]}, provenance={"source": "scan1"})
    n2 = graph.add_node("Endpoint", {"path": "/a"}, label="/a-updated", attributes={"auth": True}, provenance={"source": "scan2"})
    assert n1.id == n2.id
    assert n1.id.startswith("Endpoint:")
    assert graph.get_node(n1.id) is n2
    assert n2.label == "/a-updated"
    assert n2.attributes["methods"] == ["GET"]
    assert n2.attributes["auth"] is True
    assert {"source": "scan1"} in n2.provenance
    assert {"source": "scan2"} in n2.provenance
    assert len(graph.nodes) == 1
    # explicit stable id helper
    assert AttackSurfaceGraph.make_node_id("Endpoint", {"path": "/a"}) == n1.id


def test_duplicate_prevention_for_relationships(tmp_path: Path) -> None:
    graph = AttackSurfaceGraph(tmp_path)
    a = graph.add_node("Host", {"host": "h"})
    b = graph.add_node("API", {"name": "api"})
    r1 = graph.add_relationship("HOSTS", a.id, b.id, attributes={"x": 1}, provenance={"source": "one"})
    r2 = graph.add_relationship("HOSTS", a.id, b.id, attributes={"y": 2}, provenance={"source": "two"})
    assert r1.id == r2.id
    assert len(graph.relationships) == 1
    assert r2.attributes["x"] == 1
    assert r2.attributes["y"] == 2
    assert {"source": "one"} in r2.provenance
    assert {"source": "two"} in r2.provenance
    assert r1.id.startswith("HOSTS:")


def test_invalid_relationships_rejected(tmp_path: Path) -> None:
    graph = AttackSurfaceGraph(tmp_path)
    host = graph.add_node("Host", {"host": "h"})
    evidence = graph.add_node("Evidence", {"evidence_id": "e"})
    with pytest.raises(ValueError, match="invalid relationship"):
        graph.add_relationship("HOSTS", host.id, evidence.id)
    with pytest.raises(ValueError, match="unsupported relationship type"):
        graph.add_relationship("NOPE", host.id, evidence.id)
    with pytest.raises(ValueError, match="unsupported node type"):
        graph.add_node("UnknownType", {"k": "v"})


def test_missing_nodes_errors(tmp_path: Path) -> None:
    graph = AttackSurfaceGraph(tmp_path)
    host = graph.add_node("Host", {"host": "h"})
    with pytest.raises(KeyError, match="missing node"):
        graph.add_relationship("HOSTS", host.id, "API:missing")
    assert graph.get_node("missing") is None
    with pytest.raises(KeyError, match="missing node"):
        graph.neighbors("missing")


def test_persistence_reload_and_serialization(tmp_path: Path) -> None:
    graph = build_basic_graph(tmp_path)
    path = graph.save()
    assert path.exists()
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["version"] == 1
    assert len(payload["nodes"]) == len(graph.nodes)
    assert len(payload["relationships"]) == len(graph.relationships)

    reloaded = AttackSurfaceGraph.load(tmp_path)
    assert set(reloaded.nodes.keys()) == set(graph.nodes.keys())
    assert set(reloaded.relationships.keys()) == set(graph.relationships.keys())
    # reload in-place
    fresh = AttackSurfaceGraph(tmp_path)
    fresh.reload()
    assert set(fresh.nodes.keys()) == set(graph.nodes.keys())

    export_path = tmp_path / "export.json"
    graph.export_json(export_path)
    assert export_path.exists()
    exported = json.loads(export_path.read_text(encoding="utf-8"))
    assert "nodes" in exported and "relationships" in exported


def test_neighbor_and_endpoint_queries(tmp_path: Path) -> None:
    graph = build_basic_graph(tmp_path)
    endpoint = graph.find_nodes("Endpoint", path="/v1/invoices")[0]
    out = graph.neighbors(endpoint.id, direction="out", rel_type="ACCEPTS", node_type="Method")
    assert [n["node"].type for n in out] == ["Method"]
    assert out[0]["node"].key["method"] == "GET"
    incoming = graph.neighbors(endpoint.id, direction="in")
    incoming_types = sorted(n["node"].type for n in incoming)
    assert "API" in incoming_types

    queried = graph.query_endpoints(host="api.example.com", path="/v1/invoices", method="GET")
    assert len(queried) == 1
    assert queried[0]["endpoint"].id == endpoint.id
    assert queried[0]["methods"][0].key["method"] == "GET"
    assert graph.query_endpoints(host="other.example.com") == []


def test_finding_and_evidence_relationship_queries(tmp_path: Path) -> None:
    graph = build_basic_graph(tmp_path)
    endpoint = graph.find_nodes("Endpoint", path="/v1/invoices")[0]
    findings = graph.findings_for_endpoint(endpoint.id)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.type == "Finding"
    evidence = graph.evidence_for_finding(finding.id)
    assert len(evidence) == 1
    assert evidence[0].type == "Evidence"

    links = graph.finding_evidence_relationships()
    assert len(links) == 1
    assert links[0]["finding"].id == finding.id
    assert links[0]["evidence"].id == evidence[0].id
    assert links[0]["relationship"].type == "SUPPORTED_BY"
    assert graph.finding_evidence_relationships(finding_id="missing") == []


def test_dashboard_ready_graph_data(tmp_path: Path) -> None:
    graph = build_basic_graph(tmp_path)
    data = graph.to_dashboard_graph()
    assert set(data.keys()) == {"nodes", "edges"}
    assert isinstance(data["nodes"], list) and isinstance(data["edges"], list)
    assert all("id" in n and "type" in n and "label" in n for n in data["nodes"])
    assert all("id" in e and "source" in e and "target" in e and "type" in e for e in data["edges"])
    node_ids = {n["id"] for n in data["nodes"]}
    assert all(e["source"] in node_ids and e["target"] in node_ids for e in data["edges"])


def test_provenance_preserved_on_updates_and_relationships(tmp_path: Path) -> None:
    graph = AttackSurfaceGraph(tmp_path)
    n = graph.add_node("Host", {"host": "h"}, provenance={"source": "a", "ts": "1"})
    graph.add_node("Host", {"host": "h"}, provenance=[{"source": "b", "ts": "2"}])
    assert {"source": "a", "ts": "1"} in n.provenance
    assert {"source": "b", "ts": "2"} in n.provenance
    api = graph.add_node("API", {"name": "x"})
    rel = graph.add_relationship("HOSTS", n.id, api.id, provenance={"source": "r1"})
    graph.add_relationship("HOSTS", n.id, api.id, provenance={"source": "r2"})
    assert {"source": "r1"} in rel.provenance and {"source": "r2"} in rel.provenance


def test_allowed_relationships_include_required_core_edges() -> None:
    required = {
        ("Host", "HOSTS", "API"),
        ("API", "EXPOSES", "Endpoint"),
        ("Endpoint", "ACCEPTS", "Method"),
        ("Endpoint", "ACCEPTS", "Parameter"),
        ("Endpoint", "ACCEPTS", "RequestSchema"),
        ("Endpoint", "RETURNS", "ResponseSchema"),
        ("Endpoint", "AUTHENTICATES_WITH", "AuthenticationMechanism"),
        ("Endpoint", "ACCESSED_BY", "Identity"),
        ("Identity", "OWNS", "Resource"),
        ("Endpoint", "TESTED_BY", "SecurityCheck"),
        ("SecurityCheck", "PRODUCED", "Finding"),
        ("Finding", "SUPPORTED_BY", "Evidence"),
    }
    assert required.issubset(ALLOWED_RELATIONSHIPS)
