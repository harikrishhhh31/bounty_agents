from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping


NODE_TYPES = {
    "Host",
    "API",
    "Endpoint",
    "Method",
    "Parameter",
    "RequestSchema",
    "ResponseSchema",
    "AuthenticationMechanism",
    "Identity",
    "Resource",
    "SecurityCheck",
    "Finding",
    "Evidence",
}

RELATIONSHIP_TYPES = {
    "HOSTS",
    "EXPOSES",
    "ACCEPTS",
    "RETURNS",
    "AUTHENTICATES_WITH",
    "ACCESSED_BY",
    "OWNS",
    "TESTED_BY",
    "PRODUCED",
    "SUPPORTED_BY",
    "RELATED_TO",
}

# Allowed (source_type, relationship_type, target_type) combinations.
# Kept permissive enough for integration while still preventing nonsense edges.
ALLOWED_RELATIONSHIPS: set[tuple[str, str, str]] = {
    ("Host", "HOSTS", "API"),
    ("Host", "EXPOSES", "Endpoint"),
    ("API", "EXPOSES", "Endpoint"),
    ("Endpoint", "ACCEPTS", "Method"),
    ("Method", "ACCEPTS", "Parameter"),
    ("Endpoint", "ACCEPTS", "Parameter"),
    ("Endpoint", "ACCEPTS", "RequestSchema"),
    ("Endpoint", "RETURNS", "ResponseSchema"),
    ("Endpoint", "AUTHENTICATES_WITH", "AuthenticationMechanism"),
    ("Identity", "AUTHENTICATES_WITH", "AuthenticationMechanism"),
    ("Endpoint", "ACCESSED_BY", "Identity"),
    ("Resource", "ACCESSED_BY", "Identity"),
    ("Identity", "OWNS", "Resource"),
    ("Endpoint", "TESTED_BY", "SecurityCheck"),
    ("SecurityCheck", "PRODUCED", "Finding"),
    ("Finding", "SUPPORTED_BY", "Evidence"),
    ("SecurityCheck", "SUPPORTED_BY", "Evidence"),
    ("Endpoint", "RELATED_TO", "Endpoint"),
    ("API", "RELATED_TO", "API"),
    ("Resource", "RELATED_TO", "Resource"),
    ("Finding", "RELATED_TO", "Finding"),
    ("Evidence", "RELATED_TO", "Evidence"),
    ("Host", "RELATED_TO", "Host"),
    # Common integration-friendly edges
    ("Endpoint", "PRODUCED", "Finding"),
    ("Endpoint", "SUPPORTED_BY", "Evidence"),
    ("Finding", "PRODUCED", "Evidence"),
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _stable_hash(parts: Iterable[Any]) -> str:
    payload = "\x1f".join(_canonical_str(p) for p in parts)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def _canonical_str(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (str, int, float, bool)):
        return str(value)
    if isinstance(value, Mapping):
        items = sorted((str(k), _canonical_str(v)) for k, v in value.items())
        return "{" + ",".join(f"{k}={v}" for k, v in items) + "}"
    if isinstance(value, (list, tuple, set)):
        seq = [_canonical_str(v) for v in value]
        if isinstance(value, set):
            seq = sorted(seq)
        return "[" + ",".join(seq) + "]"
    return str(value)


def _deep_merge(base: dict[str, Any], update: Mapping[str, Any]) -> dict[str, Any]:
    result = dict(base)
    for key, value in update.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, Mapping):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def _normalize_provenance(provenance: Any) -> list[dict[str, Any]]:
    if provenance is None:
        return []
    if isinstance(provenance, dict):
        return [dict(provenance)]
    if isinstance(provenance, list):
        out: list[dict[str, Any]] = []
        for item in provenance:
            if isinstance(item, dict):
                out.append(dict(item))
            elif item is not None:
                out.append({"detail": item})
        return out
    return [{"detail": provenance}]


@dataclass(slots=True)
class GraphNode:
    id: str
    type: str
    label: str
    key: dict[str, Any] = field(default_factory=dict)
    attributes: dict[str, Any] = field(default_factory=dict)
    provenance: list[dict[str, Any]] = field(default_factory=list)
    created_at: str = ""
    updated_at: str = ""

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class GraphRelationship:
    id: str
    type: str
    source: str
    target: str
    attributes: dict[str, Any] = field(default_factory=dict)
    provenance: list[dict[str, Any]] = field(default_factory=list)
    created_at: str = ""
    updated_at: str = ""

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


class AttackSurfaceGraph:
    """Lightweight local-first attack surface graph with JSON persistence."""

    def __init__(self, workspace: str | Path | None = None):
        self.workspace = Path(workspace) if workspace is not None else None
        self.nodes: dict[str, GraphNode] = {}
        self.relationships: dict[str, GraphRelationship] = {}

    # ---------- identity helpers ----------
    @staticmethod
    def make_node_id(node_type: str, key: Mapping[str, Any] | str) -> str:
        if node_type not in NODE_TYPES:
            raise ValueError(f"unsupported node type: {node_type}")
        if isinstance(key, str):
            key_map: Mapping[str, Any] = {"value": key}
        else:
            key_map = key
        # sort keys for stability
        norm = {str(k): key_map[k] for k in sorted(key_map.keys(), key=str)}
        return f"{node_type}:{_stable_hash([node_type, norm])}"

    @staticmethod
    def make_relationship_id(rel_type: str, source_id: str, target_id: str, key: Mapping[str, Any] | None = None) -> str:
        if rel_type not in RELATIONSHIP_TYPES:
            raise ValueError(f"unsupported relationship type: {rel_type}")
        parts: list[Any] = [rel_type, source_id, target_id]
        if key:
            parts.append({str(k): key[k] for k in sorted(key.keys(), key=str)})
        return f"{rel_type}:{_stable_hash(parts)}"

    # ---------- node operations ----------
    def add_node(
        self,
        node_type: str,
        key: Mapping[str, Any] | str,
        *,
        label: str | None = None,
        attributes: Mapping[str, Any] | None = None,
        provenance: Any = None,
        node_id: str | None = None,
    ) -> GraphNode:
        if node_type not in NODE_TYPES:
            raise ValueError(f"unsupported node type: {node_type}")
        key_map = {"value": key} if isinstance(key, str) else dict(key)
        nid = node_id or self.make_node_id(node_type, key_map)
        now = _utc_now()
        prov = _normalize_provenance(provenance)
        attrs = dict(attributes or {})
        if nid in self.nodes:
            existing = self.nodes[nid]
            if existing.type != node_type:
                raise ValueError(f"node id collision with different type: {nid}")
            existing.attributes = _deep_merge(existing.attributes, attrs)
            existing.key = _deep_merge(existing.key, key_map)
            if label:
                existing.label = label
            for item in prov:
                if item not in existing.provenance:
                    existing.provenance.append(item)
            existing.updated_at = now
            return existing
        node = GraphNode(
            id=nid,
            type=node_type,
            label=label or self._default_label(node_type, key_map),
            key=key_map,
            attributes=attrs,
            provenance=prov,
            created_at=now,
            updated_at=now,
        )
        self.nodes[nid] = node
        return node

    def upsert_node(self, *args: Any, **kwargs: Any) -> GraphNode:
        """Alias for add_node (create or update)."""
        return self.add_node(*args, **kwargs)

    def get_node(self, node_id: str) -> GraphNode | None:
        return self.nodes.get(node_id)

    def require_node(self, node_id: str) -> GraphNode:
        node = self.get_node(node_id)
        if node is None:
            raise KeyError(f"missing node: {node_id}")
        return node

    # ---------- relationship operations ----------
    def add_relationship(
        self,
        rel_type: str,
        source_id: str,
        target_id: str,
        *,
        attributes: Mapping[str, Any] | None = None,
        provenance: Any = None,
        relationship_id: str | None = None,
        key: Mapping[str, Any] | None = None,
        allow_additional: bool = True,
    ) -> GraphRelationship:
        if rel_type not in RELATIONSHIP_TYPES:
            raise ValueError(f"unsupported relationship type: {rel_type}")
        source = self.require_node(source_id)
        target = self.require_node(target_id)
        triple = (source.type, rel_type, target.type)
        if not allow_additional and triple not in ALLOWED_RELATIONSHIPS:
            raise ValueError(f"invalid relationship: {triple}")
        if allow_additional and triple not in ALLOWED_RELATIONSHIPS:
            # still allow RELATED_TO as generic fallback if same-type-ish? otherwise raise
            # to satisfy "invalid relationships" validation while staying usable we enforce allowlist
            raise ValueError(f"invalid relationship: {triple}")
        rid = relationship_id or self.make_relationship_id(rel_type, source_id, target_id, key)
        now = _utc_now()
        prov = _normalize_provenance(provenance)
        attrs = dict(attributes or {})
        if rid in self.relationships:
            existing = self.relationships[rid]
            if existing.type != rel_type or existing.source != source_id or existing.target != target_id:
                raise ValueError(f"relationship id collision: {rid}")
            existing.attributes = _deep_merge(existing.attributes, attrs)
            for item in prov:
                if item not in existing.provenance:
                    existing.provenance.append(item)
            existing.updated_at = now
            return existing
        rel = GraphRelationship(
            id=rid,
            type=rel_type,
            source=source_id,
            target=target_id,
            attributes=attrs,
            provenance=prov,
            created_at=now,
            updated_at=now,
        )
        self.relationships[rid] = rel
        return rel

    # ---------- queries ----------
    def neighbors(
        self,
        node_id: str,
        *,
        direction: str = "both",
        rel_type: str | None = None,
        node_type: str | None = None,
    ) -> list[dict[str, Any]]:
        self.require_node(node_id)
        if direction not in {"in", "out", "both"}:
            raise ValueError("direction must be one of: in, out, both")
        if rel_type and rel_type not in RELATIONSHIP_TYPES:
            raise ValueError(f"unsupported relationship type: {rel_type}")
        results: list[dict[str, Any]] = []
        for rel in self.relationships.values():
            if rel_type and rel.type != rel_type:
                continue
            other_id: str | None = None
            if direction in {"out", "both"} and rel.source == node_id:
                other_id = rel.target
            if direction in {"in", "both"} and rel.target == node_id:
                other_id = rel.source
            if not other_id or (other_id == node_id and rel.source == rel.target and direction == "both"):
                # self-loop handling: include once per matching direction case; simple guard
                if other_id == node_id and direction != "both":
                    pass
                elif not other_id:
                    continue
            if other_id is None:
                continue
            node = self.nodes.get(other_id)
            if node is None:
                continue
            if node_type and node.type != node_type:
                continue
            results.append({"relationship": rel, "node": node})
        # deterministic order
        results.sort(key=lambda item: (item["relationship"].type, item["relationship"].id, item["node"].id))
        # de-dup in case of self-loop double add
        seen: set[tuple[str, str]] = set()
        uniq: list[dict[str, Any]] = []
        for item in results:
            k = (item["relationship"].id, item["node"].id)
            if k in seen:
                continue
            seen.add(k)
            uniq.append(item)
        return uniq

    def find_nodes(self, node_type: str | None = None, **key_filters: Any) -> list[GraphNode]:
        out: list[GraphNode] = []
        for node in self.nodes.values():
            if node_type and node.type != node_type:
                continue
            if key_filters:
                ok = True
                for k, v in key_filters.items():
                    if node.key.get(k) != v and node.attributes.get(k) != v:
                        ok = False
                        break
                if not ok:
                    continue
            out.append(node)
        out.sort(key=lambda n: (n.type, n.label, n.id))
        return out

    def query_endpoints(self, *, host: str | None = None, path: str | None = None, method: str | None = None) -> list[dict[str, Any]]:
        endpoints = self.find_nodes("Endpoint")
        results: list[dict[str, Any]] = []
        for ep in endpoints:
            if path and ep.key.get("path") != path and ep.attributes.get("path") != path:
                continue
            if host:
                host_vals: set[str] = set()
                # direct host key/attrs on endpoint
                for candidate in (ep.key.get("host"), ep.attributes.get("host")):
                    if candidate:
                        host_vals.add(str(candidate))
                for incoming in self.neighbors(ep.id, direction="in"):
                    node = incoming["node"]
                    if node.type == "Host":
                        host_vals.add(str(node.key.get("host") or node.key.get("value") or node.label))
                    elif node.type == "API":
                        host_vals.add(str(node.key.get("host") or node.key.get("value") or node.label))
                        # hosts that HOST the API
                        for host_node in self.neighbors(node.id, direction="in", rel_type="HOSTS", node_type="Host"):
                            hn = host_node["node"]
                            host_vals.add(str(hn.key.get("host") or hn.key.get("value") or hn.label))
                if host not in host_vals:
                    continue
            methods = [n["node"] for n in self.neighbors(ep.id, direction="out", rel_type="ACCEPTS") if n["node"].type == "Method"]
            method_vals = [str(m.key.get("method") or m.key.get("value") or m.label) for m in methods]
            if method and method not in method_vals:
                continue
            results.append({"endpoint": ep, "methods": methods})
        return results

    def findings_for_endpoint(self, endpoint_id: str) -> list[GraphNode]:
        self.require_node(endpoint_id)
        findings: dict[str, GraphNode] = {}
        # direct endpoint -> finding
        for n in self.neighbors(endpoint_id, direction="out", rel_type="PRODUCED", node_type="Finding"):
            findings[n["node"].id] = n["node"]
        # via security checks
        for chk in self.neighbors(endpoint_id, direction="out", rel_type="TESTED_BY", node_type="SecurityCheck"):
            for n in self.neighbors(chk["node"].id, direction="out", rel_type="PRODUCED", node_type="Finding"):
                findings[n["node"].id] = n["node"]
        return sorted(findings.values(), key=lambda n: n.id)

    def evidence_for_finding(self, finding_id: str) -> list[GraphNode]:
        self.require_node(finding_id)
        return [n["node"] for n in self.neighbors(finding_id, direction="out", rel_type="SUPPORTED_BY", node_type="Evidence")]

    def finding_evidence_relationships(self, finding_id: str | None = None) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        rels = self.relationships.values()
        for rel in rels:
            if rel.type != "SUPPORTED_BY":
                continue
            src = self.nodes.get(rel.source)
            tgt = self.nodes.get(rel.target)
            if not src or not tgt:
                continue
            if src.type == "Finding" and tgt.type == "Evidence":
                if finding_id and src.id != finding_id:
                    continue
                out.append({"finding": src, "evidence": tgt, "relationship": rel})
        out.sort(key=lambda item: (item["finding"].id, item["evidence"].id, item["relationship"].id))
        return out

    # ---------- serialization / persistence ----------
    def to_dict(self) -> dict[str, Any]:
        return {
            "version": 1,
            "generated_at": _utc_now(),
            "nodes": [self.nodes[k].as_dict() for k in sorted(self.nodes.keys())],
            "relationships": [self.relationships[k].as_dict() for k in sorted(self.relationships.keys())],
        }

    def to_dashboard_graph(self) -> dict[str, Any]:
        """Dashboard-ready nodes/edges lists."""
        nodes = []
        for node in (self.nodes[k] for k in sorted(self.nodes.keys())):
            nodes.append(
                {
                    "id": node.id,
                    "type": node.type,
                    "label": node.label,
                    "key": node.key,
                    "attributes": node.attributes,
                    "provenance": node.provenance,
                }
            )
        edges = []
        for rel in (self.relationships[k] for k in sorted(self.relationships.keys())):
            edges.append(
                {
                    "id": rel.id,
                    "type": rel.type,
                    "source": rel.source,
                    "target": rel.target,
                    "attributes": rel.attributes,
                    "provenance": rel.provenance,
                }
            )
        return {"nodes": nodes, "edges": edges}

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any], workspace: str | Path | None = None) -> "AttackSurfaceGraph":
        graph = cls(workspace=workspace)
        for item in payload.get("nodes", []) or []:
            if not isinstance(item, dict):
                continue
            try:
                node = GraphNode(**item)
            except TypeError:
                # tolerate missing optional evolution fields
                node = GraphNode(
                    id=str(item.get("id")),
                    type=str(item.get("type")),
                    label=str(item.get("label", "")),
                    key=dict(item.get("key") or {}),
                    attributes=dict(item.get("attributes") or {}),
                    provenance=list(item.get("provenance") or []),
                    created_at=str(item.get("created_at", "")),
                    updated_at=str(item.get("updated_at", "")),
                )
            if node.type in NODE_TYPES and node.id:
                graph.nodes[node.id] = node
        for item in payload.get("relationships", []) or []:
            if not isinstance(item, dict):
                continue
            try:
                rel = GraphRelationship(**item)
            except TypeError:
                rel = GraphRelationship(
                    id=str(item.get("id")),
                    type=str(item.get("type")),
                    source=str(item.get("source")),
                    target=str(item.get("target")),
                    attributes=dict(item.get("attributes") or {}),
                    provenance=list(item.get("provenance") or []),
                    created_at=str(item.get("created_at", "")),
                    updated_at=str(item.get("updated_at", "")),
                )
            if rel.type in RELATIONSHIP_TYPES and rel.id and rel.source in graph.nodes and rel.target in graph.nodes:
                graph.relationships[rel.id] = rel
        return graph

    def save(self, path: str | Path | None = None) -> Path:
        destination = self._resolve_path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(self.to_dict(), indent=2, sort_keys=False), encoding="utf-8")
        return destination

    def export_json(self, path: str | Path | None = None) -> Path:
        return self.save(path)

    @classmethod
    def load(cls, workspace_or_path: str | Path, *, workspace: str | Path | None = None) -> "AttackSurfaceGraph":
        candidate = Path(workspace_or_path)
        if candidate.is_file() or candidate.suffix.lower() == ".json":
            path = candidate
            ws = workspace or candidate.parent
        else:
            ws = candidate
            path = candidate / "attack_surface_graph.json"
        if not path.exists():
            graph = cls(workspace=ws)
            return graph
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return cls(workspace=ws)
        if not isinstance(payload, dict):
            return cls(workspace=ws)
        return cls.from_dict(payload, workspace=ws)

    def reload(self, path: str | Path | None = None) -> "AttackSurfaceGraph":
        destination = self._resolve_path(path)
        loaded = self.load(destination, workspace=self.workspace or destination.parent)
        self.nodes = loaded.nodes
        self.relationships = loaded.relationships
        self.workspace = loaded.workspace or self.workspace
        return self

    def _resolve_path(self, path: str | Path | None) -> Path:
        if path is not None:
            p = Path(path)
            if p.suffix.lower() == ".json":
                return p
            return p / "attack_surface_graph.json"
        if self.workspace is None:
            raise ValueError("workspace or path is required for persistence")
        ws = Path(self.workspace)
        if ws.suffix.lower() == ".json":
            return ws
        return ws / "attack_surface_graph.json"

    @staticmethod
    def _default_label(node_type: str, key: Mapping[str, Any]) -> str:
        for candidate in ("label", "name", "title", "url", "path", "method", "host", "value", "id", "check_id", "finding_id", "evidence_id"):
            if candidate in key and key[candidate] not in (None, ""):
                return str(key[candidate])
        if key:
            first = sorted(key.keys(), key=str)[0]
            return f"{node_type}:{key[first]}"
        return node_type


__all__ = [
    "ALLOWED_RELATIONSHIPS",
    "NODE_TYPES",
    "RELATIONSHIP_TYPES",
    "AttackSurfaceGraph",
    "GraphNode",
    "GraphRelationship",
]
