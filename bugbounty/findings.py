from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable


STATUSES = {"candidate", "verified", "rejected", "not_verified"}


@dataclass(slots=True)
class Finding:
    title: str
    category: str
    endpoint: str
    severity: str
    confidence: float
    status: str
    description: str
    impact: str
    evidence_ids: list[str]
    reproduction_summary: str
    remediation: str
    references: list[str] = field(default_factory=list)
    affected_endpoints: list[str] = field(default_factory=list)
    finding_id: str = ""
    method: str = ""
    identity: str | None = None
    context: dict[str, object] = field(default_factory=dict)
    expected_behavior: str = ""
    observed_behavior: str = ""
    timestamp: str = ""

    def __post_init__(self) -> None:
        if self.status not in STATUSES:
            raise ValueError(f"unsupported finding status: {self.status}")
        if not self.finding_id:
            key = f"{self.category}|{self.title}|{self.endpoint}".encode()
            self.finding_id = "finding-" + hashlib.sha256(key).hexdigest()[:12]
        if self.endpoint not in self.affected_endpoints:
            self.affected_endpoints.insert(0, self.endpoint)

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(slots=True)
class FindingStore:
    findings: list[Finding] = field(default_factory=list)

    def add(self, finding: Finding) -> Finding:
        if not finding.evidence_ids and finding.status == "verified":
            raise ValueError("verified findings require evidence")
        for existing in self.findings:
            if _duplicate_key(existing) == _duplicate_key(finding):
                for endpoint in finding.affected_endpoints:
                    if endpoint not in existing.affected_endpoints:
                        existing.affected_endpoints.append(endpoint)
                existing.evidence_ids.extend(item for item in finding.evidence_ids if item not in existing.evidence_ids)
                existing.confidence = max(existing.confidence, finding.confidence)
                if finding.status == "verified":
                    existing.status = "verified"
                return existing
        self.findings.append(finding)
        return finding

    def write_json(self, path: str | Path) -> Path:
        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps([item.as_dict() for item in self.findings], indent=2), encoding="utf-8")
        return destination


def _duplicate_key(finding: Finding) -> tuple[str, str]:
    return finding.category, finding.title


def deterministic_severity(*, authorization_impact: int = 0, confidentiality_impact: int = 0, integrity_impact: int = 0, availability_impact: int = 0, exploitability: int = 0, authentication_required: bool = True, confidence: float = 0.0) -> str:
    score = authorization_impact + confidentiality_impact + integrity_impact + availability_impact + exploitability
    score += 2 if not authentication_required else 0
    score += round(confidence * 3)
    if score >= 16:
        return "critical"
    if score >= 11:
        return "high"
    if score >= 6:
        return "medium"
    return "low"


__all__ = ["Finding", "FindingStore", "deterministic_severity"]
