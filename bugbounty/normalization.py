"""Unified observation schema and central result classification.

The assessment engine is the single authority for collecting, correlating,
verifying, and classifying results. External tools (Nuclei, ZAP, Burp,
Schemathesis, RESTler, ffuf, Kiterunner) produce *observations* — never proof.
This module defines the shared, source-agnostic schema used to ingest those
observations and the one classification pass that decides whether every finding
is confirmed, probable, unverified, or rejected.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Iterable, Mapping

from .evidence import Evidence, EvidenceStore
from .findings import Finding, FindingStore


# Central classification vocabulary. Persisted ``Finding.status`` uses the legacy
# names for backward compatibility; the mapping is 1:1 and lossless.
CONFIRMED = "confirmed"
PROBABLE = "probable"
UNVERIFIED = "unverified"
REJECTED = "rejected"

CLASSIFICATION_TO_FINDING_STATUS: dict[str, str] = {
    CONFIRMED: "verified",
    PROBABLE: "candidate",
    UNVERIFIED: "not_verified",
    REJECTED: "rejected",
}
FINDING_STATUS_TO_CLASSIFICATION: dict[str, str] = {
    value: key for key, value in CLASSIFICATION_TO_FINDING_STATUS.items()
}

EXTERNAL_CATEGORY_PREFIX = "external-"


@dataclass(frozen=True, slots=True)
class Observation:
    """Source-agnostic observation produced by a check or an external adapter."""

    source: str
    source_id: str
    title: str
    category: str
    endpoint: str
    severity: str
    confidence: float
    status: str
    description: str
    evidence: Mapping[str, Any] = field(default_factory=dict)
    provenance: Mapping[str, Any] = field(default_factory=dict)
    method: str = ""
    identity: str | None = None
    verification_status: str = "potential"

    @property
    def is_external(self) -> bool:
        return str(self.category).startswith(EXTERNAL_CATEGORY_PREFIX)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ClassificationSummary:
    """Counts of findings by central classification."""

    confirmed: int = 0
    probable: int = 0
    unverified: int = 0
    rejected: int = 0

    def as_dict(self) -> dict[str, int]:
        return asdict(self)

    @property
    def total(self) -> int:
        return self.confirmed + self.probable + self.unverified + self.rejected


def observation_from_tool_finding(record: Any, *, verification_status: str = "potential") -> Observation:
    """Convert an adapter ``ToolFindingRecord`` into a unified :class:`Observation`."""

    return Observation(
        source=str(getattr(record, "source_tool", "") or ""),
        source_id=str(getattr(record, "source_id", "") or ""),
        title=str(getattr(record, "title", "") or ""),
        category=str(getattr(record, "category", "") or ""),
        endpoint=str(getattr(record, "endpoint", "") or ""),
        severity=str(getattr(record, "severity", "info") or "info").lower(),
        confidence=float(getattr(record, "confidence", 0.0) or 0.0),
        status=str(getattr(record, "status", "candidate") or "candidate"),
        description=str(getattr(record, "description", "") or ""),
        evidence=dict(getattr(record, "evidence", {}) or {}),
        provenance=dict(getattr(record, "provenance", {}) or {}),
        verification_status=verification_status,
    )


def _is_external(finding: Finding) -> bool:
    if str(finding.category).startswith(EXTERNAL_CATEGORY_PREFIX):
        return True
    return any(str(reference).startswith("external") for reference in finding.references)


def classify_findings(findings: FindingStore, evidence: EvidenceStore) -> ClassificationSummary:
    """Apply the single central classification pass over a :class:`FindingStore`.

    Rules (the engine is authoritative; external output is never proof):

    * A finding with no evidence is **rejected**.
    * A finding already marked ``verified`` by a central check stays **confirmed**.
    * A finding whose evidence was independently verified becomes **confirmed**.
    * External-tool findings without independent verification are **unverified**.
    * Everything else is **probable** (retained as ``candidate``).
    """

    summary = ClassificationSummary()
    for finding in findings.findings:
        evidence_items = [
            item for evidence_id in finding.evidence_ids if (item := evidence.get(evidence_id)) is not None
        ]
        if not finding.evidence_ids:
            finding.status = "rejected"
        elif finding.status == "verified":
            pass
        elif any(_is_verified_evidence(item) for item in evidence_items):
            finding.status = "verified"
        elif _is_external(finding):
            finding.status = "not_verified"

        classification = FINDING_STATUS_TO_CLASSIFICATION.get(finding.status, PROBABLE)
        if classification == CONFIRMED:
            summary.confirmed += 1
        elif classification == UNVERIFIED:
            summary.unverified += 1
        elif classification == REJECTED:
            summary.rejected += 1
        else:
            summary.probable += 1
    return summary


def _is_verified_evidence(evidence: Evidence) -> bool:
    return str(getattr(evidence, "verification_status", "")).lower() == "verified"


def correlate_by_endpoint(findings: Iterable[Finding]) -> dict[str, list[str]]:
    """Group finding ids by endpoint to support correlation reporting.

    This does not change finding status; it surfaces where multiple sources
    (internal checks and external tools) converge on the same endpoint.
    """

    groups: dict[str, list[str]] = {}
    for finding in findings:
        groups.setdefault(finding.endpoint, []).append(finding.finding_id)
    return groups


__all__ = [
    "CLASSIFICATION_TO_FINDING_STATUS",
    "CONFIRMED",
    "ClassificationSummary",
    "EXTERNAL_CATEGORY_PREFIX",
    "FINDING_STATUS_TO_CLASSIFICATION",
    "Observation",
    "PROBABLE",
    "REJECTED",
    "UNVERIFIED",
    "classify_findings",
    "correlate_by_endpoint",
    "observation_from_tool_finding",
]
