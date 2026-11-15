from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


@dataclass(slots=True)
class CachedCheckResult:
    """Cached result from a prior check execution.

    Cache key includes: endpoint, check_id, and identities used.
    This ensures results from different identity contexts are not conflated.
    """

    check_id: str
    endpoint: str
    status: str
    identities: list[str] = field(default_factory=list)
    reason: str = ""
    confidence: float = 0.0
    evidence_ids: list[str] = field(default_factory=list)
    severity: str = ""
    timestamp: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class InvestigationMemory:
    """Cache of prior investigation results to accelerate incremental assessments.

    Cache key includes: endpoint, check_id, and identity context.
    This ensures results from different identity contexts are not conflated.
    """

    cached_results: dict[tuple[str, str, str], CachedCheckResult] = field(default_factory=dict)
    workspace: str | Path = ""

    @classmethod
    def load(cls, workspace: str | Path) -> InvestigationMemory:
        """Load investigation memory from workspace directory."""
        cache_file = Path(workspace) / "investigation_cache.json"
        instance = cls(cached_results={}, workspace=workspace)

        if cache_file.exists():
            try:
                data = json.loads(cache_file.read_text(encoding="utf-8"))
                for item in data.get("cached_results", []):
                    result = CachedCheckResult(
                        check_id=item["check_id"],
                        endpoint=item["endpoint"],
                        status=item["status"],
                        identities=item.get("identities", []),
                        reason=item.get("reason", ""),
                        confidence=item.get("confidence", 0.0),
                        evidence_ids=item.get("evidence_ids", []),
                        severity=item.get("severity", ""),
                        timestamp=item.get("timestamp", ""),
                    )
                    identities_key = "|".join(sorted(result.identities))
                    instance.cached_results[(item["endpoint"], item["check_id"], identities_key)] = result
            except (json.JSONDecodeError, ValueError, KeyError):
                pass

        return instance

    def get(self, endpoint: str, check_id: str, identities: list[str] | None = None) -> CachedCheckResult | None:
        """Retrieve a cached check result if available and identities match.

        Args:
            endpoint: API endpoint URL
            check_id: Security check identifier
            identities: List of authentication identities for this test context.
                        If None or empty, no identity-aware caching is used.

        Returns:
            CachedCheckResult if found and context matches, else None.
        """
        if not identities:
            return None
        identities_key = "|".join(sorted(identities))
        return self.cached_results.get((endpoint, check_id, identities_key))

    def store(self, endpoint: str, check_id: str, status: str, identities: list[str] | None = None, reason: str = "", confidence: float = 0.0, evidence_ids: list[str] | None = None, severity: str = "", timestamp: str = "") -> None:
        """Store a check result in the cache with identity context.

        Args:
            endpoint: API endpoint URL
            check_id: Security check identifier
            status: Check result status (PASS, FAIL, VULNERABLE, etc.)
            identities: List of authentication identities used in this test.
            reason: Explanation of the result
            confidence: Confidence level (0.0 to 1.0)
            evidence_ids: List of evidence object IDs backing this result
            severity: Vulnerability severity if applicable
            timestamp: ISO 8601 timestamp of check execution
        """
        result = CachedCheckResult(
            check_id=check_id,
            endpoint=endpoint,
            status=status,
            identities=identities or [],
            reason=reason,
            confidence=confidence,
            evidence_ids=evidence_ids or [],
            severity=severity,
            timestamp=timestamp,
        )
        identities_key = "|".join(sorted(identities or []))
        self.cached_results[(endpoint, check_id, identities_key)] = result

    def save(self) -> Path:
        """Persist investigation memory to workspace."""
        destination = Path(self.workspace) / "investigation_cache.json"
        destination.parent.mkdir(parents=True, exist_ok=True)

        data = {
            "cached_results": [result.to_dict() for result in self.cached_results.values()],
        }
        destination.write_text(json.dumps(data, indent=2), encoding="utf-8")
        return destination


__all__ = ["InvestigationMemory", "CachedCheckResult"]
