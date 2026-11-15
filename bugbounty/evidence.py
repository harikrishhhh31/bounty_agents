from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4


@dataclass(frozen=True, slots=True)
class Evidence:
    evidence_id: str
    timestamp: str
    check_id: str
    endpoint: str
    request_metadata: dict[str, Any]
    response_metadata: dict[str, Any]
    observation: str
    expected_behavior: str
    actual_behavior: str
    verification_status: str

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class EvidenceStore:
    workspace: str = "."
    artifacts: list[Evidence] = field(default_factory=list)

    def add(self, *, check_id: str, endpoint: str, request_metadata: dict[str, Any], response_metadata: dict[str, Any], observation: str, expected_behavior: str, actual_behavior: str, verification_status: str) -> Evidence:
        evidence = Evidence(
            evidence_id=f"evidence-{uuid4().hex}",
            timestamp=datetime.now(timezone.utc).isoformat(),
            check_id=check_id,
            endpoint=endpoint,
            request_metadata=_sanitize(request_metadata),
            response_metadata=_sanitize(response_metadata),
            observation=observation,
            expected_behavior=expected_behavior,
            actual_behavior=actual_behavior,
            verification_status=verification_status,
        )
        self.artifacts.append(evidence)
        return evidence

    def write(self, path: str | Path | None = None) -> Path:
        requested = Path(path) if path is not None else None
        destination = requested if requested and requested.suffix.lower() == ".json" else Path(path or self.workspace) / "evidence.json"
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps([item.as_dict() for item in self.artifacts], indent=2), encoding="utf-8")
        return destination


def _sanitize(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): "[REDACTED]" if any(token in str(key).lower() for token in ("authorization", "token", "secret", "password", "api-key", "cookie")) else _sanitize(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_sanitize(item) for item in value]
    return value


__all__ = ["Evidence", "EvidenceStore"]
