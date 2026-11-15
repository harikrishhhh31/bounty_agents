from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Set


@dataclass(slots=True)
class ExecutionHistory:
    """Track (endpoint, check_id, identity_context) tuples that have been executed.

    Identity-dependent checks are tracked per identity context to ensure
    the same check can run independently with different authentication scenarios.
    """

    executed_pairs: Set[tuple[str, str, str]] = field(default_factory=set)
    workspace: str | Path = ""

    @classmethod
    def load(cls, workspace: str | Path) -> ExecutionHistory:
        """Load execution history from workspace directory."""
        history_file = Path(workspace) / "execution_history.json"
        instance = cls(executed_pairs=set(), workspace=workspace)

        if history_file.exists():
            try:
                data = json.loads(history_file.read_text(encoding="utf-8"))
                instance.executed_pairs = set(tuple(pair) for pair in data.get("executed_pairs", []))
            except (json.JSONDecodeError, ValueError):
                pass

        return instance

    def record(self, endpoint: str, check_id: str, identities: list[str] | None = None) -> None:
        """Record that a check has been executed for an endpoint with given identity context.

        Args:
            endpoint: API endpoint URL
            check_id: Security check identifier
            identities: List of authentication identities used in this execution.
                       If None or empty, recorded as context-agnostic execution.
        """
        identities_key = "|".join(sorted(identities or []))
        self.executed_pairs.add((endpoint, check_id, identities_key))

    def has_executed(self, endpoint: str, check_id: str, identities: list[str] | None = None) -> bool:
        """Check if a check has already been executed for an endpoint with given identity context.

        Args:
            endpoint: API endpoint URL
            check_id: Security check identifier
            identities: List of authentication identities for this test context.
                       If None or empty, checks for context-agnostic execution record.

        Returns:
            True if this exact (endpoint, check_id, identity_context) has been executed.
        """
        identities_key = "|".join(sorted(identities or []))
        return (endpoint, check_id, identities_key) in self.executed_pairs

    def save(self) -> Path:
        """Persist execution history to workspace."""
        destination = Path(self.workspace) / "execution_history.json"
        destination.parent.mkdir(parents=True, exist_ok=True)

        data = {
            "executed_pairs": sorted(list(self.executed_pairs)),
        }
        destination.write_text(json.dumps(data, indent=2), encoding="utf-8")
        return destination


__all__ = ["ExecutionHistory"]
