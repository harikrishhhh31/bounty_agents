from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from bugbounty.assessment import AssessmentEngine
from bugbounty.engagement import AuthIdentity, Engagement, ObjectAuthorizationCase
from tests.fixtures.vulnerable_api import RunningVulnerableApi


def test_evidence_survives_process_restart_and_cache_reuse(tmp_path: Path):
    """Persisted evidence artifacts must be reloadable in a new process and available on cache hits."""
    workspace = tmp_path / "ws"
    workspace.mkdir()
    fixture = RunningVulnerableApi(enforce_object_ownership=True)
    try:
        target = fixture.target
        # First process/run: execute and persist
        engagement = Engagement.from_target(
            target,
            allowed_schemes=["http"],
            allowed_methods=["GET"],
            identities=[AuthIdentity("alice", bearer_token="alice-token"), AuthIdentity("bob", bearer_token="bob-token")],
            object_authorization_cases=[ObjectAuthorizationCase("/objects/{id}", "alice", "A", "bob", "B")],
            maximum_requests=40,
            request_rate_limit=100,
            timeout=2,
            dry_run=False,
            workspace=str(workspace),
        )
        result1 = AssessmentEngine(engagement).run(endpoint=f"{target}/objects/{{id}}")
        ev_path = workspace / "evidence.json"
        assert ev_path.exists(), "evidence.json must be written"
        data1 = json.loads(ev_path.read_text(encoding="utf-8"))
        assert isinstance(data1, list) and len(data1) >= 1
        # Find an executed api1 result with evidence ids (from cache store perspective it may be populated)
        executed = [r for r in result1.check_results if r.check_id == "api1-bola" and r.executed]
        assert executed
        # Second run in a separate Python process: should load persisted evidence/history/cache and restore objects on cache hit
        code = r'''
import json, sys
from pathlib import Path
from bugbounty.assessment import AssessmentEngine
from bugbounty.engagement import AuthIdentity, Engagement, ObjectAuthorizationCase
ws = Path(sys.argv[1])
target = sys.argv[2]
eng = Engagement.from_target(target, allowed_schemes=["http"], allowed_methods=["GET"], identities=[AuthIdentity("alice", bearer_token="alice-token"), AuthIdentity("bob", bearer_token="bob-token")], object_authorization_cases=[ObjectAuthorizationCase("/objects/{id}", "alice", "A", "bob", "B")], maximum_requests=40, request_rate_limit=100, timeout=2, dry_run=False, workspace=str(ws))
res = AssessmentEngine(eng).run(endpoint=f"{target}/objects/{{id}}")
cached = [r for r in res.check_results if r.check_id=="api1-bola" and r.executed and "cache" in r.reason.lower()]
out = {"cached": len(cached), "cached_has_evidence_objs": any(len(r.evidence)>0 for r in cached), "cached_evidence_ids": [list(r.evidence_ids) for r in cached], "store_count": len(res.evidence.artifacts)}
print(json.dumps(out))
'''
        proc = subprocess.run([sys.executable, "-c", code, str(workspace), target], capture_output=True, text=True, cwd=str(Path.cwd()))
        assert proc.returncode == 0, f"subprocess failed: {proc.stdout}\n{proc.stderr}"
        # last line should be json
        lines = [ln for ln in proc.stdout.splitlines() if ln.strip()]
        payload = json.loads(lines[-1])
        assert payload["cached"] >= 1, f"expected cache hit in restarted process, got {payload}\nstdout={proc.stdout}\nstderr={proc.stderr}"
        # Evidence artifacts must be present in reloaded store
        assert payload["store_count"] >= 1
        # If cached evidence ids exist, restored evidence objects should be available
        if any(ids for ids in payload["cached_evidence_ids"]):
            assert payload["cached_has_evidence_objs"] is True, f"cached ids not restored to objects: {payload}"
    finally:
        fixture.close()
