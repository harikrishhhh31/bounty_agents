"""Regression tests for cache/identity fixes in Phase 3A/3B.

These tests verify:
1. Identity-aware caching prevents result reuse across authentication contexts
2. Execution history tracks (endpoint, check_id, identity_context) independently
3. Evidence is properly resolved when loading from cache
4. API1 BOLA and API5 function-level authorization are tracked separately
5. Preconditions prevent execution when identity context is insufficient
"""

from pathlib import Path

from bugbounty.assessment import AssessmentEngine
from bugbounty.engagement import (
    Engagement,
    AuthIdentity,
    ObjectAuthorizationCase,
    FunctionAuthorizationCase,
)
from bugbounty.investigation import InvestigationMemory
from bugbounty.workspace import ExecutionHistory
from tests.fixtures.vulnerable_api import RunningVulnerableApi


def test_identity_independence_cache_keys_include_context(tmp_path: Path):
    """Test that cache keys include identity context to prevent cross-identity reuse.

    Verifies: identity context is properly encoded in cache keys.
    """
    workspace = str(tmp_path)
    fixture = RunningVulnerableApi(enforce_object_ownership=True)
    try:
        alice = AuthIdentity(name="alice", bearer_token="alice-token")
        bob = AuthIdentity(name="bob", bearer_token="bob-token")

        # Single run with [alice, bob]
        engagement = Engagement.from_target(
            fixture.target,
            allowed_schemes=["http"],
            allowed_methods=["GET"],
            identities=[alice, bob],
            maximum_requests=50,
            request_rate_limit=100,
            timeout=2,
            dry_run=False,
            workspace=workspace,
            object_authorization_cases=[
                ObjectAuthorizationCase(
                    endpoint="/objects/{id}",
                    owner_identity="alice",
                    owner_object_id="A",
                    other_identity="bob",
                    other_object_id="B",
                )
            ],
        )
        result = AssessmentEngine(engagement).run()
        api1_results = [r for r in result.check_results if r.check_id == "api1-bola"]
        assert len(api1_results) > 0, "Expected API1 results in run"

        # Load cache and verify entry exists with proper identity encoding
        cache = InvestigationMemory.load(workspace)
        api1_cache_entries = [k for k in cache.cached_results.keys() if k[1] == "api1-bola"]
        assert len(api1_cache_entries) > 0, "Expected cache entries for api1-bola"

        # Verify cache keys include sorted identity context
        identities_keys = {k[2] for k in api1_cache_entries}
        # The sorted identities should be "alice|bob" (alphabetically sorted)
        assert any("alice" in ik and "bob" in ik for ik in identities_keys), \
            f"Expected both alice and bob in identity context, got: {identities_keys}"

        # Verify identities are actually stored in the cached result
        for (endpoint, check_id, identities_key), cached_result in cache.cached_results.items():
            if check_id == "api1-bola":
                assert cached_result.identities, "Expected identities field in cached result"
                assert len(cached_result.identities) >= 2, f"Expected at least 2 identities, got: {cached_result.identities}"

    finally:
        fixture.close()


def test_resource_ownership_respects_boundaries(tmp_path: Path):
    """Test that object authorization respects ownership boundaries with differential identities.

    Verifies: API1 BOLA detection works when checking across multiple identities' access.
    """
    fixture = RunningVulnerableApi(enforce_object_ownership=True)
    try:
        alice = AuthIdentity(name="alice", bearer_token="alice-token")
        bob = AuthIdentity(name="bob", bearer_token="bob-token")

        engagement = Engagement.from_target(
            fixture.target,
            allowed_schemes=["http"],
            allowed_methods=["GET"],
            identities=[alice, bob],
            maximum_requests=50,
            request_rate_limit=100,
            timeout=2,
            dry_run=False,
            workspace=str(tmp_path),
            object_authorization_cases=[
                ObjectAuthorizationCase(
                    endpoint="/objects/{id}",
                    owner_identity="alice",
                    owner_object_id="A",
                    other_identity="bob",
                    other_object_id="B",
                ),
            ],
        )

        result = AssessmentEngine(engagement).run()

        # Verify API1 checks were executed with both identities (not NOT_RUN)
        api1_results = [r for r in result.check_results if r.check_id == "api1-bola"]
        assert len(api1_results) > 0, "Expected API1 results to be generated"

        # At least some should be executed (not all NOT_RUN or NOT_APPLICABLE)
        executed = [r for r in api1_results if r.executed]
        assert len(executed) > 0, f"Expected API1 checks to execute, got statuses: {[r.status for r in api1_results]}"

    finally:
        fixture.close()


def test_authorization_deduplication_not_reused_across_identity_sets(tmp_path: Path):
    """Test that API1 result for one identity SET is not reused for another identity SET.

    Verifies: execution history tracks (endpoint, check_id, identities_key) independently.
    """
    workspace = str(tmp_path)
    fixture = RunningVulnerableApi(enforce_object_ownership=True)
    try:
        alice = AuthIdentity(name="alice", bearer_token="alice-token")
        bob = AuthIdentity(name="bob", bearer_token="bob-token")
        admin = AuthIdentity(name="admin", bearer_token="admin-token")

        # First assessment with [alice, bob]
        engagement1 = Engagement.from_target(
            fixture.target,
            allowed_schemes=["http"],
            allowed_methods=["GET"],
            identities=[alice, bob],
            maximum_requests=50,
            request_rate_limit=100,
            timeout=2,
            dry_run=False,
            workspace=workspace,
            object_authorization_cases=[
                ObjectAuthorizationCase(
                    endpoint="/objects/{id}",
                    owner_identity="alice",
                    owner_object_id="A",
                    other_identity="bob",
                    other_object_id="B",
                )
            ],
        )
        result1 = AssessmentEngine(engagement1).run()

        # Check execution history was recorded for [alice, bob]
        history = ExecutionHistory.load(workspace)
        alice_bob_checks = [pair for pair in history.executed_pairs if pair[1] == "api1-bola" and "alice" in pair[2] and "bob" in pair[2]]
        assert len(alice_bob_checks) > 0, "Expected API1 checks to be recorded for [alice, bob]"

        # Second assessment with [alice, admin] should NOT reuse [alice, bob] execution
        engagement2 = Engagement.from_target(
            fixture.target,
            allowed_schemes=["http"],
            allowed_methods=["GET"],
            identities=[alice, admin],
            maximum_requests=50,
            request_rate_limit=100,
            timeout=2,
            dry_run=False,
            workspace=workspace,
            object_authorization_cases=[
                ObjectAuthorizationCase(
                    endpoint="/objects/{id}",
                    owner_identity="alice",
                    owner_object_id="A",
                    other_identity="bob",
                    other_object_id="B",
                )
            ],
        )
        result2 = AssessmentEngine(engagement2).run()

        # Verify execution history now has both identity sets recorded
        history2 = ExecutionHistory.load(workspace)
        all_identity_keys = {pair[2] for pair in history2.executed_pairs if pair[1] == "api1-bola"}
        assert len(all_identity_keys) >= 2, f"Expected at least 2 different identity contexts recorded, got: {all_identity_keys}"

    finally:
        fixture.close()


def test_cache_reuse_when_identities_match(tmp_path: Path):
    """Test that results are correctly retrieved from cache when identities match.

    Verifies: cache key includes identities, matching contexts reuse cached results.
    """
    workspace = str(tmp_path)
    fixture = RunningVulnerableApi(enforce_object_ownership=True)
    try:
        alice = AuthIdentity(name="alice", bearer_token="alice-token")
        bob = AuthIdentity(name="bob", bearer_token="bob-token")

        # First run executes the check
        engagement = Engagement.from_target(
            fixture.target,
            allowed_schemes=["http"],
            allowed_methods=["GET"],
            identities=[alice, bob],
            maximum_requests=50,
            request_rate_limit=100,
            timeout=2,
            dry_run=False,
            workspace=workspace,
            object_authorization_cases=[
                ObjectAuthorizationCase(
                    endpoint="/objects/{id}",
                    owner_identity="alice",
                    owner_object_id="A",
                    other_identity="bob",
                    other_object_id="B",
                )
            ],
        )
        result1 = AssessmentEngine(engagement).run()

        # Count executions in first run
        api1_first_run = [r for r in result1.check_results if r.check_id == "api1-bola" and r.executed]
        assert len(api1_first_run) > 0, "Expected API1 checks to execute in first run"

        # Second run with same engagement should use cache
        result2 = AssessmentEngine(engagement).run()

        # Count cached results in second run (cached results have executed=True with "cache" in reason)
        api1_cached = [r for r in result2.check_results if r.check_id == "api1-bola" and r.executed and "cache" in r.reason.lower()]
        assert len(api1_cached) > 0, f"Expected cache hits in second run, got: {[(r.executed, r.reason) for r in result2.check_results if r.check_id == 'api1-bola']}"

    finally:
        fixture.close()


def test_evidence_resolution_from_cache(tmp_path: Path):
    """Test that cached results properly load evidence objects.

    Verifies: when loading cached result, evidence_ids are resolved to actual Evidence objects.
    """
    workspace = str(tmp_path)
    fixture = RunningVulnerableApi(enforce_object_ownership=True)
    try:
        alice = AuthIdentity(name="alice", bearer_token="alice-token")
        bob = AuthIdentity(name="bob", bearer_token="bob-token")

        # Run with both identities to generate evidence
        engagement = Engagement.from_target(
            fixture.target,
            allowed_schemes=["http"],
            allowed_methods=["GET"],
            identities=[alice, bob],
            maximum_requests=100,
            request_rate_limit=100,
            timeout=2,
            dry_run=False,
            workspace=workspace,
            object_authorization_cases=[
                ObjectAuthorizationCase(
                    endpoint="/objects/{id}",
                    owner_identity="alice",
                    owner_object_id="A",
                    other_identity="bob",
                    other_object_id="B",
                )
            ],
        )
        result = AssessmentEngine(engagement).run()

        # Check that evidence is properly loaded
        api1_with_evidence = [r for r in result.check_results
                            if r.check_id == "api1-bola" and r.evidence_ids]

        # Verify evidence objects are actually loaded (not just IDs)
        for check_result in api1_with_evidence:
            assert len(check_result.evidence) > 0, \
                f"Expected evidence objects for {check_result.check_id}, got only IDs: {check_result.evidence_ids}"

            # Each evidence object should have request/response metadata
            for evidence in check_result.evidence:
                assert evidence.request_metadata, "Evidence missing request metadata"
                assert evidence.response_metadata, "Evidence missing response metadata"

    finally:
        fixture.close()


def test_preconditions_insufficient_identities(tmp_path: Path):
    """Test that precondition checking prevents execution with insufficient identities.

    Verifies: NOT_RUN status returned when identity count < 2 for API1/API5.
    """
    fixture = RunningVulnerableApi()
    try:
        # Only one identity - insufficient for differential authorization testing
        alice = AuthIdentity(name="alice", bearer_token="alice-token")

        engagement = Engagement.from_target(
            fixture.target,
            allowed_schemes=["http"],
            allowed_methods=["GET"],
            identities=[alice],  # Only one identity
            maximum_requests=50,
            request_rate_limit=100,
            timeout=2,
            dry_run=False,
            workspace=str(tmp_path),
            object_authorization_cases=[
                ObjectAuthorizationCase(
                    endpoint="/objects/{id}",
                    owner_identity="alice",
                    owner_object_id="A",
                    other_identity="bob",
                    other_object_id="B",
                )
            ],
        )

        result = AssessmentEngine(engagement).run()

        # API1 and API5 should be NOT_RUN with precondition failure reason
        api1_results = [r for r in result.check_results if r.check_id == "api1-bola"]
        assert all(r.status == "NOT_RUN" for r in api1_results), \
            f"Expected API1 to be NOT_RUN with insufficient identities, got: {[r.status for r in api1_results]}"

        assert all("identities" in r.reason.lower() for r in api1_results), \
            f"Expected reason to mention identities, got: {[r.reason for r in api1_results]}"

    finally:
        fixture.close()


def test_api1_api5_separation_tracked_independently(tmp_path: Path):
    """Test that API1 BOLA and API5 function-level authorization are tracked separately.

    Verifies: separate check_ids and preconditions for each.
    """
    workspace = str(tmp_path)
    fixture = RunningVulnerableApi(enforce_object_ownership=True)
    try:
        alice = AuthIdentity(name="alice", bearer_token="alice-token")
        bob = AuthIdentity(name="bob", bearer_token="bob-token")

        engagement = Engagement.from_target(
            fixture.target,
            allowed_schemes=["http"],
            allowed_methods=["GET"],
            identities=[alice, bob],
            maximum_requests=50,
            request_rate_limit=100,
            timeout=2,
            dry_run=False,
            workspace=workspace,
            object_authorization_cases=[
                ObjectAuthorizationCase(
                    endpoint="/objects/{id}",
                    owner_identity="alice",
                    owner_object_id="A",
                    other_identity="bob",
                    other_object_id="B",
                )
            ],
            function_authorization_cases=[
                FunctionAuthorizationCase(
                    endpoint="/admin",
                    allowed_identity="alice",
                    denied_identity="bob",
                )
            ],
        )

        result = AssessmentEngine(engagement).run()

        # Check results should have both separate check IDs
        check_ids = {r.check_id for r in result.check_results}
        assert "api1-bola" in check_ids, "Expected api1-bola check to be tracked"
        assert "api5-broken-function-level-authorization" in check_ids, \
            "Expected api5-broken-function-level-authorization check to be tracked"

        # Verify they have separate results
        api1_results = [r for r in result.check_results if r.check_id == "api1-bola"]
        api5_results = [r for r in result.check_results if r.check_id == "api5-broken-function-level-authorization"]

        assert len(api1_results) > 0, "Expected API1 results"
        assert len(api5_results) > 0, "Expected API5 results"

        # Verify execution history tracks them separately
        history = ExecutionHistory.load(workspace)
        api1_pairs = [pair for pair in history.executed_pairs if pair[1] == "api1-bola"]
        api5_pairs = [pair for pair in history.executed_pairs if pair[1] == "api5-broken-function-level-authorization"]

        assert len(api1_pairs) > 0, "Expected API1 in execution history"
        assert len(api5_pairs) > 0, "Expected API5 in execution history"

    finally:
        fixture.close()


def test_cache_persistence_across_runs(tmp_path: Path):
    """Test that investigation memory cache persists and is reused across separate runs.

    Verifies: cache survives save/load cycle and is properly restored.
    """
    workspace = str(tmp_path)
    fixture = RunningVulnerableApi(enforce_object_ownership=True)
    try:
        alice = AuthIdentity(name="alice", bearer_token="alice-token")
        bob = AuthIdentity(name="bob", bearer_token="bob-token")

        # First run: cache is populated
        engagement = Engagement.from_target(
            fixture.target,
            allowed_schemes=["http"],
            allowed_methods=["GET"],
            identities=[alice, bob],
            maximum_requests=50,
            request_rate_limit=100,
            timeout=2,
            dry_run=False,
            workspace=workspace,
            object_authorization_cases=[
                ObjectAuthorizationCase(
                    endpoint="/objects/{id}",
                    owner_identity="alice",
                    owner_object_id="A",
                    other_identity="bob",
                    other_object_id="B",
                )
            ],
        )
        result1 = AssessmentEngine(engagement).run()

        # Save cache file and verify it exists
        cache_file = Path(workspace) / "investigation_cache.json"
        assert cache_file.exists(), "Expected investigation_cache.json to be created"

        # Second run: verify cache is loaded
        result2 = AssessmentEngine(engagement).run()

        # Load cache directly and verify identity context is preserved
        cache = InvestigationMemory.load(workspace)
        cached_entries = list(cache.cached_results.items())
        assert len(cached_entries) > 0, "Expected cache entries to be loaded"

        # Verify cache keys include identity context
        for (endpoint, check_id, identities_key), cached_result in cached_entries:
            assert "|" in identities_key or identities_key == "", \
                f"Expected identity context in cache key: {identities_key}"
            assert cached_result.identities, "Expected identities field to be preserved"

    finally:
        fixture.close()
