"""Offline coverage for the benchmark harness's pure logic.

The harness exists to measure a live directory (docs/adr/0001-bfs-over-in-chain.md),
so timing numbers here are not the point — only that each function counts,
compares and probes correctly is, which the fake directory can prove without a
socket, the same way the rest of the suite does.
"""

from ldap3.core.exceptions import LDAPInvalidFilterError

from tests.conftest import ANN, BASE_DN, BO, CY, searcher, searcher_for
from tests.fake_directory import FakeDirectory, Failure, group, user

from scripts.benchmark import (
    benchmark_group,
    benchmark_manager_traversal,
    gather_sample_dns,
    probe_filter_complexity,
    walk_tree_shape,
)


# --- walk_tree_shape ----------------------------------------------------------


def test_walk_tree_shape_counts_every_depth_and_excludes_the_root():
    ad = searcher(
        user(ANN, sAMAccountName="alee"),
        user(BO, sAMAccountName="bng", manager=ANN),
        user(CY, sAMAccountName="coh", manager=BO),
    )
    assert walk_tree_shape(ad, ANN) == {"size": 2, "depth": 2}


def test_walk_tree_shape_is_zero_for_a_manager_with_no_reports():
    ad = searcher(user(ANN, sAMAccountName="alee"))
    assert walk_tree_shape(ad, ANN) == {"size": 0, "depth": 0}


# --- benchmark_manager_traversal ----------------------------------------------


def test_benchmark_manager_traversal_agrees_between_the_walk_and_in_chain():
    ad = searcher(
        user(ANN, sAMAccountName="alee"),
        user(BO, sAMAccountName="bng", manager=ANN),
        user(CY, sAMAccountName="coh", manager=BO),
    )

    result = benchmark_manager_traversal(ad, "alee")

    assert result["root"] == "alee"
    assert result["tree_size"] == 2
    assert result["tree_depth"] == 2
    assert result["counts_agree"] is True
    assert result["walk"]["count"] == 2
    assert result["in_chain"]["count"] == 2
    assert result["walk"]["seconds"] >= 0
    assert result["in_chain"]["seconds"] >= 0


# --- benchmark_group -----------------------------------------------------------

GROUP = f"CN=Engineers,OU=Groups,{BASE_DN}"
PARENT_GROUP = f"CN=All Staff,OU=Groups,{BASE_DN}"


def test_benchmark_group_counts_members_reached_only_through_nesting():
    ad = searcher(
        group(PARENT_GROUP),
        group(GROUP, member_of=[PARENT_GROUP]),
        user(ANN, sAMAccountName="alee", member_of=[GROUP]),  # nested only
        user(BO, sAMAccountName="bng", member_of=[PARENT_GROUP]),  # direct
    )

    result = benchmark_group(ad, "All Staff")

    assert result["group"] == "All Staff"
    assert result["transitive"]["count"] == 2
    assert result["direct"]["count"] == 1
    assert result["members_only_through_nesting"] == 1


def test_benchmark_group_is_zero_when_nesting_adds_nobody():
    ad = searcher(
        group(GROUP),
        user(ANN, sAMAccountName="alee", member_of=[GROUP]),
    )

    result = benchmark_group(ad, "Engineers")

    assert result["members_only_through_nesting"] == 0


# --- gather_sample_dns ---------------------------------------------------------


def test_gather_sample_dns_respects_the_limit():
    ad = searcher(
        user(ANN, sAMAccountName="alee"),
        user(BO, sAMAccountName="bng"),
        user(CY, sAMAccountName="coh"),
    )

    dns = gather_sample_dns(ad, limit=2)

    assert len(dns) == 2
    assert set(dns) <= {ANN, BO, CY}


# --- probe_filter_complexity ---------------------------------------------------


def test_probe_filter_complexity_does_not_run_without_sample_dns():
    ad = searcher()
    assert probe_filter_complexity(ad, []) == {
        "ran": False,
        "reason": "no DNs available to build a probe filter from",
    }


def test_probe_filter_complexity_succeeds_when_the_directory_accepts_the_filter():
    ad = searcher(user(ANN, sAMAccountName="alee"))

    result = probe_filter_complexity(ad, [ANN, BO])

    assert result == {"ran": True, "width": 2, "rejected": False}


def test_probe_filter_complexity_detects_a_rejected_filter():
    directory = FakeDirectory(
        failure=Failure(LDAPInvalidFilterError("too complex"), during="call")
    )
    ad, _connection = searcher_for(directory)

    result = probe_filter_complexity(ad, [ANN, BO])

    assert result == {"ran": True, "width": 2, "rejected": True, "error": "too complex"}
