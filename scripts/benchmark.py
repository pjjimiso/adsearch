"""Benchmark harness for ADR-0001's manager-traversal comparison and the
group-membership question it left open.

Requires a live directory (`ADSEARCH_SERVER`, `ADSEARCH_BASE_DN`, ...; see
README.md). Nothing here is exercised against a socket by the test suite —
`tests/test_benchmark.py` covers the pure logic through the same fake
directory the library itself is tested against; only a real run produces
figures worth recording.

    uv run python scripts/benchmark.py manager <username>
    uv run python scripts/benchmark.py group <group name or DN>
    uv run python scripts/benchmark.py filter-complexity

Each subcommand prints one JSON object. See docs/adr/0001-bfs-over-in-chain.md
for how the results feed back into that decision.
"""

from __future__ import annotations

import argparse
import json
import time

from collections.abc import Callable, Sequence
from typing import TypedDict, TypeVar

from adsearch.config import LDAPConfig
from adsearch.errors import LDAPQueryError
from adsearch.filters import any_of, eq_dn, in_chain
from adsearch.models import DEFAULT_ATTRIBUTES, User
from adsearch.search import LDAPSearch


T = TypeVar("T")


class Timing(TypedDict):
    seconds: float
    count: int


def _timed(fn: Callable[[], list[T]]) -> tuple[Timing, list[T]]:
    start = time.perf_counter()
    result = fn()
    elapsed = time.perf_counter() - start
    return Timing(seconds=elapsed, count=len(result)), result


class TreeShape(TypedDict):
    size: int
    depth: int


def walk_tree_shape(ad: LDAPSearch, root_dn: str) -> TreeShape:
    """Size and depth of the reporting tree rooted at `root_dn`, re-walked
    unbatched through `find_users(manager_dn=...)` since depth isn't part of
    `reporting_tree`'s contract (DESIGN §8.7's benchmark harness note)."""
    seen = {root_dn.casefold()}
    size = 0
    depth = 0
    level = [root_dn]

    while level:
        new: list[User] = []
        for dn in level:
            for report in ad.find_users(manager_dn=dn, include_disabled=True):
                key = report["dn"].casefold()
                if key in seen:
                    continue
                seen.add(key)
                new.append(report)
        if not new:
            break
        depth += 1
        size += len(new)
        level = [report["dn"] for report in new]

    return TreeShape(size=size, depth=depth)


class ManagerTraversalResult(TypedDict):
    root: str
    tree_size: int
    tree_depth: int
    walk: Timing
    in_chain: Timing
    in_chain_slower_by: float | None
    counts_agree: bool


def benchmark_manager_traversal(ad: LDAPSearch, username: str) -> ManagerTraversalResult:
    """ADR-0001's comparison, reproduced: the walk against the single `IN_CHAIN` query it replaced."""
    manager_dn = ad.resolve_user_dn(username)

    walk_timing, walk_result = _timed(lambda: ad.reporting_tree(username))
    chain_timing, chain_result = _timed(
        lambda: ad.find_users(
            extra_filter=in_chain(DEFAULT_ATTRIBUTES.manager, manager_dn),
            include_disabled=True,
        )
    )
    shape = walk_tree_shape(ad, manager_dn)

    return ManagerTraversalResult(
        root=username,
        tree_size=shape["size"],
        tree_depth=shape["depth"],
        walk=walk_timing,
        in_chain=chain_timing,
        in_chain_slower_by=(
            chain_timing["seconds"] / walk_timing["seconds"] if walk_timing["seconds"] else None
        ),
        counts_agree=len(walk_result) == len(chain_result),
    )


class GroupBenchmarkResult(TypedDict):
    group: str
    transitive: Timing
    direct: Timing
    members_only_through_nesting: int
    transitive_slower_by: float | None


def benchmark_group(ad: LDAPSearch, group: str) -> GroupBenchmarkResult:
    """Transitive membership against direct-only (DESIGN §8.8)."""
    transitive_timing, transitive_result = _timed(lambda: ad.by_group(group, transitive=True))
    direct_timing, direct_result = _timed(lambda: ad.by_group(group, transitive=False))

    return GroupBenchmarkResult(
        group=group,
        transitive=transitive_timing,
        direct=direct_timing,
        members_only_through_nesting=len(transitive_result) - len(direct_result),
        transitive_slower_by=(
            transitive_timing["seconds"] / direct_timing["seconds"] if direct_timing["seconds"] else None
        ),
    )


def gather_sample_dns(ad: LDAPSearch, limit: int) -> list[str]:
    """Up to `limit` real DNs, to build a probe filter as wide as a level can get."""
    return [found["dn"] for found in ad.find_users(limit=limit, include_disabled=True)]


class FilterComplexityResult(TypedDict, total=False):
    ran: bool
    reason: str
    width: int
    rejected: bool
    error: str


def probe_filter_complexity(ad: LDAPSearch, dns: Sequence[str]) -> FilterComplexityResult:
    """Whether a `len(dns)`-wide disjunction of `eq_dn(manager, ...)` clauses — the
    shape a wide reporting-tree level batches into (DESIGN §8.7) — is rejected."""
    if not dns:
        return FilterComplexityResult(ran=False, reason="no DNs available to build a probe filter from")

    clause = any_of(*[eq_dn(DEFAULT_ATTRIBUTES.manager, dn) for dn in dns])
    try:
        ad.find_users(extra_filter=clause, limit=1, include_disabled=True)
    except LDAPQueryError as exc:
        return FilterComplexityResult(ran=True, width=len(dns), rejected=True, error=str(exc))
    return FilterComplexityResult(ran=True, width=len(dns), rejected=False)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Reproduces ADR-0001's manager-traversal comparison and benchmarks "
        "transitive group membership. Requires a live directory."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    manager_parser = subparsers.add_parser(
        "manager", help="Compare the BFS walk against one IN_CHAIN query for a manager's reporting tree"
    )
    manager_parser.add_argument("username", help="manager username to benchmark")

    group_parser = subparsers.add_parser(
        "group", help="Compare transitive and direct-only queries for one group"
    )
    group_parser.add_argument("group", help="group common name or DN")

    subparsers.add_parser(
        "filter-complexity",
        help="Probe whether a batch_size-wide disjunction of manager clauses is rejected by the directory",
    )

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    config = LDAPConfig.from_env()

    with LDAPSearch(config) as ad:
        match args.command:
            case "manager":
                result = benchmark_manager_traversal(ad, args.username)
            case "group":
                result = benchmark_group(ad, args.group)
            case "filter-complexity":
                result = probe_filter_complexity(ad, gather_sample_dns(ad, config.batch_size))
            case _:
                raise AssertionError(f"unhandled command: {args.command}")

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
