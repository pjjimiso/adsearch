"""Search behaviour through the connection seam.

Every test here runs the real `_search` body — referral skipping, entry mapping,
and whatever is layered above it — against an in-memory directory rather than a
stubbed-out search. The fake accepts `paged_size` and ignores it, so paging
itself is not exercised here; the seam is placed so that the result cap and
error translation land inside `_search` where these tests already reach.

Nothing opens a socket, and no test asserts result order: a real paged_search
yields each page in reverse.
"""

from dataclasses import replace
from typing import cast

import pytest

from ldap3 import Connection

from adsearch.errors import NotFoundError
from adsearch.search import LDAPSearch

from tests.conftest import ANN, BASE_DN, BO, CY, CONFIG, searcher
from tests.fake_directory import Entry, FakeDirectory, reports_to, user

DI = f"CN=Di Pu,OU=Users,{BASE_DN}"


def usernames(users):
    return sorted(u["username"] for u in users)


def managed_by(entry: Entry, *manager_dns: str) -> Entry:
    """`entry` with several managers.

    Active Directory's `manager` is single-valued, so this is a directory the
    library will not meet — but it is the cheapest way to put one user on two
    branches of one tree, which is a case the walk promises to handle
    (DESIGN.md 8.7) and which a cycle alone does not reproduce."""
    return Entry(dn=entry.dn, attributes={**entry.attributes, "manager": list(manager_dns)})


class RecordingDirectory(FakeDirectory):
    """A fake directory that remembers every filter it was asked.

    The reporting tree's cost is a count of round trips, so the filters
    themselves are the only place the batching contract of ADR-0001 is
    observable: a walk that issued one query per DN would return exactly the
    same users."""

    def __init__(self, *entries: Entry, **kwargs) -> None:
        super().__init__(*entries, **kwargs)
        self.filters: list[str] = []

    def search(self, base: str, filter_text: str) -> list[Entry]:
        self.filters.append(filter_text)
        return super().search(base, filter_text)


def test_direct_reports_are_one_hop_from_a_manager_username():
    """One hop only: dpu reports to bng, and bng reports to alee."""
    ad = searcher(
        user(ANN, sAMAccountName="alee"),
        user(BO, sAMAccountName="bng", manager=ANN),
        user(CY, sAMAccountName="coh", manager=ANN),
        user(DI, sAMAccountName="dpu", manager=BO),
    )
    assert usernames(ad.direct_reports("alee")) == ["bng", "coh"]


def test_a_manager_with_no_direct_reports_returns_an_empty_list():
    ad = searcher(user(ANN, sAMAccountName="alee"))
    assert ad.direct_reports("alee") == []


def test_direct_reports_raises_when_the_username_resolves_to_nobody():
    ad = searcher(user(ANN, sAMAccountName="alee"))
    with pytest.raises(NotFoundError):
        ad.direct_reports("nobody")


def test_direct_reports_raises_when_the_username_is_ambiguous():
    ad = searcher(
        user(ANN, sAMAccountName="alee"),
        user(BO, sAMAccountName="alee"),
    )
    with pytest.raises(NotFoundError):
        ad.direct_reports("alee")


def test_find_users_searches_on_employee_id():
    ad = searcher(
        user(ANN, sAMAccountName="alee", employeeID="123"),
        user(BO, sAMAccountName="bng", employeeID="456"),
    )
    assert usernames(ad.find_users("123")) == ["alee"]


def test_an_employee_id_matching_several_entries_returns_all_of_them():
    """Employee ID is a search key, never a resolve key (CONTEXT.md)."""
    ad = searcher(
        user(ANN, sAMAccountName="alee", employeeID="123"),
        user(BO, sAMAccountName="bng", employeeID="123"),
    )
    assert usernames(ad.find_users("123")) == ["alee", "bng"]


def test_referrals_are_not_returned_as_users():
    ad = searcher(
        user(ANN, sAMAccountName="alee"),
        user(BO, sAMAccountName="bng", manager=ANN),
        referrals=["ldap://other.test.com/DC=other,DC=com"],
    )
    assert usernames(ad.direct_reports("alee")) == ["bng"]


def test_a_user_without_a_display_name_falls_back_to_cn():
    ad = searcher(
        user(ANN, sAMAccountName="alee"),
        user(BO, sAMAccountName="bng", cn="Bo Ng", manager=ANN),
    )
    assert [u["name"] for u in ad.direct_reports("alee")] == ["Bo Ng"]


def test_the_reporting_tree_reaches_every_depth_and_excludes_the_manager():
    ad = searcher(
        user(ANN, sAMAccountName="alee"),
        user(BO, sAMAccountName="bng", manager=ANN),
        user(CY, sAMAccountName="coh", manager=BO),
        user(DI, sAMAccountName="dpu", manager=CY),
        user(f"CN=Ed Vo,OU=Users,{BASE_DN}", sAMAccountName="evo"),
    )
    assert usernames(ad.reporting_tree("alee")) == ["bng", "coh", "dpu"]


def test_a_management_cycle_terminates():
    """alee reports to dpu, who is inside alee's own tree. The walk ends
    because the level that reaches alee again yields nobody new."""
    ad = searcher(
        user(ANN, sAMAccountName="alee", manager=DI),
        user(BO, sAMAccountName="bng", manager=ANN),
        user(CY, sAMAccountName="coh", manager=BO),
        user(DI, sAMAccountName="dpu", manager=CY),
    )
    assert usernames(ad.reporting_tree("alee")) == ["bng", "coh", "dpu"]


def test_a_manager_who_manages_himself_is_not_his_own_report():
    ad = searcher(
        user(ANN, sAMAccountName="alee", manager=ANN),
        user(BO, sAMAccountName="bng", manager=ANN),
    )
    assert usernames(ad.reporting_tree("alee")) == ["bng"]


def test_a_user_reachable_under_two_managers_is_returned_once():
    """dpu is found twice: once under bng at the second level, once under coh
    at the third. The seen set is what makes the count right."""
    ad = searcher(
        user(ANN, sAMAccountName="alee"),
        user(BO, sAMAccountName="bng", manager=ANN),
        user(CY, sAMAccountName="coh", manager=BO),
        managed_by(user(DI, sAMAccountName="dpu"), BO, CY),
    )
    assert usernames(ad.reporting_tree("alee")) == ["bng", "coh", "dpu"]


def test_a_user_under_two_managers_in_one_level_is_returned_once():
    """One manager DN to a query, so bng and coh are asked for separately
    inside the same level and each answer contains dpu."""
    ad = searcher(
        user(ANN, sAMAccountName="alee"),
        user(BO, sAMAccountName="bng", manager=ANN),
        user(CY, sAMAccountName="coh", manager=ANN),
        managed_by(user(DI, sAMAccountName="dpu"), BO, CY),
        config=replace(CONFIG, batch_size=1),
    )
    assert usernames(ad.reporting_tree("alee")) == ["bng", "coh", "dpu"]


def test_the_reporting_tree_raises_when_the_username_resolves_to_nobody():
    ad = searcher(user(ANN, sAMAccountName="alee"))
    with pytest.raises(NotFoundError):
        ad.reporting_tree("nobody")


def test_a_level_wider_than_the_batch_size_is_split_across_queries():
    """Five reports at one level, two DNs to a query. Every report comes back,
    including the one reached through the last and shortest batch, and no
    query carries more manager clauses than the batch size allows."""
    boss = user(ANN, sAMAccountName="alee")
    level = reports_to(boss, 5, prefix="r", base_dn=BASE_DN)
    child = user(f"CN=Kid,OU=Users,{BASE_DN}", sAMAccountName="kid", manager=level[-1].dn)
    directory = RecordingDirectory(boss, *level, child)
    ad = LDAPSearch(
        replace(CONFIG, batch_size=2),
        connect=lambda _config: cast(Connection, directory.connection()),
    )

    assert usernames(ad.reporting_tree("alee")) == ["kid", "r0", "r1", "r2", "r3", "r4"]

    clauses = [f.count("(manager=") for f in directory.filters]
    assert max(clauses) <= 2, "a query carried more manager DNs than the batch size permits"
    assert clauses.count(2) == 2, "the five-DN level should have been split into 2, 2 and 1"


def test_a_level_wider_than_the_default_batch_size_returns_every_report():
    """600 reports at one level against the shipped batch size of 500, with
    children hung either side of the boundary between the two queries."""
    boss = user(ANN, sAMAccountName="alee")
    level = reports_to(boss, 600, prefix="r", base_dn=BASE_DN)
    edges = [level[0], level[499], level[500], level[599]]
    children = [
        user(f"CN=Kid {i},OU=Users,{BASE_DN}", sAMAccountName=f"kid{i}", manager=edge.dn)
        for i, edge in enumerate(edges)
    ]
    ad = searcher(boss, *level, *children, config=CONFIG)

    tree = ad.reporting_tree("alee")
    assert len(tree) == 604
    assert {u["username"] for u in tree} >= {"kid0", "kid1", "kid2", "kid3"}
