"""Search behaviour through the connection seam.

Every test here runs the real `_search` body — referral skipping, entry mapping,
and whatever is layered above it — against an in-memory directory rather than a
stubbed-out search. The fake accepts `paged_size` and ignores it, so paging
itself is not exercised here; the result cap is, being a decision about how
much of the result generator to consume rather than about page size.

Nothing opens a socket, and no test asserts result order: a real paged_search
yields each page in reverse.
"""

import logging

from dataclasses import replace

import pytest

from adsearch.errors import NotFoundError

from tests.conftest import (
    ANN,
    BASE_DN,
    BO,
    CONFIG,
    CY,
    searcher,
    searcher_for,
    searcher_with_connection,
)
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
    ad, _connection = searcher_for(directory, config=replace(CONFIG, batch_size=2))

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


def test_context_manager_releases_the_connection_on_exit():
    ad, connection = searcher_with_connection(user(ANN, sAMAccountName="alee", employeeID="123"))

    with ad as opened:
        assert opened is ad
        opened.find_users("123")

    assert connection.bound is False


def test_close_is_safe_to_call_repeatedly():
    ad, _connection = searcher_with_connection(user(ANN, sAMAccountName="alee"))

    ad.conn  # force the lazy connection open
    ad.close()
    ad.close()


def test_a_teardown_failure_does_not_replace_the_propagating_exception():
    ad, connection = searcher_with_connection(user(ANN, sAMAccountName="alee"))

    def failing_unbind() -> None:
        raise RuntimeError("boom during teardown")

    connection.unbind = failing_unbind

    with pytest.raises(ValueError, match="from inside the block"):
        with ad:
            ad.conn
            raise ValueError("from inside the block")


def test_search_filter_values_are_logged_at_debug_and_nothing_higher(caplog: pytest.LogCaptureFixture):
    """DESIGN §7.4: filter values carry names and employee IDs, so they may
    only ever surface at debug."""
    ad = searcher(user(ANN, sAMAccountName="alee", employeeID="123"))
    with caplog.at_level(logging.DEBUG, logger="adsearch.search"):
        ad.find_users("123")

    assert caplog.records
    assert any("123" in record.getMessage() for record in caplog.records)
    assert all(record.levelno == logging.DEBUG for record in caplog.records)


# --- Resolving stops as soon as it can tell one match from several -----------


def twins(count: int, *, username: str = "alee") -> list[Entry]:
    """`count` entries a site should never have: one username, several users."""
    return [
        user(f"CN=Twin {i},OU=Users,{BASE_DN}", sAMAccountName=username)
        for i in range(count)
    ]


def test_an_ambiguous_resolve_stops_pulling_after_two_entries():
    """What the search consumed is the only thing separating a cap that stops
    the generator from one that collects everything and slices (§8.3)."""
    directory = FakeDirectory(*twins(5))
    ad, _connection = searcher_for(directory)

    with pytest.raises(NotFoundError):
        ad.resolve_user_dn("alee")

    assert directory.consumed == 2


def test_a_resolve_matching_exactly_one_user_returns_its_dn():
    ad = searcher(user(ANN, sAMAccountName="alee"), user(BO, sAMAccountName="bng"))
    assert ad.resolve_user_dn("alee") == ANN


def test_a_resolve_matching_nobody_raises():
    ad = searcher(user(ANN, sAMAccountName="alee"))
    with pytest.raises(NotFoundError, match="nobody"):
        ad.resolve_user_dn("nobody")


def test_an_ambiguous_resolve_names_the_matches_it_saw():
    """Never a silent pick: the caller is handed DNs to disambiguate with, and
    no count, the entries past the second never having been fetched."""
    entries = twins(5)
    ad = searcher(*entries)

    with pytest.raises(NotFoundError) as raised:
        ad.resolve_user_dn("alee")

    named = [entry.dn for entry in entries if entry.dn in str(raised.value)]
    assert len(named) == 2


def test_referrals_do_not_count_against_the_cap():
    """A cap spent on the raw stream would burn itself on the two referrals and
    report the ambiguous username as missing."""
    ad = searcher(
        *twins(2),
        referrals=["ldap://a.test.com/DC=a,DC=com", "ldap://b.test.com/DC=b,DC=com"],
    )
    with pytest.raises(NotFoundError, match="More than one"):
        ad.resolve_user_dn("alee")
