"""Search behaviour through the connection seam.

Every test here runs the real `_search` body — referral skipping, entry mapping,
and whatever is layered above it — against an in-memory directory rather than a
stubbed-out search. The fake accepts `paged_size` and ignores it, so paging
itself is not exercised here; the seam is placed so that the result cap and
error translation land inside `_search` where these tests already reach.

Nothing opens a socket, and no test asserts result order: a real paged_search
yields each page in reverse.
"""

import pytest

from adsearch.errors import NotFoundError

from tests.conftest import ANN, BASE_DN, BO, CY, searcher
from tests.fake_directory import user


def usernames(users):
    return sorted(u["username"] for u in users)


def test_direct_reports_are_the_users_whose_manager_matches():
    ad = searcher(
        user(ANN, sAMAccountName="alee"),
        user(BO, sAMAccountName="bng", manager=ANN),
        user(CY, sAMAccountName="coh", manager=ANN),
        user(f"CN=Di Pu,OU=Users,{BASE_DN}", sAMAccountName="dpu", manager=BO),
    )
    assert usernames(ad.find_reports(ANN)) == ["bng", "coh"]


def test_a_manager_with_no_direct_reports_returns_an_empty_list():
    ad = searcher(user(ANN, sAMAccountName="alee"))
    assert ad.find_reports(ANN) == []


def test_by_manager_resolves_the_username_then_searches():
    ad = searcher(
        user(ANN, sAMAccountName="alee"),
        user(BO, sAMAccountName="bng", manager=ANN),
    )
    assert usernames(ad.by_manager("alee")) == ["bng"]


def test_by_manager_raises_when_the_username_resolves_to_nobody():
    ad = searcher(user(ANN, sAMAccountName="alee"))
    with pytest.raises(NotFoundError):
        ad.by_manager("nobody")


def test_by_manager_raises_when_the_username_is_ambiguous():
    ad = searcher(
        user(ANN, sAMAccountName="alee"),
        user(BO, sAMAccountName="alee"),
    )
    with pytest.raises(NotFoundError):
        ad.by_manager("alee")


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
    assert usernames(ad.find_reports(ANN)) == ["bng"]


def test_a_user_without_a_display_name_falls_back_to_cn():
    ad = searcher(
        user(ANN, sAMAccountName="alee"),
        user(BO, sAMAccountName="bng", cn="Bo Ng", manager=ANN),
    )
    assert [u["name"] for u in ad.find_reports(ANN)] == ["Bo Ng"]
