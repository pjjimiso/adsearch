"""The fake's own matcher.

The fake now contains a filter parser, and a parser that mis-read `(&(&...)(...))`
as match-everything would turn the search tests green for the wrong reason.
"""

import pytest

from ldap3 import NO_ATTRIBUTES

from adsearch.filters import USER_OBJECT, all_of, any_of, eq, eq_dn, in_chain

from tests.conftest import ANN, BASE_DN, BO
from tests.fake_directory import (
    FakeDirectory,
    FilterSyntaxError,
    group,
    reports_to,
    unescape,
    user,
)


def dns(entries):
    return sorted(entry.dn for entry in entries)


def one_entry(directory, *, attributes):
    """The single raw response dict the fake yields, with the exact keyword
    surface LDAPSearch._search uses."""
    response = directory.connection().extend.standard.paged_search(
        search_base=BASE_DN,
        search_filter=USER_OBJECT,
        attributes=attributes,
        search_scope="SUBTREE",
        paged_size=1000,
        time_limit=120,
        generator=True,
    )
    return list(response)[0]


def test_equality_matches_a_single_attribute():
    directory = FakeDirectory(user(ANN, sAMAccountName="alee"), user(BO, sAMAccountName="bng"))
    assert dns(directory.search(BASE_DN, eq("sAMAccountName", "alee"))) == [ANN]


def test_conjunction_requires_every_clause():
    directory = FakeDirectory(user(ANN, sAMAccountName="alee", employeeID="1"))
    assert directory.search(BASE_DN, all_of(eq("sAMAccountName", "alee"), eq("employeeID", "1")))
    assert not directory.search(BASE_DN, all_of(eq("sAMAccountName", "alee"), eq("employeeID", "2")))


def test_disjunction_matches_any_clause():
    cy = f"CN=Cy Oh,OU=Users,{BASE_DN}"
    directory = FakeDirectory(
        user(ANN, sAMAccountName="alee"),
        user(BO, sAMAccountName="bng"),
        user(cy, sAMAccountName="coh"),
    )
    found = directory.search(BASE_DN, any_of(eq("sAMAccountName", "alee"), eq("sAMAccountName", "bng")))
    assert dns(found) == sorted([ANN, BO])


def test_nested_conjunction_parses():
    """The literal shape the library emits: all_of does not flatten, so
    USER_OBJECT nests and the filter is (&(&...)(...))."""
    directory = FakeDirectory(user(ANN, sAMAccountName="alee"), group(f"CN=Admins,OU=Groups,{BASE_DN}"))
    found = directory.search(BASE_DN, all_of(USER_OBJECT, eq("sAMAccountName", "alee")))
    assert dns(found) == [ANN]


def test_object_class_and_category_exclude_a_group():
    directory = FakeDirectory(user(ANN), group(f"CN=Admins,OU=Groups,{BASE_DN}"))
    assert dns(directory.search(BASE_DN, USER_OBJECT)) == [ANN]


def test_escaped_value_is_compared_unescaped():
    team = f"CN=Team (West),OU=Groups,{BASE_DN}"
    directory = FakeDirectory(user(ANN, memberOf=[team]))
    assert dns(directory.search(BASE_DN, eq_dn("memberOf", team))) == [ANN]


def test_a_neutralised_wildcard_matches_nobody():
    """esc turns a caller's '*' into the four characters \\2a. If the matcher
    unescaped before testing for presence, this would match everyone."""
    directory = FakeDirectory(user(ANN, sAMAccountName="alee"))
    assert directory.search(BASE_DN, eq("sAMAccountName", "*")) == []


def test_a_real_presence_filter_still_matches():
    directory = FakeDirectory(user(ANN, employeeID="1"), user(BO))
    assert dns(directory.search(BASE_DN, "(employeeID=*)")) == [ANN]


def test_attribute_names_are_case_insensitive():
    directory = FakeDirectory(user(ANN, sAMAccountName="alee"))
    assert dns(directory.search(BASE_DN, eq("samaccountname", "alee"))) == [ANN]


def test_dn_comparison_ignores_case():
    directory = FakeDirectory(user(BO, manager=ANN))
    assert dns(directory.search(BASE_DN, eq_dn("manager", ANN.upper()))) == [BO]


def test_the_search_base_scopes_the_result():
    outside = "CN=Zed Ox,OU=Users,DC=other,DC=com"
    directory = FakeDirectory(user(ANN), user(outside))
    assert dns(directory.search(BASE_DN, USER_OBJECT)) == [ANN]


def test_no_attributes_projects_only_the_dn():
    directory = FakeDirectory(user(ANN, sAMAccountName="alee"))
    entry = one_entry(directory, attributes=[NO_ATTRIBUTES])
    assert entry["dn"] == ANN
    assert entry["attributes"] == {}


def test_unpopulated_attributes_are_omitted():
    directory = FakeDirectory(user(ANN, sAMAccountName="alee"))
    entry = one_entry(directory, attributes=["sAMAccountName", "employeeID"])
    assert entry["attributes"] == {"sAMAccountName": ["alee"]}


def test_transitive_membership_follows_nested_groups():
    parent = f"CN=All Staff,OU=Groups,{BASE_DN}"
    child = f"CN=Engineers,OU=Groups,{BASE_DN}"
    directory = FakeDirectory(
        group(parent),
        group(child, member_of=[parent]),
        user(ANN, member_of=[child]),
        user(BO),
    )
    assert dns(directory.search(BASE_DN, in_chain("memberOf", parent))) == sorted([ANN, child])


def test_transitive_membership_terminates_on_a_cycle():
    left = f"CN=Left,OU=Groups,{BASE_DN}"
    right = f"CN=Right,OU=Groups,{BASE_DN}"
    absent = f"CN=Absent,OU=Groups,{BASE_DN}"
    directory = FakeDirectory(
        group(left, member_of=[right]),
        group(right, member_of=[left]),
        user(ANN, member_of=[left]),
    )
    assert directory.search(BASE_DN, in_chain("memberOf", absent)) == []


def test_an_unparseable_filter_is_an_error_not_a_silent_match():
    directory = FakeDirectory(user(ANN))
    with pytest.raises(FilterSyntaxError):
        directory.search(BASE_DN, "(sAMAccountName")


def test_unescape_inverts_esc_for_a_literal_backslash_sequence():
    """ldap3's own unescape_filter_chars gets this wrong: it substitutes \\5c
    before \\2a, so the escaping of the literal text a\\2ab comes back as a*b."""
    from adsearch.filters import esc

    assert unescape(esc(r"a\2ab")) == r"a\2ab"


def test_a_disjunction_wider_than_a_batch_matches_every_clause():
    """The shape the reporting-tree walk emits once a level exceeds
    LDAPConfig.batch_size (500): one OR over a batch of manager DNs. This is
    why the fake matches filters instead of looking up canned strings."""
    manager = user(ANN, sAMAccountName="alee")
    level = reports_to(manager, 600, prefix="r", base_dn=BASE_DN)
    grandchildren = [
        user(f"CN=g{i},OU=Users,{BASE_DN}", sAMAccountName=f"g{i}", manager=level[i].dn)
        for i in range(600)
    ]
    directory = FakeDirectory(manager, *level, *grandchildren)

    batch = [eq_dn("manager", report.dn) for report in level[:500]]
    found = directory.search(BASE_DN, all_of(USER_OBJECT, any_of(*batch)))
    assert len(found) == 500
