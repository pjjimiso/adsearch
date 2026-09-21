"""The translation boundary (DESIGN §6), asserted from outside the library.

A consumer catches `LDAPSearchError` and is done. That promise is only as good
as the narrowest place it can leak, so these tests do not call `translated()`
directly: they drive the public operations of `LDAPSearch` with a directory
that raises where a real one would, and assert on what comes back out.

Three fault sites matter and they are not the same. A bind rejection reaches
only the `conn` property. `during="call"` is a rejection the server issues
outright. `during="iteration"` arrives after entries have already been yielded,
because `paged_search` hands back a generator — a handler wrapped around the
call alone would let it straight through, and the caller would see a raw ldap3
exception from inside a loop somewhere downstream.
"""

import ast
import pathlib

from typing import Literal

import pytest

from ldap3.core.exceptions import (
    LDAPBindError,
    LDAPCertificateError,
    LDAPException,
    LDAPInvalidCredentialsResult,
    LDAPInvalidFilterError,
    LDAPResponseTimeoutError,
    LDAPSessionTerminatedByServerError,
    LDAPSizeLimitExceededResult,
    LDAPSocketOpenError,
    LDAPSocketReceiveError,
    LDAPSocketSendError,
    LDAPStartTLSError,
    LDAPTimeLimitExceededResult,
    LDAPUndefinedAttributeTypeResult,
)

from adsearch import errors
from adsearch.errors import (
    LDAPAuthError,
    LDAPConfigError,
    LDAPConnectionError,
    LDAPQueryError,
    LDAPSearchError,
    NotFoundError,
)
from adsearch.search import LDAPSearch

from tests.conftest import ANN, BO, searcher, unbindable
from tests.fake_directory import Failure, user


BAD_PASSWORD = (
    "80090308: LdapErr: DSID-0C09042A, comment: AcceptSecurityContext error, data 52e, v4563"
)

DIRECTORY = (
    user(ANN, sAMAccountName="alee", employeeID="123"),
    user(BO, sAMAccountName="bng", manager=ANN),
)


def rejected_credentials() -> LDAPInvalidCredentialsResult:
    """What a domain controller actually returns on a bad bind: result 49,
    with the diagnostic sub-code buried in the message. `data 52e` is a wrong
    password, `775` a locked-out account, `532` an expired one — a distinction
    a consumer has to make and cannot reconstruct from the result code alone."""
    return LDAPInvalidCredentialsResult(
        result=49, description="invalidCredentials", message=BAD_PASSWORD
    )


def size_limit() -> LDAPSizeLimitExceededResult:
    return LDAPSizeLimitExceededResult(
        result=4, description="sizeLimitExceeded", message="size limit exceeded"
    )


UNKNOWN = "something ldap3 has not given a name"

# The mappings that hold wherever the failure happened. The bare base class is
# absent on purpose: what an unnamed exception becomes depends on the site, and
# `test_an_unrecognised_exception_is_filed_by_where_it_happened` owns that.
#
# Ordering is what these rows really protect. Every key below is an
# `LDAPException`, so a handler that caught the base first would turn the whole
# table into one type and still satisfy any test asking only whether something
# from `adsearch` came out.
TRANSLATIONS = {
    "LDAPBindError": (lambda: LDAPBindError("bind failed"), LDAPAuthError),
    "LDAPInvalidCredentialsResult": (rejected_credentials, LDAPAuthError),
    "LDAPSocketOpenError": (
        lambda: LDAPSocketOpenError("socket connection error while opening"),
        LDAPConnectionError,
    ),
    "LDAPSocketReceiveError": (
        lambda: LDAPSocketReceiveError("error receiving data"),
        LDAPConnectionError,
    ),
    # Named individually in neither §6.2's original table nor the AC, and the
    # reason the handler now catches the communication family rather than three
    # of its members: a send that fails mid-search is not a bad filter.
    "LDAPSocketSendError": (
        lambda: LDAPSocketSendError("error sending data"),
        LDAPConnectionError,
    ),
    "LDAPSessionTerminatedByServerError": (
        lambda: LDAPSessionTerminatedByServerError("session terminated by server"),
        LDAPConnectionError,
    ),
    # §6.1 promises a timeout is a connection failure, and `open_connection`
    # sets `receive_timeout`, so this arrives in production rather than in
    # theory. It is outside the communication family, hence its own entry.
    "LDAPResponseTimeoutError": (
        lambda: LDAPResponseTimeoutError("no response received"),
        LDAPConnectionError,
    ),
    # §6.1 lists TLS beside DNS and TCP.
    "LDAPStartTLSError": (lambda: LDAPStartTLSError("start TLS failed"), LDAPConnectionError),
    "LDAPCertificateError": (
        lambda: LDAPCertificateError("certificate verify failed"),
        LDAPConnectionError,
    ),
    "LDAPInvalidFilterError": (
        lambda: LDAPInvalidFilterError("malformed filter"),
        LDAPQueryError,
    ),
    "LDAPUndefinedAttributeTypeResult": (
        lambda: LDAPUndefinedAttributeTypeResult(
            result=17, description="undefinedAttributeType", message="000020F6"
        ),
        LDAPQueryError,
    ),
    "LDAPSizeLimitExceededResult": (size_limit, LDAPQueryError),
    "LDAPTimeLimitExceededResult": (
        lambda: LDAPTimeLimitExceededResult(
            result=3, description="timeLimitExceeded", message="time limit exceeded"
        ),
        LDAPQueryError,
    ),
}

# "bind" is the `conn` property. The other two are `Failure.during` values,
# reached through any query at all.
Site = Literal["bind", "call", "iteration"]

FAULT_SITES: tuple[Site, ...] = ("bind", "call", "iteration")


def fails_at(site: Site, error: Exception) -> None:
    """Drive a public operation into `error`, raised at `site`.

    `find_users` stands in for every query because `_search` is the only route
    to the directory; the sweep further down is what proves that claim rather
    than assuming it."""
    if site == "bind":
        unbindable(error).conn
    else:
        searcher(*DIRECTORY, failure=Failure(error, during=site)).find_users("123")


def test_the_two_exception_hierarchies_are_disjoint():
    """Why `pytest.raises(LDAPSearchError)` below is the whole of the no-escape
    assertion: nothing from ldap3 can satisfy it."""
    assert not issubclass(LDAPSearchError, LDAPException)
    assert not issubclass(LDAPException, LDAPSearchError)


@pytest.mark.parametrize("site", FAULT_SITES)
@pytest.mark.parametrize("name", TRANSLATIONS)
def test_every_ldap3_exception_is_translated_wherever_it_is_raised(name, site):
    """`site="iteration"` is the subtlety the boundary exists for: it raises
    only after entries have been yielded, because `paged_search` returns a
    generator and a handler wrapped around the call alone would miss it."""
    build, expected = TRANSLATIONS[name]
    original = build()
    with pytest.raises(expected) as caught:
        fails_at(site, original)
    assert caught.value.__cause__ is original


def test_an_unrecognised_exception_is_filed_by_where_it_happened():
    """A bind issues no query, so reporting an unnamed bind-time failure as a
    query error tells the caller to go and fix a filter that was never sent.
    The site is the only thing known about an exception ldap3 has not given a
    name, so the site decides — and it is exactly these unnamed types that
    decide whether a consumer can retry a transient network fault without
    retrying a bad password."""
    with pytest.raises(LDAPConnectionError):
        fails_at("bind", LDAPException(UNKNOWN))
    for site in ("call", "iteration"):
        with pytest.raises(LDAPQueryError):
            fails_at(site, LDAPException(UNKNOWN))


def test_the_diagnostic_sub_code_survives_translation():
    """DESIGN §6.2. Losing the message leaves a consumer unable to tell a wrong
    password from a locked account, which is the one thing `LDAPAuthError` is
    for. The cause carries it, and so does the message, so neither
    `str(e)` nor `e.__cause__` alone is a dead end."""
    with pytest.raises(LDAPAuthError) as caught:
        unbindable(rejected_credentials()).conn
    assert "data 52e" in str(caught.value)
    assert "data 52e" in str(caught.value.__cause__)


def test_a_failure_partway_through_a_result_stream_raises_rather_than_returning_what_arrived():
    """DESIGN §8.3: an incomplete answer that resembles success is the most
    dangerous failure here. The fake raises only after yielding every matching
    entry, so `_search` is holding a complete-looking list of one user at the
    moment the error arrives — the first assertion is what proves that."""
    assert len(searcher(*DIRECTORY).find_reports(ANN)) == 1

    ad = searcher(*DIRECTORY, failure=Failure(size_limit(), during="iteration"))
    with pytest.raises(LDAPQueryError):
        ad.find_reports(ANN)


@pytest.mark.parametrize(
    "error",
    [NotFoundError("no user found"), KeyError("dn")],
    ids=["an adsearch error", "an unrelated error"],
)
def test_the_boundary_does_not_over_catch(error):
    """It translates ldap3's exceptions and nothing else. A handler written as
    `except Exception` passes every test above while quietly relabelling a
    `NotFoundError` — or a plain bug in this library — as a query error."""
    ad = searcher(*DIRECTORY, failure=Failure(error, during="call"))
    with pytest.raises(type(error)):
        ad.find_users("123")


# --- No third-party exception escapes any public operation -------------------

OPERATIONS = {
    "conn": lambda ad: ad.conn,
    "find_users": lambda ad: ad.find_users("123"),
    "resolve_user_dn": lambda ad: ad.resolve_user_dn("alee"),
    "find_reports": lambda ad: ad.find_reports(ANN),
    "by_manager": lambda ad: ad.by_manager("alee"),
}

QUERIES = {name: call for name, call in OPERATIONS.items() if name != "conn"}


def test_the_sweep_covers_every_public_operation():
    """The boundary's real claim is that a *newly added* query method cannot
    forget to translate, because `_search` is the only route out. That holds
    only while this sweep actually covers everything public, so a new operation
    fails here until it is listed."""
    assert {name for name in vars(LDAPSearch) if not name.startswith("_")} == set(OPERATIONS)


def test_conn_is_the_only_public_operation_that_does_not_query():
    """`conn` binds and returns; everything else reaches the directory through
    `_search`. The split is what lets the query sweep below assume a failing
    directory is enough to make each operation raise."""
    assert set(OPERATIONS) - set(QUERIES) == {"conn"}


@pytest.mark.parametrize("operation", OPERATIONS)
def test_no_ldap3_exception_escapes_when_the_bind_fails(operation):
    """The base class is the fault injected here on purpose: a boundary that
    listed only the specific types of §6.2 would let it through."""
    ad = unbindable(LDAPException(UNKNOWN))
    with pytest.raises(LDAPSearchError):
        OPERATIONS[operation](ad)


@pytest.mark.parametrize("during", ["call", "iteration"])
@pytest.mark.parametrize("operation", QUERIES)
def test_no_ldap3_exception_escapes_when_a_query_fails(operation, during):
    failure = Failure(LDAPException(UNKNOWN), during=during)
    ad = searcher(*DIRECTORY, failure=failure)
    with pytest.raises(LDAPSearchError):
        QUERIES[operation](ad)


# --- Exit codes stay out of the library (DESIGN §6.4) ------------------------

HIERARCHY = {
    LDAPSearchError,
    LDAPConfigError,
    LDAPAuthError,
    LDAPConnectionError,
    LDAPQueryError,
    NotFoundError,
}


def test_the_hierarchy_is_exactly_the_six_classes_design_names():
    defined = {
        value
        for value in vars(errors).values()
        if isinstance(value, type) and issubclass(value, BaseException)
    }
    assert defined == HIERARCHY
    assert all(issubclass(error, LDAPSearchError) for error in HIERARCHY)


def test_no_error_carries_an_exit_code():
    """DESIGN §6.4: the exit-code map belongs to `cli.py`, because a library
    does not own the process. Translation is where an exit code is most
    tempting to attach, since it is the moment a failure is first classified."""
    for error in HIERARCHY:
        added = {
            name
            for name in set(dir(error)) - set(dir(Exception))
            if not name.startswith("__")
        }
        assert added == set(), f"{error.__name__} gained {added}"


def test_the_errors_module_imports_nothing():
    """DESIGN §3.2. `errors.py` is the root of the dependency graph, and
    `import sys` is the first line of an exit-code map."""
    tree = ast.parse(pathlib.Path(errors.__file__).read_text())
    imports = [n for n in ast.walk(tree) if isinstance(n, (ast.Import, ast.ImportFrom))]
    assert imports == []
