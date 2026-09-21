"""The translation boundary (DESIGN §6), asserted from outside the library.

These tests do not call `translated()` directly: they drive the public
operations of `LDAPSearch` against a directory that raises where a real one
would, and assert on what comes back out.

Three fault sites, and they are not the same: a bind rejection reaches only the
`conn` property, `during="call"` is a rejection the server issues outright, and
`during="iteration"` arrives after entries have already been yielded.
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

from adsearch import cli, errors
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
    """What a DC returns on a bad bind: result 49, with the diagnostic sub-code
    buried in the message. `data 52e` is a wrong password, `775` a locked-out
    account, `532` an expired one — indistinguishable from the result code."""
    return LDAPInvalidCredentialsResult(
        result=49, description="invalidCredentials", message=BAD_PASSWORD
    )


def size_limit() -> LDAPSizeLimitExceededResult:
    return LDAPSizeLimitExceededResult(
        result=4, description="sizeLimitExceeded", message="size limit exceeded"
    )


UNKNOWN = "something ldap3 has not given a name"

# The mappings that hold wherever the failure happened; the bare base class is
# site-dependent and has its own test. Every key below is an `LDAPException`, so
# a handler catching the base first would turn the whole table into one type.
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
    # Why the handler catches the communication family, not three of its
    # members: a send that fails mid-search is not a bad filter.
    "LDAPSocketSendError": (
        lambda: LDAPSocketSendError("error sending data"),
        LDAPConnectionError,
    ),
    "LDAPSessionTerminatedByServerError": (
        lambda: LDAPSessionTerminatedByServerError("session terminated by server"),
        LDAPConnectionError,
    ),
    # `open_connection` sets `receive_timeout`, so this arrives in production
    # rather than in theory. Outside the communication family, hence its own row.
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
    to the directory — which the sweep further down proves rather than assumes."""
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
    """The site is the only thing known about an exception ldap3 has not named,
    so the site decides. A bind issues no query, and calling a bind-time failure
    a query error sends the caller to debug a filter that was never sent."""
    with pytest.raises(LDAPConnectionError):
        fails_at("bind", LDAPException(UNKNOWN))
    for site in ("call", "iteration"):
        with pytest.raises(LDAPQueryError):
            fails_at(site, LDAPException(UNKNOWN))


def test_the_diagnostic_sub_code_survives_translation():
    """Losing the message leaves a consumer unable to tell a wrong password from
    a locked account. Both the cause and the message carry it, so neither is a
    dead end."""
    with pytest.raises(LDAPAuthError) as caught:
        unbindable(rejected_credentials()).conn
    assert "data 52e" in str(caught.value)
    assert "data 52e" in str(caught.value.__cause__)


def test_a_failure_partway_through_a_result_stream_raises_rather_than_returning_what_arrived():
    """DESIGN §8.3: an incomplete answer that resembles success is the most
    dangerous failure here. The fake raises only after yielding every match, so
    `_search` has a complete-looking list of one user when the error arrives,
    which is what the first assertion proves."""
    assert len(searcher(*DIRECTORY).find_users("123")) == 1

    ad = searcher(*DIRECTORY, failure=Failure(size_limit(), during="iteration"))
    with pytest.raises(LDAPQueryError):
        ad.find_users("123")


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
    "close": lambda ad: ad.close(),
    "find_users": lambda ad: ad.find_users("123"),
    "resolve_user_dn": lambda ad: ad.resolve_user_dn("alee"),
    "direct_reports": lambda ad: ad.direct_reports("alee"),
    "reporting_tree": lambda ad: ad.reporting_tree("alee"),
}

# Everything that reaches the directory, and so must translate. `close` is
# excluded by §8.1 rather than by oversight; the test below pins that.
REACHES_THE_DIRECTORY = {
    name: call for name, call in OPERATIONS.items() if name != "close"
}
QUERIES = {
    name: call for name, call in REACHES_THE_DIRECTORY.items() if name != "conn"
}


def test_the_sweep_covers_every_public_operation():
    """The claim is that a *newly added* query method cannot forget to
    translate, because `_search` is the only route out. That holds only while
    this sweep covers everything public, so a new operation fails here until it
    is listed — as `direct_reports` and `reporting_tree` did."""
    assert {name for name in vars(LDAPSearch) if not name.startswith("_")} == set(OPERATIONS)


def test_close_is_the_only_public_operation_outside_the_boundary():
    """§8.1 requires `close` to *swallow* a teardown failure, not translate it:
    an exception from `__exit__` replaces whatever was already propagating out
    of the `with` block. A translated escaping error is still an escaping error,
    so `close` is excluded on purpose — test_search.py's
    `test_a_teardown_failure_does_not_replace_the_propagating_exception` holds
    it to that. `conn` binds; everything else queries."""
    assert set(OPERATIONS) - set(REACHES_THE_DIRECTORY) == {"close"}
    assert set(REACHES_THE_DIRECTORY) - set(QUERIES) == {"conn"}


@pytest.mark.parametrize("operation", REACHES_THE_DIRECTORY)
def test_no_ldap3_exception_escapes_when_the_bind_fails(operation):
    """The base class is the fault injected here on purpose: a boundary that
    listed only the specific types of §6.2 would let it through."""
    ad = unbindable(LDAPException(UNKNOWN))
    with pytest.raises(LDAPSearchError):
        REACHES_THE_DIRECTORY[operation](ad)


@pytest.mark.parametrize("during", ["call", "iteration"])
@pytest.mark.parametrize("operation", QUERIES)
def test_no_ldap3_exception_escapes_when_a_query_fails(operation, during):
    failure = Failure(LDAPException(UNKNOWN), during=during)
    ad = searcher(*DIRECTORY, failure=failure)
    with pytest.raises(LDAPSearchError):
        QUERIES[operation](ad)


def test_the_cli_test_subcommand_translates_a_failure_from_who_am_i(
    monkeypatch: pytest.MonkeyPatch,
):
    """The third place the library reaches the network. `who_am_i()` is issued
    straight at the connection, past both handlers, so `test_command` applies
    `translated()` itself — and `adsearch test` exists to surface a bad bind,
    which makes it the last command that should report one raw."""

    class Unreachable:
        """A bind that succeeded and an extended operation that then fails."""

        bound = True

        class extend:
            class standard:
                @staticmethod
                def who_am_i() -> str:
                    raise LDAPSocketReceiveError("error receiving data")

    class Bound:
        def __init__(self, config, *args, **kwargs) -> None:
            self.conn = Unreachable()

    monkeypatch.setenv("ADSEARCH_SERVER", "ldaps://dc.test.com")
    monkeypatch.setenv("ADSEARCH_BASE_DN", "DC=test,DC=com")
    monkeypatch.delenv("ADSEARCH_BIND_USER", raising=False)
    monkeypatch.delenv("ADSEARCH_BIND_PASSWORD", raising=False)
    monkeypatch.setattr(cli, "LDAPSearch", Bound)

    with pytest.raises(LDAPConnectionError):
        cli.test_command()


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
    does not own the process. Translation is where one is most tempting to
    attach, being the moment a failure is first classified."""
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
