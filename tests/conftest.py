import socket

from collections.abc import Sequence
from typing import cast

import pytest

from ldap3 import Connection

from adsearch.config import LDAPConfig
from adsearch.models import DEFAULT_ATTRIBUTES, AttributeMap
from adsearch.search import LDAPSearch

from tests.fake_directory import Entry, FakeConnection, FakeDirectory, Failure


BASE_DN = "DC=test,DC=com"
CONFIG = LDAPConfig(server="ldaps://dc.test.com", base_dn=BASE_DN)

ANN = f"CN=Ann Lee,OU=Users,{BASE_DN}"
BO = f"CN=Bo Ng,OU=Users,{BASE_DN}"
CY = f"CN=Cy Oh,OU=Users,{BASE_DN}"


@pytest.fixture(autouse=True)
def offline(monkeypatch: pytest.MonkeyPatch) -> None:
    """No test in this suite is allowed to reach the network.

    A test that dials out is a bug in the test, not a slow test, so it fails
    immediately instead of hanging on a connect timeout. `socket.inet_pton` is
    deliberately left alone: `Server._is_ipv6` calls it at construction time,
    and it opens nothing."""

    def refuse(*args: object, **kwargs: object) -> None:
        raise AssertionError("a test tried to open a network connection")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket.socket, "connect_ex", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)


def searcher_with_connection(
    *entries: Entry,
    referrals: Sequence[str] = (),
    failure: Failure | None = None,
    config: LDAPConfig = CONFIG,
    attrs: AttributeMap = DEFAULT_ATTRIBUTES,
) -> tuple[LDAPSearch, FakeConnection]:
    """Like `searcher`, but also hands back the raw fake connection for tests
    that need to assert on it directly — e.g. that it was unbound on exit.

    The cast is the one lie in this suite: `FakeConnection` implements the
    slice of ldap3's `Connection` that `adsearch` uses, and nothing else."""
    directory = FakeDirectory(*entries, referrals=referrals, failure=failure)
    connection = directory.connection()
    ad = LDAPSearch(config, attrs, connect=lambda _config: cast(Connection, connection))
    return ad, connection


def searcher(
    *entries: Entry,
    referrals: Sequence[str] = (),
    failure: Failure | None = None,
    config: LDAPConfig = CONFIG,
    attrs: AttributeMap = DEFAULT_ATTRIBUTES,
) -> LDAPSearch:
    """An `LDAPSearch` backed by an in-memory directory instead of a socket.

    `failure` makes the directory raise where a real one would. The bind still
    succeeds, which is what separates it from `unbindable`."""
    ad, _connection = searcher_with_connection(
        *entries, referrals=referrals, failure=failure, config=config, attrs=attrs
    )
    return ad


def unbindable(
    error: Exception,
    *,
    config: LDAPConfig = CONFIG,
    attrs: AttributeMap = DEFAULT_ATTRIBUTES,
) -> LDAPSearch:
    """An `LDAPSearch` whose connection factory raises instead of binding.

    `open_connection` passes `auto_bind`, so the bind happens inside
    `Connection.__init__` — which makes a factory that raises a faithful stand-in
    for a rejected bind."""

    def refuse(_config: LDAPConfig) -> Connection:
        raise error

    return LDAPSearch(config, attrs, connect=refuse)
