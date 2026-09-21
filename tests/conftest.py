import socket

from collections.abc import Sequence
from typing import cast

import pytest

from ldap3 import Connection

from adsearch.config import LDAPConfig
from adsearch.models import DEFAULT_ATTRIBUTES, AttributeMap
from adsearch.search import LDAPSearch

from tests.fake_directory import Entry, FakeDirectory, Failure


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


def searcher(
    *entries: Entry,
    referrals: Sequence[str] = (),
    failure: Failure | None = None,
    config: LDAPConfig = CONFIG,
    attrs: AttributeMap = DEFAULT_ATTRIBUTES,
) -> LDAPSearch:
    """An `LDAPSearch` backed by an in-memory directory instead of a socket.

    The cast is the one lie in this suite: `FakeConnection` implements the
    slice of ldap3's `Connection` that `adsearch` uses, and nothing else.

    `failure` makes the directory raise where a real one would, at the call or
    partway through the result stream. The bind still succeeds, which is what
    separates a query failure from the bind failure `unbindable` builds."""
    directory = FakeDirectory(*entries, referrals=referrals, failure=failure)
    connection = cast(Connection, directory.connection())
    return LDAPSearch(config, attrs, connect=lambda _config: connection)


def unbindable(
    error: Exception,
    *,
    config: LDAPConfig = CONFIG,
    attrs: AttributeMap = DEFAULT_ATTRIBUTES,
) -> LDAPSearch:
    """An `LDAPSearch` whose connection factory raises instead of binding.

    Binding is the whole of what the factory does — `open_connection` passes
    `auto_bind`, so the bind happens inside `Connection.__init__` — which makes
    a factory that raises a faithful stand-in for a rejected bind, and keeps
    the `conn` property's own body running exactly as it does in production."""

    def refuse(_config: LDAPConfig) -> Connection:
        raise error

    return LDAPSearch(config, attrs, connect=refuse)
