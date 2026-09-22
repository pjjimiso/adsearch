"""An in-memory directory and a connection-shaped object that queries it.

The fake exists so that everything downstream of `LDAPSearch.conn` — paging,
referral skipping, the result cap and error translation — runs for real in
tests. `consumed` tallies the entries handed to the client, which is the only
place a cap that stops the generator is distinguishable from one that truncates
a list it already collected.

It is a directory with a filter matcher, not a lookup table keyed on filter
strings: the reporting-tree walk batches manager DNs into disjunctions whose
exact text depends on `LDAPConfig.batch_size`, so no hand-maintained expected
filter survives a level wider than one batch.
"""

from __future__ import annotations

import re

from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from typing import Literal

from ldap3 import NO_ATTRIBUTES, SUBTREE

from adsearch.filters import IN_CHAIN


def _fold(value: str) -> str:
    """Active Directory's default matching rule is caseIgnoreMatch, and DN
    comparison ignores case too. The fake does not implement per-syntax
    matching rules; one case-insensitive comparison covers every form this
    library asks of it. Values are deliberately NOT trimmed: the fake being
    more forgiving than a real DC would mask a caller passing whitespace."""
    return value.casefold()


class FilterSyntaxError(ValueError):
    """The fake could not parse a filter the library emitted."""


_HEX_ESCAPE = re.compile(r"\\([0-9a-fA-F]{2})")


def unescape(value: str) -> str:
    """Invert `filters.esc`.

    Hand-rolled on purpose. ldap3's own `unescape_filter_chars` returns bytes
    and substitutes `\\5c` before `\\2a`, so it is not the inverse of
    `escape_filter_chars`: the escaping of the literal string `a\\2ab` comes
    back out as `a*b`. A single left-to-right pass is correct.
    """
    return _HEX_ESCAPE.sub(lambda match: chr(int(match.group(1), 16)), value)


@dataclass
class Entry:
    """One directory object.

    Attribute values are always lists, which is the shape ldap3 returns when
    the server was built with `get_info=NONE` and so has no schema to unwrap
    single values against."""

    dn: str
    attributes: dict[str, list[str]]
    _folded: dict[str, list[str]] = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        self._folded = {name.casefold(): values for name, values in self.attributes.items()}

    def values(self, attribute: str) -> list[str]:
        return self._folded.get(attribute.casefold(), [])

    def project(self, attributes: Sequence[str] | None) -> dict[str, list[str]]:
        """What the server would return for the requested attribute list.

        Unpopulated attributes are omitted, which is what a real DC does and
        what keeps `to_user`'s displayName -> cn -> dn fallback reachable in a
        test."""
        if attributes is None or NO_ATTRIBUTES in attributes:
            return {}
        projected: dict[str, list[str]] = {}
        for name in attributes:
            values = self.values(name)
            if values:
                projected[name] = list(values)
        return projected


@dataclass(frozen=True)
class Failure:
    """An error the directory raises instead of — or partway through — answering.

    `during="iteration"` raises only after every matching entry has been
    yielded, which is how a real paged search fails: during consumption, where
    a handler wrapped around the call alone would never see it."""

    error: Exception
    during: Literal["call", "iteration"] = "call"


@dataclass(frozen=True)
class Equal:
    attribute: str
    value: str

    def matches(self, entry: Entry, directory: FakeDirectory) -> bool:
        wanted = _fold(self.value)
        return any(_fold(value) == wanted for value in entry.values(self.attribute))


@dataclass(frozen=True)
class Present:
    attribute: str

    def matches(self, entry: Entry, directory: FakeDirectory) -> bool:
        return bool(entry.values(self.attribute))


@dataclass(frozen=True)
class Extensible:
    attribute: str
    oid: str
    value: str

    def matches(self, entry: Entry, directory: FakeDirectory) -> bool:
        """LDAP_MATCHING_RULE_IN_CHAIN: follow `attribute` transitively."""
        if self.oid != IN_CHAIN:
            raise FilterSyntaxError(f"unsupported matching rule {self.oid}")
        wanted = _fold(self.value)
        seen: set[str] = set()
        frontier = list(entry.values(self.attribute))
        while frontier:
            dn = frontier.pop()
            key = _fold(dn)
            if key in seen:      # nested groups can cycle
                continue
            seen.add(key)
            if key == wanted:
                return True
            linked = directory.entry(dn)
            if linked is not None:
                frontier.extend(linked.values(self.attribute))
        return False


@dataclass(frozen=True)
class And:
    clauses: tuple[Node, ...]

    def matches(self, entry: Entry, directory: FakeDirectory) -> bool:
        return all(clause.matches(entry, directory) for clause in self.clauses)


@dataclass(frozen=True)
class Or:
    clauses: tuple[Node, ...]

    def matches(self, entry: Entry, directory: FakeDirectory) -> bool:
        return any(clause.matches(entry, directory) for clause in self.clauses)


Node = And | Or | Equal | Present | Extensible


class _Parser:
    """Recursive descent over the RFC 4515 subset this library emits.

    Covers exactly what `filters.py` emits and nothing more — negation has no
    branch here because no helper produces one. Relies on one property of the
    library: every assertion value has passed through `filters.esc`, so a bare
    `(` or `)` can never appear inside a value and a clause can be read up to
    the next `)`."""

    def __init__(self, text: str) -> None:
        self._text = text
        self._pos = 0

    def filter(self) -> Node:
        self._take("(")
        char = self._peek()
        if char == "&":
            self._pos += 1
            return And(tuple(self._clauses()))
        if char == "|":
            self._pos += 1
            return Or(tuple(self._clauses()))
        node = self._simple()
        self._take(")")
        return node

    def _clauses(self) -> list[Node]:
        nodes: list[Node] = []
        while self._peek() == "(":
            nodes.append(self.filter())
        if not nodes:
            raise FilterSyntaxError(f"empty clause list in {self._text!r}")
        self._take(")")
        return nodes

    def _simple(self) -> Node:
        end = self._text.find(")", self._pos)
        if end == -1:
            raise FilterSyntaxError(f"unterminated clause in {self._text!r}")
        body, self._pos = self._text[self._pos:end], end

        # Split on the FIRST '=' — a DN value is full of them.
        attribute, separator, value = body.partition("=")
        if not separator:
            raise FilterSyntaxError(f"no '=' in clause {body!r} of {self._text!r}")

        if attribute.endswith(":"):                       # (attr:OID:=value)
            name, _, oid = attribute[:-1].partition(":")
            return Extensible(name, oid, unescape(value))

        # Test for presence BEFORE unescaping. A neutralised wildcard is the
        # four characters `\2a`; unescaping first would turn it into a presence
        # filter and quietly make every injection test meaningless.
        if value == "*":
            return Present(attribute)
        return Equal(attribute, unescape(value))

    def _peek(self) -> str:
        return self._text[self._pos] if self._pos < len(self._text) else ""

    def _take(self, char: str) -> None:
        if self._peek() != char:
            raise FilterSyntaxError(f"expected {char!r} at {self._pos} in {self._text!r}")
        self._pos += 1

    def expect_end(self) -> None:
        if self._pos != len(self._text):
            raise FilterSyntaxError(f"trailing text in {self._text!r}")


def parse(text: str) -> Node:
    parser = _Parser(text)
    node = parser.filter()
    parser.expect_end()
    return node


def user(
    dn: str,
    *,
    manager: str | None = None,
    member_of: Sequence[str] = (),
    **attributes: str | Sequence[str],
) -> Entry:
    """A person entry carrying the object class and category `USER_OBJECT` filters on.

    Real Active Directory stores `objectCategory` as a DN and resolves the
    `person` shorthand server-side. The fake stores the shorthand, because the
    shorthand is what the library's filter actually says."""
    values: dict[str, list[str]] = {
        "objectClass": ["top", "person", "organizationalPerson", "user"],
        "objectCategory": ["person"],
    }
    if manager is not None:
        values["manager"] = [manager]
    if member_of:
        values["memberOf"] = list(member_of)
    for name, value in attributes.items():
        values[name] = [value] if isinstance(value, str) else list(value)
    return Entry(dn=dn, attributes=values)


def group(dn: str, *, member_of: Sequence[str] = ()) -> Entry:
    """A group entry. `member_of` nests it inside another group, which is what
    the transitive matching rule walks."""
    values: dict[str, list[str]] = {
        "objectClass": ["top", "group"],
        "objectCategory": ["group"],
    }
    if member_of:
        values["memberOf"] = list(member_of)
    return Entry(dn=dn, attributes=values)


def reports_to(manager: Entry, count: int, *, prefix: str, base_dn: str) -> list[Entry]:
    """`count` direct reports of `manager`. Cheap enough to build a reporting
    level wider than `LDAPConfig.batch_size`."""
    return [
        user(
            f"CN={prefix}{i},OU=Users,{base_dn}",
            sAMAccountName=f"{prefix}{i}",
            displayName=f"{prefix} {i}",
            manager=manager.dn,
        )
        for i in range(count)
    ]


def _in_scope(dn: str, base: str) -> bool:
    """SUBTREE scope: the base itself and everything beneath it."""
    entry, root = _fold(dn), _fold(base)
    return entry == root or entry.endswith("," + root)


class _Standard:
    """`connection.extend.standard`."""

    def __init__(self, directory: FakeDirectory) -> None:
        self._directory = directory

    def paged_search(
        self,
        *,
        search_base: str,
        search_filter: str,
        attributes: Sequence[str] | None = None,
        search_scope: str = SUBTREE,
        paged_size: int = 100,
        time_limit: int = 0,
        generator: bool = True,
    ):
        """The exact keyword surface `LDAPSearch._search` calls, spelled out
        rather than taken as `**kwargs`, so a renamed keyword fails loudly here
        instead of being silently swallowed. `paged_size` is accepted and
        ignored: chunking changes nothing `_search` can observe."""
        self._directory.fail_now("call")
        stream = self._stream(search_base, search_filter, attributes)
        return stream if generator else list(stream)

    def _stream(
        self, search_base: str, search_filter: str, attributes: Sequence[str] | None
    ) -> Iterator[dict]:
        for uri in self._directory.referrals:
            # A real searchResRef carries no 'dn' and no 'attributes'. Keeping
            # it that way means dropping the referral check raises KeyError,
            # loudly, rather than yielding a malformed user.
            yield {"uri": [uri], "type": "searchResRef"}
        for entry in self._directory.search(search_base, search_filter):
            self._directory.pulled()
            yield {
                "dn": entry.dn,
                "attributes": entry.project(attributes),
                "type": "searchResEntry",
            }
        # Last, not first: the point is a failure that arrives after partial
        # results.
        self._directory.fail_now("iteration")


class _Extend:
    def __init__(self, directory: FakeDirectory) -> None:
        self.standard = _Standard(directory)


class FakeConnection:
    """The slice of ldap3's Connection that `adsearch` actually uses."""

    def __init__(self, directory: FakeDirectory) -> None:
        self.extend = _Extend(directory)
        self.bound = True

    def unbind(self) -> None:
        self.bound = False


class FakeDirectory:
    def __init__(
        self,
        *entries: Entry,
        referrals: Sequence[str] = (),
        failure: Failure | None = None,
    ) -> None:
        self._entries = list(entries)
        self._by_dn = {_fold(entry.dn): entry for entry in entries}
        self.referrals = list(referrals)
        self.failure = failure
        self.consumed = 0

    def pulled(self) -> None:
        """One entry handed over. Called before the yield, so the tally is what
        the client took rather than what matched."""
        self.consumed += 1

    def fail_now(self, during: Literal["call", "iteration"]) -> None:
        """Raise the configured failure if this is the point it was set for."""
        if self.failure is not None and self.failure.during == during:
            raise self.failure.error

    def entry(self, dn: str) -> Entry | None:
        return self._by_dn.get(_fold(dn))

    def search(self, base: str, filter_text: str) -> list[Entry]:
        node = parse(filter_text)
        return [
            entry
            for entry in self._entries
            if _in_scope(entry.dn, base) and node.matches(entry, self)
        ]

    def connection(self) -> FakeConnection:
        return FakeConnection(self)
