import logging
import ssl

from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from itertools import batched

from ldap3 import (
    SIMPLE, 
    NONE,
    AUTO_BIND_NO_TLS,
    SUBTREE,
    NO_ATTRIBUTES,
    Connection,
    Server,
    Tls
)
from ldap3.core.exceptions import (
    LDAPBindError,
    LDAPCertificateError,
    LDAPCommunicationError,
    LDAPException,
    LDAPInvalidCredentialsResult,
    LDAPInvalidFilterError,
    LDAPInvalidTlsSpecificationError,
    LDAPMaximumRetriesError,
    LDAPResponseTimeoutError,
    LDAPSizeLimitExceededResult,
    LDAPSSLConfigurationError,
    LDAPSSLNotSupportedError,
    LDAPStartTLSError,
    LDAPTimeLimitExceededResult,
    LDAPUndefinedAttributeTypeResult,
)

from adsearch.config import LDAPConfig
from adsearch.models import DEFAULT_ATTRIBUTES, AttributeMap, User, to_user
from adsearch.errors import (
    LDAPAuthError,
    LDAPConnectionError,
    LDAPQueryError,
    LDAPSearchError,
    NotFoundError,
)
from adsearch.filters import (
    USER_OBJECT, 
    eq, 
    all_of,
    any_of,
    eq_dn,
)


logger = logging.getLogger(__name__)

ConnectionFactory = Callable[[LDAPConfig], Connection]


AUTH_ERRORS = (LDAPBindError, LDAPInvalidCredentialsResult)

CONNECTION_ERRORS = (
    # The whole communication family, not the three members §6.2 first named:
    # a failed send, a socket the DC closed and an unintelligible response are
    # connection failures every bit as much as a failed open. Naming members
    # one at a time is what let `LDAPSocketSendError` reach a caller labelled
    # a query error.
    LDAPCommunicationError,
    # §6.1 promises a timeout is a connection failure, and `open_connection`
    # sets `receive_timeout`, so this is a live path rather than a hypothetical.
    LDAPResponseTimeoutError,
    LDAPMaximumRetriesError,
    # §6.1 lists TLS alongside DNS and TCP. These are raised while assembling
    # or negotiating the transport, all of it inside `open_connection`.
    LDAPStartTLSError,
    LDAPCertificateError,
    LDAPSSLConfigurationError,
    LDAPSSLNotSupportedError,
    LDAPInvalidTlsSpecificationError,
)

QUERY_ERRORS = (
    LDAPInvalidFilterError,
    LDAPUndefinedAttributeTypeResult,
    LDAPSizeLimitExceededResult,
    LDAPTimeLimitExceededResult,
)


@contextmanager
def translated(fallback: type[LDAPSearchError] = LDAPQueryError) -> Iterator[None]:
    """Re-raise anything `ldap3` throws as this library's own error (§6.2).

    The whole point is that `ldap3` never reaches a consumer: if a caller has
    to write `except LDAPSocketOpenError`, the client library is part of the
    public contract permanently and can never be replaced.

    This wraps blocks rather than decorating methods so it can cover the
    *consumption* of a paged search as well as the call. `paged_search` hands
    back a generator, so a size limit or a dropped session surfaces while
    results are being read — a decorator on `_search` would still catch it,
    but only because `_search` consumes the generator itself, and nothing
    would keep that true.

    `except` clauses are tried in order, so the specific families come first
    and the base class last; inverting that would collapse every failure into
    one type while still satisfying any test that only asked whether
    *something* from `adsearch` came out. Nothing outside `ldap3`'s hierarchy
    is caught: `NotFoundError`, a filter rejection, and a plain bug in this
    library all pass through untouched.

    `fallback` is what an `ldap3` exception none of the families names becomes,
    and it differs by where the failure happened, because that is the only
    thing known about it. A bind issues no query, so an unrecognised failure
    there is a connection problem; calling it a query error would tell a
    caller to fix a filter that was never sent, and telling a transient
    network fault apart from a bad password is the whole reason these types
    are distinct.

    `str(exc)` is carried onto the new exception as well as being reachable
    through `__cause__`, because the message is where Active Directory puts
    its diagnostic sub-code — `data 52e` for a bad password, `775` for a
    locked-out account, `532` for an expired one — and a consumer that can
    only see `LDAPAuthError` cannot tell those apart."""
    try:
        yield
    except AUTH_ERRORS as exc:
        raise LDAPAuthError(str(exc)) from exc
    except CONNECTION_ERRORS as exc:
        raise LDAPConnectionError(str(exc)) from exc
    except QUERY_ERRORS as exc:
        raise LDAPQueryError(str(exc)) from exc
    except LDAPException as exc:
        raise fallback(str(exc)) from exc


def build_server(config: LDAPConfig) -> Server:
    """The transport configuration, assembled without opening anything.

    `Server` resolves addresses at open time rather than at construction, which
    is what makes this callable offline and the certificate invariant (§7.3)
    assertable without a socket. The `Tls` is built here rather than passed in
    because `Server(use_ssl=True, tls=None)` silently substitutes a default
    `Tls()` with `validate=CERT_NONE` — so the assertion that matters is on the
    assembled server, not on a `Tls` that may never have reached it."""
    if config.validate_cert:
        cert_validation = ssl.CERT_REQUIRED
    else:
        cert_validation = ssl.CERT_NONE

    tls = Tls(
        validate = cert_validation,
        ca_certs_file = config.ca_certs_file
    )
    return Server(
        host = config.server,
        use_ssl = config.use_ssl,
        tls = tls,
        get_info = NONE,
        connect_timeout = config.connect_timeout,
    )


def open_connection(config: LDAPConfig) -> Connection:
    """Build and bind a connection. The only place this library opens a socket."""
    return Connection(
        build_server(config),
        user = config.bind_user,
        password = config.bind_password,
        authentication = SIMPLE,
        auto_bind = AUTO_BIND_NO_TLS,
        raise_exceptions = True,
        receive_timeout = config.receive_timeout,
        auto_referrals = False,
        auto_range = True,
    )


class LDAPSearch:
    def __init__(
        self,
        config: LDAPConfig,
        attrs: AttributeMap = DEFAULT_ATTRIBUTES,
        *,
        connect: ConnectionFactory | None = None,
    ) -> None:
        self._conn: Connection | None = None
        self._config = config
        self._attrs = attrs
        self._connect: ConnectionFactory = open_connection if connect is None else connect


    @property
    def conn(self) -> Connection:
        """The connection, opened and bound on first use.

        One of the two places this library reaches the network, and the only
        one that binds — which is what makes it the only place a bind
        rejection can be translated (§6.2). `_conn` stays `None` on failure,
        so a caller that fixes its credentials and retries is not stuck with
        a half-open instance."""
        if self._conn is None:
            with translated(LDAPConnectionError):
                self._conn = self._connect(self._config)
        return self._conn


    def close(self) -> None:
        """Unbind the connection if one was opened.

        Safe to call more than once, and swallows any error raised during
        teardown: an exception raised from `__exit__` replaces whatever
        exception was already propagating out of a `with` block, hiding the
        real failure (§8.1)."""
        if self._conn is not None:
            conn, self._conn = self._conn, None
            try:
                conn.unbind()
            except Exception:
                pass


    def __enter__(self) -> "LDAPSearch":
        return self


    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: object,
    ) -> None:
        self.close()


    def _search(self, search_filter: str, attributes: Sequence[str]) -> list[dict]:
        """Runs a paged subtree search and returns raw entries.

        The other place this library reaches the network, and the only place
        it queries — so a query method added later cannot forget to translate,
        because there is no other route out.

        The loop is inside `translated()`, not just the call: `paged_search`
        returns a generator, so a failure the server raises partway through a
        result set arrives here during consumption. Leaving the loop outside
        would return the entries that did arrive, which is an incomplete
        answer wearing the shape of a complete one (§8.3)."""
        # Debug only: filter values carry names and employee IDs (§7.4). Outside
        # the handler: it cannot raise an ldap3 error, and a log line is not
        # something to translate.
        logger.debug("search base=%s filter=%s", self._config.base_dn, search_filter)
        results = []
        with translated():
            response = self.conn.extend.standard.paged_search(
                search_base=self._config.base_dn,
                search_filter=search_filter,
                attributes=attributes,
                search_scope=SUBTREE,
                paged_size=self._config.page_size,
                time_limit=self._config.time_limit,
                generator=True,
            )
            for entry in response:
                # ignore referrals (searchResRef)
                if entry["type"] == "searchResEntry":
                    results.append(entry)
        return results


    def _search_users(self, search_filter: str) -> list[User]:
        entries = self._search(search_filter, self._attrs.fetch_attributes())
        users = []
        for entry in entries:
            users.append(to_user(entry, self._attrs))
        return users


    def find_users(self, employee_id: str) -> list[User]:
        """Look up users by employee ID. Returns a list of User objects."""
        search_filter = all_of(USER_OBJECT, eq(self._attrs.employee_id, employee_id))
        return self._search_users(search_filter)


    def resolve_user_dn(self, value: str, *, by: str | None = None) -> str: 
        """DN of the single user whose `by` attribute equals `value`.
        `by` defaults to the AttributeMap's username attribute (sAMAccountName).
        Raises NotFoundError on no match and on multiple matches."""
        attribute = self._attrs.username if by is None else by
        search_filter = all_of(USER_OBJECT, eq(attribute, value))
        entries = self._search(search_filter, [NO_ATTRIBUTES])
        count = len(entries)
        if count == 0:
            raise NotFoundError(f"No user found with {attribute}={value}")
        if count > 1: 
            raise NotFoundError(f"Found {count} with {attribute}={value}: {[e["dn"] for e in entries]}")
        return entries[0]["dn"]


    def _reports_of(self, manager_dns: Sequence[str]) -> list[User]:
        """Every user whose manager is one of `manager_dns`, one query per
        `LDAPConfig.batch_size` DNs. A single DN is a single query: `any_of`
        collapses a one-clause disjunction, so the one-hop case pays nothing
        for being expressed the same way as a traversal level."""
        found: list[User] = []
        for batch in batched(manager_dns, self._config.batch_size):
            clauses = [eq_dn(self._attrs.manager, dn) for dn in batch]
            found.extend(self._search_users(all_of(USER_OBJECT, any_of(*clauses))))
        return found


    def direct_reports(self, username: str) -> list[User]:
        """The users whose manager is this manager: one hop, one query.

        Takes a username rather than a DN because `manager` holds a DN and
        resolving it is this library's job, not the caller's (CONTEXT.md)."""
        return self._reports_of([self.resolve_user_dn(username)])


    def reporting_tree(self, username: str) -> list[User]:
        """Every direct report of this manager, and every direct report of
        those, to any depth.

        The expensive operation in this library: a breadth-first walk of one
        round trip per batch per level, deliberately not the directory's
        `LDAP_MATCHING_RULE_IN_CHAIN` (ADR-0001). It is a separate name from
        `direct_reports` rather than a flag on it so that its cost is always
        visible at the call site."""
        return self._walk_reports(self.resolve_user_dn(username))


    def _walk_reports(self, root_dn: str) -> list[User]:
        """Breadth-first from `root_dn`, one level at a time, until a level
        yields nobody new.

        The seen set is what makes the walk terminate and the result honest:
        a management cycle re-reaches a DN already visited, and a user under
        two managers within the tree is discovered twice. Both are dropped by
        the same check. `root_dn` seeds it, so a manager who manages himself
        is not reported as his own report. Keys are case-folded because DN
        comparison in Active Directory ignores case.

        A DN is marked seen as it is taken, not once the level is done: one
        level is several queries, and a user under two managers that fall in
        different batches is answered by both of them."""
        seen = {root_dn.casefold()}
        tree: list[User] = []
        level = [root_dn]

        while level:
            new: list[User] = []
            for report in self._reports_of(level):
                if report["dn"].casefold() in seen:
                    continue
                seen.add(report["dn"].casefold())
                new.append(report)
            tree.extend(new)
            level = [report["dn"] for report in new]

        return tree


#   We'll re-implement this later after building out find_users more
#    def by_employee_id(self, employee_id: str) -> list[Userg:
#        """Look up a list of users by employee ID""
#        return self.find_users(employee_id)

