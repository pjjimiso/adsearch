import logging
import ssl

from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from itertools import batched, islice

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
    NOT_DISABLED,
    USER_OBJECT,
    all_of,
    any_of,
    contains,
    eq,
    attr,
    eq_dn,
    in_chain,
    valid_dn,
    valid_fragment,
)


logger = logging.getLogger(__name__)

ConnectionFactory = Callable[[LDAPConfig], Connection]


AUTH_ERRORS = (LDAPBindError, LDAPInvalidCredentialsResult)

# The communication family rather than three of its members: a failed send or a
# response timeout is a connection failure too, and naming members one at a time
# is what let those reach callers labelled query errors.
CONNECTION_ERRORS = (
    LDAPCommunicationError,
    LDAPResponseTimeoutError,
    LDAPMaximumRetriesError,
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

    Specific families first, the base class last. `fallback` is what an
    unrecognised `ldap3` exception becomes, and it follows the site: a bind
    issues no query, so an unknown failure there is a connection problem.
    `str(exc)` is carried across because AD's diagnostic sub-code lives in the
    message."""
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
    is what makes this callable offline and the certificate invariant assertable 
    without a socket."""
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

        The only place this library binds, and so the only place a bind
        rejection can be translated. `_conn` stays `None` on failure, so a
        retry is a fresh attempt rather than a half-open instance."""
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


    def _search(
        self,
        search_filter: str,
        attributes: Sequence[str],
        *,
        base: str | None = None,
        limit: int | None = None,
    ) -> list[dict]:
        """Runs a paged subtree search and returns at most `limit` raw entries.

        The only place this library queries, so a query method added later
        cannot forget to translate. The result loop is inside `translated()`
        because `paged_search` returns a generator: a failure partway through
        arrives during consumption, not at the call.

        `limit` stops consuming that generator rather than trimming a finished
        list, so the pages behind it are never fetched (§8.3)."""
        search_base = self._config.base_dn if base is None else base
        # Debug only: filter values carry names and employee IDs (§7.4).
        logger.debug("search base=%s filter=%s", search_base, search_filter)
        with translated():
            response = self.conn.extend.standard.paged_search(
                search_base=search_base,
                search_filter=search_filter,
                attributes=attributes,
                search_scope=SUBTREE,
                paged_size=self._config.page_size,
                time_limit=self._config.time_limit,
                generator=True,
            )
            # Referrals (searchResRef) are dropped before the cap counts, so
            # they cannot spend it (§8.4).
            entries = (e for e in response if e["type"] == "searchResEntry")
            results = list(islice(entries, limit))
        return results


    def _search_users(
        self,
        search_filter: str,
        *,
        base: str | None = None,
        attributes: Sequence[str] | None = None,
        limit: int | None = None,
    ) -> list[User]:
        entries = self._search(
            search_filter, self._requested_attributes(attributes), base=base, limit=limit
        )
        users = []
        for entry in entries:
            users.append(to_user(entry, self._attrs))
        return users


    def _requested_attributes(self, requested: Sequence[str] | None) -> list[str]:
        """The attribute map's own attributes, plus any the caller asked for.
        Additive rather than a replacement (§8.5)."""
        attributes = self._attrs.fetch_attributes()
        if requested is None:
            return attributes
        return list(dict.fromkeys(attributes + [attr(name) for name in requested]))


    def _name_clause(self, fragment: str) -> str:
        """A fragment matches either name attribute (§8.5)."""
        return any_of(
            contains(self._attrs.name, fragment),
            contains(self._attrs.cn, fragment),
        )


    def _group_clause(self, group_dn: str, transitive: bool) -> str:
        """Membership of one group, optionally through nested groups."""
        if transitive:
            return in_chain(self._attrs.member_of, group_dn)
        return eq_dn(self._attrs.member_of, group_dn)


    def find_users(
        self,
        *,
        employee_id: str | None = None,
        username: str | None = None,
        name_contains: str | None = None,
        cost_center: str | None = None,
        manager_dn: str | None = None,
        group_dn: str | None = None,
        transitive: bool = False,
        include_disabled: bool = False,
        base_dn: str | None = None,
        extra_filter: str | None = None,
        attributes: Sequence[str] | None = None,
        limit: int | None = None,
    ) -> list[User]:
        """Every user matching all of the criteria supplied, as a list (§8.5).

        The criteria are spelled out rather than taken as `**criteria` so that a
        mistyped name raises. `manager_dn` is direct reports only (§8.7)."""
        clauses = [
            USER_OBJECT,
            None if include_disabled else NOT_DISABLED,
            None if employee_id is None else eq(self._attrs.employee_id, employee_id),
            None if username is None else eq(self._attrs.username, username),
            None if name_contains is None else self._name_clause(name_contains),
            None if cost_center is None else eq(self._attrs.cost_center, cost_center),
            None if manager_dn is None else eq_dn(self._attrs.manager, manager_dn),
            None if group_dn is None else self._group_clause(group_dn, transitive),
            # Trusted input by design, and sanity-checked so a typo fails here
            # rather than at the domain controller (§7.2).
            None if extra_filter is None else valid_fragment(extra_filter),
        ]
        return self._search_users(
            all_of(*clauses),
            # The search base is escaped by nothing, so it is validated (§7.2).
            base=None if base_dn is None else valid_dn(base_dn),
            attributes=attributes,
            limit=limit,
        )


    def resolve_user_dn(self, value: str, *, by: str | None = None) -> str: 
        """DN of the single user whose `by` attribute equals `value`.
        `by` defaults to the AttributeMap's username attribute (sAMAccountName).
        Raises NotFoundError on no match and on multiple matches, which it
        names rather than counting: the search stops at the second."""
        attribute = self._attrs.username if by is None else by
        search_filter = all_of(USER_OBJECT, eq(attribute, value))
        entries = self._search(search_filter, [NO_ATTRIBUTES], limit=2)
        if not entries:
            raise NotFoundError(f"No user found with {attribute}={value}")
        if len(entries) > 1:
            matches = ", ".join(entry["dn"] for entry in entries)
            raise NotFoundError(f"More than one user with {attribute}={value}: {matches}")
        return entries[0]["dn"]


    def _reports_of(self, manager_dns: Sequence[str]) -> list[User]:
        """Every user whose manager is one of `manager_dns`, one query per
        `LDAPConfig.batch_size` DNs."""
        found: list[User] = []
        for batch in batched(manager_dns, self._config.batch_size):
            clauses = [eq_dn(self._attrs.manager, dn) for dn in batch]
            found.extend(self._search_users(all_of(USER_OBJECT, any_of(*clauses))))
        return found


    def direct_reports(self, username: str) -> list[User]:
        """The users whose manager is this manager: one hop, one query."""
        return self._reports_of([self.resolve_user_dn(username)])


    def reporting_tree(self, username: str) -> list[User]:
        """Every direct report of this manager, and every direct report of
        those, to any depth."""
        return self._walk_reports(self.resolve_user_dn(username))


    def _walk_reports(self, root_dn: str) -> list[User]:
        """Breadth-first from `root_dn`, one level at a time, until a level
        yields nobody new."""
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

