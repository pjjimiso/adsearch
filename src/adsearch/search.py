import logging
import ssl

from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from itertools import batched, islice
from typing import Literal

from ldap3 import (
    SIMPLE,
    NONE,
    ALL,
    ALL_ATTRIBUTES,
    ALL_OPERATIONAL_ATTRIBUTES,
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
    GROUP_OBJECT,
    NOT_DISABLED,
    USER_OBJECT,
    all_of,
    any_of,
    contains,
    eq,
    attr,
    eq_dn,
    in_chain,
    is_dn,
    valid_dn,
    valid_fragment,
)


logger = logging.getLogger(__name__)

ConnectionFactory = Callable[[LDAPConfig], Connection]
GetInfo = Literal["NO_INFO", "DSA", "SCHEMA", "ALL"]


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


def build_server(config: LDAPConfig, *, get_info: GetInfo = NONE) -> Server:
    """The transport configuration, assembled without opening anything.

    `Server` resolves addresses at open time rather than at construction, which
    is what makes this callable offline and the certificate invariant assertable
    without a socket.

    `get_info` defaults to `NONE`: `ALL` pulls the entire AD schema on every
    bind, so only `server_info`'s throwaway connection asks for it (§8.2)."""
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
        get_info = get_info,
        connect_timeout = config.connect_timeout,
    )


def _unbind_quietly(conn: Connection) -> None:
    """Swallow a failed unbind during teardown (§8.1): an exception escaping
    here would replace whatever was already propagating out of the caller."""
    try:
        conn.unbind()
    except Exception:
        pass


def open_connection(config: LDAPConfig, *, get_info: GetInfo = NONE) -> Connection:
    """Build and bind a connection. The only place this library opens a socket."""
    return Connection(
        build_server(config, get_info=get_info),
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
        schema_connect: ConnectionFactory | None = None,
    ) -> None:
        self._conn: Connection | None = None
        self._config = config
        self._attrs = attrs
        self._connect: ConnectionFactory = open_connection if connect is None else connect
        # A second, independent substitution point for §9's throwaway
        # `get_info=ALL` connection, so pulling the schema can never happen
        # over the same connection an ordinary bind opens.
        self._schema_connect: ConnectionFactory = (
            (lambda cfg: open_connection(cfg, get_info=ALL))
            if schema_connect is None
            else schema_connect
        )


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
            _unbind_quietly(conn)


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


    def _find_one(
        self,
        search_filter: str,
        attributes: Sequence[str],
        *,
        noun: str,
        criterion: str,
        base: str | None = None,
    ) -> dict:
        """The one entry `search_filter` matches, carrying `attributes`.

        Raises NotFoundError on no match and on more than one, which it names
        rather than counting: the search stops at the second (§6.3). Shared by
        every operation that promises exactly one result, so a silent pick
        among several matches can never reach a caller dressed up as the one
        it asked for."""
        entries = self._search(search_filter, attributes, base=base, limit=2)
        if not entries:
            raise NotFoundError(f"No {noun} found with {criterion}")
        if len(entries) > 1:
            matches = ", ".join(entry["dn"] for entry in entries)
            raise NotFoundError(f"More than one {noun} with {criterion}: {matches}")
        return entries[0]


    def _resolve_dn(
        self,
        search_filter: str,
        *,
        noun: str,
        criterion: str,
        base: str | None = None,
    ) -> str:
        """DN of the one entry `search_filter` matches (§6.3)."""
        return self._find_one(
            search_filter, [NO_ATTRIBUTES], noun=noun, criterion=criterion, base=base
        )["dn"]


    def server_info(self) -> str:
        """Naming contexts and supported controls, read from a throwaway
        `get_info=ALL` connection rather than `conn` (§9): the first thing to
        run against a new deployment, since it proves bind and TLS work
        before any query semantics are in question."""
        with translated(LDAPConnectionError):
            conn = self._schema_connect(self._config)
        try:
            return str(conn.server.info)
        finally:
            _unbind_quietly(conn)


    def describe_user(self, value: str, *, by: str = "sAMAccountName") -> dict[str, object]:
        """Every populated attribute of the one user whose `by` attribute
        equals `value` (§9) — real data, rather than the schema's list of what
        AD merely defines.

        `by` defaults to `sAMAccountName`, reliable everywhere, so a site's
        real attribute names can be discovered before an `AttributeMap` names
        them. Raises NotFoundError on zero matches and on more than one: `by`
        pointed at a one-to-many attribute — an employee ID, say — makes a
        silent pick a live risk, not a theoretical one, and a wrong pick here
        would show one person's data labelled as another's (§6.3)."""
        entry = self._find_one(
            all_of(USER_OBJECT, eq(by, value)),
            [ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES],
            noun="user",
            criterion=f"{by}={value}",
        )
        return {"dn": entry["dn"], **entry["attributes"]}


    def resolve_user_dn(self, value: str, *, by: str | None = None) -> str:
        """DN of the single user whose `by` attribute equals `value`.
        `by` defaults to the AttributeMap's username attribute (sAMAccountName).
        Raises NotFoundError on no match and on multiple matches."""
        attribute = self._attrs.username if by is None else by
        return self._resolve_dn(
            all_of(USER_OBJECT, eq(attribute, value)),
            noun="user",
            criterion=f"{attribute}={value}",
        )


    def resolve_group_dn(self, group: str) -> str:
        """DN of one group, named either by DN or by common name.

        A name is searched for under `LDAPConfig.group_search_base`; raises
        NotFoundError on no match and on an ambiguous one (§8.6)."""
        if is_dn(group):
            return group
        return self._resolve_dn(
            all_of(GROUP_OBJECT, eq(self._attrs.cn, group)),
            noun="group",
            criterion=f"{self._attrs.cn}={group}",
            base=self._config.group_search_base,
        )


    def by_group(
        self,
        group: str,
        *,
        transitive: bool = True,
        include_disabled: bool = False,
        attributes: Sequence[str] | None = None,
    ) -> list[User]:
        """Every user in `group`, named by DN or by common name, including
        anyone holding it through a nested group unless `transitive=False` (§8.8).

        Membership implied by `primaryGroupID` is not reflected (§14)."""
        return self.find_users(
            group_dn=self.resolve_group_dn(group),
            transitive=transitive,
            include_disabled=include_disabled,
            attributes=attributes,
        )


    def _reports_of(
        self, manager_dns: Sequence[str], *, attributes: Sequence[str] | None = None
    ) -> list[User]:
        """Every user whose manager is one of `manager_dns`, one query per
        `LDAPConfig.batch_size` DNs."""
        found: list[User] = []
        for batch in batched(manager_dns, self._config.batch_size):
            clauses = [eq_dn(self._attrs.manager, dn) for dn in batch]
            found.extend(
                self._search_users(all_of(USER_OBJECT, any_of(*clauses)), attributes=attributes)
            )
        return found


    def direct_reports(self, username: str, *, attributes: Sequence[str] | None = None) -> list[User]:
        """The users whose manager is this manager: one hop, one query."""
        return self._reports_of([self.resolve_user_dn(username)], attributes=attributes)


    def reporting_tree(self, username: str, *, attributes: Sequence[str] | None = None) -> list[User]:
        """Every direct report of this manager, and every direct report of
        those, to any depth."""
        return self._walk_reports(self.resolve_user_dn(username), attributes=attributes)


    def _walk_reports(
        self, root_dn: str, *, attributes: Sequence[str] | None = None
    ) -> list[User]:
        """Breadth-first from `root_dn`, one level at a time, until a level
        yields nobody new."""
        seen = {root_dn.casefold()}
        tree: list[User] = []
        level = [root_dn]

        while level:
            new: list[User] = []
            for report in self._reports_of(level, attributes=attributes):
                if report["dn"].casefold() in seen:
                    continue
                seen.add(report["dn"].casefold())
                new.append(report)
            tree.extend(new)
            level = [report["dn"] for report in new]

        return tree

