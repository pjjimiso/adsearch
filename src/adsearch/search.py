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


    def _search(self, search_filter: str, attributes: Sequence[str]) -> list[dict]:
        """Runs a paged subtree search and returns raw entries.

        The only place this library queries, so a query method added later
        cannot forget to translate. The result loop is inside `translated()`
        because `paged_search` returns a generator: a failure partway through
        arrives during consumption, not at the call."""
        # Debug only: filter values carry names and employee IDs (§7.4).
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


#   We'll re-implement this later after building out find_users more
#    def by_employee_id(self, employee_id: str) -> list[Userg:
#        """Look up a list of users by employee ID""
#        return self.find_users(employee_id)

