import ssl

from ldap3 import Connection, Server, Tls, SIMPLE, NONE, AUTO_BIND_NO_TLS, SUBTREE
from collections.abc import Sequence

from adsearch.config import LDAPConfig
from adsearch.models import User
from adsearch.filters import USER_OBJECT, eq, all_of


DEFAULT_USER_ATTRIBUTES = (
  "distinguishedName", "sAMAccountName", "displayName", "mail",
  "employeeID", "department", "title", "manager", "userAccountControl",
)


class LDAPSearch:
    def __init__(self, config: LDAPConfig) -> None:
        self._conn: Connection | None = None
        self._config = config


    @property
    def conn(self) -> Connection:
        if self._conn is None:
            if self._config.validate_cert:
                cert_validation = ssl.CERT_REQUIRED
            else:
                cert_validation = ssl.CERT_NONE

            tls = Tls(
                validate = cert_validation,
                ca_certs_file = self._config.ca_certs_file
            )
            server = Server(
                host = self._config.server,
                use_ssl = self._config.use_ssl,
                tls = tls,
                get_info = NONE,
                connect_timeout = self._config.connect_timeout,
            )
            connection = Connection(
                server,
                user = self._config.bind_user,
                password = self._config.bind_password,
                authentication = SIMPLE,
                auto_bind = AUTO_BIND_NO_TLS,
                raise_exceptions = True,
                receive_timeout = self._config.receive_timeout,
                auto_referrals = False,
                auto_range = True,
            )
            self._conn = connection
        return self._conn


    def _search(self, search_filter: str, attributes: Sequence[str]) -> list[dict]:
        """Runs a paged subtree search and returns raw entries.
        A Sequence is returned because DEFAULT_USER_ATTRIBUTES needs to be an immutable tuple"""
        results = []
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


    def find_users(self, employee_id: str) -> list[dict]:
        """Look up users by employee ID. Returns a list of User objects."""
        search_filter = all_of(USER_OBJECT, eq("employeeID", employee_id))
        return self._search(search_filter, DEFAULT_USER_ATTRIBUTES)


    def by_employee_id(self, employee_id: str) -> User | None:
        """Look up a single user by employee ID. Returns None if not found"""
        users = self.find_users(employee_id)
        return users[0] if users else None

