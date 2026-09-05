import ssl

from collections.abc import Sequence

from ldap3 import (
    SIMPLE, 
    NONE,
    AUTO_BIND_NO_TLS,
    SUBTREE,
    Connection,
    Server,
    Tls
)

from adsearch.config import LDAPConfig
from adsearch.models import DEFAULT_ATTRIBUTES, AttributeMap, User, to_user
from adsearch.filters import USER_OBJECT, eq, all_of


class LDAPSearch:
    def __init__(self, config: LDAPConfig, attrs: AttributeMap = DEFAULT_ATTRIBUTES) -> None:
        self._conn: Connection | None = None
        self._config = config
        self._attrs = attrs

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
        """Runs a paged subtree search and returns raw entries."""
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

    def find_users(self, employee_id: str) -> list[User]:
        """Look up users by employee ID. Returns a list of User objects."""
        search_filter = all_of(USER_OBJECT, eq(self._attrs.employee_id, employee_id))
        entries = self._search(search_filter, self._attrs.fetch_attributes())
        users = []
        for entry in entries:
            users.append(to_user(entry, self._attrs))
        return users


#   We'll re-implement this later after building out find_users more
#    def by_employee_id(self, employee_id: str) -> list[User]:
#        """Look up a list of users by employee ID""
#        return self.find_users(employee_id)

