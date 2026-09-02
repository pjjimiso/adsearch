import ssl

from ldap3 import Connection, Server, Tls, SIMPLE, NONE, AUTO_BIND_NO_TLS

from adsearch.config import LDAPConfig
from adsearch.models import User


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


    def find_users(self, employee_id: str) -> list[User] | None:
        """Look up users by employee ID. Returns a single User object."""
        # TODO - implement LDAP search logic here
        pass


    def by_employee_id(self, employee_id: str) -> User | None:
        """Look up a single user by employee ID. Returns None if not found"""
        users = self.find_users(employee_id)
        return users[0] if users else None

