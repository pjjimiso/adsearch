import ssl

from collections.abc import Sequence
from itertools import batched
from dataclasses import replace

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

from adsearch.config import LDAPConfig
from adsearch.models import DEFAULT_ATTRIBUTES, AttributeMap, User, to_user
from adsearch.errors import NotFoundError
from adsearch.filters import (
    USER_OBJECT, 
    eq, 
    all_of,
    any_of,
    eq_dn,
    in_chain,
)



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


    def find_reports_in_chain(self, dn: str, *, recursive: bool = False) -> list[User]:
        """Returns a list of users in the manager's reporting tree using Active Directory's 
        LDAP_MATCHING_RULE_IN_CHAIN OID"""
        attr_clause = in_chain(self._attrs.manager, dn) if recursive else eq_dn(self._attrs.manager, dn)
        search_filter = all_of(USER_OBJECT, attr_clause)
        return self._search_users(search_filter)




    def find_reports(self, dn: str, *, recursive: bool = False) -> list[User]:
        """Find all users who reports to the given manager. Non-recursive returns
        direct reports only, while recursive returns the entire reporting tree"""
        reports = self._search_users(all_of(USER_OBJECT, eq_dn(self._attrs.manager, dn)))
        if recursive is False: 
            return reports

        all_reports = reports.copy()
        seen = {dn}
        current_level = [r["dn"] for r in reports]
        seen.update(current_level)

        i = 0
        while current_level:
            print(f"DEBUG: Level {i}: found {len(current_level)} reports...")
            found = []
            for batch in batched(current_level, self._config.batch_size):
                print("\tDEBUG: querying next batch of 100 reports...")
                clauses  = [eq_dn(self._attrs.manager, dn) for dn in batch]
                found.extend(self._search_users(all_of(USER_OBJECT, any_of(*clauses))))
                print("\tDEBUG: batch finished.")
            new = [r for r in found if r["dn"] not in seen]
            seen.update(r["dn"] for r in new)
            all_reports.extend(new)
            current_level = [r["dn"] for r in new]
            i += 1

        return all_reports


    def by_manager(self, username: str, *, recursive: bool = False) -> list[User]:
        """A wrapper around find_reports that returns a list of users reporting to
        the specified manager by manager's username."""
        dn = self.resolve_user_dn(username)
        return self.find_reports(dn, recursive=recursive)


    def by_manager_in_chain(self, username: str, *, recursive: bool = False) -> list[User]:
        """A wrapper around find_reports_in_chain that returns a list of users reporting to
        the specified manager using LDAP_MATCHING_RULE_IN_CHAIN."""
        dn = self.resolve_user_dn(username)
        return self.find_reports_in_chain(dn, recursive=recursive)


#   We'll re-implement this later after building out find_users more
#    def by_employee_id(self, employee_id: str) -> list[Userg:
#        """Look up a list of users by employee ID""
#        return self.find_users(employee_id)

