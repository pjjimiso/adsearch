import re

from ldap3.utils.conv import escape_filter_chars
from ldap3.utils.dn import parse_dn
from ldap3.core.exceptions import LDAPInvalidDnError

from adsearch.errors import LDAPQueryError


USER_OBJECT = "(&(objectCategory=person)(objectClass=user))"
IN_CHAIN = "1.2.840.113556.1.4.1941"   # LDAP_MATCHING_RULE_IN_CHAIN OID
_ATTRIBUTE_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9-]*$")


def esc(value: str) -> str: 
    """The only place escape_filter_chars is called; everything else goes through this."""
    return escape_filter_chars(value)


def is_valid_attr(attribute: str) -> bool:
    """Validates whether the attribute matches the accepted regex pattern."""
    return _ATTRIBUTE_PATTERN.fullmatch(attribute) is not None


def eq(attribute: str, value: str) -> str:
    """Returns an equality filter for the given valid attribute and escaped value."""
    if not is_valid_attr(attribute):
        raise LDAPQueryError(f"Invalid attribute name: {attribute}")
    return f"({attribute}={esc(value)})"


def all_of(*clauses: str | None) -> str:
    """Returns an AND filter for the given clauses, ignoring None values."""
    clauses = [c for c in clauses if c is not None]
    if not clauses:
        raise LDAPQueryError("Invalid AND filter: no clauses provided")
    if len(clauses) == 1:
        return clauses[0]
    return f"(&{''.join(clauses)})"


def valid_dn(dn: str) -> str:
    """Return dn unchanged if it parses as a DN; raise LDAPQueryError if not.
    Wraps ldap3's parse_dn."""
    try:
        parse_dn(dn)
    except LDAPInvalidDnError as e:
        raise LDAPQueryError(f"Invalid DN: {dn}") from e
    return dn


def eq_dn(attribute: str, dn: str) -> str:
    """(attribute=dn) - the DN validated, then escaped as a filter value."""
    # TODO
    return ""


def in_chain(attribute: str, dn: str) -> str:
    """(attribute:1.2.840.113556.1.4.1941:=dn) - transitive match down the chain."""
    # TODO
    return ""

