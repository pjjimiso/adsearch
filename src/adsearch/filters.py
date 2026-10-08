import re

from ldap3.utils.conv import escape_filter_chars
from ldap3.utils.dn import parse_dn
from ldap3.core.exceptions import LDAPInvalidDnError

from adsearch.errors import LDAPQueryError


USER_OBJECT = "(&(objectCategory=person)(objectClass=user))"
GROUP_OBJECT = "(objectCategory=group)"
IN_CHAIN = "1.2.840.113556.1.4.1941"   # LDAP_MATCHING_RULE_IN_CHAIN OID
BIT_AND = "1.2.840.113556.1.4.803"     # LDAP_MATCHING_RULE_BIT_AND OID
ACCOUNTDISABLE = 2                     # the userAccountControl bit for a disabled account
_ATTRIBUTE_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9-]*$")


def esc(value: str) -> str: 
    """The only place escape_filter_chars is called; everything else goes through this."""
    return escape_filter_chars(value)


def is_valid_attr(attribute: str) -> bool:
    """Validates whether the attribute matches the accepted regex pattern."""
    return _ATTRIBUTE_PATTERN.fullmatch(attribute) is not None


def attr(attribute: str) -> str:
    """Return an attribute name unchanged if it is one; raise LDAPQueryError if
    not. Escaping covers values and not names, so names are checked here (§7.2)."""
    if not is_valid_attr(attribute):
        raise LDAPQueryError(f"Invalid attribute name: {attribute}")
    return attribute


def eq(attribute: str, value: str) -> str:
    """Returns an equality filter for the given valid attribute and escaped value."""
    return f"({attr(attribute)}={esc(value)})"


def contains(attribute: str, value: str) -> str:
    """Returns a substring filter for the given valid attribute. The wildcards
    are this library's; the value is escaped, so a caller never supplies one."""
    return f"({attr(attribute)}=*{esc(value)}*)"


def none_of(clause: str) -> str:
    """Returns the negation of a clause, translated into (!...)."""
    return f"(!{clause})"


# Enabled state is the one question userAccountControl answers correctly, and it
# is one bit inside an integer rather than the whole value (§8.5).
NOT_DISABLED = none_of(f"(userAccountControl:{BIT_AND}:={ACCOUNTDISABLE})")


def all_of(*clauses: str | None) -> str:
    """Returns an AND filter translated into (&...) for the given clauses, 
    skipping None values. Raises LDAPQueryError if no clauses are provided,
    empty (&) is not a valid filter"""
    valid_clauses = [c for c in clauses if c is not None]
    if not valid_clauses:
        raise LDAPQueryError("Invalid AND filter: no clauses provided")
    if len(valid_clauses) == 1:
        return valid_clauses[0]
    return f"(&{''.join(valid_clauses)})"


def any_of(*clauses: str | None) -> str: 
    """Returns an OR filter translated into (|...) for the given clauses, 
    skipping None values. Raises LDAPQueryError if no clauses are provided, 
    empty (|) is not valid"""
    valid_clauses = [c for c in clauses if c is not None]
    if not valid_clauses:
        raise LDAPQueryError("Invalid OR filter: no clauses provided")
    if len(valid_clauses) == 1:
        return valid_clauses[0]
    return f"(|{''.join(valid_clauses)})"


def valid_dn(dn: str) -> str:
    """Return dn unchanged if it parses as a DN; raise LDAPQueryError if not."""
    try:
        parse_dn(dn)
    except LDAPInvalidDnError as e:
        raise LDAPQueryError(f"Invalid DN: {dn}") from e
    return dn


def is_dn(value: str) -> bool:
    """Whether a value parses as a DN, asked rather than asserted (§8.6)."""
    try:
        parse_dn(value)
    except LDAPInvalidDnError:
        return False
    return True


def eq_dn(attribute: str, dn: str) -> str:
    """(attribute=dn) - the DN validated, then escaped as a filter value."""
    return eq(attribute, valid_dn(dn))


def valid_fragment(fragment: str) -> str:
    """Return a raw filter fragment unchanged if it is shaped like one single
    clause; raise LDAPQueryError if not. A shape check, not a parse (§7.2)."""
    if not fragment.startswith("(") or not fragment.endswith(")"):
        raise LDAPQueryError(f"Filter fragment must be parenthesised: {fragment}")
    if len(fragment) < 3:
        raise LDAPQueryError(f"Empty filter fragment: {fragment}")
    depth = 0
    for position, char in enumerate(fragment):
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            # A fragment closing before its end is two filters, and would be
            # ANDed into the query as one clause with the rest dangling.
            if depth == 0 and position != len(fragment) - 1:
                raise LDAPQueryError(f"Filter fragment is not a single clause: {fragment}")
    if depth != 0:
        raise LDAPQueryError(f"Unbalanced parentheses in filter fragment: {fragment}")
    return fragment


def in_chain(attribute: str, dn: str) -> str:
    """(attribute:1.2.840.113556.1.4.1941:=dn) - transitive match down the chain."""
    return f"({attr(attribute)}:{IN_CHAIN}:={esc(valid_dn(dn))})"

