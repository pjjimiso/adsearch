import pytest

from adsearch.errors import LDAPQueryError
from adsearch.filters import (
    BIT_AND,
    attr,
    IN_CHAIN,
    NOT_DISABLED,
    USER_OBJECT,
    contains,
    esc,
    is_valid_attr,
    eq,
    all_of,
    any_of,
    none_of,
    valid_dn,
    valid_fragment,
    eq_dn,
    in_chain,
)


def test_esc_filter():
    assert esc('a*b') == 'a\\2ab'
    assert esc('x)(objectClass=*') == 'x\\29\\28objectClass=\\2a'


def test_attr_filter():
    assert is_valid_attr('cn')
    assert not is_valid_attr('cn*')
    assert not is_valid_attr('cn\n')
    assert not is_valid_attr('')


def test_attr_raises_on_a_name_that_is_not_one():
    """DESIGN §13. Escaping covers values and not names, so the name is the
    second injection point and gets its own allowlist."""
    assert attr('cn') == 'cn'
    with pytest.raises(LDAPQueryError):
        attr('cn)(x')
    with pytest.raises(LDAPQueryError):
        attr('')


def test_eq_filter():
    assert eq('cn', 'Billy Bob') == '(cn=Billy Bob)'
    assert eq('employeeID', '*') == r'(employeeID=\2a)'
    with pytest.raises(LDAPQueryError):
        eq('', 'x')


def test_all_of_filter():
    assert all_of(eq('cn', 'Billy Bob'), eq('sn', 'Smith')) == '(&(cn=Billy Bob)(sn=Smith))'
    assert all_of(eq('cn', 'Billy Bob'), None) == '(cn=Billy Bob)'
    assert all_of(USER_OBJECT, eq('empID', '123')) == '(&(&(objectCategory=person)(objectClass=user))(empID=123))'
    with pytest.raises(LDAPQueryError):
        all_of()
    with pytest.raises(LDAPQueryError):
        all_of(None)
    with pytest.raises(LDAPQueryError):
        all_of(None, None)


def test_any_of_filter():
    assert any_of(eq('cn', 'Billy Bob'), eq('sn', 'Smith')) == '(|(cn=Billy Bob)(sn=Smith))'
    assert any_of(eq('cn', 'Billy Bob'), None) == '(cn=Billy Bob)'
    assert any_of(USER_OBJECT, eq('empID', '123')) == '(|(&(objectCategory=person)(objectClass=user))(empID=123))'
    with pytest.raises(LDAPQueryError):
        any_of()
    with pytest.raises(LDAPQueryError):
        any_of(None)
    with pytest.raises(LDAPQueryError):
        any_of(None, None)


def test_valid_dn():
    assert valid_dn('CN=John Doe,OU=Users,DC=example,DC=com')
    assert valid_dn('CN=Jane Smith,OU=Employees,DC=company,DC=org')


def test_invalid_empty_dn():
    with pytest.raises(LDAPQueryError):
        valid_dn('')


def test_invalid_dn():
    with pytest.raises(LDAPQueryError):
        valid_dn('not a dn')
    with pytest.raises(LDAPQueryError):
        valid_dn('CN=x)(objectClass=*')


def test_eq_dn():
    manager = eq_dn('manager', valid_dn('CN=John Doe,OU=Users,DC=example,DC=com'))
    assert manager == '(manager=CN=John Doe,OU=Users,DC=example,DC=com)'


def test_eq_dn_escapes_metacharacters():
    """DESIGN §13: eq_dn escapes a DN containing parentheses rather than merely validating it."""
    assert eq_dn('manager', 'CN=Team (West),DC=x,DC=com') == r'(manager=CN=Team \28West\29,DC=x,DC=com)'


def test_in_chain():
    chain_filter = in_chain('manager', 'CN=John Doe,OU=Users,DC=example,DC=com')
    assert chain_filter == f'(manager:{IN_CHAIN}:=CN=John Doe,OU=Users,DC=example,DC=com)'


def test_in_chain_invalid_attr():
    with pytest.raises(LDAPQueryError):
        in_chain('invalid*', "DC=com")


def test_contains_wraps_the_wildcards_around_an_escaped_value():
    """DESIGN §7.2: the wildcards are ours, the value is escaped."""
    assert contains('displayName', 'Bob') == '(displayName=*Bob*)'
    assert contains('displayName', '*') == r'(displayName=*\2a*)'
    with pytest.raises(LDAPQueryError):
        contains('display*Name', 'Bob')


def test_none_of_negates_a_clause():
    assert none_of(eq('cn', 'Billy Bob')) == '(!(cn=Billy Bob))'


def test_not_disabled_reads_the_account_control_bit():
    """The user account control attribute is the right one for enabled state,
    read with the bitwise matching rule — and the wrong one for worker type."""
    assert NOT_DISABLED == f'(!(userAccountControl:{BIT_AND}:=2))'


def test_valid_fragment_accepts_a_well_formed_filter():
    assert valid_fragment('(title=Director)') == '(title=Director)'
    assert valid_fragment('(|(a=1)(b=2))') == '(|(a=1)(b=2))'


def test_valid_fragment_rejects_a_typo_locally():
    """DESIGN §7.2: extra_filter is a raw passthrough, sanity-checked so that a
    typo fails here rather than at the domain controller."""
    for typo in ('title=Director', '(title=Director', '(a=1))(b=2', '', '()'):
        with pytest.raises(LDAPQueryError):
            valid_fragment(typo)
