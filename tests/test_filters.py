import pytest

from adsearch.errors import LDAPQueryError
from adsearch.filters import (
    USER_OBJECT,
    IN_CHAIN,
    esc,
    is_valid_attr,
    eq,
    all_of,
    any_of,
    valid_dn,
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
