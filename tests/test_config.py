import pytest

from adsearch.config import LDAPConfig
from adsearch.errors import LDAPConfigError


def test_empty_server():
    with pytest.raises(LDAPConfigError):
        LDAPConfig(server="", base_dn="DC=x,DC=com")


def test_empty_base_dn():
    with pytest.raises(LDAPConfigError):
        LDAPConfig(server="ldaps://x", base_dn="")


def test_cleartext_bind_without_transport_security_raises():
    """DESIGN §13: a misconfiguration must not silently put a bind password on
    the wire."""
    with pytest.raises(LDAPConfigError):
        LDAPConfig(server="ldap://x", base_dn="DC=x,DC=com", bind_password="password123", use_ssl=False)


def test_password_not_in_repr():
    config = LDAPConfig(server="ldaps://x", base_dn='DC=x,DC=com', bind_password='password123')
    assert 'password123' not in repr(config), "bind_password should not be in the repr output"


def test_empty_env():
    with pytest.raises(LDAPConfigError):
        LDAPConfig.from_env({})
