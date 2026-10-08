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


def test_the_group_search_base_falls_back_to_the_base_dn():
    """DESIGN §5.1: a site that keeps its groups in the same tree as its users
    configures nothing, rather than repeating the base DN."""
    config = LDAPConfig(server="ldaps://x", base_dn="DC=x,DC=com")
    assert config.group_search_base == "DC=x,DC=com"


def test_a_configured_group_base_dn_is_the_group_search_base():
    config = LDAPConfig(
        server="ldaps://x", base_dn="DC=x,DC=com", group_base_dn="OU=Groups,DC=x,DC=com"
    )
    assert config.group_search_base == "OU=Groups,DC=x,DC=com"


def test_the_group_base_dn_comes_from_the_environment():
    config = LDAPConfig.from_env({
        "ADSEARCH_SERVER": "ldaps://x",
        "ADSEARCH_BASE_DN": "DC=x,DC=com",
        "ADSEARCH_GROUP_BASE_DN": "OU=Groups,DC=x,DC=com",
    })
    assert config.group_search_base == "OU=Groups,DC=x,DC=com"
