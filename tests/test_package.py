"""The public surface promised by DESIGN.md §4.1, and the package-level
logging setup that keeps the library silent until a consumer asks (§7.4)."""

import logging

import adsearch
from adsearch import filters


def test_root_exports_the_full_public_surface():
    expected = {
        "LDAPSearch",
        "LDAPConfig",
        "AttributeMap",
        "User",
        "LDAPSearchError",
        "LDAPConfigError",
        "LDAPAuthError",
        "LDAPConnectionError",
        "LDAPQueryError",
        "NotFoundError",
    }
    assert expected <= set(adsearch.__all__)
    for name in expected:
        assert hasattr(adsearch, name)


def test_filter_helpers_are_not_promoted_to_the_root():
    assert not hasattr(adsearch, "eq")
    assert not hasattr(adsearch, "all_of")
    assert filters.eq  # still importable from its own module


def test_package_root_attaches_a_null_handler():
    handlers = logging.getLogger("adsearch").handlers
    assert any(isinstance(h, logging.NullHandler) for h in handlers)
