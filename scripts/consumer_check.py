"""A consumer of the *installed* `adsearch`, run and type-checked from outside
the repository (#14).

This script never opens a socket. It exists to answer three questions that only
an installed package can answer, and that the repo's own test suite cannot:

1. Does `import adsearch` resolve to site-packages rather than a stray `src`
   directory dropped into it by a build-backend misconfiguration?
2. Did `py.typed` survive the build? Without it a type checker must treat every
   call as `Any`, and the library's annotations are worthless to a consumer.
3. Does the public surface `__all__` promises actually import?

`scripts/verify_packaging.sh` runs it and type-checks it; run on its own it
checks only (1) and (3), since (2) is a question for pyright rather than for
the interpreter.
"""

from __future__ import annotations

import importlib.util
import sys

from pathlib import Path
from typing import assert_type

import adsearch

from adsearch import (
    AttributeMap,
    LDAPAuthError,
    LDAPConfig,
    LDAPConfigError,
    LDAPConnectionError,
    LDAPQueryError,
    LDAPSearch,
    LDAPSearchError,
    NotFoundError,
    User,
)


def _type_surface(ad: LDAPSearch, config: LDAPConfig) -> None:
    """Never called: pyright checks this body, the interpreter only compiles it.

    Every `assert_type` here fails if the installed package lost `py.typed`,
    because an untyped import makes each of these expressions `Any` — which is
    the whole point of checking a consumer script rather than the source tree.
    The calls stay inside an uncalled function so that asserting a return type
    costs no connection."""
    assert_type(ad.find_users(employee_id="12345678"), list[User])
    assert_type(ad.by_group("Some Group Name"), list[User])
    assert_type(ad.direct_reports("jdoe"), list[User])
    assert_type(ad.reporting_tree("jdoe"), list[User])
    assert_type(ad.resolve_user_dn("jdoe"), str)
    assert_type(ad.resolve_group_dn("Some Group Name"), str)
    assert_type(ad.describe_user("jdoe"), dict[str, object])
    assert_type(ad.server_info(), str)
    assert_type(config.group_search_base, str)
    assert_type(AttributeMap().fetch_attributes(), list[str])

    for person in ad.by_group("Some Group Name"):
        # A `User` is a TypedDict, so a key lookup is typed per key rather
        # than collapsing to one value type.
        assert_type(person["dn"], str)
        assert_type(person["email"], str | None)
        assert_type(person["attributes"], dict[str, object])


def check_import_is_not_the_source_tree() -> None:
    """`import adsearch` has to come from site-packages.

    A flat layout, or a wheel built without `sources = ["src"]`, both pass the
    repo's own tests and fail here — which is why this runs from a directory
    that is not the repo root."""
    location = Path(adsearch.__file__).resolve()
    assert "site-packages" in location.parts, f"imported from {location}, not site-packages"

    # The failure mode `sources = ["src"]` prevents: a wheel shipping
    # `src/adsearch/…` drops a generic top-level `src` into site-packages.
    leaked = importlib.util.find_spec("src")
    assert leaked is None, f"the wheel leaked a top-level `src` package: {leaked}"


def check_py_typed_shipped() -> None:
    """PEP 561's marker file, which the wheel has to include explicitly."""
    marker = Path(adsearch.__file__).resolve().parent / "py.typed"
    assert marker.is_file(), f"py.typed missing from the installed package at {marker}"


def check_public_surface_imports() -> None:
    """Every name `__all__` promises, imported rather than merely listed."""
    promised = {
        "LDAPSearch": LDAPSearch,
        "LDAPConfig": LDAPConfig,
        "AttributeMap": AttributeMap,
        "User": User,
        "LDAPSearchError": LDAPSearchError,
        "LDAPConfigError": LDAPConfigError,
        "LDAPAuthError": LDAPAuthError,
        "LDAPConnectionError": LDAPConnectionError,
        "LDAPQueryError": LDAPQueryError,
        "NotFoundError": NotFoundError,
    }
    assert set(promised) == set(adsearch.__all__), (
        f"__all__ is {sorted(adsearch.__all__)}, this script imports {sorted(promised)}"
    )


def check_the_library_works_offline() -> None:
    """The work a consumer can do before a socket is opened, which is where a
    newer-only syntax error on the declared Python floor would surface."""
    config = LDAPConfig(server="ldaps://dc.example.com", base_dn="DC=example,DC=com")
    assert config.group_search_base == "DC=example,DC=com"

    grouped = LDAPConfig(
        server="ldaps://dc.example.com",
        base_dn="DC=example,DC=com",
        group_base_dn="OU=Groups,DC=example,DC=com",
    )
    assert grouped.group_search_base == "OU=Groups,DC=example,DC=com"

    try:
        LDAPConfig(server="", base_dn="DC=example,DC=com")
    except LDAPConfigError:
        pass
    else:
        raise AssertionError("an empty server should raise LDAPConfigError")

    schema = AttributeMap(cost_center="extensionAttribute3", extra=("employeeType",))
    requested = schema.fetch_attributes()
    assert "extensionAttribute3" in requested
    assert "employeeType" in requested
    assert len(requested) == len(set(requested)), f"duplicate attributes requested: {requested}"

    # Constructing one opens nothing; the connection is bound on first use.
    LDAPSearch(config, schema)


def main() -> int:
    check_import_is_not_the_source_tree()
    check_py_typed_shipped()
    check_public_surface_imports()
    check_the_library_works_offline()
    print(f"adsearch imported from {Path(adsearch.__file__).resolve().parent}")
    print(f"python {sys.version.split()[0]} — consumer checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
