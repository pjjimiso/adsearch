"""A consumer of the *installed* `adsearch`, run and type-checked from outside
the repository (DESIGN §11, #14).

Three questions only an installed package can answer, and that the repo's own
suite cannot because it imports the source tree: does `import adsearch` resolve
to site-packages rather than a stray `src` directory, did `py.typed` survive
the build, and do the names `__all__` promises actually import — which the
import below settles by failing outright.

Everything else the installed package should do is covered by running the real
suite against the same ref, which `scripts/verify_packaging.sh` does in its
fourth step. Nothing here opens a socket.
"""

from __future__ import annotations

import importlib.util
import sys

from pathlib import Path
from typing import assert_type

import adsearch

from adsearch import (  # noqa: F401 — importing the promised surface IS the check
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

    Without `py.typed` every expression here is `Any` and every `assert_type`
    fails. The calls sit in an uncalled function so asserting a return type
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

    for person in ad.by_group("Some Group Name"):
        # A `User` is a TypedDict, so each key is typed individually rather
        # than collapsing to one value type.
        assert_type(person["dn"], str)
        assert_type(person["email"], str | None)
        assert_type(person["attributes"], dict[str, object])


def check_import_is_not_the_source_tree() -> None:
    """`import adsearch` has to come from site-packages, with no `src` beside it."""
    location = Path(adsearch.__file__).resolve()
    assert "site-packages" in location.parts, f"imported from {location}, not site-packages"

    # The failure `sources = ["src"]` prevents: a wheel shipping
    # `src/adsearch/…` drops a generic top-level `src` into site-packages.
    leaked = importlib.util.find_spec("src")
    assert leaked is None, f"the wheel leaked a top-level `src` package: {leaked}"


def check_py_typed_shipped() -> None:
    """PEP 561's marker file, which the wheel has to include explicitly."""
    marker = Path(adsearch.__file__).resolve().parent / "py.typed"
    assert marker.is_file(), f"py.typed missing from the installed package at {marker}"


def main() -> int:
    check_import_is_not_the_source_tree()
    check_py_typed_shipped()
    # Constructing one opens nothing, and is the least a consumer must be able
    # to do on the declared Python floor.
    LDAPSearch(
        LDAPConfig(server="ldaps://dc.example.com", base_dn="DC=example,DC=com"),
        AttributeMap(cost_center="extensionAttribute3"),
    )
    print(f"adsearch imported from {Path(adsearch.__file__).resolve().parent}")
    print(f"python {sys.version.split()[0]} — consumer checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
