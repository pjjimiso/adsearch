"""adsearch — a generic Active Directory / LDAP query library.

Only names listed in __all__ are public
"""

import logging

from adsearch.config import LDAPConfig
from adsearch.errors import (
    LDAPAuthError,
    LDAPConfigError,
    LDAPConnectionError,
    LDAPQueryError,
    LDAPSearchError,
    NotFoundError,
)
from adsearch.models import AttributeMap, User
from adsearch.search import LDAPSearch

# A library adds nothing to a consumer's logs until the consumer configures a
# handler; without this, an application that hasn't configured logging gets a
# "no handlers could be found" warning on stderr the first time this package
# logs anything. logging.basicConfig is the CLI's prerogative, never the
# library's.
logging.getLogger(__name__).addHandler(logging.NullHandler())

__all__ = [
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
]
