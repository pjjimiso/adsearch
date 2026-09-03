class LDAPSearchError(Exception):
    """Base exception for all adsearch errors. Callers should catch only this
    if they don't need to distinguish failure types."""


class LDAPConfigError(LDAPSearchError):
    """Raised for invalid configuration: missing required fields/env vars,
    a malformed DN, or SIMPLE bind requested without TLS."""


class LDAPAuthError(LDAPSearchError):
    """Raised when the LDAP server rejects the bind (bad credentials,
    locked account, expired password, etc.)."""


class LDAPConnectionError(LDAPSearchError):
    """Raised for network-level failures: DNS resolution, TCP connect,
    TLS handshake, or a timeout reaching the server."""


class LDAPQueryError(LDAPSearchError):
    """ Raised when the LDAP server rejects a query (malformed filter, 
    invalid DN, etc.)"""

