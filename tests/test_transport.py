import socket
import ssl

import pytest

from adsearch.config import LDAPConfig
from adsearch.search import build_server

from tests.conftest import CONFIG


def test_no_test_can_open_a_socket():
    """The offline guard itself. Without this, a future refactor can delete the
    fixture in conftest and nothing goes red."""
    with pytest.raises(AssertionError):
        socket.create_connection(("127.0.0.1", 9))


def test_certificate_validation_is_required():
    """DESIGN §7.3/§13. Asserted on the Server rather than the Tls: ldap3
    substitutes a default Tls() with CERT_NONE when use_ssl=True and tls=None,
    so only the assembled Server proves the Tls actually reached it."""
    assert build_server(CONFIG).tls.validate == ssl.CERT_REQUIRED


def test_validate_cert_false_yields_cert_none_and_warns():
    with pytest.warns(UserWarning):
        insecure = LDAPConfig(server="ldaps://dc.test.com", base_dn="DC=test,DC=com", validate_cert=False)
    assert build_server(insecure).tls.validate == ssl.CERT_NONE
