import unittest

from adsearch.config import LDAPConfig
from adsearch.errors import LDAPConfigError


class TestLDAPConfig(unittest.TestCase):
    def test_empty_server(self):
        with self.assertRaises(LDAPConfigError):
            LDAPConfig(server="", base_dn="DC=x,DC=com")

    def test_empty_base_dn(self):
        with self.assertRaises(LDAPConfigError):
            LDAPConfig(server="ldaps://x", base_dn="")

    def test_password_not_in_repl(self):
        config = LDAPConfig(server="ldaps://x", base_dn='DC=x,DC=com', bind_password='password123')
        self.assertNotIn('password123', repr(config), "bind_password should not be in the repr output")

    def test_empty_env(self):
        with self.assertRaises(LDAPConfigError):
            LDAPConfig.from_env({})


if __name__ == "__main__":
    unittest.main()
