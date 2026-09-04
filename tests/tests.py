import unittest

from adsearch.config import LDAPConfig
from adsearch.models import AttributeMap
from adsearch.errors import LDAPConfigError, LDAPQueryError
from adsearch.filters import esc, is_valid_attr, eq, all_of, USER_OBJECT


class TestLDAPConfig(unittest.TestCase):
    def test_empty_server(self):
        with self.assertRaises(LDAPConfigError):
            LDAPConfig(server="", base_dn="DC=x,DC=com")

    def test_empty_base_dn(self):
        with self.assertRaises(LDAPConfigError):
            LDAPConfig(server="ldaps://x", base_dn="")

    def test_password_not_in_repr(self):
        config = LDAPConfig(server="ldaps://x", base_dn='DC=x,DC=com', bind_password='password123')
        self.assertNotIn('password123', repr(config), "bind_password should not be in the repr output")

    def test_empty_env(self):
        with self.assertRaises(LDAPConfigError):
            LDAPConfig.from_env({})


class TestFilters(unittest.TestCase): 
    def test_esc_filter(self):
        self.assertEqual(esc('a*b'), 'a\\2ab')
        self.assertEqual(esc('x)(objectClass=*'), 'x\\29\\28objectClass=\\2a')

    def test_attr_filter(self):
        self.assertTrue(is_valid_attr('cn'))
        self.assertFalse(is_valid_attr('cn*'))
        self.assertFalse(is_valid_attr('cn\n'))
        self.assertFalse(is_valid_attr(''))

    def test_eq_filter(self): 
        self.assertEqual(eq('cn', 'Billy Bob'), '(cn=Billy Bob)')
        self.assertNotIn('(employeeID=*)', eq('employeeID', '*'))
        with self.assertRaises(LDAPQueryError):
            eq('', 'x')

    def test_all_of_filter(self): 
        self.assertEqual(all_of(eq('cn', 'Billy Bob'), eq('sn', 'Smith')), '(&(cn=Billy Bob)(sn=Smith))')
        self.assertEqual(all_of(eq('cn', 'Billy Bob'), None), '(cn=Billy Bob)')
        self.assertEqual(all_of(USER_OBJECT, eq('empID', '123')), '(&(&(objectCategory=person)(objectClass=user))(empID=123))')
        with self.assertRaises(LDAPQueryError):
            all_of(None)
        with self.assertRaises(LDAPQueryError):
            all_of(None, None)


class TestAttributeMap(unittest.TestCase):
    def test_fetch_attributes(self):
        main_attrs = ['displayName', 'cn', 'employeeID', 'sAMAccountName', 'mail', 'manager']
        self.assertEqual(AttributeMap().fetch_attributes(), main_attrs)
        self.assertEqual(AttributeMap(extra=('mail',)).fetch_attributes(), main_attrs)
        self.assertEqual(AttributeMap(extra=('customfield',)).fetch_attributes(), main_attrs + ['customfield'])



if __name__ == "__main__":
    unittest.main()
