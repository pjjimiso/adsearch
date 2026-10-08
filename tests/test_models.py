from adsearch.models import AttributeMap


MAIN_ATTRS = [
    'displayName',
    'cn',
    'employeeID',
    'sAMAccountName',
    'userPrincipalName',
    'mail',
    'manager',
    'memberOf',
    'departmentNumber',
]


def test_fetch_attributes():
    assert AttributeMap().fetch_attributes() == MAIN_ATTRS
    assert AttributeMap(extra=('mail',)).fetch_attributes() == MAIN_ATTRS
    assert AttributeMap(extra=('customfield',)).fetch_attributes() == MAIN_ATTRS + ['customfield']


def test_a_site_overrides_the_low_confidence_cost_center_default():
    """The attribute holding a cost center is almost always a site-specific
    extension attribute, so the default is a hypothesis (DESIGN §5.2)."""
    site = AttributeMap(cost_center='extensionAttribute3')
    assert 'extensionAttribute3' in site.fetch_attributes()
    assert 'departmentNumber' not in site.fetch_attributes()
