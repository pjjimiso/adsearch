from adsearch.models import AttributeMap


def test_fetch_attributes():
    main_attrs = ['displayName', 'cn', 'employeeID', 'sAMAccountName', 'mail', 'manager']
    assert AttributeMap().fetch_attributes() == main_attrs
    assert AttributeMap(extra=('mail',)).fetch_attributes() == main_attrs
    assert AttributeMap(extra=('customfield',)).fetch_attributes() == main_attrs + ['customfield']
