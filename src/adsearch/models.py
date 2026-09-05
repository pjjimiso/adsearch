from dataclasses import dataclass
from typing import TypedDict




class User(TypedDict):
    dn: str
    name: str
    employee_id: str | None
    username: str | None
    email: str | None
    attributes: dict[str, object] 


@dataclass(frozen=True, slots=True)
class AttributeMap:
    """Maps logical field names to the real AD attribute names at a site."""
    name: str = "displayName"
    cn: str = "cn"
    employee_id: str = "employeeID"
    username: str = "sAMAccountName"
    mail: str = "mail"
    manager: str = "manager"
    extra: tuple[str, ...] = ()


    def fetch_attributes(self) -> list[str]:
        """Every attribute name to request on a search, including extras.
        Remove duplicates from combining main attrs with extras"""
        attrs = [self.name, self.cn, self.employee_id, self.username, self.mail, self.manager]
        return list(dict.fromkeys(attrs + list(self.extra)))


DEFAULT_ATTRIBUTES = AttributeMap()


def _first(values: object) -> str | None:
    """Return the first value from a list, or the value itself if not a list.
    Return None if the value is None or an empty list."""
    if values is None:
        return None
    if isinstance(values, list):
        if len(values) == 0:
            return None
        return str(values[0])
    return str(values)


def to_user(entry: dict, attrs: AttributeMap) -> User:
    """Build a User from one raw ldap3 searchResEntry."""
    return User(
        dn = entry['dn'],
        name = _first(entry['attributes'].get(attrs.name)) 
            or _first(entry['attributes'].get(attrs.cn)) 
            or entry['dn'],
        employee_id = _first(entry['attributes'].get(attrs.employee_id)),
        username = _first(entry['attributes'].get(attrs.username)),
        email = _first(entry['attributes'].get(attrs.mail)),
        attributes = dict(entry['attributes'])
    )

