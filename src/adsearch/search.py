from models import User


class LDAPSearch:


    def find_users(self, employee_id: str) -> list[User] | None:
        """Look up users by employee ID. Returns a single User object."""
        # TODO - implement LDAP search logic here
        pass


    def by_employee_id(self, employee_id: str) -> User | None:
        """Look up a single user by employee ID. Returns None if not found"""
        users = self.find_users(employee_id)
        return users[0] if users else None

