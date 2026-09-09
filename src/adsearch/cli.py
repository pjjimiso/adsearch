import argparse
import json

from adsearch.config import LDAPConfig
from adsearch.search import LDAPSearch



def main() -> None:
    parser = argparse.ArgumentParser(description="LDAP Search CLI")

    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    subparsers.add_parser("test", help="Test the LDAP connection")

    employee_id_parser = subparsers.add_parser("employee", help="Search for a user by employee id")
    employee_id_parser.add_argument("employee_id", type=str, help="employee id")

    manager_parser = subparsers.add_parser("manager", help="Search for direct reports of a manager by username")
    manager_parser.add_argument("username", type=str, help="manager username")
    manager_parser.add_argument("--recursive", action="store_true", help="Transverse the manager's entire reporting tree")

    args = parser.parse_args()

    match args.command:
        case "test": 
            test_command()
            pass

        case "employee":
            employee_id_command(args.employee_id)
            pass

        case "manager":
            if args.recursive:
                manager_command(args.username, recursive=True)
            else:
                manager_command(args.username)
            pass

        case _:
            parser.print_help()


def test_command() -> None:
    config = LDAPConfig.from_env()
    search = LDAPSearch(config)
    print(f"bound: {search.conn.bound}")
    print(f"whoami: {search.conn.extend.standard.who_am_i()}")


def employee_id_command(id: str) -> None:
    config = LDAPConfig.from_env()
    search = LDAPSearch(config)
    print(f"Searching for Employee ID: {id}")
    results = search.find_users(employee_id=id)
    print(len(results), 'user(s)')
    print(json.dumps(results, indent=2))


def manager_command(username: str, recursive: bool = False) -> None:
    config = LDAPConfig.from_env()
    search = LDAPSearch(config)
    if recursive:
        print(f"Searching the entire reporting tree for manager with username: {username}")
        results = search.by_manager(username, recursive=True)
    else:
        print(f"Searching for direct reports of manager with username: {username}")
        results = search.by_manager(username)
    print(json.dumps(results, indent=2))
    print(len(results), 'report(s)')


if __name__ == "__main__":
    main()
