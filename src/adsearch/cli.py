import argparse
import json

from adsearch.config import LDAPConfig
from adsearch.search import LDAPSearch




def main() -> None:
    parser = argparse.ArgumentParser(description="LDAP Search CLI")

    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    subparsers.add_parser("test", help="Test the LDAP connection")

    employee_id_parser = subparsers.add_parser("employee", help="Search for a user by Employee ID")
    employee_id_parser.add_argument("employee_id", type=str, help="Employee ID")

    args = parser.parse_args()

    match args.command:
        case "test": 
            test_command()

        case "employee":
            employee_id_command(args.employee_id)
            pass
        case _:
            parser.print_help()


def test_command() -> None:
    config = LDAPConfig.from_env()
    search = LDAPSearch(config)
    print(f"bound: {search.conn.bound}")
    print(f"whoami: {search.conn.extend.standard.who_am_i()}")


def employee_id_command(employee_id: str) -> None:
    config = LDAPConfig.from_env()
    search = LDAPSearch(config)
    print(f"Searching for Employee ID: {employee_id}")
    print(
        json.dumps(
            search.find_users(employee_id='11510745'), 
            indent=2
        )
    )




if __name__ == "__main__":
    main()
