import argparse
import json
import csv
import io

from adsearch.config import LDAPConfig
from adsearch.search import LDAPSearch
from adsearch.models import User



def main() -> None:
    common = argparse.ArgumentParser(add_help=False)
    group = common.add_mutually_exclusive_group()
    group.add_argument("--table", dest="fmt", action="store_const", const="table", 
                       help="Output in table format (default)")
    group.add_argument("--csv", dest="fmt", action="store_const", const="csv",
                       help="Output in CSV format")
    group.add_argument("--json", dest="fmt", action="store_const", const="json", 
                       help="Output in JSON format")
    common.set_defaults(fmt="table")

    parser = argparse.ArgumentParser(description="LDAP Search CLI")

    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    subparsers.add_parser("test", help="Test the LDAP connection")

    employee_id_parser = subparsers.add_parser("employee", parents=[common], help="Search for a user by employee id")
    employee_id_parser.add_argument("employee_id", type=str, help="employee id")

    manager_parser = subparsers.add_parser("manager", parents=[common], help="Search for direct reports of a manager by username")
    manager_parser.add_argument("username", type=str, help="manager username")
    manager_parser.add_argument("--recursive", action="store_true", help="Transverse the manager's entire reporting tree")

    args = parser.parse_args()

    match args.command:
        case "test": 
            test_command()
            pass

        case "employee":
            results = employee_id_command(args.employee_id)
            print(format_users(results, args.fmt))
            pass

        case "manager":
            results = manager_command(args.username, recursive=args.recursive)
            print(format_users(results, args.fmt))
            print()
            print(len(results), 'report(s) found')
            pass

        case _:
            parser.print_help()


def test_command() -> None:
    config = LDAPConfig.from_env()
    search = LDAPSearch(config)
    print(f"bound: {search.conn.bound}")
    print(f"whoami: {search.conn.extend.standard.who_am_i()}")


def employee_id_command(id: str) -> list[User]:
    config = LDAPConfig.from_env()
    search = LDAPSearch(config)
    return search.find_users(employee_id=id)


def manager_command(username: str, recursive: bool = False) -> list[User]:
    config = LDAPConfig.from_env()
    search = LDAPSearch(config)
    return search.by_manager(username, recursive=recursive)


_COLUMNS = ("username", "dn", "name", "employee_id", "email")
_TABLE_COLUMNS = ("username", "name", "employee_id", "email") # Exclude dn for readability

def populate_rows(users: list[User]) -> list[list[str]]: 
    rows = []
    rows.append(_TABLE_COLUMNS)
    for user in users:
        row = []
        for col in _TABLE_COLUMNS:
            value = user[col]
            if value is None: 
                value = ''
            row.append(value)
        rows.append(row)
    return rows


def define_column_widths(rows: list[list[str]]) -> list[int]:
    widths = []
    for i in range(len(rows[0])):
        longest = 0
        for row in rows:
            if len(row[i]) > longest: 
                longest = len(row[i])
        widths.append(longest)
    return widths


def build_table(rows: list[list[str]], widths: list[int]) -> str:
    lines = []
    for row_index, row in enumerate(rows):
        cells = []
        for i in range(len(row)):
            cells.append(row[i].ljust(widths[i]))
        lines.append("  ".join(cells).rstrip())

        if row_index == 0:
            dashes = []
            for w in widths:
                dashes.append("-" * w)
            lines.append("  ".join(dashes))
    return "\n".join(lines)


def format_users(users: list[User], fmt: str) -> str: 
    match fmt:
        case "csv":
            buffer = io.StringIO()
            writer = csv.writer(buffer, lineterminator='\n')
            writer.writerow(_COLUMNS)
            for user in users:
                writer.writerow([user[col] for col in _COLUMNS])
            return buffer.getvalue()

        case "json": 
            return json.dumps(users, indent=2)

        case "table": 
            rows = populate_rows(users)
            widths = define_column_widths(rows)
            return build_table(rows, widths)

        case _:
            raise ValueError(f"Unknown format: {fmt}")


if __name__ == "__main__":
    main()
