import argparse
import base64
import datetime
import json
import csv
import io
import sys
import traceback

from collections.abc import Sequence

from adsearch.config import LDAPConfig
from adsearch.errors import (
    LDAPAuthError,
    LDAPConfigError,
    LDAPConnectionError,
    LDAPQueryError,
    LDAPSearchError,
    NotFoundError,
)
from adsearch.search import LDAPSearch, translated
from adsearch.models import User


EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2

# DESIGN §6.4
_EXIT_CODES: dict[type[LDAPSearchError], int] = {
    LDAPConfigError: 3,
    LDAPAuthError: 4,
    LDAPConnectionError: 5,
    LDAPQueryError: 6,
    NotFoundError: 7,
}


def exit_code_for(exc: Exception) -> int:
    """The documented exit code for a failure, or the unexpected-failure code."""
    for cls in type(exc).__mro__:
        code = _EXIT_CODES.get(cls)
        if code is not None:
            return code
    return EXIT_ERROR


_DEBUG_HELP = "Print the traceback on failure, not just the message"


def build_parser() -> argparse.ArgumentParser:
    # --debug is accepted on either side of the subcommand; SUPPRESS is what
    # makes that work (DESIGN §10).
    diagnostics = argparse.ArgumentParser(add_help=False)
    diagnostics.add_argument("--debug", action="store_true",
                             default=argparse.SUPPRESS, help=_DEBUG_HELP)

    common = argparse.ArgumentParser(add_help=False, parents=[diagnostics])
    group = common.add_mutually_exclusive_group()
    group.add_argument("--table", dest="fmt", action="store_const", const="table", 
                       help="Output in table format (default)")
    group.add_argument("--csv", dest="fmt", action="store_const", const="csv",
                       help="Output in CSV format")
    group.add_argument("--json", dest="fmt", action="store_const", const="json", 
                       help="Output in JSON format")
    common.set_defaults(fmt="table")

    parser = argparse.ArgumentParser(description="LDAP Search CLI")
    parser.add_argument("--debug", action="store_true", help=_DEBUG_HELP)

    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    subparsers.add_parser("test", parents=[diagnostics], help="Test the LDAP connection")

    employee_id_parser = subparsers.add_parser("employee", parents=[common], help="Search for a user by employee id")
    employee_id_parser.add_argument("employee_id", type=str, help="employee id")

    manager_parser = subparsers.add_parser("manager", parents=[common], help="Search for a manager's direct reports by username")
    manager_parser.add_argument("username", type=str, help="manager username")
    manager_parser.add_argument("--all-reports", action="store_true",
                                help="Walk the manager's entire reporting tree instead of one hop. Many queries; see ADR-0001")

    cost_center_parser = subparsers.add_parser("cost-center", parents=[common], help="Search for a cost center's users")
    cost_center_parser.add_argument("cost_center", type=str,
                                    help="cost center, keyed on the attribute map's cost_center attribute "
                                         "(default departmentNumber: low confidence, verify it per site)")

    group_parser = subparsers.add_parser("group", parents=[common], help="Search for a group's members by common name or DN")
    group_parser.add_argument("group", type=str, help="group common name or DN")
    group_parser.add_argument("--no-transitive", dest="transitive", action="store_false",
                              help="Direct members only, excluding anyone who holds the group through a nested group")

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run one subcommand and return its exit code (DESIGN §6.4)."""
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        return dispatch(args, parser)
    except Exception as exc:
        return report_failure(exc, debug=args.debug)


def report_failure(exc: Exception, *, debug: bool) -> int:
    """Write a failure to stderr and hand back its exit code."""
    if debug:
        traceback.print_exc()
    print(f"{type(exc).__name__}: {exc}", file=sys.stderr)
    return exit_code_for(exc)


def dispatch(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    match args.command:
        case "test": 
            test_command()

        case "employee":
            results = employee_id_command(args.employee_id)
            print(format_users(results, args.fmt))

        case "manager":
            results = manager_command(args.username, all_reports=args.all_reports)
            print(render_reports(results, args.fmt))

        case "cost-center":
            results = cost_center_command(args.cost_center)
            print(format_users(results, args.fmt))

        case "group":
            results = group_command(args.group, transitive=args.transitive)
            print(format_users(results, args.fmt))

        case _:
            # A usage error, so it goes where argparse sends its own: stderr,
            # leaving stdout empty for the caller that redirected it.
            parser.print_help(sys.stderr)
            return EXIT_USAGE

    return EXIT_OK


def test_command() -> None:
    config = LDAPConfig.from_env()
    with LDAPSearch(config) as search:
        # who_am_i() is an extended operation issued straight at the connection,
        # past both of the library's handlers (§6.2).
        with translated():
            print(f"bound: {search.conn.bound}")
            print(f"whoami: {search.conn.extend.standard.who_am_i()}")


def employee_id_command(id: str) -> list[User]:
    config = LDAPConfig.from_env()
    with LDAPSearch(config) as search:
        return search.find_users(employee_id=id)


def manager_command(username: str, *, all_reports: bool = False) -> list[User]:
    config = LDAPConfig.from_env()
    with LDAPSearch(config) as search:
        if all_reports:
            return search.reporting_tree(username)
        return search.direct_reports(username)


def cost_center_command(cost_center: str) -> list[User]:
    config = LDAPConfig.from_env()
    with LDAPSearch(config) as search:
        return search.find_users(cost_center=cost_center)


def group_command(group: str, *, transitive: bool = True) -> list[User]:
    config = LDAPConfig.from_env()
    with LDAPSearch(config) as search:
        return search.by_group(group, transitive=transitive)


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


class DirectoryEncoder(json.JSONEncoder):
    """JSON for the raw directory values `json.dumps` refuses (DESIGN §10)."""

    def default(self, o: object) -> object:
        if isinstance(o, (datetime.datetime, datetime.date, datetime.time)):
            return o.isoformat()
        if isinstance(o, (bytes, bytearray, memoryview)):
            return base64.b64encode(bytes(o)).decode("ascii")
        return str(o)


def render_reports(users: list[User], fmt: str) -> str:
    """The manager subcommand's output: the people who report to the manager"""
    return f"{format_users(users, fmt)}\n\n{len(users)} report(s) found"


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
            return json.dumps(users, indent=2, cls=DirectoryEncoder)

        case "table": 
            rows = populate_rows(users)
            widths = define_column_widths(rows)
            return build_table(rows, widths)

        case _:
            raise ValueError(f"Unknown format: {fmt}")


if __name__ == "__main__":
    raise SystemExit(main())
