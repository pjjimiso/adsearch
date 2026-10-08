import argparse
import base64
import csv
import dataclasses
import datetime
import io
import json
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
from adsearch.search import LDAPSearch
from adsearch.models import DEFAULT_ATTRIBUTES, User


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
_INSECURE_HELP = "Skip TLS certificate validation — a first-contact debugging escape hatch (DESIGN §7.3), never for production"
_RAW_HELP = "Emit the unmapped directory response instead of a mapped User, bypassing the User mapper (DESIGN §10)"
_ATTRIBUTES_HELP = "Comma-separated attribute names to add to the result"
_INCLUDE_DISABLED_HELP = "Include disabled accounts"


def attribute_list(value: str) -> list[str]:
    """Parses `--attributes a,b,c`. Names reach `filters.attr()` for real
    validation once the search runs (DESIGN §10); this just splits the list."""
    return [name.strip() for name in value.split(",") if name.strip()]


def build_parser() -> argparse.ArgumentParser:
    # --debug and --insecure are accepted on either side of the subcommand;
    # SUPPRESS is what makes that work (DESIGN §10).
    diagnostics = argparse.ArgumentParser(add_help=False)
    diagnostics.add_argument("--debug", action="store_true",
                             default=argparse.SUPPRESS, help=_DEBUG_HELP)
    diagnostics.add_argument("--insecure", action="store_true",
                             default=argparse.SUPPRESS, help=_INSECURE_HELP)

    common = argparse.ArgumentParser(add_help=False, parents=[diagnostics])
    group = common.add_mutually_exclusive_group()
    group.add_argument("--table", dest="fmt", action="store_const", const="table",
                       help="Output in table format (default)")
    group.add_argument("--csv", dest="fmt", action="store_const", const="csv",
                       help="Output in CSV format")
    group.add_argument("--json", dest="fmt", action="store_const", const="json",
                       help="Output in JSON format")
    common.set_defaults(fmt="table")

    # --raw and --attributes are the discovery pair, useful on any search
    # subcommand while a site's real attribute names are still unconfirmed.
    discovery = argparse.ArgumentParser(add_help=False, parents=[common])
    discovery.add_argument("--raw", action="store_true", help=_RAW_HELP)
    discovery.add_argument("--attributes", type=attribute_list, default=None,
                           metavar="a,b,c", help=_ATTRIBUTES_HELP)

    # `manager`'s two operations have no `include_disabled` of their own to
    # forward it to (DESIGN §8.5), so this parent is not shared with `manager`.
    searchable = argparse.ArgumentParser(add_help=False, parents=[discovery])
    searchable.add_argument("--include-disabled", action="store_true",
                            help=_INCLUDE_DISABLED_HELP)

    parser = argparse.ArgumentParser(description="LDAP Search CLI")
    parser.add_argument("--debug", action="store_true", help=_DEBUG_HELP)
    parser.add_argument("--insecure", action="store_true", help=_INSECURE_HELP)

    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    subparsers.add_parser(
        "server-info", parents=[diagnostics],
        help="Confirm bind and transport configuration before any query (DESIGN §9)",
    )

    employee_id_parser = subparsers.add_parser("employee", parents=[searchable], help="Search for a user by employee id")
    employee_id_parser.add_argument("employee_id", type=str, help="employee id")

    manager_parser = subparsers.add_parser("manager", parents=[discovery], help="Search for a manager's direct reports by username")
    manager_parser.add_argument("username", type=str, help="manager username")
    manager_parser.add_argument("--all-reports", action="store_true",
                                help="Walk the manager's entire reporting tree instead of one hop. Many queries; see ADR-0001")

    cost_center_parser = subparsers.add_parser("cost-center", parents=[searchable], help="Search for a cost center's users")
    cost_center_parser.add_argument("cost_center", type=str,
                                    help="cost center, keyed on the attribute map's cost_center attribute "
                                         "(default departmentNumber: low confidence, verify it per site)")

    group_parser = subparsers.add_parser("group", parents=[searchable], help="Search for a group's members by common name or DN")
    group_parser.add_argument("group", type=str, help="group common name or DN")
    group_parser.add_argument("--no-transitive", dest="transitive", action="store_false",
                              help="Direct members only, excluding anyone who holds the group through a nested group")

    describe_parser = subparsers.add_parser(
        "describe", parents=[diagnostics],
        help="Dump every populated attribute for one known user (DESIGN §9)",
    )
    describe_selector = describe_parser.add_mutually_exclusive_group(required=True)
    describe_selector.add_argument("--username", type=str,
                                   help="Look up by username (sAMAccountName)")
    describe_selector.add_argument("--employee-id", dest="employee_id", type=str,
                                   help="Look up by the default employee-id attribute (employeeID)")

    resolve_dn_parser = subparsers.add_parser(
        "resolve-dn", parents=[diagnostics],
        help="Resolve a user or group to a DN (DESIGN §8.6)",
    )
    resolve_selector = resolve_dn_parser.add_mutually_exclusive_group(required=True)
    resolve_selector.add_argument("--username", type=str,
                                  help="Resolve a user by username — one-to-one, the safe resolve key")
    resolve_selector.add_argument("--employee-id", dest="employee_id", type=str,
                                  help="Resolve a user by employee id. One-to-many at most sites, "
                                       "so this raises NotFoundError on an ambiguous — i.e. ordinary — match")
    resolve_selector.add_argument("--group", type=str,
                                  help="Resolve a group by common name or DN")

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
        case "server-info":
            print(server_info_command(insecure=args.insecure))

        case "employee":
            results = employee_id_command(
                args.employee_id,
                include_disabled=args.include_disabled,
                attributes=args.attributes,
                insecure=args.insecure,
            )
            print(render_users(results, args.fmt, raw=args.raw))

        case "manager":
            results = manager_command(
                args.username,
                all_reports=args.all_reports,
                attributes=args.attributes,
                insecure=args.insecure,
            )
            print(render_reports(results, args.fmt, raw=args.raw))

        case "cost-center":
            results = cost_center_command(
                args.cost_center,
                include_disabled=args.include_disabled,
                attributes=args.attributes,
                insecure=args.insecure,
            )
            print(render_users(results, args.fmt, raw=args.raw))

        case "group":
            results = group_command(
                args.group,
                transitive=args.transitive,
                include_disabled=args.include_disabled,
                attributes=args.attributes,
                insecure=args.insecure,
            )
            print(render_users(results, args.fmt, raw=args.raw))

        case "describe":
            result = describe_command(
                username=args.username, employee_id=args.employee_id, insecure=args.insecure
            )
            print(format_dict(result))

        case "resolve-dn":
            print(resolve_dn_command(
                username=args.username,
                employee_id=args.employee_id,
                group=args.group,
                insecure=args.insecure,
            ))

        case _:
            # A usage error, so it goes where argparse sends its own: stderr,
            # leaving stdout empty for the caller that redirected it.
            parser.print_help(sys.stderr)
            return EXIT_USAGE

    return EXIT_OK


def build_config(*, insecure: bool = False) -> LDAPConfig:
    """`LDAPConfig.from_env`, with `--insecure` punched through as the one
    post-hoc override the CLI needs (DESIGN §7.3's escape hatch)."""
    config = LDAPConfig.from_env()
    if insecure:
        config = dataclasses.replace(config, validate_cert=False)
    return config


def server_info_command(*, insecure: bool = False) -> str:
    config = build_config(insecure=insecure)
    with LDAPSearch(config) as search:
        return search.server_info()


def employee_id_command(
    id: str,
    *,
    include_disabled: bool = False,
    attributes: Sequence[str] | None = None,
    insecure: bool = False,
) -> list[User]:
    config = build_config(insecure=insecure)
    with LDAPSearch(config) as search:
        return search.find_users(
            employee_id=id, include_disabled=include_disabled, attributes=attributes
        )


def manager_command(
    username: str,
    *,
    all_reports: bool = False,
    attributes: Sequence[str] | None = None,
    insecure: bool = False,
) -> list[User]:
    config = build_config(insecure=insecure)
    with LDAPSearch(config) as search:
        if all_reports:
            return search.reporting_tree(username, attributes=attributes)
        return search.direct_reports(username, attributes=attributes)


def cost_center_command(
    cost_center: str,
    *,
    include_disabled: bool = False,
    attributes: Sequence[str] | None = None,
    insecure: bool = False,
) -> list[User]:
    config = build_config(insecure=insecure)
    with LDAPSearch(config) as search:
        return search.find_users(
            cost_center=cost_center, include_disabled=include_disabled, attributes=attributes
        )


def group_command(
    group: str,
    *,
    transitive: bool = True,
    include_disabled: bool = False,
    attributes: Sequence[str] | None = None,
    insecure: bool = False,
) -> list[User]:
    config = build_config(insecure=insecure)
    with LDAPSearch(config) as search:
        return search.by_group(
            group,
            transitive=transitive,
            include_disabled=include_disabled,
            attributes=attributes,
        )


def describe_command(
    *,
    username: str | None = None,
    employee_id: str | None = None,
    insecure: bool = False,
) -> dict[str, object]:
    """Resolve the `--username`/`--employee-id` selector through the
    library's own default guesses (DESIGN §9's bootstrapping `by`) — there is
    no way for the CLI to take in a custom `AttributeMap`."""
    config = build_config(insecure=insecure)
    with LDAPSearch(config) as search:
        if employee_id is not None:
            return search.describe_user(employee_id, by=DEFAULT_ATTRIBUTES.employee_id)
        assert username is not None, "argparse guarantees exactly one selector"
        return search.describe_user(username)


def resolve_dn_command(
    *,
    username: str | None = None,
    employee_id: str | None = None,
    group: str | None = None,
    insecure: bool = False,
) -> str:
    config = build_config(insecure=insecure)
    with LDAPSearch(config) as search:
        if group is not None:
            return search.resolve_group_dn(group)
        if employee_id is not None:
            return search.resolve_user_dn(employee_id, by=DEFAULT_ATTRIBUTES.employee_id)
        assert username is not None, "argparse guarantees exactly one selector"
        return search.resolve_user_dn(username)


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


def format_dict(result: dict[str, object]) -> str:
    """A single raw dict as JSON — `describe`'s output, which has no
    table/CSV form since its field set varies per user (DESIGN §10)."""
    return json.dumps(result, indent=2, cls=DirectoryEncoder)


def format_raw(users: list[User]) -> str:
    """The unmapped directory response for each user — the DN plus every
    attribute as `ldap3` returned it, bypassing the User mapper (DESIGN §10).
    Always JSON: a raw attribute set varies per user and has no fixed columns
    to render as a table or CSV."""
    entries = [{"dn": user["dn"], **user["attributes"]} for user in users]
    return json.dumps(entries, indent=2, cls=DirectoryEncoder)


def render_users(users: list[User], fmt: str, *, raw: bool = False) -> str:
    """Mapped or raw, depending on `--raw` (DESIGN §10)."""
    return format_raw(users) if raw else format_users(users, fmt)


def render_reports(users: list[User], fmt: str, *, raw: bool = False) -> str:
    """The manager subcommand's output: the people who report to the manager"""
    return f"{render_users(users, fmt, raw=raw)}\n\n{len(users)} report(s) found"


if __name__ == "__main__":
    raise SystemExit(main())
