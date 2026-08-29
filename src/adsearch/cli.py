import argparse

from search import employee_id_command


def main() -> None:
    parser = argparse.ArgumentParser(description="LDAP Search CLI")

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    employee_id_parser = subparsers.add_parser("employee", help="Search for a user by Employee ID")
    employee_id_parser.add_argument("employee_id", type=str, help="Employee ID")

    args = parser.parse_args()

    match args.command:
        case "employee":
            employee_id_command(args.employee_id)
            pass
        case _:
            parser.print_help()


if __name__ == "__main__":
    main()
