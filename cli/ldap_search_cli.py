import argparse

from lib.search_utils import wwid_command

def main() -> None:
    parser = argparse.ArgumentParser(description="LDAP Search CLI")

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    wwid_parser = subparsers.add_parser("wwid", help="Search for a user by WWID")
    wwid_parser.add_argument("wwid", type=str, help="Employee WWID")

    args = parser.parse_args()

    match args.command:
        case "wwid":
            wwid_command(args.wwid)
            pass
        case _:
            parser.print_help()


if __name__ == "__main__":
    main()
