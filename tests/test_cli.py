"""The manager subcommand's two operations, and the count it reports.

Argument parsing and rendering are pure, so they are tested directly; the
command functions themselves read the environment and open a connection, and
are covered by the library tests behind the seam instead.
"""

import pytest

from adsearch import cli
from adsearch.cli import build_parser, render_reports
from adsearch.models import User


def parse(*argv: str):
    return build_parser().parse_args(argv)


def bo() -> User:
    return User(
        dn="CN=Bo Ng,OU=Users,DC=test,DC=com",
        name="Bo Ng",
        employee_id="123",
        username="bng",
        email=None,
        attributes={},
    )


def test_manager_asks_for_direct_reports_by_default():
    args = parse("manager", "jdoe")
    assert args.username == "jdoe"
    assert args.all_reports is False


def test_manager_asks_for_the_reporting_tree_on_request():
    assert parse("manager", "jdoe", "--all-reports").all_reports is True


def test_the_superseded_recursive_flag_is_gone():
    """The flag named a traversal after the boolean that hid its cost, in a
    word CONTEXT.md avoids. Nothing should answer to it."""
    with pytest.raises(SystemExit):
        parse("manager", "jdoe", "--recursive")


def test_the_rendered_output_reports_how_many_were_found():
    rendered = render_reports([bo()], "table")
    assert "bng" in rendered
    assert rendered.endswith("1 report(s) found")


def test_no_reports_still_reports_a_count():
    assert render_reports([], "json").endswith("0 report(s) found")


def test_the_flag_chooses_which_library_operation_is_called(monkeypatch: pytest.MonkeyPatch):
    """The criterion is which operation runs, not which flag parsed: were both
    arms to call the same method, every other test in this file would still
    pass."""
    called: list[tuple[str, str]] = []

    class Recorder:
        def __init__(self, config, *args, **kwargs) -> None:
            pass

        def direct_reports(self, username: str) -> list[User]:
            called.append(("direct_reports", username))
            return []

        def reporting_tree(self, username: str) -> list[User]:
            called.append(("reporting_tree", username))
            return []

    monkeypatch.setenv("ADSEARCH_SERVER", "ldaps://dc.test.com")
    monkeypatch.setenv("ADSEARCH_BASE_DN", "DC=test,DC=com")
    monkeypatch.delenv("ADSEARCH_BIND_USER", raising=False)
    monkeypatch.delenv("ADSEARCH_BIND_PASSWORD", raising=False)
    monkeypatch.setattr(cli, "LDAPSearch", Recorder)

    cli.manager_command("jdoe")
    cli.manager_command("jdoe", all_reports=True)

    assert called == [("direct_reports", "jdoe"), ("reporting_tree", "jdoe")]
