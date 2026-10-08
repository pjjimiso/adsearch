"""What each subcommand parses, and which library operation it reaches for.

Argument parsing and rendering are pure, so they are tested directly; the
command functions themselves read the environment and open a connection, and
are covered by the library tests behind the seam instead.

Releasing that connection is the exception: `LDAPSearch.close()` is a library
guarantee already covered in test_search.py, but only the CLI decides whether a
command's `with` block actually reaches it (issue #15), so that one thing is
tested here, through the same fake-connection seam.
"""

import pytest

from ldap3.core.exceptions import LDAPInvalidFilterError

from adsearch import cli
from adsearch.cli import build_parser, render_reports
from adsearch.errors import LDAPQueryError
from adsearch.models import User

from tests.conftest import NullContext, searcher_with_connection
from tests.fake_directory import Failure


def parse(*argv: str):
    return build_parser().parse_args(argv)


def configured_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """The two variables `LDAPConfig.from_env` requires, and no credentials."""
    monkeypatch.setenv("ADSEARCH_SERVER", "ldaps://dc.test.com")
    monkeypatch.setenv("ADSEARCH_BASE_DN", "DC=test,DC=com")
    monkeypatch.delenv("ADSEARCH_BIND_USER", raising=False)
    monkeypatch.delenv("ADSEARCH_BIND_PASSWORD", raising=False)


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

    class Recorder(NullContext):
        def __init__(self, config, *args, **kwargs) -> None:
            pass

        def direct_reports(self, username: str) -> list[User]:
            called.append(("direct_reports", username))
            return []

        def reporting_tree(self, username: str) -> list[User]:
            called.append(("reporting_tree", username))
            return []

    configured_env(monkeypatch)
    monkeypatch.setattr(cli, "LDAPSearch", Recorder)

    cli.manager_command("jdoe")
    cli.manager_command("jdoe", all_reports=True)

    assert called == [("direct_reports", "jdoe"), ("reporting_tree", "jdoe")]


def test_the_group_subcommand_takes_a_name_or_a_dn():
    """Either form reaches the library unchanged; which one it is, is the
    library's question to ask and not the parser's."""
    assert parse("group", "Some Group Name").group == "Some Group Name"
    dn = "CN=Engineers,OU=Groups,DC=test,DC=com"
    assert parse("group", dn).group == dn


def test_the_group_subcommand_parses_as_transitive_unless_restricted():
    """DESIGN §10: the flag is subcommand-scoped because it selects between two
    questions about the group, not between two output shapes."""
    assert parse("group", "Some Group Name").transitive is True
    assert parse("group", "Some Group Name", "--no-transitive").transitive is False


def test_the_no_transitive_flag_reaches_the_library(monkeypatch: pytest.MonkeyPatch):
    """Both arms call one method, so what the flag decides is the argument —
    and a flag parsed but not passed through would leave every other test in
    this file green."""
    called: list[tuple[str, bool]] = []

    class Recorder(NullContext):
        def __init__(self, config, *args, **kwargs) -> None:
            pass

        def by_group(self, group: str, *, transitive: bool = True) -> list[User]:
            called.append((group, transitive))
            return []

    configured_env(monkeypatch)
    monkeypatch.setattr(cli, "LDAPSearch", Recorder)

    cli.group_command("Engineers")
    cli.group_command("Engineers", transitive=False)

    assert called == [("Engineers", True), ("Engineers", False)]


def test_the_cost_center_subcommand_takes_one_cost_center():
    assert parse("cost-center", "1234").cost_center == "1234"


def test_the_cost_center_subcommand_names_no_attribute(monkeypatch: pytest.MonkeyPatch):
    """Which attribute holds a cost center is the AttributeMap's answer and not
    the CLI's (DESIGN §5.2), so the subcommand passes the value as the criterion
    and nothing else."""
    called: list[dict[str, object]] = []

    class Recorder(NullContext):
        def __init__(self, config, *args, **kwargs) -> None:
            pass

        def find_users(self, **criteria: object) -> list[User]:
            called.append(criteria)
            return []

    configured_env(monkeypatch)
    monkeypatch.setattr(cli, "LDAPSearch", Recorder)

    cli.cost_center_command("1234")

    assert called == [{"cost_center": "1234"}]


def test_a_command_releases_its_connection_on_success(monkeypatch: pytest.MonkeyPatch):
    """The CLI's own `with` block, not just the library's `close()` (issue #15).
    No socket opens: `ad` is backed by the fake connection behind the seam."""
    ad, connection = searcher_with_connection()
    configured_env(monkeypatch)
    monkeypatch.setattr(cli, "LDAPSearch", lambda config: ad)

    cli.employee_id_command("123")

    assert connection.bound is False


# Every arm reaches `_search` for its first query — `direct_reports` and
# `by_group` resolve a DN before they search, `employee_id_command` and
# `cost_center_command` search directly — so a `Failure(during="call")` fires
# on all four alike (issue #15).
SEARCH_COMMANDS = {
    "employee": lambda: cli.employee_id_command("123"),
    "manager": lambda: cli.manager_command("jdoe"),
    "cost-center": lambda: cli.cost_center_command("1234"),
    "group": lambda: cli.group_command("Engineers"),
}


@pytest.mark.parametrize("name", SEARCH_COMMANDS)
def test_a_command_still_releases_its_connection_when_the_search_fails(
    name: str, monkeypatch: pytest.MonkeyPatch
):
    """A failure inside the block must not leave the connection bound behind,
    whichever subcommand hit it."""
    ad, connection = searcher_with_connection(failure=Failure(LDAPInvalidFilterError("bad filter")))
    configured_env(monkeypatch)
    monkeypatch.setattr(cli, "LDAPSearch", lambda config: ad)

    with pytest.raises(LDAPQueryError):
        SEARCH_COMMANDS[name]()

    assert connection.bound is False


def test_the_test_subcommand_releases_its_connection_too(monkeypatch: pytest.MonkeyPatch):
    """`test_command` reads bind state and identity off the connection before
    the block closes (§10), but it still has to close like every other
    subcommand (issue #15). `who_am_i()` sits outside the fake-connection seam
    (§6.2's "third place the library reaches the network"), so this fake tracks
    release directly instead."""

    class Conn:
        bound = True

        class extend:
            class standard:
                @staticmethod
                def who_am_i() -> str:
                    return "u:test"

    class Bound(NullContext):
        def __init__(self, config, *args, **kwargs) -> None:
            self.conn = Conn()
            self.closed = False

        def __exit__(self, *exc_info) -> None:
            self.closed = True

    configured_env(monkeypatch)
    fake_search = Bound(None)
    monkeypatch.setattr(cli, "LDAPSearch", lambda config: fake_search)

    cli.test_command()

    assert fake_search.closed is True
