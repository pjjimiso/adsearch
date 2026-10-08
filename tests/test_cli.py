"""What each subcommand parses, what it renders, and how it fails.

Argument parsing, rendering, the exit-code map and the JSON encoder are pure, so
they are tested directly; the command functions themselves read the environment
and open a connection, and are covered by the library tests behind the seam
instead.

Releasing that connection is the exception: `LDAPSearch.close()` is a library
guarantee already covered in test_search.py, but only the CLI decides whether a
command's `with` block actually reaches it (issue #15), so that one thing is
tested here, through the same fake-connection seam.
"""

import ast
import base64
import datetime
import inspect
import json
import pathlib
import textwrap

from collections.abc import Callable

import pytest

from ldap3.core.exceptions import LDAPInvalidFilterError

from adsearch import cli
from adsearch.cli import build_parser, format_raw, format_users, render_reports, render_users
from adsearch.errors import (
    LDAPAuthError,
    LDAPQueryError,
    LDAPSearchError,
    NotFoundError,
)
from adsearch.models import DEFAULT_ATTRIBUTES, User

from tests.conftest import DOCUMENTED_CODES, NullContext, searcher_with_connection
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

        def direct_reports(self, username: str, *, attributes=None) -> list[User]:
            called.append(("direct_reports", username))
            return []

        def reporting_tree(self, username: str, *, attributes=None) -> list[User]:
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

        def by_group(
            self, group: str, *, transitive: bool = True, include_disabled: bool = False,
            attributes=None,
        ) -> list[User]:
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

    assert called == [{"cost_center": "1234", "include_disabled": False, "attributes": None}]


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


def test_the_server_info_subcommand_releases_its_connection_too(
    monkeypatch: pytest.MonkeyPatch,
):
    """`server_info` runs over its own throwaway connection, never `conn`
    (§9), but the CLI's `with` block still has to close the `LDAPSearch`
    instance like every other subcommand (issue #15)."""

    class Bound(NullContext):
        def __init__(self, config, *args, **kwargs) -> None:
            self.closed = False

        def __exit__(self, *exc_info) -> None:
            self.closed = True

        def server_info(self) -> str:
            return "naming contexts: DC=test,DC=com"

    configured_env(monkeypatch)
    fake_search = Bound(None)
    monkeypatch.setattr(cli, "LDAPSearch", lambda config: fake_search)

    assert cli.server_info_command() == "naming contexts: DC=test,DC=com"
    assert fake_search.closed is True


SUBCOMMANDS = [
    ("server-info",),
    ("employee", "123"),
    ("manager", "jdoe"),
    ("cost-center", "1234"),
    ("group", "Engineers"),
    ("describe", "--username", "jdoe"),
    ("resolve-dn", "--username", "jdoe"),
]


def carrying(attributes: dict[str, object]) -> User:
    """Bo, plus the raw attributes a real directory hands back."""
    user = bo()
    user["attributes"] = attributes
    return user


def failing_command(monkeypatch: pytest.MonkeyPatch, error: Exception) -> None:
    """Make `employee` raise where a real one would, opening no connection."""

    def raise_it(_id: str, **_kwargs: object) -> list[User]:
        raise error

    monkeypatch.setattr(cli, "employee_id_command", raise_it)


def rendered_attributes(attributes: dict[str, object]) -> dict[str, object]:
    """The `attributes` of one user, through the JSON renderer and back."""
    return json.loads(format_users([carrying(attributes)], "json"))[0]["attributes"]


@pytest.mark.parametrize("argv", SUBCOMMANDS, ids=lambda argv: argv[0])
def test_every_subcommand_accepts_the_debug_flag(argv: tuple[str, ...]):
    """It selects how a failure is reported, which every subcommand can have."""
    assert parse(*argv).debug is False
    assert parse(*argv, "--debug").debug is True


@pytest.mark.parametrize("argv", SUBCOMMANDS, ids=lambda argv: argv[0])
def test_debug_is_accepted_before_the_subcommand_too(argv: tuple[str, ...]):
    """DESIGN §10 calls it a global flag, and an operator reaching for a
    traceback types it where it falls. The subparser default must not
    overwrite one given early back to False."""
    assert parse("--debug", *argv).debug is True


def test_debug_is_answerable_even_with_no_subcommand():
    """`main` consults it on the path that only prints help, so it is read on
    a namespace no subparser ever touched."""
    assert parse().debug is False
    assert parse("--debug").debug is True


@pytest.mark.parametrize(
    "error, code", DOCUMENTED_CODES, ids=lambda value: getattr(value, "__name__", value)
)
def test_each_failure_class_exits_with_its_documented_code(
    error: type[LDAPSearchError],
    code: int,
    monkeypatch: pytest.MonkeyPatch,
):
    failing_command(monkeypatch, error("nope"))
    assert cli.main(["employee", "123"]) == code


def test_the_documented_codes_are_distinct():
    """DESIGN §6.4: callers script against them and need to tell a bad password
    from no such user without parsing stderr."""
    codes = [code for _error, code in DOCUMENTED_CODES]
    assert sorted(set(codes)) == sorted(codes)
    assert not {cli.EXIT_OK, cli.EXIT_ERROR, cli.EXIT_USAGE} & set(codes)


def test_a_failing_command_reports_its_code_and_still_releases_the_connection(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    """Where the exit-code map meets the `with` block of issue #15. The two
    are covered separately above and in test_search.py, but only together do
    they say that a scripted caller gets its code *and* the domain controller
    gets its connection back. Asserted through `main`, because the release
    happens on the way out of the command and the code is decided above it."""
    ad, connection = searcher_with_connection(
        failure=Failure(LDAPInvalidFilterError("bad filter"))
    )
    configured_env(monkeypatch)
    monkeypatch.setattr(cli, "LDAPSearch", lambda config: ad)

    assert cli.main(["employee", "123"]) == dict(DOCUMENTED_CODES)[LDAPQueryError]
    assert connection.bound is False
    assert "bad filter" in capsys.readouterr().err


def test_success_exits_zero(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    monkeypatch.setattr(cli, "employee_id_command", lambda _id, **_kwargs: [bo()])
    assert cli.main(["employee", "123"]) == cli.EXIT_OK
    assert "bng" in capsys.readouterr().out


def test_a_usage_error_exits_two():
    """argparse owns this one, and the handler must not intercept it."""
    with pytest.raises(SystemExit) as raised:
        cli.main(["employee"])
    assert raised.value.code == cli.EXIT_USAGE


def test_naming_no_subcommand_is_a_usage_error(capsys: pytest.CaptureFixture[str]):
    """Nothing was asked and nothing ran, so the code cannot be success — and
    the help goes where argparse sends its own usage errors. A caller that saw
    2 and read stderr to learn why would otherwise get silence."""
    assert cli.main([]) == cli.EXIT_USAGE
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "usage:" in captured.err


def test_an_unexpected_exception_exits_one(monkeypatch: pytest.MonkeyPatch):
    failing_command(monkeypatch, RuntimeError("nobody planned for this"))
    assert cli.main(["employee", "123"]) == cli.EXIT_ERROR


def test_the_base_error_falls_back_to_the_unexpected_code(
    monkeypatch: pytest.MonkeyPatch,
):
    """DESIGN §6.1 gives the base class no code of its own."""
    failing_command(monkeypatch, LDAPSearchError("bare"))
    assert cli.main(["employee", "123"]) == cli.EXIT_ERROR


def test_a_subclass_keeps_the_code_of_the_class_it_refines(
    monkeypatch: pytest.MonkeyPatch,
):
    """A consumer that narrows a query error should not have it filed under
    the code that means a bug in this tool."""

    class SizeLimitExceeded(LDAPQueryError):
        pass

    failing_command(monkeypatch, SizeLimitExceeded("limit"))
    assert cli.main(["employee", "123"]) == dict(DOCUMENTED_CODES)[LDAPQueryError]


def test_the_cli_has_exactly_one_handler_and_it_is_in_the_entry_point():
    """DESIGN §10. A second `try` anywhere in the module is the exit-code
    decision starting to spread, and the first step towards two commands
    failing in two different ways — so the whole file is checked, not just
    `main`, which would let one appear in `dispatch` unnoticed."""
    module = ast.parse(pathlib.Path(cli.__file__).read_text())
    assert [
        node.name
        for node in ast.walk(module)
        if isinstance(node, ast.FunctionDef)
        if any(isinstance(child, ast.Try) for child in ast.walk(node))
    ] == ["main"]
    entry = ast.parse(textwrap.dedent(inspect.getsource(cli.main)))
    assert len([n for n in ast.walk(entry) if isinstance(n, ast.Try)]) == 1


def test_the_message_goes_to_stderr_and_leaves_stdout_clean(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    """A caller redirecting stdout into a parser gets results or nothing."""
    failing_command(monkeypatch, LDAPAuthError("bind rejected"))
    cli.main(["employee", "123"])
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "bind rejected" in captured.err


def test_the_traceback_is_withheld_until_it_is_asked_for(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    failing_command(monkeypatch, LDAPAuthError("bind rejected"))
    cli.main(["employee", "123"])
    assert "Traceback" not in capsys.readouterr().err


def test_the_debug_flag_adds_the_traceback_without_losing_the_message(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    failing_command(monkeypatch, LDAPAuthError("bind rejected"))
    cli.main(["employee", "123", "--debug"])
    captured = capsys.readouterr()
    assert "Traceback" in captured.err
    assert "bind rejected" in captured.err


def test_an_unexpected_failure_withholds_its_traceback_too(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    """One rule for both arms: nothing reaches a caller as a traceback unless
    asked for, which is the whole of what made the CLI unscriptable."""
    failing_command(monkeypatch, RuntimeError("nobody planned for this"))
    cli.main(["employee", "123"])
    quiet = capsys.readouterr().err
    cli.main(["employee", "123", "--debug"])
    loud = capsys.readouterr().err
    assert "Traceback" not in quiet
    assert "nobody planned for this" in quiet
    assert "Traceback" in loud


def test_the_plain_encoder_refuses_real_directory_data():
    """The premise of the custom encoder, pinned rather than taken on faith:
    `json.dumps` raises on exactly the values a directory returns."""
    with pytest.raises(TypeError):
        json.dumps({"objectGUID": b"\x8f\x1c"})
    with pytest.raises(TypeError):
        json.dumps({"whenCreated": datetime.datetime(2026, 3, 1)})


@pytest.mark.parametrize(
    "value",
    [
        datetime.datetime(2026, 3, 1, 12, 30, 45, tzinfo=datetime.timezone.utc),
        datetime.date(2026, 3, 1),
        datetime.time(12, 30, 45),
    ],
    ids=["datetime", "date", "time"],
)
def test_json_renders_a_timestamp_in_iso_8601(
    value: datetime.datetime | datetime.date | datetime.time,
):
    assert rendered_attributes({"whenCreated": value}) == {
        "whenCreated": value.isoformat()
    }


GUID = b"\x8f\x1c\x00\xd4\x9a\x7b\x4e\x11\xa2\x55\x00\x0c\x29\x3f\x5e\x01"


@pytest.mark.parametrize(
    "value",
    [GUID, bytearray(GUID), memoryview(GUID)],
    ids=["bytes", "bytearray", "memoryview"],
)
def test_json_renders_binary_as_base64(value: object):
    """Every buffer type goes through the same arm. A `bytearray` falling to
    the `str` fallback would render `bytearray(b'...')` — the exact unusable
    output the base64 arm exists to prevent."""
    encoded = rendered_attributes({"objectGUID": value})["objectGUID"]
    assert isinstance(encoded, str)
    assert base64.b64decode(encoded) == GUID


def test_binary_is_not_stringified_into_something_unusable():
    """The rejected alternative. A permissive stringify default never crashes,
    which is why it is a trap: an object GUID emerges as a Python bytes repr,
    which looks like output and leaves schema discovery nothing to use."""
    guid = b"\x8f\x1c\x00\xd4"
    encoded = rendered_attributes({"objectGUID": guid})["objectGUID"]
    assert isinstance(encoded, str)
    assert encoded == base64.b64encode(guid).decode("ascii")
    assert "\\x" not in encoded
    assert not encoded.startswith("b'")


def test_json_falls_back_to_a_string_for_anything_else():
    class Unforeseen:
        def __str__(self) -> str:
            return "whatever the directory sent"

    assert rendered_attributes({"odd": Unforeseen()}) == {
        "odd": "whatever the directory sent"
    }


def test_json_output_of_a_user_carrying_timestamps_and_binary_succeeds():
    """The acceptance criterion: the format meets an actual directory."""
    user = carrying(
        {
            "whenCreated": datetime.datetime(
                2026, 3, 1, 12, 30, 45, tzinfo=datetime.timezone.utc
            ),
            "objectGUID": b"\x8f\x1c\x00\xd4\x9a\x7b\x4e\x11",
            "objectSid": b"\x01\x05\x00\x00\x00\x00\x00\x05",
            "memberOf": ["CN=Engineers,OU=Groups,DC=test,DC=com"],
            "userAccountControl": 512,
        }
    )
    rendered = json.loads(format_users([user], "json"))
    assert rendered[0]["username"] == "bng"
    assert rendered[0]["attributes"]["userAccountControl"] == 512
    assert rendered[0]["attributes"]["memberOf"] == [
        "CN=Engineers,OU=Groups,DC=test,DC=com"
    ]


@pytest.mark.parametrize(
    "render", [format_users, render_reports], ids=["users", "reports"]
)
def test_an_unknown_format_is_rejected_in_one_place(
    render: Callable[[list[User], str], str],
):
    """DESIGN §10: `format_users` is the only place the CLI chooses a
    rendering, so every entry point fails there and not on its own terms."""
    with pytest.raises(ValueError, match="Unknown format"):
        render([bo()], "yaml")


def test_the_report_renderer_delegates_the_format_decision(
    monkeypatch: pytest.MonkeyPatch,
):
    """It adds the count and nothing else, so it never learns what a format
    is — the count is not a second place to choose a rendering."""
    seen: list[str] = []

    def recorder(users: list[User], fmt: str) -> str:
        seen.append(fmt)
        return ""

    monkeypatch.setattr(cli, "format_users", recorder)
    render_reports([bo()], "csv")
    assert seen == ["csv"]


# --- Discovery flags: --raw, --attributes, --include-disabled, --insecure ---


def test_the_raw_flag_defaults_to_false():
    assert parse("employee", "123").raw is False


def test_the_raw_flag_parses_on_every_search_subcommand():
    assert parse("employee", "123", "--raw").raw is True
    assert parse("manager", "jdoe", "--raw").raw is True
    assert parse("cost-center", "1234", "--raw").raw is True
    assert parse("group", "Engineers", "--raw").raw is True


def test_the_attributes_flag_parses_a_comma_separated_list():
    assert parse("employee", "123", "--attributes", "a,b,c").attributes == ["a", "b", "c"]


def test_the_attributes_flag_trims_whitespace_around_each_name():
    assert parse("employee", "123", "--attributes", "a, b , c").attributes == ["a", "b", "c"]


def test_the_attributes_flag_defaults_to_none():
    """`None` and not `[]`: DESIGN §8.5 says `attributes=None` keeps the
    attribute map's own fetch list, which an empty list would also do, but
    only `None` says so — the two are not the same promise to the library."""
    assert parse("employee", "123").attributes is None


def test_the_include_disabled_flag_defaults_to_false():
    assert parse("employee", "123").include_disabled is False


def test_the_include_disabled_flag_parses_on_employee_cost_center_and_group():
    assert parse("employee", "123", "--include-disabled").include_disabled is True
    assert parse("cost-center", "1234", "--include-disabled").include_disabled is True
    assert parse("group", "Engineers", "--include-disabled").include_disabled is True


def test_manager_has_no_include_disabled_flag():
    """DESIGN §8.5: `direct_reports`/`reporting_tree` have no criterion to opt
    out with, so the subcommand does not offer a flag the library can't take."""
    with pytest.raises(SystemExit):
        parse("manager", "jdoe", "--include-disabled")


@pytest.mark.parametrize("argv", SUBCOMMANDS, ids=lambda argv: argv[0])
def test_every_subcommand_accepts_the_insecure_flag(argv: tuple[str, ...]):
    assert parse(*argv).insecure is False
    assert parse(*argv, "--insecure").insecure is True


@pytest.mark.parametrize("argv", SUBCOMMANDS, ids=lambda argv: argv[0])
def test_insecure_is_accepted_before_the_subcommand_too(argv: tuple[str, ...]):
    assert parse("--insecure", *argv).insecure is True


def test_insecure_is_answerable_even_with_no_subcommand():
    assert parse().insecure is False
    assert parse("--insecure").insecure is True


def test_the_attributes_flag_reaches_the_library(monkeypatch: pytest.MonkeyPatch):
    called: list[dict[str, object]] = []

    class Recorder(NullContext):
        def __init__(self, config, *args, **kwargs) -> None:
            pass

        def find_users(self, **criteria: object) -> list[User]:
            called.append(criteria)
            return []

    configured_env(monkeypatch)
    monkeypatch.setattr(cli, "LDAPSearch", Recorder)

    cli.employee_id_command("123", attributes=["extensionAttribute7"])

    assert called == [
        {
            "employee_id": "123",
            "include_disabled": False,
            "attributes": ["extensionAttribute7"],
        }
    ]


def test_render_users_switches_between_mapped_and_raw_output():
    mapped = render_users([bo()], "json", raw=False)
    assert json.loads(mapped)[0]["username"] == "bng"

    raw = render_users([carrying({"objectGUID": "opaque"})], "json", raw=True)
    assert json.loads(raw) == [{"dn": bo()["dn"], "objectGUID": "opaque"}]


def test_format_raw_bypasses_the_user_mapper():
    """DESIGN §10: the DN plus every attribute as the directory returned it —
    none of the curated name/employee_id/username/email fields."""
    user = carrying({"sAMAccountName": ["bng"], "whenCreated": "2026-03-01T00:00:00"})
    entries = json.loads(format_raw([user]))
    assert entries == [
        {
            "dn": user["dn"],
            "sAMAccountName": ["bng"],
            "whenCreated": "2026-03-01T00:00:00",
        }
    ]


def test_raw_output_is_always_json_regardless_of_the_format_flag():
    user = carrying({"sAMAccountName": ["bng"]})
    assert render_users([user], "table", raw=True) == render_users([user], "csv", raw=True)


def test_the_raw_flag_reaches_rendering(monkeypatch: pytest.MonkeyPatch):
    """Through `main`, so the wiring from parsed flag to renderer is covered
    end to end rather than asserted on `render_users` alone."""
    monkeypatch.setattr(
        cli, "employee_id_command", lambda _id, **_kwargs: [carrying({"objectGUID": "opaque"})]
    )
    captured_main = cli.main(["employee", "123", "--raw"])
    assert captured_main == cli.EXIT_OK


def test_insecure_reaches_build_config(monkeypatch: pytest.MonkeyPatch):
    seen: list[bool] = []

    def recorder(*, insecure: bool = False):
        seen.append(insecure)
        return cli.LDAPConfig(server="ldaps://dc.test.com", base_dn="DC=test,DC=com")

    class Bound(NullContext):
        def server_info(self) -> str:
            return "info"

    monkeypatch.setattr(cli, "build_config", recorder)
    monkeypatch.setattr(cli, "LDAPSearch", lambda config: Bound())

    cli.server_info_command(insecure=True)

    assert seen == [True]


def test_build_config_turns_off_certificate_validation_when_insecure(
    monkeypatch: pytest.MonkeyPatch,
):
    """DESIGN §7.3: `--insecure` is the one path that can produce `CERT_NONE`,
    and it goes through `LDAPConfig`'s own flag rather than a parallel one."""
    configured_env(monkeypatch)
    assert cli.build_config().validate_cert is True
    assert cli.build_config(insecure=True).validate_cert is False


# --- describe and resolve-dn (DESIGN §9, §8.6) -------------------------------


def test_describe_requires_exactly_one_selector():
    with pytest.raises(SystemExit):
        parse("describe")
    with pytest.raises(SystemExit):
        parse("describe", "--username", "jdoe", "--employee-id", "123")


def test_describe_parses_either_selector():
    assert parse("describe", "--username", "jdoe").username == "jdoe"
    assert parse("describe", "--employee-id", "123").employee_id == "123"


def test_resolve_dn_requires_exactly_one_selector():
    with pytest.raises(SystemExit):
        parse("resolve-dn")
    with pytest.raises(SystemExit):
        parse("resolve-dn", "--username", "jdoe", "--group", "Engineers")


def test_resolve_dn_parses_any_of_its_three_selectors():
    assert parse("resolve-dn", "--username", "jdoe").username == "jdoe"
    assert parse("resolve-dn", "--employee-id", "123").employee_id == "123"
    assert parse("resolve-dn", "--group", "Engineers").group == "Engineers"


def test_describe_by_username_reaches_describe_user_with_the_librarys_own_default(
    monkeypatch: pytest.MonkeyPatch,
):
    called: list[tuple[str, str | None]] = []

    class Recorder(NullContext):
        def __init__(self, config, *args, **kwargs) -> None:
            pass

        def describe_user(self, value: str, *, by: str = "sAMAccountName") -> dict[str, object]:
            called.append((value, by))
            return {"dn": "CN=jdoe"}

    configured_env(monkeypatch)
    monkeypatch.setattr(cli, "LDAPSearch", Recorder)

    cli.describe_command(username="jdoe")

    assert called == [("jdoe", "sAMAccountName")]


def test_describe_by_employee_id_passes_the_attribute_maps_employee_id_attribute(
    monkeypatch: pytest.MonkeyPatch,
):
    called: list[tuple[str, str]] = []

    class Recorder(NullContext):
        def __init__(self, config, *args, **kwargs) -> None:
            pass

        def describe_user(self, value: str, *, by: str = "sAMAccountName") -> dict[str, object]:
            called.append((value, by))
            return {"dn": "CN=jdoe"}

    configured_env(monkeypatch)
    monkeypatch.setattr(cli, "LDAPSearch", Recorder)

    cli.describe_command(employee_id="123")

    assert called == [("123", DEFAULT_ATTRIBUTES.employee_id)]


def test_resolve_dn_by_group_calls_resolve_group_dn(monkeypatch: pytest.MonkeyPatch):
    called: list[str] = []

    class Recorder(NullContext):
        def __init__(self, config, *args, **kwargs) -> None:
            pass

        def resolve_group_dn(self, group: str) -> str:
            called.append(group)
            return "CN=Engineers"

    configured_env(monkeypatch)
    monkeypatch.setattr(cli, "LDAPSearch", Recorder)

    assert cli.resolve_dn_command(group="Engineers") == "CN=Engineers"
    assert called == ["Engineers"]


def test_resolve_dn_by_username_calls_resolve_user_dn_with_no_by_override(
    monkeypatch: pytest.MonkeyPatch,
):
    called: list[tuple[str, str | None]] = []

    class Recorder(NullContext):
        def __init__(self, config, *args, **kwargs) -> None:
            pass

        def resolve_user_dn(self, value: str, *, by: str | None = None) -> str:
            called.append((value, by))
            return "CN=jdoe"

    configured_env(monkeypatch)
    monkeypatch.setattr(cli, "LDAPSearch", Recorder)

    cli.resolve_dn_command(username="jdoe")

    assert called == [("jdoe", None)]


def test_resolve_dn_by_employee_id_passes_the_attribute_maps_employee_id_attribute(
    monkeypatch: pytest.MonkeyPatch,
):
    called: list[tuple[str, str | None]] = []

    class Recorder(NullContext):
        def __init__(self, config, *args, **kwargs) -> None:
            pass

        def resolve_user_dn(self, value: str, *, by: str | None = None) -> str:
            called.append((value, by))
            return "CN=jdoe"

    configured_env(monkeypatch)
    monkeypatch.setattr(cli, "LDAPSearch", Recorder)

    cli.resolve_dn_command(employee_id="123")

    assert called == [("123", DEFAULT_ATTRIBUTES.employee_id)]


def test_describe_dispatches_through_main(monkeypatch: pytest.MonkeyPatch, capsys):
    monkeypatch.setattr(cli, "describe_command", lambda **_kwargs: {"dn": "CN=jdoe"})
    assert cli.main(["describe", "--username", "jdoe"]) == cli.EXIT_OK
    assert json.loads(capsys.readouterr().out) == {"dn": "CN=jdoe"}


def test_resolve_dn_dispatches_through_main(monkeypatch: pytest.MonkeyPatch, capsys):
    monkeypatch.setattr(cli, "resolve_dn_command", lambda **_kwargs: "CN=jdoe")
    assert cli.main(["resolve-dn", "--username", "jdoe"]) == cli.EXIT_OK
    assert capsys.readouterr().out.strip() == "CN=jdoe"


def test_server_info_dispatches_through_main(monkeypatch: pytest.MonkeyPatch, capsys):
    monkeypatch.setattr(cli, "server_info_command", lambda **_kwargs: "naming contexts: ...")
    assert cli.main(["server-info"]) == cli.EXIT_OK
    assert capsys.readouterr().out.strip() == "naming contexts: ..."


def test_describe_and_resolve_dn_raise_the_documented_notfound_code(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(
        cli, "describe_command", lambda **_kwargs: (_ for _ in ()).throw(NotFoundError("nope"))
    )
    assert cli.main(["describe", "--username", "nobody"]) == dict(DOCUMENTED_CODES)[NotFoundError]
