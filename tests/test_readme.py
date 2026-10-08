"""README.md's examples, executed and parsed rather than trusted (DESIGN §4.2,
§10, §11; #14).

The README is the library's only consumer-facing documentation, and every
example in it was false at some point: a method that was never written, a
default output format that was not the default, an indented fragment that could
not run at all. A block that runs here cannot drift from the API without this
file going red.

Python blocks are executed against the in-memory directory of
`tests.fake_directory`, seeded with exactly the identifiers the README names —
`jdoe`, employee id `12345678`, cost center `1234`, and the group `Some Group
Name`. Renaming one in the README without renaming it here is itself a failure:
the examples are checked against a directory, not merely compiled.
"""

import argparse
import re
import shlex
import tomllib

from pathlib import Path
from typing import cast

import pytest

from ldap3 import Connection

from adsearch import cli
from adsearch.config import LDAPConfig

from tests.conftest import DOCUMENTED_CODES, searcher_for
from tests.fake_directory import Entry, FakeDirectory, group, user


REPO_ROOT = Path(__file__).resolve().parent.parent
README = REPO_ROOT / "README.md"

# The README's own worked examples: `ldaps://dc.example.com` and
# `DC=example,DC=com` are what its environment-variable table shows, so the
# fake directory is built under the base the documentation advertises.
SERVER = "ldaps://dc.example.com"
BASE_DN = "DC=example,DC=com"

GROUP_DN = f"CN=Some Group Name,OU=Groups,{BASE_DN}"
NESTED_DN = f"CN=Nested Group,OU=Groups,{BASE_DN}"

JDOE_DN = f"CN=J Doe,OU=Users,{BASE_DN}"
ALEE_DN = f"CN=A Lee,OU=Users,{BASE_DN}"
BNG_DN = f"CN=B Ng,OU=Users,{BASE_DN}"
CYOH_DN = f"CN=C Oh,OU=Users,{BASE_DN}"
DAWN_DN = f"CN=D Awn,OU=Users,{BASE_DN}"
EZE_DN = f"CN=E Ze,OU=Users,{BASE_DN}"


def documented_directory() -> FakeDirectory:
    """A directory holding every identifier the README's examples name.

    `jdoe` manages A Lee, B Ng and the disabled D Awn, and A Lee manages C Oh,
    so the reporting tree is strictly larger than the direct reports and both
    contain a disabled account — the two distinctions the README draws have to
    be visible for its claims to mean anything. B Ng holds `Some Group Name`
    only through `Nested Group`, and the disabled E Ze holds it directly, so
    transitive-vs-direct and the group's disabled exclusion both bite."""
    entries: list[Entry] = [
        group(GROUP_DN),
        group(NESTED_DN, member_of=[GROUP_DN]),
        user(
            JDOE_DN,
            sAMAccountName="jdoe",
            displayName="J Doe",
            employeeID="12345678",
            mail="jdoe@example.com",
            departmentNumber="1234",
            employeeType="Employee",
        ),
        user(
            ALEE_DN,
            sAMAccountName="alee",
            displayName="A Lee",
            employeeID="22222222",
            mail="alee@example.com",
            departmentNumber="1234",
            employeeType="Contractor",
            manager=JDOE_DN,
            member_of=[GROUP_DN],
        ),
        user(
            BNG_DN,
            sAMAccountName="bng",
            displayName="B Ng",
            employeeID="33333333",
            mail="bng@example.com",
            departmentNumber="5678",
            employeeType="Employee",
            manager=JDOE_DN,
            member_of=[NESTED_DN],
        ),
        user(
            CYOH_DN,
            sAMAccountName="cyoh",
            displayName="C Oh",
            employeeID="44444444",
            mail="cyoh@example.com",
            departmentNumber="1234",
            employeeType="Contractor",
            manager=ALEE_DN,
        ),
        user(
            DAWN_DN,
            sAMAccountName="dawn",
            displayName="D Awn",
            employeeID="55555555",
            mail="dawn@example.com",
            departmentNumber="1234",
            employeeType="Employee",
            manager=JDOE_DN,
            disabled=True,
        ),
        user(
            EZE_DN,
            sAMAccountName="eze",
            displayName="E Ze",
            employeeID="66666666",
            mail="eze@example.com",
            departmentNumber="1234",
            employeeType="Employee",
            member_of=[GROUP_DN],
            disabled=True,
        ),
    ]
    return FakeDirectory(*entries)


@pytest.fixture
def documented_site(monkeypatch: pytest.MonkeyPatch) -> FakeDirectory:
    """The environment and connection factory a README example assumes.

    Patching `adsearch.search.open_connection` rather than using conftest's
    `connect=` seam is forced: the examples construct their own
    `LDAPSearch(LDAPConfig.from_env())`, so there is no parameter to thread a
    fake through, and an example that took one would be documenting the test
    suite instead of the library."""
    directory = documented_directory()

    monkeypatch.setenv("ADSEARCH_SERVER", SERVER)
    monkeypatch.setenv("ADSEARCH_BASE_DN", BASE_DN)
    for name in ("ADSEARCH_GROUP_BASE_DN", "ADSEARCH_BIND_USER",
                 "ADSEARCH_BIND_PASSWORD", "ADSEARCH_CA_CERTS"):
        monkeypatch.delenv(name, raising=False)

    def connect(_config: LDAPConfig, **_kwargs: object) -> Connection:
        return cast(Connection, directory.connection())

    monkeypatch.setattr("adsearch.search.open_connection", connect)
    return directory


def readme_text() -> str:
    return README.read_text(encoding="utf-8")


def pyproject() -> dict:
    return tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))


def fenced_blocks() -> list[tuple[int, str, str]]:
    """Every fenced block as (line, language, source).

    The language is captured even when empty so `test_every_fence_is_labelled`
    can refuse an unlabelled or misspelled fence. An earlier version matched
    `^```(\\w+)` and silently skipped anything it did not recognise, which
    would have let a ```` ```py ```` block escape execution entirely while the
    block-count guard still passed."""
    text = readme_text()
    found = []
    for match in re.finditer(r"^```([^\n]*)\n(.*?)^```", text, re.MULTILINE | re.DOTALL):
        line = text.count("\n", 0, match.start()) + 1
        found.append((line, match.group(1).strip(), match.group(2)))
    return found


# Languages this file knows how to check. A fence in any other language is a
# fence nothing verifies, so the set is closed and adding to it is deliberate.
PYTHON = "python"
BASH = "bash"
CHECKED_LANGUAGES = {PYTHON, BASH}

PYTHON_BLOCKS = [(line, source) for line, lang, source in fenced_blocks() if lang == PYTHON]
BASH_BLOCKS = [(line, source) for line, lang, source in fenced_blocks() if lang == BASH]


def adsearch_commands() -> list[tuple[int, str]]:
    """Every `adsearch …` invocation shown in a shell block.

    `--help` is excluded because argparse answers it by exiting, which says
    nothing about whether the command line was valid."""
    found = []
    for line, block in BASH_BLOCKS:
        for offset, text in enumerate(block.splitlines()):
            command = text.strip()
            if command.startswith("adsearch ") and "--help" not in command:
                found.append((line + offset + 1, command))
    return found


ADSEARCH_COMMANDS = adsearch_commands()


def subcommand_action() -> argparse._SubParsersAction:
    """The CLI's subparser action.

    Reaching into `_actions` and `_SubParsersAction` is this file's one
    compromise, in the spirit of conftest's `FakeConnection` cast: argparse
    publishes no way to enumerate subcommands or their flags, and the
    alternative — a hand-written list — is the very thing that goes stale and
    that these tests exist to catch."""
    for action in cli.build_parser()._actions:
        if isinstance(action, argparse._SubParsersAction):
            return action
    raise AssertionError("the CLI parser has no subcommands")


def defined_flags() -> set[str]:
    """Every long option the CLI accepts, on the root parser or any subparser."""
    action = subcommand_action()
    parsers = [cli.build_parser(), *action.choices.values()]
    flags = set()
    for parser in parsers:
        for option in parser._actions:
            flags.update(s for s in option.option_strings if s.startswith("--"))
    return flags - {"--help"}


def test_every_fence_is_labelled_with_a_language_this_file_checks():
    """Otherwise a block escapes verification by being spelled `py`.

    The count guards below cannot catch that: they assert a floor, and the
    README has enough blocks to clear it after losing several."""
    unchecked = [
        (line, language or "<unlabelled>")
        for line, language, _ in fenced_blocks()
        if language not in CHECKED_LANGUAGES
    ]
    assert not unchecked


def test_readme_shows_at_least_one_example_of_each_kind():
    """A guard on the harness itself: a regex that silently matched nothing
    would make every test below vacuously pass."""
    assert len(PYTHON_BLOCKS) >= 5
    assert len(ADSEARCH_COMMANDS) >= 5


@pytest.mark.parametrize("example", PYTHON_BLOCKS, ids=lambda example: f"line-{example[0]}")
def test_every_python_example_runs(example: tuple[int, str], documented_site: FakeDirectory):
    """Each block runs on its own, against a real — if in-memory — directory.

    Blocks execute in a fresh namespace rather than a shared one, so an example
    that silently depends on a name an earlier block defined fails here, the way
    it would for a reader who copied just that block.

    An example that queries must also come back with something. Without that,
    "it did not raise" passes a block whose filter matches nobody, and a reader
    copying it would see an empty list where the prose promised people."""
    line, source = example
    namespace: dict[str, object] = {"__name__": "readme_example"}
    try:
        exec(compile(source, f"README.md:{line}", "exec"), namespace)
    except Exception as exc:
        pytest.fail(f"README.md:{line} raised {type(exc).__name__}: {exc}")

    if "LDAPSearch(" in source:
        assert documented_site.consumed > 0, (
            f"README.md:{line} opened a search but the directory handed back nothing; "
            "the example's filters match none of the fixture's entries"
        )


@pytest.mark.parametrize(
    "invocation", ADSEARCH_COMMANDS, ids=lambda invocation: f"line-{invocation[0]}"
)
def test_every_documented_command_parses(invocation: tuple[int, str]):
    """Argparse is the arbiter: it rejects an unknown subcommand, an unknown
    flag, and a flag offered on a subcommand that does not take it."""
    line, command = invocation
    argv = shlex.split(command)[1:]
    try:
        cli.build_parser().parse_args(argv)
    except SystemExit as exc:
        pytest.fail(f"README.md:{line} does not parse: `{command}` (exit {exc.code})")


def test_every_cli_flag_is_documented():
    """The direction a README goes stale in: a flag added to the CLI and never
    written down. The opposite direction needs no test, since argparse rejects
    an undocumented flag in `test_every_documented_command_parses`."""
    text = readme_text()
    undocumented = sorted(flag for flag in defined_flags() if flag not in text)
    assert not undocumented


def test_every_subcommand_is_documented():
    """Both directions at once: a subcommand the README never shows, and a
    README still showing one the CLI dropped.

    The subcommand is the first token that names one rather than simply the
    first token, because `--debug` and `--insecure` are accepted *before* the
    subcommand and one example shows them there."""
    defined = set(subcommand_action().choices)
    documented = set()
    for _, command in ADSEARCH_COMMANDS:
        named = [token for token in shlex.split(command)[1:] if token in defined]
        assert named, f"`{command}` names no subcommand"
        documented.add(named[0])
    assert defined == documented


def test_the_documented_default_format_is_the_real_default():
    """A claim no example catches, since both flags exist and both parse."""
    flagged = re.findall(r"`--(table|csv|json)`\s*\(default\)", readme_text())
    assert len(flagged) == 1, f"expected exactly one format flag marked default, got {flagged}"
    assert flagged[0] == cli.build_parser().parse_args(["employee", "12345678"]).fmt


def test_the_documented_install_tag_matches_the_package_version():
    """The install command pins a tag, so the tag it names has to be the
    version this package builds as — otherwise the documented install either
    fails or quietly delivers a different library."""
    version = pyproject()["project"]["version"]
    pinned = set(re.findall(r"git\+[^\s\"']+@v([0-9][^\s\"']*)", readme_text()))
    assert pinned == {version}


def test_the_documented_exit_codes_are_the_real_ones():
    """Every row of the README's exit-code table, against the list DESIGN §6.4
    publishes rather than against `cli`'s own map."""
    rows = re.findall(r"^\|\s*(\d+)\s*\|\s*`?(\w+)`?\s*\|", readme_text(), re.MULTILINE)
    documented = {name: int(code) for code, name in rows}
    expected = {error.__name__: code for error, code in DOCUMENTED_CODES}
    assert documented == expected


def test_the_documented_python_floor_is_the_declared_one():
    """Development happens above the floor, so the floor is a claim about
    untested ground unless the README and the metadata agree on it."""
    floor = pyproject()["project"]["requires-python"].lstrip(">=")
    assert f"Python {floor}" in readme_text()


def test_the_readme_describes_the_disabled_account_split_correctly():
    """The README claims a specific asymmetry, and claimed the opposite before.

    Excluding disabled accounts is a `find_users` criterion (DESIGN §8.5), so
    `direct_reports` and `reporting_tree` — which take no `include_disabled` —
    return them, while `find_users` and `by_group` drop them by default. The
    prose is checked against the library here because no runnable example can:
    an example only shows what it asks for, never what the default did to the
    rows it never mentions."""
    ad, _connection = searcher_for(
        documented_directory(), config=LDAPConfig(server=SERVER, base_dn=BASE_DN)
    )

    def usernames(users: list) -> list[str]:
        return sorted(person["username"] for person in users)

    # The two manager walks return the disabled report.
    assert "dawn" in usernames(ad.direct_reports("jdoe"))
    assert "dawn" in usernames(ad.reporting_tree("jdoe"))

    # The one-hop search the README offers instead drops it.
    assert "dawn" not in usernames(ad.find_users(manager_dn=ad.resolve_user_dn("jdoe")))

    # Group membership drops the disabled member unless asked.
    assert "eze" not in usernames(ad.by_group("Some Group Name"))
    assert "eze" in usernames(ad.by_group("Some Group Name", include_disabled=True))

    text = readme_text()
    assert "**Both return disabled accounts.**" in text
    assert "Disabled accounts are excluded unless you pass `include_disabled=True`" in text
