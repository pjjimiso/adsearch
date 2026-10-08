"""README.md's examples, executed and parsed rather than trusted (#14).

The README is the library's only consumer-facing documentation, and every
example in it was false at some point: an import that did not resolve, a method
that was never written, a default output format that was not the default. A
block that runs here cannot drift from the API without this file going red.

Python blocks are executed against the in-memory directory of
`tests.fake_directory`, which is seeded with exactly the identifiers the README
names — `jdoe`, employee id `12345678`, cost center `1234`, and the group
`Some Group Name`. Renaming one in the README without renaming it here is
itself a failure, which is the point: the examples are checked against a
directory, not merely compiled.
"""

import argparse
import re
import shlex
import tomllib

from collections.abc import Iterator
from pathlib import Path
from typing import cast

import pytest

from ldap3 import Connection

import adsearch

from adsearch import cli
from adsearch.config import LDAPConfig

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


def documented_directory() -> FakeDirectory:
    """A directory holding every identifier the README's examples name.

    `jdoe` manages A Lee and B Ng, and A Lee manages C Oh, so the reporting
    tree is strictly larger than the direct reports — the distinction the
    README draws has to be visible for its example to mean anything. B Ng holds
    `Some Group Name` only through `Nested Group`, so transitive and direct
    membership differ too."""
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
        ),
        user(
            ALEE_DN,
            sAMAccountName="alee",
            displayName="A Lee",
            employeeID="22222222",
            mail="alee@example.com",
            departmentNumber="1234",
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
            manager=ALEE_DN,
        ),
    ]
    return FakeDirectory(*entries)


@pytest.fixture
def documented_site(monkeypatch: pytest.MonkeyPatch) -> FakeDirectory:
    """The environment and the connection factory a README example assumes.

    Every example reaches the directory through `LDAPConfig.from_env`, so the
    variables its own table documents are the ones set here. Patching
    `adsearch.search.open_connection` rather than passing a `connect=` factory
    is what lets the examples stay free of test seams: an example that named
    one would be documenting the test suite instead of the library."""
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


def code_blocks(language: str) -> Iterator[tuple[int, str]]:
    """Every fenced block of one language, with the line it starts on so a
    failure names a place in the file rather than an index."""
    text = readme_text()
    for match in re.finditer(r"^```(\w+)\n(.*?)^```", text, re.MULTILINE | re.DOTALL):
        if match.group(1) == language:
            line = text.count("\n", 0, match.start()) + 1
            yield line, match.group(2)


def python_blocks() -> list[tuple[int, str]]:
    return list(code_blocks("python"))


def adsearch_commands() -> list[tuple[int, str]]:
    """Every `adsearch …` invocation shown in a shell block.

    `--help` is excluded because argparse answers it by exiting, which says
    nothing about whether the command line was valid."""
    found = []
    for line, block in code_blocks("bash"):
        for offset, text in enumerate(block.splitlines()):
            command = text.strip()
            if command.startswith("adsearch ") and "--help" not in command:
                found.append((line + offset + 1, command))
    return found


def subcommand_action() -> argparse._SubParsersAction:
    """The CLI's subparser action, which is the only place the real list of
    subcommands and their flags can be read from."""
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


def test_readme_shows_at_least_one_example_of_each_kind():
    """A guard on the harness itself: a regex that silently matched nothing
    would make every test below vacuously pass."""
    assert len(python_blocks()) >= 5
    assert len(adsearch_commands()) >= 5


@pytest.mark.parametrize(
    "line, source",
    python_blocks(),
    ids=[f"line-{line}" for line, _ in python_blocks()],
)
def test_every_python_example_runs(line: int, source: str, documented_site: FakeDirectory):
    """Each block runs on its own, against a real — if in-memory — directory.

    Blocks are executed in a fresh namespace rather than a shared one, so an
    example that silently depends on a name defined by an earlier block fails
    here, the way it would for a reader who copied just that block."""
    namespace: dict[str, object] = {"__name__": "readme_example"}
    try:
        exec(compile(source, f"README.md:{line}", "exec"), namespace)
    except Exception as exc:
        pytest.fail(f"README.md:{line} raised {type(exc).__name__}: {exc}")


@pytest.mark.parametrize(
    "line, command",
    adsearch_commands(),
    ids=[f"line-{line}" for line, _ in adsearch_commands()],
)
def test_every_documented_command_parses(line: int, command: str):
    """Argparse is the arbiter: it rejects an unknown subcommand, an unknown
    flag, and a flag offered on a subcommand that does not take it."""
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
    README that still shows one the CLI dropped.

    The subcommand is the first token that names one rather than simply the
    first token, because `--debug` and `--insecure` are accepted *before* the
    subcommand and one example shows them there."""
    defined = set(subcommand_action().choices)
    documented = set()
    for _, command in adsearch_commands():
        named = [token for token in shlex.split(command)[1:] if token in defined]
        assert named, f"`{command}` names no subcommand"
        documented.add(named[0])
    assert defined == documented


def test_the_documented_default_format_is_the_real_default():
    """The README marked `--json` as the default while the CLI defaulted to
    `--table`, which is the kind of claim no example would have caught: both
    flags exist and both parse."""
    flagged = re.findall(r"`--(table|csv|json)`\s*\(default\)", readme_text())
    assert len(flagged) == 1, f"expected exactly one format flag marked default, got {flagged}"
    assert flagged[0] == cli.build_parser().parse_args(["employee", "12345678"]).fmt


def test_the_documented_install_tag_matches_the_package_version():
    """The install command pins a tag, so the tag it names has to be the
    version this package builds as — otherwise the documented install either
    fails or quietly delivers a different library."""
    pyproject = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    version = pyproject["project"]["version"]
    pinned = set(re.findall(r"git\+[^\s\"']+@v([0-9][^\s\"']*)", readme_text()))
    assert pinned == {version}


def test_the_documented_exit_codes_are_the_real_ones():
    """Every row of the README's exit-code table, checked against the map the
    CLI actually classifies with."""
    rows = re.findall(r"^\|\s*(\d+)\s*\|\s*`?(\w+)`?\s*\|", readme_text(), re.MULTILINE)
    documented = {name: int(code) for code, name in rows}

    for name, code in documented.items():
        exception = getattr(adsearch, name, None)
        if exception is None:
            continue
        assert cli.exit_code_for(exception("")) == code, name

    for exception_class, code in cli._EXIT_CODES.items():
        assert documented.get(exception_class.__name__) == code


def test_the_documented_python_floor_is_the_declared_one():
    """Development happens above the floor, so the floor is a claim about
    untested ground unless the README and the metadata agree on it."""
    pyproject = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    floor = pyproject["project"]["requires-python"].lstrip(">=")
    assert f"Python {floor}" in readme_text()
