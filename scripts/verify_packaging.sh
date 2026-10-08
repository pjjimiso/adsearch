#!/usr/bin/env bash
#
# Verify that `adsearch` installs and type-checks the way the README says it
# does (#14, DESIGN §11).
#
# Four things the repo's own test suite cannot check, because it imports the
# source tree rather than a built package:
#
#   1. Installing from a *git URL pinned to a tag* — the documented install.
#   2. Importing the installed package from a directory that is not the repo
#      root, so an `src`-layout mistake cannot hide behind the local tree.
#   3. Type-checking a consumer script against the installed package, which is
#      the only way to confirm `py.typed` survived the build.
#   4. Running the full test suite on the lowest Python version the package
#      declares, since development happens above that floor.
#
# Every step verifies ONE git ref, and that ref must be the commit you are
# sitting on unless you say otherwise — see `assert_ref_is_head`.

set -euo pipefail

usage() {
    cat <<'USAGE'
Verify adsearch's packaging from outside the repository.

Usage:
  scripts/verify_packaging.sh                    Local repo at tag v<version>
  scripts/verify_packaging.sh --ref <git-ref>    A branch, tag or SHA instead
  scripts/verify_packaging.sh --remote           The README's GitHub URL (post-push)
  scripts/verify_packaging.sh --allow-stale-ref  Permit a ref that is not HEAD

Defaults to the local repository, so the documented install path can be
verified before the tag is pushed. `--remote` is the post-push check.

The ref must resolve to HEAD. A ref pointing elsewhere would install, import
and type-check a tree unrelated to your working copy and report success, so it
is refused rather than warned about. `--allow-stale-ref` is for deliberately
checking an older release.
USAGE
}

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname -- "$SCRIPT_DIR")"
PYPROJECT="$REPO_ROOT/pyproject.toml"
README="$REPO_ROOT/README.md"

# `sed` rather than `tomllib`: these two values are needed to pick the
# interpreter, so they must be read before any interpreter is available, and
# this platform has no system `python3` at all. The regexes are anchored and
# the results format-checked below, so a `pyproject.toml` reformat fails loudly
# here instead of yielding an empty version.
VERSION="$(sed -n 's/^version = "\([^"]*\)"$/\1/p' "$PYPROJECT" | head -1)"
FLOOR="$(sed -n 's/^requires-python = ">=\([^"]*\)"$/\1/p' "$PYPROJECT" | head -1)"

if [[ ! "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+ ]]; then
    echo "could not read a version from $PYPROJECT (got '${VERSION}')" >&2
    exit 1
fi
if [[ ! "$FLOOR" =~ ^[0-9]+\.[0-9]+$ ]]; then
    echo "could not read requires-python from $PYPROJECT (got '${FLOOR}')" >&2
    exit 1
fi

REF="v$VERSION"
REMOTE=0
ALLOW_STALE=0

# `$2` is checked rather than assumed: under `set -u` a bare `--ref` would
# otherwise abort with "unbound variable" instead of a usage error.
need_value() {
    if [[ $# -lt 2 || -z "$2" ]]; then
        echo "$1 needs a value" >&2
        exit 2
    fi
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --ref)             need_value "$@"; REF="$2"; shift 2 ;;
        --remote)          REMOTE=1; shift ;;
        --allow-stale-ref) ALLOW_STALE=1; shift ;;
        -h|--help)         usage; exit 0 ;;
        *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
    esac
done

for tool in uv git pyright; do
    command -v "$tool" >/dev/null || { echo "$tool is required but not installed" >&2; exit 1; }
done

if [[ "$REMOTE" == 1 ]]; then
    # The URL out of the README's own install command, so the two cannot
    # drift. Anchored on `git+https://` up to the `@` that introduces the tag,
    # and the `.git` is kept: stripping at `@` and re-appending `$REF` would
    # silently discard whichever tag the README documents.
    CLONE_URL="$(grep -oE 'git\+https://[^"@[:space:]]+\.git' "$README" | head -1 | sed 's/^git+//')"
    if [[ -z "$CLONE_URL" ]]; then
        echo "no git+https://….git URL found in $README" >&2
        exit 1
    fi
else
    # The local repository, reached as a git URL so the install exercises
    # clone-build-install rather than a path install. Linked worktrees share
    # one object store, so the common dir's parent is the clone source.
    GIT_COMMON="$(git -C "$REPO_ROOT" rev-parse --path-format=absolute --git-common-dir)"
    CLONE_URL="file://$(dirname -- "$GIT_COMMON")"
fi

assert_ref_is_head() {
    # The failure this exists to prevent: `$REF` defaults to a version tag, and
    # a tag can point anywhere — at an abandoned branch, or at a release from
    # before the change you are verifying. Steps 1-3 would then install, import
    # and type-check that unrelated tree, pass, and print "all checks passed"
    # about code you never touched.
    local at head
    if ! at="$(git -C "$REPO_ROOT" rev-list -n1 "$REF" 2>/dev/null)"; then
        if [[ "$REMOTE" == 1 ]]; then
            echo "  note: $REF does not resolve locally; cannot compare it to HEAD"
            return 0
        fi
        echo "ref '$REF' does not resolve in $REPO_ROOT." >&2
        echo "Cut the tag first, or pass --ref with a branch or SHA." >&2
        exit 1
    fi
    head="$(git -C "$REPO_ROOT" rev-parse HEAD)"
    if [[ "$at" == "$head" ]]; then
        echo "  ref:     $REF -> $at (= HEAD)"
        return 0
    fi
    if [[ "$ALLOW_STALE" == 1 ]]; then
        echo "  ref:     $REF -> $at (NOT HEAD $head; allowed by --allow-stale-ref)"
        return 0
    fi
    cat >&2 <<EOF

refusing to verify a ref that is not HEAD.

  $REF resolves to  $at
  HEAD is           $head

Steps 1-3 install and check out whatever '$REF' points at, so this run would
report on that tree and not on your working copy. Either move the tag to HEAD,
pass --ref with the ref you actually mean, or pass --allow-stale-ref if you
really are checking an older release.
EOF
    git -C "$REPO_ROOT" log -1 --format='  %H %ci%n  %s' "$at" >&2 || true
    exit 1
}

# Every step installs or checks out a committed ref, so anything still
# uncommitted is invisible to this run. Counted and reported rather than
# refused — refusing would block the normal "verify before committing" loop —
# but the closing banner names it, so a green run cannot be read as covering
# edits it never saw.
DIRTY="$(git -C "$REPO_ROOT" status --porcelain | wc -l | tr -d ' ')"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

VENV="$WORK/venv"
PY="$VENV/bin/python"
CONSUMER="$WORK/consumer_check.py"
CHECKOUT="$WORK/src"

step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }

echo "adsearch $VERSION — packaging verification"
echo "  source:  git+${CLONE_URL}@${REF}"
echo "  floor:   Python $FLOOR"
echo "  workdir: $WORK  (not the repo root: $REPO_ROOT)"
assert_ref_is_head
if [[ "$DIRTY" != 0 ]]; then
    printf '\033[1m  warning: %s uncommitted file(s) in %s are NOT covered by this run\033[0m\n' \
        "$DIRTY" "$REPO_ROOT"
fi

step "1/4  Install from the git URL at the pinned ref, on Python $FLOOR"
uv venv --python "$FLOOR" "$VENV" >/dev/null
# `cd` into the temp directory first: an install run from the repo root could
# pick the local tree up through the build backend or a stray .pth file.
cd "$WORK"
uv pip install --python "$PY" --quiet "adsearch @ git+${CLONE_URL}@${REF}"
"$PY" -c 'import adsearch; print("installed adsearch", adsearch.__name__)'

step "2/4  Import and exercise the installed package from $WORK"
cp "$SCRIPT_DIR/consumer_check.py" "$CONSUMER"
# The console script is part of the distribution, so a broken entry point is a
# packaging failure like any other.
"$VENV/bin/adsearch" --help >/dev/null
echo "console script: ok"
"$PY" "$CONSUMER"

step "3/4  Type-check the consumer script against the installed package"
# `useLibraryCodeForTypes` is pyright's default and must be turned off here.
# Left on, pyright infers types from an installed package's .py files whether
# or not it shipped `py.typed`, so this step passes a wheel that a PEP
# 561-respecting consumer sees as untyped — verified by deleting the marker and
# watching the check stay green. Off, the marker is load-bearing: without it
# `adsearch` is unresolved, every expression in the consumer becomes `Any`, and
# `assert_type` fails.
cat >"$WORK/pyrightconfig.json" <<'JSONEOF'
{
  "useLibraryCodeForTypes": false
}
JSONEOF
# pyright exits non-zero both when it finds type errors and when it fails to
# run at all, so the exit code alone cannot tell those apart. The JSON report
# is the discriminator: no parseable report means pyright itself broke.
PYRIGHT_STATUS=0
pyright --pythonpath "$PY" --outputjson "$CONSUMER" >"$WORK/pyright.json" || PYRIGHT_STATUS=$?
if [[ ! -s "$WORK/pyright.json" ]]; then
    echo "pyright produced no report (exit $PYRIGHT_STATUS) — it failed to run, rather than finding errors" >&2
    exit 1
fi
"$PY" - "$WORK/pyright.json" "$PYRIGHT_STATUS" <<'PYEOF'
import json
import sys

path, status = sys.argv[1], sys.argv[2]
try:
    with open(path) as handle:
        report = json.load(handle)
except json.JSONDecodeError as exc:
    raise SystemExit(f"pyright wrote an unparseable report (exit {status}): {exc}")

errors = [d for d in report.get("generalDiagnostics", []) if d.get("severity") == "error"]
for diagnostic in errors:
    line = diagnostic.get("range", {}).get("start", {}).get("line", 0) + 1
    print(f"  line {line}: {diagnostic.get('rule', 'error')}: {diagnostic['message']}")
if errors:
    raise SystemExit(f"{len(errors)} type error(s) against the installed package")
print("pyright: 0 errors with useLibraryCodeForTypes off — py.typed survived the build")
PYEOF

step "4/4  Run the full test suite at $REF on Python $FLOOR"
# A clone of the same ref, not the working tree: running the repo's own pytest
# here would test local edits rather than the commit steps 1-3 installed, and
# would also walk back into the repo root this script exists to stay out of.
# Tests are not shipped in the wheel, so they have to come from a checkout.
git clone --quiet --no-checkout "$CLONE_URL" "$CHECKOUT"
git -C "$CHECKOUT" checkout --quiet "$REF"
cd "$CHECKOUT"
UV_PROJECT_ENVIRONMENT="$WORK/floor" uv sync --quiet --python "$FLOOR" --all-groups
"$WORK/floor/bin/python" -m pytest -q

printf '\n\033[1mall four checks passed\033[0m — adsearch %s at %s installs, imports, type-checks and tests clean on Python %s\n' \
    "$VERSION" "$REF" "$FLOOR"
if [[ "$DIRTY" != 0 ]]; then
    printf '\033[1mbut %s uncommitted file(s) were not part of it\033[0m — commit and re-run to cover them\n' "$DIRTY"
fi
