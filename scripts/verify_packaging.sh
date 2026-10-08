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
# Usage:
#   scripts/verify_packaging.sh                      # local repo, tag v<version>
#   scripts/verify_packaging.sh --ref main           # some other ref
#   scripts/verify_packaging.sh --remote             # the README's GitHub URL
#   scripts/verify_packaging.sh --url <git-url>      # an explicit source
#
# Defaults to the local repository so the documented install path can be
# verified before the tag is pushed. `--remote` is the post-push check.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname -- "$SCRIPT_DIR")"
PYPROJECT="$REPO_ROOT/pyproject.toml"
README="$REPO_ROOT/README.md"

VERSION="$(sed -n 's/^version = "\(.*\)"$/\1/p' "$PYPROJECT" | head -1)"
FLOOR="$(sed -n 's/^requires-python = ">=\(.*\)"$/\1/p' "$PYPROJECT" | head -1)"

if [[ -z "$VERSION" || -z "$FLOOR" ]]; then
    echo "could not read version and requires-python from $PYPROJECT" >&2
    exit 1
fi

REF="v$VERSION"
URL=""
REMOTE=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --ref)    REF="$2"; shift 2 ;;
        --url)    URL="$2"; shift 2 ;;
        --remote) REMOTE=1; shift ;;
        --python) FLOOR="$2"; shift 2 ;;
        -h|--help) sed -n '3,30p' "${BASH_SOURCE[0]}" | sed 's/^# \?//'; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

if [[ -z "$URL" ]]; then
    if [[ "$REMOTE" == 1 ]]; then
        # The URL the README tells a consumer to use, read from the README so
        # the two cannot drift.
        URL="$(grep -o 'git+https://[^"@]*' "$README" | head -1)"
        if [[ -z "$URL" ]]; then
            echo "no git+https URL found in $README" >&2
            exit 1
        fi
    else
        # The local repository, reached as a git URL so the install exercises
        # clone-build-install rather than a path install. Linked worktrees
        # share one object store, so the common dir is the clone source.
        GIT_COMMON="$(git -C "$REPO_ROOT" rev-parse --path-format=absolute --git-common-dir)"
        URL="git+file://$(dirname -- "$GIT_COMMON")"
    fi
fi

for tool in uv git pyright; do
    command -v "$tool" >/dev/null || { echo "$tool is required but not installed" >&2; exit 1; }
done

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

VENV="$WORK/venv"
PY="$VENV/bin/python"
CONSUMER="$WORK/consumer_check.py"

step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }

echo "adsearch $VERSION — packaging verification"
echo "  source:  $URL@$REF"
echo "  floor:   Python $FLOOR"
echo "  workdir: $WORK  (not the repo root: $REPO_ROOT)"

step "1/4  Install from the git URL at the pinned ref, on Python $FLOOR"
uv venv --python "$FLOOR" "$VENV" >/dev/null
# `cd` into the temp directory first: an install run from the repo root could
# pick the local tree up through the build backend or a stray .pth file.
cd "$WORK"
uv pip install --python "$PY" --quiet "adsearch @ ${URL}@${REF}"
"$PY" -c 'import adsearch; print("installed", adsearch.__name__)'

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
# `adsearch` is unresolved, every expression below becomes `Any`, and
# `assert_type` fails.
cat >"$WORK/pyrightconfig.json" <<'JSONEOF'
{
  "useLibraryCodeForTypes": false
}
JSONEOF
# Run from $WORK, so pyright resolves `adsearch` through the installed package
# rather than through the repo's source tree.
pyright --pythonpath "$PY" --outputjson "$CONSUMER" >"$WORK/pyright.json" || true
"$PY" - "$WORK/pyright.json" <<'PYEOF'
import json
import sys

report = json.loads(open(sys.argv[1]).read())
errors = [d for d in report.get("generalDiagnostics", []) if d.get("severity") == "error"]
for diagnostic in errors:
    line = diagnostic.get("range", {}).get("start", {}).get("line", 0) + 1
    print(f"  line {line}: {diagnostic.get('rule', 'error')}: {diagnostic['message']}")
if errors:
    print(f"{len(errors)} type error(s) against the installed package", file=sys.stderr)
    raise SystemExit(1)
print("pyright: 0 errors with useLibraryCodeForTypes off — py.typed survived the build")
PYEOF

step "4/4  Run the full test suite on Python $FLOOR"
# A separate environment outside the repo, so the project's own .venv — which
# development runs above the floor on — is left alone.
cd "$REPO_ROOT"
UV_PROJECT_ENVIRONMENT="$WORK/floor" uv sync --quiet --python "$FLOOR" --all-groups
"$WORK/floor/bin/python" -m pytest -q

printf '\n\033[1mall four checks passed\033[0m — adsearch %s installs, imports, type-checks and tests clean on Python %s\n' "$VERSION" "$FLOOR"
