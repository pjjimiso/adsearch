# adsearch

A Python library for querying Active Directory over LDAP: given an employee ID, a manager's
username, a cost center, or a group, get back a list of users.

`adsearch` ships as an importable library first. A thin console script (`adsearch`) is included for
schema discovery and debugging.

Supply your directory's topology via `LDAPConfig` and your schema via `AttributeMap`; anything
specific to your organization (e.g. how to tell an employee from a contractor) is derived by your own
code from the raw attributes this library returns.

## Install

Requires Python 3.12 or newer.

`adsearch` is distributed as a git dependency, pinned to a tag:

```bash
uv add "adsearch @ git+https://github.com/pjjimiso/adsearch.git@v0.1.0"
```

or with pip:

```bash
pip install "adsearch @ git+https://github.com/pjjimiso/adsearch.git@v0.1.0"
```

Pin a tag rather than a branch. A consumer tracking `main` gets silently rebuilt behaviour on every
push.

## Quick start

```python
from adsearch import LDAPConfig, LDAPSearch

with LDAPSearch(LDAPConfig.from_env()) as ad:
    for person in ad.direct_reports("jdoe"):
        print(person["name"], person["email"])
```

`with` is the supported form. A `LDAPSearch` opens its connection on first use and unbinds on the
way out of the block, whether the block returns or raises; left to garbage collection instead, open
sockets accumulate against the domain controller's connection limit.

A `User` is a `TypedDict`, so every field is a key rather than an attribute: `dn`, `name`,
`employee_id`, `username`, `email`, and `attributes`. The last one carries every attribute that was
requested, including any your `AttributeMap` doesn't name directly:

```python
from adsearch import LDAPConfig, LDAPSearch

with LDAPSearch(LDAPConfig.from_env()) as ad:
    for person in ad.find_users(cost_center="1234"):
        print(person["attributes"].get("departmentNumber"))
```

## Configuration

`LDAPConfig` has no defaults for `server` or `base_dn`. Build one from environment variables:

```python
from adsearch import LDAPConfig

config = LDAPConfig.from_env()
```

| Variable | Required | Notes |
|---|---|---|
| `ADSEARCH_SERVER` | yes | e.g. `ldaps://dc.example.com` |
| `ADSEARCH_BASE_DN` | yes | e.g. `DC=example,DC=com` |
| `ADSEARCH_GROUP_BASE_DN` | no | falls back to `ADSEARCH_BASE_DN` when unset |
| `ADSEARCH_BIND_USER` | no | service-account UPN or DN |
| `ADSEARCH_BIND_PASSWORD` | no | prefer a secrets manager / vault over a plain env var where possible |
| `ADSEARCH_CA_CERTS` | no | path to an internal CA bundle, if your DC's cert isn't in the system trust store |

`from_env` raises `LDAPConfigError` when `ADSEARCH_SERVER` or `ADSEARCH_BASE_DN` is missing, and
reads no other variables — everything else is a constructor argument:

```python
from adsearch import LDAPConfig

config = LDAPConfig(
    server="ldaps://dc.example.com",
    base_dn="DC=example,DC=com",
    bind_user="svc-adsearch@example.com",
    bind_password="…",            # read this from a secrets manager, not a literal
    page_size=1000,               # entries per page; paging is always on
    batch_size=500,               # manager DNs per query when walking a reporting tree
    connect_timeout=10,
    receive_timeout=60,
    time_limit=120,
)
```

Binds are SIMPLE, which sends the password in cleartext, so **setting `bind_password` requires
`use_ssl=True`** — the default. Constructing a config with a password and `use_ssl=False` raises
`LDAPConfigError` rather than binding. Setting `validate_cert=False` is allowed but warns: it is a
first-contact debugging escape hatch, not a production setting.

## Finding your attribute names

Active Directory attribute names vary by site. Rather than guessing, use the CLI's discovery
commands against your own directory before writing an `AttributeMap`:

```bash
adsearch server-info
adsearch describe --username jdoe
```

- `server-info` confirms your bind and TLS configuration work, before you worry about query
  semantics.
- `describe` dumps every populated attribute for one real user — far more useful than the full AD
  schema, which lists thousands of attributes that are *defined* but tells you nothing about which
  ones are actually *populated* at your site. Pass it a username you know exists, or
  `--employee-id` if that is what you have.

The same two operations are available on the library:

```python
from adsearch import LDAPConfig, LDAPSearch

with LDAPSearch(LDAPConfig.from_env()) as ad:
    print(ad.server_info())
    for name, value in ad.describe_user("jdoe").items():
        print(name, value)
```

`describe_user` looks up by `sAMAccountName` unless you pass `by="someOtherAttribute"`, and raises
`NotFoundError` on zero matches *and* on more than one — pointed at a one-to-many attribute it would
otherwise show one person's data labelled as another's.

Once you know your real attribute names, build an `AttributeMap` and pass it in:

```python
from adsearch import AttributeMap, LDAPConfig, LDAPSearch

schema = AttributeMap(
    employee_id="employeeNumber",
    cost_center="extensionAttribute3",
    extra=("employeeType", "title"),   # additional attributes to return in User["attributes"]
)

with LDAPSearch(LDAPConfig.from_env(), attrs=schema) as ad:
    reports = ad.direct_reports("jdoe")
```

The fields an `AttributeMap` names are `name`, `cn`, `employee_id`, `username`, `upn`, `mail`,
`manager`, `member_of`, `cost_center`, and `extra`. The defaults are standard AD / inetOrgPerson
names and are a reasonable starting guess anywhere, but should still be verified per site —
especially `cost_center`, which is very commonly a site-specific extension attribute rather than the
default `departmentNumber`.

## Direct reports and the reporting tree

Active Directory stores a person's manager as the manager's DN, not as an ID, so every manager query
is two steps: resolve a person to a DN, then search on that DN. Both operations therefore take a
**username**, the one-to-one resolve key — not an employee ID, which matches any number of entries
at most sites.

```python
from adsearch import LDAPConfig, LDAPSearch

with LDAPSearch(LDAPConfig.from_env()) as ad:
    direct = ad.direct_reports("jdoe")       # one hop, one query
    everyone = ad.reporting_tree("jdoe")     # every depth, one query per level
    manager_dn = ad.resolve_user_dn("jdoe")
```

`direct_reports` is one hop. `reporting_tree` walks breadth-first until a level yields nobody new,
issuing one query per level (per `batch_size` managers within a level) rather than asking the
directory to resolve the whole tree in one filter — see
[ADR-0001](docs/adr/0001-bfs-over-in-chain.md) for the measurements behind that. Full depth is
opt-in, by choosing the method.

**Both return disabled accounts.** Excluding them is a `find_users` criterion, and these two
wrappers take no `include_disabled` parameter, so they have no criterion to opt out of. If you want
direct reports with disabled accounts dropped, ask for the one-hop search instead, which applies the
default exclusion:

```python
from adsearch import LDAPConfig, LDAPSearch

with LDAPSearch(LDAPConfig.from_env()) as ad:
    manager_dn = ad.resolve_user_dn("jdoe")
    enabled_only = ad.find_users(manager_dn=manager_dn)       # disabled dropped
    including_disabled = ad.direct_reports("jdoe")            # disabled returned
```

## Group membership

A group is named either by its DN or by the common name a human would use. A name that doesn't parse
as a DN is searched for under `ADSEARCH_GROUP_BASE_DN` (falling back to `ADSEARCH_BASE_DN`), and a
name matching more than one group raises `NotFoundError` rather than picking one:

```python
from adsearch import LDAPConfig, LDAPSearch

with LDAPSearch(LDAPConfig.from_env()) as ad:
    members = ad.by_group("Some Group Name")                    # transitive
    direct = ad.by_group("Some Group Name", transitive=False)   # direct members only
    audited = ad.by_group("Some Group Name", include_disabled=True)
    dn = ad.resolve_group_dn("Some Group Name")
```

**Membership is transitive by default**: anyone who holds the group through a nested group is
included. This is the opposite of `reporting_tree`, where full depth is opt-in, and the asymmetry is
deliberate. The question a group answers is "who actually holds this access", and a nested group
silently hiding a member is the wrong answer that matters in an audit.

Members are found by filtering users on their group-membership attribute rather than by reading the
group's `member` attribute. Reading `member` would hit Active Directory's cap on multi-valued reads,
return bare DNs needing a follow-up lookup each, and mix group objects in among the people. The
search itself is paged, so a group larger than the directory's page size returns every member rather
than truncating. Disabled accounts are excluded unless you pass `include_disabled=True` — a disabled
account still in a privileged group is itself an audit finding.

**Caveat: membership implied by `primaryGroupID` is not reflected.** Active Directory stores a user's
primary group as an integer RID on the user rather than as a membership link, so neither `member` nor
`memberOf` reports it. In practice this affects only Domain Users and is usually ignorable, but it is
recorded here so that it isn't rediscovered mid-audit.

## Searching on anything else

The named wrappers above are conveniences over one general operation. `find_users` takes every
criterion as a keyword and ANDs together the ones you supply, so there is no `by_employee_id` or
`by_cost_center` — there is this:

```python
from adsearch import LDAPConfig, LDAPSearch

with LDAPSearch(LDAPConfig.from_env()) as ad:
    matches = ad.find_users(
        cost_center="1234",
        name_contains="Lee",
        include_disabled=True,
        attributes=("title",),       # added to the map's attributes, not a replacement
        limit=50,
    )
```

The criteria are `employee_id`, `username`, `name_contains`, `cost_center`, `manager_dn`,
`group_dn`, `transitive`, `include_disabled`, `base_dn`, `extra_filter`, `attributes`, and `limit`.
They are spelled out rather than taken as `**kwargs`, so a mistyped name raises instead of being
silently ignored. `manager_dn` is direct reports only; `reporting_tree` is the walk.

An empty result is a valid answer. Zero matches means nobody qualified, not that something failed.

For a criterion the keywords don't cover, `extra_filter` takes one raw LDAP clause. Build it with the
helpers in `adsearch.filters`, which escape values for you — they are importable from that module
but deliberately not re-exported at the top level, because they exist for this case rather than for
everyday use:

```python
from adsearch import LDAPConfig, LDAPSearch
from adsearch.filters import eq

with LDAPSearch(LDAPConfig.from_env()) as ad:
    contractors = ad.find_users(
        cost_center="1234",
        extra_filter=eq("employeeType", "Contractor"),
    )
```

## Error handling

Catch `LDAPSearchError` to handle any failure from this library in one place:

```python
from adsearch import LDAPConfig, LDAPSearch, LDAPSearchError

try:
    with LDAPSearch(LDAPConfig.from_env()) as ad:
        matches = ad.find_users(employee_id="12345678")
except LDAPSearchError as exc:
    print(f"lookup failed: {exc}")
```

More specific subclasses are available if you need to distinguish, for example, a bad bind from a
query that rests on a premise that doesn't exist:

| Exception | Raised for |
|---|---|
| `LDAPConfigError` | Missing required fields or env vars, or a bind password without TLS |
| `LDAPAuthError` | The server rejected the bind: bad credentials, locked account, expired password |
| `LDAPConnectionError` | DNS, TCP connect, TLS handshake, or a timeout reaching the server |
| `LDAPQueryError` | A rejected query: a malformed filter, DN or attribute name — whether this library rejected it before sending, or the server did — plus a size or time limit exceeded |
| `NotFoundError` | A resolve step that must return exactly one entry returned zero, or more than one |

Everything `ldap3` raises is translated into one of these at the boundary, so a consumer never has
to catch an `ldap3` exception or depend on that package directly.

An empty result (`[]`) is not an error — it's a valid answer meaning nobody matched. `NotFoundError`
is reserved for a resolve step that must succeed but returned zero, or ambiguously more than one,
match.

### Exit codes

Exit codes belong to the console script, not the library: nothing in `adsearch` the library knows
about them. The script exits `0` on success, `1` on an unexpected failure (a bug in this tool), and
`2` on a usage error. The five library failures get codes of their own, so a shell caller can tell a
bad password from no such user without parsing stderr:

| Code | Exception |
|---|---|
| 3 | `LDAPConfigError` |
| 4 | `LDAPAuthError` |
| 5 | `LDAPConnectionError` |
| 6 | `LDAPQueryError` |
| 7 | `NotFoundError` |

A consumer's own subclass of one of the five exits with the code it inherits. Failures are written to
stderr as `TypeName: message`, never to stdout, with the traceback only under `--debug`.

## CLI usage

The console script is a thin wrapper for discovery and debugging. Seven subcommands:

```bash
adsearch employee 12345678
adsearch manager jdoe
adsearch manager jdoe --all-reports
adsearch cost-center 1234
adsearch group "Some Group Name" --no-transitive
adsearch describe --employee-id 12345678
adsearch resolve-dn --username jdoe
adsearch resolve-dn --group "Some Group Name"
adsearch server-info
```

- `employee`, `cost-center` and `group` take their value as a positional argument; `manager` takes a
  **username**, since resolving the manager to a DN needs a one-to-one key.
- `manager --all-reports` walks the whole reporting tree instead of one hop, and `manager` prints how
  many reports were found beneath the result — which is what tells you a short answer from an empty
  one.
- `group --no-transitive` asks for direct members only. Without it, membership through nested groups
  is included, matching the library default.
- `cost-center` keys on whatever the attribute map's `cost_center` names, which defaults to
  `departmentNumber`. That default is a low-confidence guess; verify it for your site first.
- `describe` and `resolve-dn` take exactly one required selector rather than a positional value,
  because which attribute the value names would otherwise be ambiguous: `--username` or
  `--employee-id`, plus `--group` for `resolve-dn`. These resolve through the library's own default
  attribute names (`sAMAccountName`, `employeeID`) — the CLI has no way to take an `AttributeMap`,
  which is consistent with discovery running *before* one is confirmed correct.

Output format is `--table` (default), `--csv`, or `--json`, accepted after the subcommand on any of
the four search subcommands:

```bash
adsearch employee 12345678 --csv
adsearch group "Some Group Name" --json --include-disabled
adsearch cost-center 1234 --raw --attributes employeeType,title
adsearch --debug --insecure employee 12345678
```

| Flag | Where | Meaning |
|---|---|---|
| `--table` / `--csv` / `--json` | search subcommands | Output format; table is the default |
| `--raw` | search subcommands | The unmapped directory response as JSON, bypassing the `User` mapper. Always JSON, since a raw attribute set has no fixed columns |
| `--attributes a,b,c` | search subcommands | Extra attributes to return, added to the map's own |
| `--include-disabled` | `employee`, `cost-center`, `group` | Include disabled accounts. Not offered on `manager`, which has no criterion to opt out of |
| `--no-transitive` | `group` | Direct members only |
| `--all-reports` | `manager` | Walk the reporting tree instead of one hop |
| `--username` / `--employee-id` / `--group` | `describe`, `resolve-dn` | The one required selector |
| `--debug` | anywhere | Print the traceback on failure, not just the message |
| `--insecure` | anywhere | Skip TLS certificate validation. A first-contact debugging escape hatch, never for production |

`--debug` and `--insecure` are accepted on either side of the subcommand. `describe`, `resolve-dn`
and `server-info` take those two and nothing else — the format flags are offered only on the four
search subcommands, so `adsearch describe --username jdoe --json` is a usage error (exit `2`) rather
than a flag that gets ignored. `describe` always prints JSON, since its field set varies per user.
Run `adsearch --help`, or `adsearch <subcommand> --help`, for the generated list.

## What this library does not do

- No CSV/table output, no `print`, no `sys.exit` *in the library* — that's your own application's
  job, and the console script's. Nothing under `adsearch` outside `cli.py` writes to a stream or
  owns the process.
- No retry-with-backoff — failures are raised immediately; retry policy is the caller's decision.
- No organization-specific classification (e.g. employee vs. contractor) — build that on top of
  `User["attributes"]` in your own code.
- No reading of `member` on a group, and no `primaryGroupID` membership. See
  [Group membership](#group-membership).

## Development

```bash
uv sync
uv run pytest
```

Type-check with the virtualenv's interpreter, so `ldap3` resolves:

```bash
pyright --pythonpath .venv/bin/python
```

Packaging is verified from outside the repository — installed from a git URL into a temp directory
that is not the repo root, against the lowest Python version the package declares, with a consumer
script that must type-check:

```bash
scripts/verify_packaging.sh                                  # the release tag
scripts/verify_packaging.sh --ref my-branch                  # a branch, before the tag exists
scripts/verify_packaging.sh --remote                         # the published GitHub URL
```

Every step installs or checks out one git ref, and that ref has to resolve to `HEAD`. A ref pointing
anywhere else would install, import and type-check a tree unrelated to your working copy and then
report success, so it is refused rather than warned about — pass `--ref` with the branch you are on
while the release tag still points elsewhere. Uncommitted files are named in the closing summary,
since no step can see them.

The design rationale behind every choice above lives in [docs/DESIGN.md](docs/DESIGN.md), the
vocabulary in [CONTEXT.md](CONTEXT.md), and the manager-traversal measurements in
[docs/adr/0001-bfs-over-in-chain.md](docs/adr/0001-bfs-over-in-chain.md).
