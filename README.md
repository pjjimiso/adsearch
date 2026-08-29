# adsearch

A Python library for querying Active Directory over LDAP: given an employee ID, manager's employee ID, a cost center, or a group, get back a list of users.

`adsearch` ships as an importable library first. A thin console script (`adsearch`) is included for
schema discovery and debugging.

Supply your directory's topology via `LDAPConfig` and your schema via `AttributeMap`; 
anything specific to your organization (e.g. how to tell an employee from a contractor) is derived 
by your own code from the raw attributes this library returns.

## Install

`adsearch` is distributed as a git dependency, pinned to a tag:

```bash
uv add "adsearch @ git+https://github.com/pjjimiso/adsearch.git@v0.1.0"
```

or with pip:

```bash
pip install "adsearch @ git+https://github.com/pjjimiso/adsearch.git@v0.1.0"
```


## Quick start

```python
from adsearch import LDAPSearch, LDAPConfig

with LDAPSearch(LDAPConfig.from_env()) as ad:
    reports = ad.by_manager_id("12345678")
    for user in reports:
        print(user["name"], user["email"])
```

Every field an `AttributeMap` doesn't name directly is still available — a `User` carries an
`attributes` dict with everything that was requested:

```python
    for user in reports:
        print(user["attributes"].get("departmentNumber"))
```

## Configuration

`LDAPConfig` has no defaults for `server` or `base_dn`

Build a config from environment variables:

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

`LDAPConfig` requires TLS (`use_ssl=True`) whenever using SIMPLE bind auth 
since SIMPLE bind sends your password in cleartext otherwise.

## Finding your attribute names

Active Directory attribute names vary by site. Rather than guessing, use the CLI's discovery
commands against your own directory before writing an `AttributeMap`:

```bash
adsearch server-info
adsearch describe --employee-id <a known employee id>
```

- `server-info` confirms your bind and TLS configuration work, before you worry about query semantics.
- `describe` dumps every populated attribute for one real user — far more useful than the full AD
  schema, which lists thousands of attributes that are *defined* but tells you nothing about which ones
  are actually *populated* at your site.

Once you know your real attribute names, build an `AttributeMap` and pass it in:

```python
from adsearch import LDAPSearch, LDAPConfig, AttributeMap

schema = AttributeMap(
    employee_id="employeeNumber",
    cost_center="extensionAttribute3",
    extra=("employeeType",),  # any additional attribute you want back in User["attributes"]
)

with LDAPSearch(LDAPConfig.from_env(), attrs=schema) as ad:
    reports = ad.by_manager_id("12345678")
```

`AttributeMap`'s defaults are standard AD/inetOrgPerson names and are a reasonable starting guess
anywhere, but should still be verified per site — especially `cost_center`, which is very commonly a
site-specific extension attribute rather than the default `departmentNumber`.

## CLI usage

The console script is a thin wrapper for discovery and debugging:

```bash
adsearch employee 12345678
adsearch manager 12345678
adsearch cost-center 1234
adsearch group "Some Group Name"
adsearch describe --employee-id 12345678
adsearch server-info
adsearch resolve-dn --employee-id 12345678
```

Add `--json` (default), `--raw`, `--attributes a,b,c`, `--include-disabled`, `--no-transitive`, or
`--debug` as needed — run `adsearch --help` for the full list.

## Error handling

Catch `LDAPSearchError` to handle any failure from this library in one place:

```python
from adsearch import LDAPSearch, LDAPConfig, LDAPSearchError

try:
    with LDAPSearch(LDAPConfig.from_env()) as ad:
        user = ad.by_employee_id("12345678")
except LDAPSearchError as exc:
    ...
```

More specific subclasses are available (`LDAPConfigError`, `LDAPAuthError`, `LDAPConnectionError`,
`LDAPQueryError`, `NotFoundError`) if you need to distinguish, for example, a bad bind from a query that
rests on a premise that doesn't exist (e.g. resolving a manager who has no such employee ID).

An empty result (`[]`) is not an error — it's a valid answer meaning nobody matched. `NotFoundError` is
reserved for a resolve step that must succeed but returned zero, or ambiguously more than one, match.

## What this library does not do

- No CSV/table output, no `print`, no `sys.exit` — that's your own application or CLI layer's job.
- No retry-with-backoff — failures are raised immediately; retry policy is the caller's decision.
- No organization-specific classification (e.g. employee vs. contractor) — build that on top of
  `User["attributes"]` in your own code.

## Development

```bash
uv sync
uv run pytest
```
