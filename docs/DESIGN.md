# `adsearch` — Design

A generic Python library for querying Active Directory over LDAP.

> **About this document.** This is the design record: what the library is, how it is structured, and
> why each significant choice was made over its alternatives. It describes the target design in the
> present tense; parts of it are still being implemented. The build sequence, milestone ordering, and
> acceptance criteria live in [`TUTORIAL.md`](TUTORIAL.md) and are deliberately not repeated here.

---

## 1. Purpose and scope

### 1.1 What the library does

`adsearch` answers a small, fixed set of directory questions and returns user records:

| Question | Entry point |
|---|---|
| Who is this employee ID? | `by_employee_id` |
| Who reports to this manager (by employee ID)? | `by_manager_id` |
| Who is in this cost center? | `by_cost_center` |
| Who is in this group? | `by_group` |
| Who has this attribute value? | `by_attribute` |
| Arbitrary AND-composition of the above | `find_users` |

It ships a console script (`adsearch`) for schema discovery and debugging, but **the library is the
product**. The CLI exists to prove connectivity and to inspect a directory's real schema; it is not
the interface anyone is expected to build on.

### 1.2 The defining constraint: no organization-specific knowledge

The library contains no hardcoded domain, no hardcoded search base, and no employee-versus-contractor
classification. Callers supply their directory's topology through `LDAPConfig` and their schema
through `AttributeMap`. Anything site-specific is derived by the caller from the raw attributes the
library returns.

This is not a stylistic preference. Two concrete failure modes motivate it:

- A library that ships one organization's domain as a default silently queries the wrong directory
  when a consumer forgets to configure it — and the consumer gets plausible-looking wrong data rather
  than an error.
- A real base DN in library source is an information disclosure to everyone who can read the source.

Accordingly, `LDAPConfig.server` and `LDAPConfig.base_dn` have **no defaults**, and construction fails
without them.

### 1.3 The consumer boundary

`adsearch` is consumed as a dependency by a separate entitlement-audit tool, `mwaudit`, which lives in
its own repository. That separation is what makes this a library-design problem: the caller cannot be
seen, cannot be changed, and every public name is a compatibility promise.

Two tests decide placement, and are applied throughout this document:

> **If it would have to change to support a `--csv` flag, it belongs in `cli.py`, not the library.**
>
> **If it would have to change at a different company, it belongs in the consumer, not the library.**

### 1.4 Non-goals

These are consumer concepts and appear nowhere in `adsearch`:

| Concept | Why it is the caller's | Where it lives |
|---|---|---|
| `AGSEntitlement` and similar aggregates | An audit-domain type, not a directory concept | `mwaudit` |
| Blue-badge / employee-vs-contractor classification | A site policy encoded in site-specific attributes | `mwaudit`, derived from `User["attributes"]` |
| `roles-entitlements.csv` and role mapping | Audit input data | `mwaudit` |
| The specific domain, base DN, and group OU | Deployment configuration | `mwaudit`'s environment |
| The term "WWID" | Site jargon for what LDAP calls an employee ID | The library says `employee_id` throughout — API, parameters, and CLI |

**The extension mechanism that makes this split work:** every `User` carries an `attributes` dict
containing every attribute that was requested. A consumer adds its site-specific attribute name to
`AttributeMap.extra`, reads it back out of `attributes`, and classifies there. The library never needs
to know what a blue badge is.

Callers who prefer local vocabulary alias at their own boundary (`get_reports = ad.by_manager_id`),
which keeps site jargon in the site's repository.

The library also does not do: retry with backoff (fail fast — retry policy is the caller's decision),
disk caching, connection pooling, interactive prompting, or output formatting.

---

## 2. Environment and verified constraints

The design depends on specific, checked behavior of `ldap3` and Active Directory rather than on
documentation or assumption. These were verified against a real install.

### 2.1 Dependency

`ldap3==2.9.1` installs and imports cleanly on Python 3.12–3.14. It contains a dead `ssl.wrap_socket`
branch (`ldap3/core/tls.py:213,228`) referencing a function removed from the standard library in 3.12,
but the branch is guarded by `use_ssl_context`, which is `True` on modern Python, so it is
unreachable. `Server`, `Connection`, `Tls`, `escape_filter_chars`, `parse_dn`, and
`extend.standard.paged_search` all work as documented.

### 2.2 `ldap3`'s TLS default is `CERT_NONE`

`Server(..., use_ssl=True)` with no explicit `Tls` object performs **no certificate validation and no
hostname check**. `tls.py:240` invokes the hostname check only when `validate` is `CERT_REQUIRED` or
`CERT_OPTIONAL`; the default is neither.

Combined with SIMPLE bind — which transmits the password in cleartext inside the tunnel — an
unvalidated LDAPS connection is trivially MITM-able. **This single fact drives the entire transport
design in §7.3.**

### 2.3 Escaping behavior

`escape_filter_chars` hex-encodes the RFC 4515 metacharacters `\ * ( )` and NUL. Verified:

| Input | Output |
|---|---|
| `a)(b*c` | `a\29\28b\2ac` |
| `*` | `\2a` |
| `\` | `\5c` |
| `jdoe` | `jdoe` |

Note the second row: a caller-supplied `*` becomes a literal asterisk, not a wildcard. This is the
property that makes §7.2 work.

`parse_dn` raises `LDAPInvalidDnError` on malformed input, which makes it usable as a DN validator.

### 2.4 Active Directory limits

| Limit | Default | Consequence |
|---|---|---|
| `MaxPageSize` | 1000 | Unpaged searches truncate silently past 1000 entries |
| `MaxValRange` | 1500 | Multi-valued reads past 1500 require range retrieval |
| `MaxQueryDuration` | 120 s | Server-side time limit; `LDAPConfig.time_limit` matches it |

---

## 3. Architecture

### 3.1 Four pieces

The library is four components. Not one, and not eight.

| Component | Form | File | Why it is separate |
|---|---|---|---|
| `LDAPConfig` | Frozen, slotted dataclass | `config.py` | Built from the environment; keeps `bind_password` out of `repr` and tracebacks |
| Filter helpers | Module-level **functions** | `filters.py` | Pure, no I/O. The injection boundary — must be testable without a directory |
| `AttributeMap`, `User` | Frozen dataclass, `TypedDict` | `models.py` | Attribute names are site-specific; overriding must not require touching code |
| `LDAPSearch` | Class | `search.py` | Owns the connection, runs paged searches, maps entries to `User` |

Plus two leaf modules: `errors.py` (the exception hierarchy, importing nothing) and `cli.py` (argparse,
formatting, and exit codes, importing everything).

### 3.2 Dependency direction

```
errors.py     ← imports nothing
filters.py    ← errors
config.py     ← errors
models.py     ← (nothing internal)
search.py     ← errors, filters, config, models
cli.py        ← everything
__init__.py   ← re-exports the public surface
```

The direction is strictly one-way. In particular **`filters.py` never imports `search.py`**, which is
what keeps the security-critical code testable in isolation.

### 3.3 Why filter building lives outside the class

If escaping were a method on `LDAPSearch`, testing it would require constructing an `LDAPSearch` —
which needs a config, which needs credentials, which needs a socket. The most security-critical code
in the system would be the most inconvenient to test, and would therefore be the least tested.

As free functions, the security tests are one-liners with no fixtures:

```python
assert eq("employeeID", "*") == r"(employeeID=\2a)"
```

Testability here is not an abstract virtue; it is the difference between having security tests and not
having them.

### 3.4 What `LDAPSearch` does not own

Excluded by the two placement tests in §1.3:

`print` and any write to stdout · JSON, CSV, or table formatting · column selection · `argparse` and
the `args` namespace · `sys.exit` and the exit-code map · `os.environ` reads inside methods (confined
to `LDAPConfig.from_env`) · any organization-specific classification or vocabulary · disk caching ·
interactive password prompting (the CLI calls `getpass` and passes the value to `LDAPConfig`) ·
retry-with-backoff · `logging.basicConfig`.

---

## 4. Public API

### 4.1 Surface

Everything a consumer imports. The list is deliberately short — each name is a compatibility promise.

```python
from adsearch import (
    LDAPSearch, LDAPConfig, AttributeMap, User,
    LDAPSearchError, LDAPConfigError, LDAPAuthError,
    LDAPConnectionError, LDAPQueryError, NotFoundError,
)
```

Filter helpers remain importable from `adsearch.filters` but are **not** re-exported at top level.
They exist for building custom `extra_filter` values, not for everyday use, and promoting them would
widen the compatibility surface for a rare case.

### 4.2 Intended usage

```python
with LDAPSearch(LDAPConfig.from_env(), attrs=MY_SCHEMA) as ad:
    reports = ad.by_manager_id("12345678")
```

`with` is the supported form and is documented as such. A library that leaves sockets open until
garbage collection exhausts a domain controller's connection limit inside a long-running consumer,
and the symptom surfaces in someone else's process.

### 4.3 Compatibility

The consumer depends on this library via a **git URL pinned to a tag**, never a branch. A consumer
tracking `main` receives silently rebuilt behavior on every push — exactly the failure mode that
splitting the repositories was meant to prevent.

Vocabulary was normalized to `employee_id` while there were zero consumers. After `mwaudit` imports
the library, such a rename becomes a breaking change requiring a major version bump and a coordinated
two-repository update.

---

## 5. Data model

### 5.1 `LDAPConfig`

A frozen, slotted dataclass. Frozen because configuration that mutates after a connection is open
produces bugs that cannot be reproduced; slotted because it turns field-name typos into
`AttributeError`.

| Field | Type | Default | Notes |
|---|---|---|---|
| `server` | `str` | **required** | e.g. `ldaps://dc.example.com` |
| `base_dn` | `str` | **required** | |
| `group_base_dn` | `str \| None` | `None` | Falls back to `base_dn` when unset |
| `bind_user` | `str \| None` | `None` | Service-account UPN or DN |
| `bind_password` | `str \| None` | `None` | **`field(repr=False)`** |
| `use_ssl` | `bool` | `True` | |
| `validate_cert` | `bool` | `True` | → `ssl.CERT_REQUIRED` |
| `ca_certs_file` | `str \| None` | `None` | Internal CA bundle |
| `connect_timeout` | `int` | `10` | TCP connect |
| `receive_timeout` | `int` | `60` | Per-response read; stops a wedged process |
| `time_limit` | `int` | `120` | Server-side, matching AD's `MaxQueryDuration` |
| `page_size` | `int` | `1000` | Matching AD's `MaxPageSize` |

`from_env(env: Mapping[str, str] | None = None)` builds a config from `ADSEARCH_*` variables and raises
`LDAPConfigError` when `server` or `base_dn` is absent. **`env` is a parameter rather than a direct
`os.environ` read** so that configuration can be tested without monkeypatching global state.

Validation lives in `__post_init__`, not in `from_env`, so that a directly constructed `LDAPConfig`
cannot bypass the transport guard in §7.3.

`bind_password` is `field(repr=False)` because a dataclass `__repr__` otherwise reproduces the
password in every traceback frame, log interpolation, and debugger view that touches a config.

| Variable | Required | Maps to |
|---|---|---|
| `ADSEARCH_SERVER` | yes | `server` |
| `ADSEARCH_BASE_DN` | yes | `base_dn` |
| `ADSEARCH_GROUP_BASE_DN` | no | `group_base_dn` |
| `ADSEARCH_BIND_USER` | no | `bind_user` |
| `ADSEARCH_BIND_PASSWORD` | no | `bind_password` |
| `ADSEARCH_CA_CERTS` | no | `ca_certs_file` |

### 5.2 `AttributeMap`

A frozen dataclass mapping logical names to real AD attribute names. Every default is a *hypothesis*
about a site — reasonable standard AD/inetOrgPerson names, still to be confirmed per deployment. This
is the one place a site corrects reality without editing code.

| Field | Default | Confidence |
|---|---|---|
| `name` | `displayName` (falling back to `cn`) | High — `displayName` is not guaranteed populated; `cn` always is |
| `cn` | `cn` | Certain |
| `employee_id` | `employeeID` | Medium — `employeeNumber` or an `extensionAttribute` are common alternatives |
| `username` | `sAMAccountName` | High |
| `upn` | `userPrincipalName` | Certain |
| `mail` | `mail` | High |
| `manager` | `manager` | Certain — and it holds a **DN** |
| `member_of` | `memberOf` | Certain |
| `cost_center` | `departmentNumber` | **Low — commonly a site-specific extension attribute** |
| `extra` | `()` | `tuple[str, ...]` of additional attributes to surface in `User["attributes"]` |

`extra` is a tuple rather than a list because a frozen dataclass with a mutable default is a defect.

`fetch_list()` returns every attribute name to request on a user search, including `extra`.

**No `is_bluebadge`, `bluebadge_values`, or `contractor_upn_suffixes`.** That classification is the
consumer's (§1.4). Recorded so it is not rediscovered: the plausible candidates at a given site are
`employeeType` (semantically correct), an `extensionAttribute1..15` worker-type code, or the UPN
suffix — and **not** `userAccountControl`, which encodes enabled/disabled and delegation flags and says
nothing about worker type.

### 5.3 `User`

A `TypedDict`, chosen over a dataclass because it *is* a `dict` at runtime: `json.dumps(users)` works
with no custom encoder, and consumers can treat results as plain data. The cost is subscript access
(`user["name"]`) and no runtime validation.

| Field | Type | Notes |
|---|---|---|
| `dn` | `str` | Always present; callers need it to cross-reference group membership |
| `name` | `str` | `displayName`, falling back to `cn` |
| `employee_id` | `str \| None` | |
| `username` | `str \| None` | `sAMAccountName` |
| `email` | `str \| None` | |
| `attributes` | `dict[str, object]` | **Everything requested, raw.** The extension point of §1.4 |

`ldap3` returns a `str` or a `list[str]` depending on an attribute's cardinality, so the mapper
normalizes scalar fields through a `_first` helper. Without it, single-valued fields surface as
`['Jane Doe']` — which passes a smoke test and breaks a consumer.

---

## 6. Error model

### 6.1 Hierarchy

| Exception | Raised for | CLI exit |
|---|---|---|
| `LDAPSearchError` | Base — callers catch only this | — |
| `LDAPConfigError` | Missing variable, malformed DN, SIMPLE bind without TLS | 3 |
| `LDAPAuthError` | Bind rejected | 4 |
| `LDAPConnectionError` | DNS, TCP, TLS, or timeout | 5 |
| `LDAPQueryError` | Bad filter, bad attribute name, size or time limit | 6 |
| `NotFoundError` | A required resolve returned 0 — **or 2+** — entries | 7 |

The base class exists so a consumer can write one `except LDAPSearchError` and be certain nothing from
this library escapes it. The subclasses serve callers who need to distinguish.

### 6.2 The translation boundary

**No `ldap3` exception escapes the public API.** If a caller must write `except LDAPSocketOpenError`,
then `ldap3` is part of the contract permanently and can never be replaced.

| `ldap3` exception | Re-raised as |
|---|---|
| `LDAPBindError`, `LDAPInvalidCredentialsResult` | `LDAPAuthError` |
| `LDAPSocketOpenError`, `LDAPSocketReceiveError`, `LDAPSessionTerminatedByServerError` | `LDAPConnectionError` |
| `LDAPInvalidFilterError`, `LDAPUndefinedAttributeTypeResult`, `LDAPSizeLimitExceededResult` | `LDAPQueryError` |
| bare `LDAPException` | `LDAPQueryError` (catch-all, ordered **last**) |

Translation always uses `raise ... from exc`. The original `ldap3` message carries the AD diagnostic
sub-code — `data 52e` is a bad password, `data 775` a locked-out account, `data 532` an expired
password — and discarding it makes authentication failures nearly undiagnosable.

### 6.3 Empty results are not errors

> `[]` means "nobody matches" — a valid answer.
> `NotFoundError` means "the query rests on a premise that does not exist."

`find_users` returning `[]` is correct. A *resolve* step that must succeed returning nothing is not:
the `[]` that would otherwise be returned from `by_manager_id` is indistinguishable from "this manager
has no reports", and the caller has no way to tell the difference.

`resolve_user_dn` therefore raises on **0 matches and on 2 or more**. Never picking the first of an
ambiguous match is deliberate — a silently wrong pick corrupts the caller's entire result set
undetectably, and duplicate employee IDs are a directory data-quality problem worth surfacing loudly.
Resolves search with `limit=2`, which is sufficient to detect ambiguity without paging the directory.

### 6.4 Exit codes belong to the CLI

The exit-code map lives in `cli.py`, never in `errors.py` — a library does not own the process and has
no business knowing about exit codes. `0` is success, `1` an unexpected exception, `2` an argparse
usage error, and 3–7 as tabulated above. The codes are distinct because callers script against them
and need to distinguish "bad password" from "no such user" without parsing stderr.

---

## 7. Security design

### 7.1 Assumptions

As a library, `adsearch` does not control who calls it or what they pass. Every argument is treated as
hostile. This is a stronger posture than the CLI-only predecessor required, where the only caller was
the author.

### 7.2 Filter injection

LDAP filters are a query language assembled from caller-supplied values — structurally the same
problem as SQL injection, with no parameterized-query mechanism available. Escaping is the only
defense, which means it must be applied at every construction site without exception.

> **Rule: every value reaching a filter passes through `escape_filter_chars`. No f-string
> interpolation of a raw value, anywhere.**

Two concrete attacks motivate this. An employee ID of `*` turns `(employeeID=*)` into a full directory
dump. An employee ID of `x)(objectClass=*` closes the clause early and injects a new one.

`filters.py` provides the complete vocabulary:

```python
IN_CHAIN = "1.2.840.113556.1.4.1941"   # LDAP_MATCHING_RULE_IN_CHAIN
BIT_AND  = "1.2.840.113556.1.4.803"    # LDAP_MATCHING_RULE_BIT_AND

esc(value)          # RFC 4515 escape of an assertion value
attr(name)          # validate an attribute NAME against ^[A-Za-z][A-Za-z0-9-]*$
valid_dn(dn)        # reject anything that is not a well-formed DN; wraps parse_dn
eq(a, value)        # (attr=value) — exact; a caller-supplied '*' is neutralised
contains(a, value)  # (attr=*value*) — the wildcards are ours, the value is escaped
eq_dn(a, dn)        # (attr=dn) — esc(valid_dn(dn)), in that order
in_chain(a, dn)     # (attr:1.2.840.113556.1.4.1941:=dn) — transitive match
all_of(*clauses)    # AND-combine, dropping Nones; raises rather than emitting empty
any_of(*clauses)    # OR-combine
none_of(clause)     # (!clause)

USER_OBJECT  = "(&(objectCategory=person)(objectClass=user))"
NOT_DISABLED = "(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
```

`USER_OBJECT` leads with `objectCategory` because it is indexed and single-valued in AD;
`(objectClass=user)` alone is substantially slower on a large directory.

Four properties of this design are easy to get wrong, and each is handled explicitly:

1. **DNs are escaped as filter values, not merely validated.** A legal DN can contain filter
   metacharacters — `CN=Team (West),OU=Groups,DC=example,DC=com` parses correctly and contains live
   parentheses. `eq_dn` is `esc(valid_dn(dn))`; validation and escaping answer different questions.
2. **The search base is escaped by nothing.** `escape_filter_chars` protects the filter and does not
   touch the `search_base` argument. Every caller-supplied base or group DN passes through
   `valid_dn()`. This is the vector most implementations miss, having guarded only the filter.
3. **Attribute names are a separate injection point.** `escape_filter_chars` does not cover them,
   hence `attr()` and its allowlist regex — an allowlist, not a blocklist.
4. **Wildcards are structural and opt-in.** `contains()` escapes the value and then adds its own `*`
   characters. A caller never supplies a live wildcard.

`all_of()` raises on empty input rather than returning `""`, because an empty filter means *match
everything* — a helper whose degenerate case returns the entire directory will eventually return the
entire directory.

`extra_filter` is a deliberate raw passthrough for callers who need composition the wrappers do not
offer. It is documented as trusted-input-only and sanity-checked (leading `(`, balanced parentheses)
so that typos fail locally rather than at the domain controller.

### 7.3 Transport and credentials

SIMPLE bind transmits the password in cleartext inside whatever tunnel exists. Given §2.2 — that
`ldap3` validates nothing by default — the following combination is enforced:

- **SIMPLE bind requires `use_ssl=True`.** `LDAPConfig` raises `LDAPConfigError` otherwise; it does
  not warn and continue.
- **An explicit `Tls` object is always constructed**, with `validate=ssl.CERT_REQUIRED`. The `Tls`
  object is never omitted, since omitting it is precisely the vulnerability.
- **`validate_cert=False` exists as a first-contact debugging escape hatch** and emits a
  `warnings.warn` — not a `print`, since a library that writes to stdout corrupts its caller's output.
  It is the only path that can produce `CERT_NONE`.
- **Passwords come from the environment or an interactive `getpass` in the CLI**, never from a config
  file. Should file-based configuration be added later, it should *raise* on a password key rather
  than honor it.

An offline test asserts `Server.tls.validate == ssl.CERT_REQUIRED` on the constructed server, as a
cheap regression guard against the `CERT_NONE` default silently returning after a refactor.

### 7.4 Logging

Filters are logged at `debug` and never at `info`, because filter values contain names and employee
IDs. The library uses `logging.getLogger(__name__)` and attaches a `NullHandler` in `__init__.py`;
`logging.basicConfig` is called only by the CLI. Configuring logging is the application's prerogative,
and a library that calls `basicConfig` hijacks its consumer's setup.

---

## 8. Query design

### 8.1 Connection lifecycle

`LDAPSearch.__init__` takes exactly two parameters — `config: LDAPConfig` and
`attrs: AttributeMap = DEFAULT_ATTRS` — and performs no I/O. A wide keyword-argument constructor is
where defaults drift out of sync with `LDAPConfig` and where `bind_password` ends up in a log line.

The connection is **lazy**, created and bound on first access to the `conn` property. This keeps
construction, argument validation, and the entire offline test suite off the network.

There is **one bind per instance**. `by_manager_id` performs a resolve followed by a search — two
searches over one connection. Rebinding per method would double the latency of every call.

`close()` unbinds if connected, is safe to call repeatedly, and swallows teardown errors: an exception
raised from `__exit__` replaces the exception already propagating, hiding the real failure.

### 8.2 `ldap3` construction

Every argument below is set explicitly, because the defaults are wrong for this use case and one of
them is dangerous.

| Object | Argument | Value | Rationale |
|---|---|---|---|
| `Tls` | `validate` | `ssl.CERT_REQUIRED` | The default is `CERT_NONE` — no certificate *or* hostname check (§2.2) |
| `Tls` | `ca_certs_file` | `cfg.ca_certs_file` | Internal CA |
| `Server` | `use_ssl` | `True` | LDAPS on 636 |
| `Server` | `tls` | the `Tls` above | Omitting it is the vulnerability |
| `Server` | `get_info` | `NONE` | `ALL` pulls the entire AD schema — megabytes, seconds — on *every* bind. `ALL` is used only by `server_info()`, on a throwaway connection |
| `Server` | `connect_timeout` | `cfg.connect_timeout` | |
| `Connection` | `authentication` | `SIMPLE` | |
| `Connection` | `auto_bind` | `AUTO_BIND_NO_TLS` | Correct for LDAPS-on-636; `AUTO_BIND_TLS_BEFORE_BIND` is for StartTLS on 389 |
| `Connection` | `raise_exceptions` | `True` | With the default, `search()` returns a bool and a forgotten `conn.result` check silently yields zero rows. A silent empty result is worse than a crash |
| `Connection` | `auto_referrals` | `False` | §8.4 |
| `Connection` | `auto_range` | `True` | Handles range retrieval should `member` ever be read |
| `Connection` | `receive_timeout` | `cfg.receive_timeout` | A distinct failure mode from connect timeout: the connect succeeds, then the DC stops answering |

### 8.3 Paging is mandatory

The search core uses `conn.extend.standard.paged_search(..., paged_size=cfg.page_size,
generator=True)`. This is not an optimization. AD's `MaxPageSize` is 1000, and a plain `conn.search()`
against a larger group truncates at 1000 with `sizeLimitExceeded`.

A library that silently returns 1000 of 4000 group members produces a wrong audit in its consumer, far
from the code that caused it. This is the most dangerous failure mode in the system precisely because
it resembles success.

The core also accepts a `limit` that short-circuits the generator, which is what makes
`resolve_user_dn`'s `limit=2` ambiguity check cheap.

### 8.4 Referrals

Searching at a domain root causes AD to emit referrals, which `ldap3` chases by default — frequently
to unreachable hosts, producing hangs or spurious failures. Chasing is disabled; referrals then arrive
as ordinary items in the result stream, and the result loop skips anything whose `type` is not
`searchResEntry`.

### 8.5 `find_users` contract

```python
def find_users(self, *, employee_id=None, username=None, name_contains=None, cost_center=None,
               manager_dn=None, group_dn=None, transitive=False,
               include_disabled=False, base_dn=None, extra_filter=None,
               attributes=None, limit=None) -> list[User]:
```

**Explicit keyword-only parameters, not `**criteria`.** With `**criteria`, a caller who types
`find_users(manager_dm=...)` receives every user in the directory instead of a `TypeError` — a typo
becomes a data-dump-shaped bug. In a library consumed by code the author does not own, that is the
difference between a crash and a quiet breach.

**Returns `list[User]`, not an iterator.** The paged core is a generator, so exceptions inside it fire
during consumption. Were `find_users` to return an iterator, an authentication or query failure would
surface inside the caller's loop — after partial results, in a frame with no error handling, in a
different repository. Returning a list forces the exception back to the call site. Secondarily, most
consumers need `len()`, sorting, or `json.dumps`, all of which materialize anyway. `iter_users`
remains as a documented escape hatch for streaming.

All criteria **AND**-compose. Callers needing OR loop a wrapper or build `any_of(...)` and pass it as
`extra_filter`.

Disabled accounts are excluded by default, with `include_disabled=True` to opt in. The flag exists
rather than being hardcoded because "a disabled account still in a privileged group" is itself an
audit finding.

### 8.6 Named wrappers

Three of the four primary criteria are **not single-filter operations** — manager and group both
require resolving a DN first. That logic must live somewhere, and a named wrapper is the honest place
for it. `by_attribute` covers the residual case without inventing a query DSL: any site-specific
attribute a consumer cares about is reachable without a library change.

`resolve_user_dn` and `resolve_group_dn` are public because they are independently useful and because
`resolve-dn` is a valuable debugging subcommand. `resolve_group_dn` accepts either a DN or a CN: if
the argument does not parse as a DN, it searches `(&(objectCategory=group)(cn=<escaped>))` under
`group_base_dn`, which is what lets callers pass friendly group names.

### 8.7 Manager traversal, and why it defaults to non-transitive

AD stores `manager` as a DN, so a lookup by employee ID is inherently two steps: resolve the manager's
DN, then filter on it. Direct reports use `eq_dn("manager", dn)`; the full chain uses
`in_chain("manager", dn)`.

**`transitive=False` is the default.** `LDAP_MATCHING_RULE_IN_CHAIN` on `manager` walks an entire org
subtree — for a senior executive, tens of thousands of entries and a very expensive DC-side query.
Expensive operations are opt-in.

### 8.8 Group membership, and why it defaults to the opposite

Group enumeration filters users on `(memberOf=<dn>)` with paged search. It does **not** read the
group's `member` attribute, for three reasons:

1. AD caps multi-valued reads at `MaxValRange` (1500); beyond that it is range retrieval
   (`member;range=1500-2999`), meaning N extra round trips even with `auto_range`.
2. `member` returns DNs rather than attributes. A 5000-member group becomes 5000 follow-up lookups,
   whereas `memberOf` filtering returns fully populated user entries in roughly five paged round
   trips.
3. `member` includes nested *group* objects, which would have to be recursed manually.

**`transitive=True` is the default here** — the inverse of §8.7. The question being asked is "who
actually holds this access", and a nested group silently hiding members is the wrong answer that
matters. The asymmetry between the two defaults is deliberate: it follows from which wrong answer is
more damaging in each case, not from consistency for its own sake.

Documented caveat: neither `member` nor `memberOf` reflects `primaryGroupID`, which is stored as an
integer RID on the user rather than as a link. In practice this affects only Domain Users and is
usually ignorable, but it is recorded so it is not rediscovered mid-audit.

---

## 9. Schema discovery

Real AD attribute names are site-specific and unknown when the library is written, so discovery ships
as a first-class feature rather than a development aid.

```python
def server_info(self) -> str: ...
def describe_user(self, value: str, *, by: str = "sAMAccountName") -> dict[str, object]: ...
```

`describe_user` dumps every populated attribute for one known user, requesting
`[ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES]` — both, since `['*']` alone omits constructed and
operational attributes. This is more useful than dumping the schema: the schema lists thousands of
attributes that are *defined*, whereas one real user reveals the handful actually *populated*.

**The `by` parameter exists because of a bootstrapping problem.** Looking a user up by employee ID
requires already knowing the employee-ID attribute name — the exact thing discovery is meant to find.
The default is `sAMAccountName`, reliably standard everywhere, and `by` is overridable once the real
name is known. It is validated through `filters.attr()`.

`server_info` uses a throwaway `get_info=ALL` connection and reports naming contexts and supported
controls. It is the first thing to run against a new deployment, because it proves bind and TLS work
before any query semantics are involved — which is the main justification for shipping a CLI at all.

---

## 10. CLI design

The CLI is thin by requirement, not aspiration. It exists for discovery and debugging.

Subcommands: `employee`, `manager`, `cost-center`, `group`, `describe`, `server-info`, `resolve-dn`.
Global flags: `--json` (default), `--raw`, `--attributes a,b,c`, `--include-disabled`,
`--all-reports` / `--no-transitive`, `--debug`, `--insecure`.

`--raw` emits the unmapped `ldap3` dict as JSON, bypassing the `User` mapper. During schema discovery
it is the only way to see what the directory is actually returning.

`--attributes` values are validated through `filters.attr()` before reaching a search (§7.2, point 3).

`main()` contains exactly **one** top-level `try`, catching `LDAPSearchError` and mapping exception
type to the exit code in §6.4. `str(exc)` goes to stderr; the traceback appears only under `--debug`.

Output format is decided in exactly one place:

```python
def format_users(users: list[User], fmt: str) -> str:
    """Render users as json | csv | table."""
```

JSON is implemented; CSV and table output are planned. Isolating the decision behind this seam means
adding them touches one function — which is the concrete, testable meaning of "thin CLI".

---

## 11. Packaging and distribution

| Choice | Rationale |
|---|---|
| **`src/` layout** | With a flat layout, `import adsearch` from the repo root silently picks up the source tree instead of the installed package, so tests can pass against code that was never packaged |
| **`py.typed`** (PEP 561) | Without it, type checkers must ignore the library's annotations entirely and the consumer sees `Any` for every call |
| **`[tool.hatch.build.targets.wheel] sources = ["src"]`** | `[tool.hatch.build] include` does not strip the `src` prefix; without this the wheel ships `src/adsearch/…`, dropping a generic top-level `src` into site-packages and breaking `import adsearch` |
| **`requires-python = ">=3.12"`** | A library's floor constrains every consumer, so it is set as low as is reasonable. Note that `.python-version` pins 3.14 locally, meaning development happens *above* the declared floor and newer-only syntax can slip in unnoticed |
| **`logging.NullHandler`** in `__init__.py` | Without it, a consumer that has not configured logging gets handler-of-last-resort noise on stderr |
| **Git URL pinned to a tag** | §4.3. Note that a private git dependency requires every consumer and CI job to hold credentials for the repository |
| **`typing` removed from dependencies** | The declared `typing>=3.10.0.0` was a PyPI *backport* for Python 2.7 and 3.2–3.4, inert on modern Python since the stdlib precedes site-packages on `sys.path`. Removing it does not remove type hints |

Packaging correctness is verified from outside the repository — installing from the git URL in a
directory that is not the repo root, so a `src`-layout mistake cannot hide behind the local source
tree, and type-checking a two-line consumer script to confirm `by_group` resolves to `list[User]`
rather than `Any`.

---

## 12. Alternatives considered

| Rejected | In favor of | Why |
|---|---|---|
| `FilterBuilder` class | Free functions in `filters.py` | Reintroduces the construction cost that makes security tests inconvenient (§3.3) |
| `UserMapper` class, separate connection class | Methods on `LDAPSearch` | Three indirections for a library that binds once and runs a handful of searches per session |
| `find_users(**criteria)` | Explicit keyword-only parameters | A typo silently returns the entire directory instead of raising `TypeError` (§8.5) |
| `find_users` returning an iterator | Returning `list[User]` | Exceptions would surface in the caller's loop, after partial results, in a frame with no handling (§8.5) |
| Reading a group's `member` attribute | Filtering users on `memberOf` | Range retrieval, DN-only results, and nested groups (§8.8) |
| Hardcoded attribute names | `AttributeMap` | Real names are site-specific; overriding must not require a code change (§5.2) |
| Shipping a default server / base DN | Required fields with no defaults | Silently queries the wrong directory; leaks topology (§1.2) |
| Exit codes in `errors.py` | Exit codes in `cli.py` | A library does not own the process (§6.4) |
| Warning and continuing on SIMPLE-without-TLS | Raising `LDAPConfigError` | A cleartext password on the wire is not a warning-level event (§7.3) |
| Retry with backoff in the library | Failing fast | Retry policy is the caller's decision |
| A dataclass for `User` | `TypedDict` | Direct JSON serialization; consumers treat results as plain data (§5.3) |
| Dumping the AD schema for discovery | Dumping one populated user | The schema lists what is *defined*, not what is *populated* (§9) |
| Re-exporting filter helpers at top level | `adsearch.filters` only | Every public name is a permanent compatibility promise (§4.1) |

---

## 13. Invariants

The properties below are what the test suite exists to protect. All but the last group are verifiable
offline, without a directory.

- `eq("employeeID", "a)b")` → `(employeeID=a\29b)` — metacharacters are escaped.
- `eq("employeeID", "*")` → `(employeeID=\2a)` — a caller-supplied wildcard is neutralized.
- `eq_dn` escapes a DN containing parentheses rather than merely validating it.
- `attr("cn)(x")` and `valid_dn("not a dn")` raise.
- `all_of()` raises rather than emitting an empty filter.
- The constructed `Server.tls.validate` is `ssl.CERT_REQUIRED`.
- `LDAPConfig` with SIMPLE bind and `use_ssl=False` raises `LDAPConfigError`.
- `LDAPConfig.from_env({})` raises `LDAPConfigError` — proving no baked-in server default.
- No real domain, server URI, or base DN appears in library source outside docstring examples.
- Against a live directory: a group with more than 1000 members returns more than 1000 entries, and
  transitive and non-transitive group queries return different counts.

---

## 14. Known limitations and future work

- **`primaryGroupID` is not reflected** in group membership results (§8.8).
- **SIMPLE bind only.** Kerberos/SASL would remove the cleartext-password problem at its root rather
  than mitigating it with TLS, at the cost of a more complex `LDAPConfig` and a platform dependency.
- **Single server, no failover.** `LDAPConfig.server` is one URI; multi-DC failover would interact
  with the one-bind-per-instance decision in §8.1.
- **CSV and table output are unimplemented**, though the seam for them exists (§10).
- **`extra_filter` is an unvalidated passthrough** by design (§7.2). It is the one place a caller can
  construct arbitrary filter syntax, and it is documented as trusted-input-only.
- **Development occurs above the declared Python floor** (§11), so 3.12 compatibility requires an
  explicit check rather than being continuously exercised.

---

## Appendix A — File responsibilities

| Path | Responsibility |
|---|---|
| `pyproject.toml` | Packaging metadata, wheel layout, console-script entry point |
| `src/adsearch/__init__.py` | Public re-exports, `__all__`, logging `NullHandler` |
| `src/adsearch/py.typed` | PEP 561 marker (empty) |
| `src/adsearch/errors.py` | The exception hierarchy; imports nothing |
| `src/adsearch/config.py` | `LDAPConfig`, `from_env`, transport validation |
| `src/adsearch/filters.py` | Pure filter construction and escaping; the injection boundary |
| `src/adsearch/models.py` | `AttributeMap`, `User` |
| `src/adsearch/search.py` | Connection lifecycle, paged search core, discovery, resolvers, wrappers |
| `src/adsearch/cli.py` | argparse, output formatting, exit codes, `getpass`, `basicConfig` |
| `tests/test_filters.py` | The offline security tests (§13) |

## Appendix B — References

- RFC 4511 (LDAP protocol), RFC 4514 (DN string representation), RFC 4515 (search filter string
  representation)
- Microsoft: *Search Filter Syntax*, *LDAP Matching Rules* — authoritative for the two OIDs in §7.2
- PEP 561 — distributing and packaging type information
- OWASP LDAP Injection Prevention Cheat Sheet
- `ldap3` documentation — https://ldap3.readthedocs.io/
