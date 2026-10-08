---
status: accepted
---

# Walk reporting trees level by level, not with LDAP_MATCHING_RULE_IN_CHAIN

Active Directory offers `LDAP_MATCHING_RULE_IN_CHAIN` (OID `1.2.840.113556.1.4.1941`), which resolves
an entire reporting tree in a single query against `manager`. Measured against a ~40,000-employee
reporting tree it was roughly **600x slower** than walking the tree level by level, so `adsearch`
walks: query direct reports, then batch that level's DNs into OR-filtered queries, repeating until a
level returns nothing new.

## Considered options

- **`IN_CHAIN` on `manager`.** One query; the domain controller does the walk. This is the obvious
  answer, it is what most Active Directory references recommend, and it is what this library's design
  originally specified. Rejected on measurement: ~600x slower on a 40,000-employee tree. Because the
  work happens on the domain controller, this is a load concern for the directory as well as a
  latency concern for the caller.
- **Level-by-level breadth-first walk.** Chosen. More round trips and client-side cycle detection,
  but each round trip is cheap and levels are batched.

## Consequences

- `LDAPConfig.batch_size` exists solely to serve this: each level's DNs are batched into OR filters
  rather than issued as one query per report.
- A reporting tree is a multi-query traversal, not a filter, so it cannot compose with other search
  criteria in a single query. Traversal therefore accepts no criteria; callers filter the result.
- Cycle detection is now this library's responsibility rather than the directory's.
- **This finding is specific to `manager`.** Group membership continues to use `IN_CHAIN` on
  `memberOf`, where nesting is shallow and the cost is expected to be acceptable. That expectation
  rests on a benchmark, not a measurement (see below).

## Benchmark harness

The harness that produced the 600x figure above was deleted, leaving the most consequential decision
in this codebase without reproducible evidence. `scripts/benchmark.py` replaces it and extends it to
the open question this ADR's last bullet leaves hanging:

- `manager <username>` reproduces this ADR's comparison: the level-by-level walk (`reporting_tree`)
  against the single `IN_CHAIN` query it replaced, timed against the same reporting tree, alongside
  that tree's size and depth.
- `group <name>` times `by_group` transitive against direct-only on a real group, which is the
  group-membership half of the expectation above — unmeasured until this is run against one large
  enough to be informative.
- `filter-complexity` probes whether a `batch_size`-wide disjunction of `eq_dn(manager, ...)` clauses —
  the exact shape a wide level batches into — is itself rejected by the directory, since that failure
  would hit precisely the large trees the walk exists to serve.

It requires a live directory and is not run by the test suite; `tests/test_benchmark.py` covers its
logic offline, against the same fake directory the rest of the library is tested with.

**Figures are not yet recorded.** Running the harness against a real directory, recording the result
here (tree size and depth, and the group benchmark's counts and timings), and — if transitive group
matching proves unacceptable — raising a follow-up issue to change the *mechanism* rather than the
default (§ Consequences; the default rests on correctness, not speed) is the work this ADR is still
waiting on.
