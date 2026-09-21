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
  `memberOf`, where nesting is shallow and the cost is expected to be acceptable. That expectation is
  not yet measured.
