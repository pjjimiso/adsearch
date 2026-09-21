# adsearch

`adsearch` queries an Active Directory over LDAP and returns users. It deliberately knows nothing
about what any particular organization's directory data *means*; that interpretation belongs to the
consumer.

## Language

### Identity

**Site**:
A single organization's Active Directory deployment, with its own attribute names and data
conventions. Every attribute default in this library is a hypothesis about a site, not a fact.

**Consumer**:
The application that imports this library. It owns all organization-specific interpretation —
employee versus contractor, which cost centers matter, what counts as a finding.

**Employee ID**:
The business identifier for a person. **One-to-many**: a single employee ID may match several
directory entries at a site, so it is a search key and never a resolve key.
_Avoid_: employee number, badge ID, staff ID

**Username**:
The directory's account identifier. **One-to-one**: exactly one entry per username, which is what
makes it the resolve key.
_Avoid_: login, account name, UID

**Search key**:
An attribute a query filters on, matching any number of entries. Zero matches is a valid answer
meaning nobody qualified.

**Resolve key**:
An attribute used to obtain exactly one entry, because a subsequent query needs that entry's DN.
Zero matches — or more than one — is an error, never a silent pick.

### Manager relationships

**Manager DN**:
Active Directory stores a person's manager as the manager's distinguished name, not as an ID. Every
manager query is therefore two steps: resolve a person to a DN, then search on that DN.

**Direct report**:
A user whose manager attribute equals a given manager DN exactly. One hop, one query.

**Reporting tree**:
Every direct report of a manager, plus every direct report of those, to any depth. Walked level by
level rather than resolved by the directory in one query (see ADR-0001).
_Avoid_: chain, recursive reports, hierarchy, org chart

### Group membership

**Transitive**:
Including members inherited through nested groups. Reserved for group membership only — it is never
said of a reporting tree, which is always walked in full.
_Avoid_: recursive, nested

**Cost center**:
The site's accounting unit for a person. The attribute holding it is almost always a site-specific
extension attribute rather than a standard one.
