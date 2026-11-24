# 0010 — Server accounts: a person signs in only through an account Keybash holds

Date: 2026-11-24. Status: accepted, the maintainer's decision of the same day.
It replaces three things: the per-server access lists of ADR 0005, every
person's own keys, passwords and connections, and ADR 0009's single shared
credential per server. ADR 0009's rules for keeping a secret stay.

## Context

The first real use put one person's access to one server in three places:
- the People page, where the person is made;
- the server's list ("Who can use it");
- how they sign in: either the server's one shared credential ("How they sign
  in"), or the person's own key or password on Keys & passwords and their own
  connection on Connections.

The maintainer could not tell the server's two questions apart, and the page
had to explain each in sentences.

The person's own path also undoes what a privileged access manager is for.
The person holds the server's password or key, so taking them off a list does
not take away what they know.

The maintainer decided on 2026-11-24:
- Someone who uses Keybash alone is its administrator.
- In a company, people need to connect, not to administer servers.
- So nobody brings their own credential for a server. Safety first, then plain
  pages: "the administrator does not get lost, and the user is comfortable."

## Decision

### One thing gives access: a person on a server account

- A **server account** is one sign-in on one server. It holds:
  - the account's name on that server;
  - how Keybash signs in as it: a key made by Keybash (SSH only), or a
    password an administrator typed once (SSH or Windows desktop).
- The secret follows ADR 0009:
  - nobody is ever shown it;
  - a key's private half never leaves;
  - a key's line carries `restrict,pty`;
  - replacing a key takes two steps, and replacing a password is immediate.
- Each account lists the **people** who may use it.
- A person reaches a server only through an account that lists them, and
  signs in as that account. Nothing else gives access. There are no access
  lists, no personal keys or passwords for servers, and no personal
  connections.
- Limits:
  - A server has at most 16 accounts. Their names differ, ignoring case,
    because Windows ignores case.
  - An installation has at most 2048 accounts.
  - An account lists at most 256 people.
- Auditors are on no account. A person whose role becomes auditor is taken
  off every account in the same change.

### Who does what

- **Administrators**, each change with fresh proof:
  - add and remove accounts;
  - put people on an account and take them off;
  - replace a password, or make, use or drop a new key.
  They connect only through accounts that list them.
- **Auditors** see each server's accounts: the name, the kind, a key's line
  and fingerprint, who set it and when, and who is on it. They see nothing
  else and connect to nothing.
- **Everyone who connects** sees their servers: one card per account they
  are on, with the server's name and the account's name.

### Connecting

- A connection uses a one-use lease, as in ADR 0009. It is bound to the
  person, their sign-in, the account, the account's generation and the
  server's approval.
- When the lease is used, Keybash checks again:
  - the person is still on the account;
  - the account's secret is the same generation;
  - the server's approval is the same.
  Anything else is refused, and nothing is dialled.
- These end the person's open sessions through the account at once:
  - taking them off the account;
  - removing the account;
  - removing the server;
  - a new server identity.
- Replacing a secret ends nothing, because nobody held the old one.

### What goes away, and what happens to it

- Removed:
  - personal Keys & passwords, including keys made for a person and reading
    a stored secret back;
  - personal connections and their approvals;
  - server access lists;
  - the one shared credential per server.
- On its first start, this version erases what earlier versions stored for
  those:
  - every personal key, password and connection;
  - every shared credential;
  - every access list.
  Nobody reaches a server again until an administrator sets up its
  accounts. Nothing is carried over: there are no users yet (maintainer,
  2026-11-18).
- The erased records were sealed under the instance key. The database may
  keep their freed pages until it is rewritten, still sealed.
- The credentials namespace itself stays, empty. An earlier binary, put back
  without a restore, then still opens the database and finds no personal
  records.
- A backup taken by an earlier version still restores. The erased
  namespaces are skipped, and the old access lists are erased on the next
  start.

### Pages

- **Your servers**: everyone who connects sees one card per account, and
  opens it.
- **Servers** (administrators; auditors read only):
  - the list;
  - each server's own page, with its accounts and the people on each.
- **People**: each person's page lists what they can sign in to, as which
  account, and gives or takes access there.
- Adding a server leads straight to its first account and its people.

## Tests

Following `ENGINEERING.md`, with sabotage both ways:
- refusal:
  - for a person not on the account;
  - for one taken off between grant and redeem;
  - for a removed account, or a secret replaced between grant and redeem;
  - for another account on the same server;
  - for a user or an auditor trying any change;
- fresh proof for every change;
- duplicate names and the limits;
- malformed and oversized records refused on read;
- the secret absent from every response, page and journal line;
- sessions ended on removal and not on replacement;
- the first start erasing the old records, and writing nothing when there is
  nothing to erase;
- an earlier backup restoring without its erased namespaces.

## Limits

- A password was typed by a person, who therefore knows it. Only a key made
  here is unknown to everyone.
- Everyone on one account appears on the server as that account. Only Keybash
  knows which person it was. The record of who connected where and when is
  the next phase, not this one.
- A compromised gateway can use every secret it holds. The kernel boundary
  (ADR 0005, A) still limits where it can reach, and `restrict,pty` limits what
  a key can do there.
