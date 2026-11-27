# 0012 — Activity: a record of who did what, where and when

Date: 2026-11-27. Status: accepted. The maintainer asked for the whole
privileged-access set on the same day, starting with this record, and for
"no confusion at all": users and administrators must understand it plainly.
It builds the audit record PRODUCT-PLAN decided on 1 November 2026, and the
transfer record ADR 0011 promised.

## Context

Keybash decides who may reach which server, as which account. Until now it
kept no account of what was done with that: an administrator could not see
who connected to a server last night, who changed an account's password, or
who downloaded a file. A privileged access manager is trusted for exactly
that answer.

PRODUCT-PLAN decided on 1 November 2026:
- auditors and administrators read an append-only record of administrator
  actions and of who connected where and when;
- it also holds the command lines typed in SSH sessions, as the screen showed
  them at Enter, so hidden input such as a sudo password is never recorded;
- no keystrokes, terminal output, clipboard content or session video;
- users are told that commands are recorded;
- encrypted, hash-chained, size-capped and kept for a set time, without
  claiming immutability against the host administrator.

What we build on:
- **The store.** Every change is one bbolt write transaction, and every
  record is sealed with a fresh key wrapped by the instance key.
- **Backups.** A backup holds at most 8192 records and 96 MiB.
- **Who is who.** Every handler knows the person and the source address; the
  gateway admits only its `--allow-from` networks, and there are no
  forwarded-address headers to trust.

## Decision

### What is recorded

Part 1, this change:
- **Signing in:**
  - a sign-in (after the second factor), with the address it came from;
  - refused sign-ins, grouped: one entry per person and address for each
    ten minutes, with the count. A name that is no account is never written,
    since people type their password into the name field by mistake;
  - a recovery code used, a confirmation (step-up) and a refused one, signing
    out, and a sign-in ended for being idle or at its 8 hours;
  - setting up the first administrator, and an invitation or a reset code
    taken up.
- **A person's own account:** a new password, a new phone, new recovery codes.
- **People:** invited, role changed, blocked and unblocked, phone reset,
  password reset, started over, deleted.
- **Servers:** added (with its identity's fingerprint), renamed, its picture,
  its file transfer setting, a new identity accepted, removed.
- **Server accounts:** added, a person put on or taken off, a password
  replaced, a new key made, dropped or switched to, removed, and a key made
  here used for the first time.
- **Sessions:** a terminal, a desktop or a Files page opened, with the
  server, the account and the address; and its end, with how long it lasted
  and why it ended, in the same fixed words the page shows.
- **Files:** each download, upload, replace, new folder, rename and delete,
  with the path, the size and how it ended (done, cancelled, or the failure's
  word). Opening a folder is not recorded.
- **The server's console:** an account added or recovered there, a new setup
  code, a restore.
- **The record itself:** when old entries leave it (how many, up to when).

Part 2, its own change: typed command lines as the screen showed them at
Enter, which needs a model of the screen in the gateway, and a line on the
terminal page that says so.

Never recorded: passwords, keys, codes, file contents, terminal output,
keystrokes, the clipboard, names typed that are not an account.

### Who reads it

- **Administrators and auditors** get **Activity** in the menu: newest first,
  50 at a time, filtered by person, server, kind and day.
- Each entry is one plain sentence: "aysel connected to Build box as deploy
  (terminal)", "rash allowed uploads and downloads on Build box", with the
  time, the address and, for sessions, how long.
- **Nobody** can change or remove an entry through Keybash: there is no API
  for it.
- **Users** do not read the record. The session and Files pages say that
  Keybash records who connects and what is changed.

### How it is kept

- **Blocks.** Entries go into sealed blocks in a new namespace,
  `activity-v1`: at most 32 KiB of entries per block, sealed like every other
  record (a fresh key wrapped by the instance key, the block's number and
  revision in its associated data).
- **The chain.** Each entry carries an HMAC-SHA256, keyed by a key derived
  from the instance key for this alone, over the previous entry's HMAC, its
  own number and its contents. The record's head (the next number and the
  last HMAC), and where it now starts, live in the store's metadata, which is
  itself authenticated. A removed, reordered or changed entry or block breaks
  the chain.
- **Checked.** The whole chain is checked at every start and in every backup.
  A break does not stop Keybash, which would let damage to the file stop it:
  the Activity page says so in red, with where it broke, and the record goes
  on from its head.
- **Fail closed.** An entry is written in the same transaction as the change
  it records, so there is no change without its entry. A sign-in or a session
  whose entry cannot be written does not happen.
- **Bounded.** At most 1,024 blocks (32 MiB of entries, about 90,000), so
  that sealed it still fits a backup beside everything else, and entries are
  kept for a year. The oldest whole blocks leave first, and an
  entry says how many and up to when. Refused sign-ins are grouped so that
  someone who cannot sign in cannot push the record's history out.
- **Long paths.** An entry holds at most 6 KiB once encoded, and escaping can
  make a path of control characters six times longer. Such a path is
  shortened, on a whole character, and the entry says "cut"; its operation is
  still recorded. Nothing else is cut. The page shows a control or direction
  character in a path as a visible mark, as the Files page does.
- **Backups** carry the record, and a restore keeps it, with an entry for the
  restore.

## Tests

Following `ENGINEERING.md`, with sabotage both ways:
- an entry for every recorded action, with its fixed words and no secret;
- a change and its entry together or not at all, including a store that
  cannot write the entry;
- the chain refusing a changed, removed, reordered or replayed entry or block,
  and a moved head;
- refused sign-ins grouped, unknown names never written;
- the limits: block size, count, age, and the entry that says what left;
- only administrators and auditors reading it, and no way to change it;
- backup and restore keeping it, and an earlier backup without it restoring.

## Limits

- **The host's root** holds the instance key and can rewrite the record and
  its head consistently. The record makes a change outside Keybash visible;
  it cannot make one impossible.
- **Rolling the whole file back** to an earlier copy is not detected (KB-05).
- **The server's clock** dates every entry.
- **Addresses** are as Keybash sees them: an IPv4 address or an IPv6 /64,
  and none on a gateway that serves only itself.
- **Grouped refusals** count attempts; they do not list each one.
