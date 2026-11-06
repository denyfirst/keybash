# Keybash — current status

2 November 2026. This page replaces the earlier Azerbaijani status and
readiness notes. Keybash is in active development and has not been released:
keep only test data on it. The plan is `PRODUCT-PLAN.md`; the stages are
`ROADMAP.md`.

## What exists

**Installing and running**
- A source installer for a fresh Linux x86-64 host with systemd and cgroup v2.
  It checks everything before its first change, never overwrites anything, and
  prints the bootstrap code and the instance key's recovery code once
  (`INSTALL.md`).
- An upgrader that keeps accounts, settings and data, copies the old version
  first, and puts it back if the new one does not start. There is also an
  uninstaller that keeps the data.
- Separate service identities for the gateway and the workers, with systemd
  units and checked cgroup v2 CPU, memory and task limits
  (`LINUX-SERVICE-LAB.md`).
- HTTPS only. By default it listens on loopback; it can open to named LAN or
  VPN networks only, with per-source limits (`LAN-INGRESS.md`). A test
  certificate authority can sign for exactly one name.
- The gateway reaches only loopback, its listener's networks and the target
  networks root set at install. The kernel denies every other address to its
  unit, even if the gateway is compromised. By default those are exactly the
  catalog's server addresses (`INSTALL.md`, `adr/0005-web-managed-servers.md`).

**Accounts and sign-in**
- A one-time bootstrap code for the first account; no default password.
- Argon2id passwords of at least 15 characters, checked against a blocklist.
- Mandatory TOTP on a phone and one-time recovery codes. Showing or deleting a
  secret, or changing the account's protection, needs a code from the last ten
  minutes.
- Roles: user, administrator and auditor. Administrators invite people with a
  one-time code from the Users page, and change roles, block, reset access and
  delete accounts there. Every change ends that person's sessions at once, and
  the last administrator cannot be removed.
- Resets from the web, for what a person lost:
  - **Their phone:** a code they enter after signing in with their own
    password.
  - **Their password:** "Forgot password?" with an administrator's code and
    their own phone code.
  - **Both:** start over, which deletes their keys and passwords.

  No administrator can become someone else.
- `keybash account-recover --admin` on the server, for when no administrator
  can sign in.

**Keys, passwords and servers**
- Each stored key or password is sealed under its own data key; the instance
  key is kept in a separate file.
- SSH keys (Ed25519, ECDSA, RSA 2048 and up) with passphrases, and passwords.
  Keybash can also make an Ed25519 key whose private half it never shows.
- Administrators add SSH and Windows RDP servers on the Servers page, inside the
  target networks only. Keybash reads the host key or certificate, they check it
  on the server's own console, and it is read again and pinned when added. Nobody
  can use a new server until an administrator chooses who may; taking someone
  off, a new key or removing the server ends open sessions at once.
- When Windows renews its RDP certificate, nothing accepts it by itself. Keybash
  reads each desktop's certificate hourly and before each session: the person
  connecting is told no password was sent, an administrator sees a mark and a
  line on every page, and a fingerprint from the server's own screen settles it.
- Every server has an access list, auditors read the page, and nothing is
  open to everyone. Servers in an older `targets.json` move into the page once
  at the first start, open to exactly the people who already connect to them.
  A new install needs no server file: it names only the networks servers are
  in. Changed identities block the connection until the owner accepts them
  again (`SERVER-TRUST-LAB.md`, `INSTALL.md`).
- Dials go to the pinned addresses only, with DNS answers checked and
  metadata, loopback and protected networks refused.

**In the browser**
- An SSH terminal through an isolated worker process: its own namespaces, a
  syscall filter, the host key checked before authentication, and paste
  review (`SSH-MANAGER-LAB.md`, `SSH-PROCESS-LAB.md`).
- RDP through a pinned native runtime, when built with `--with-rdp`. It offers
  text-only clipboard and display updates (`RDP-WORKSPACE-INTEGRATION.md`).
- Total and per-owner session limits (`SESSION-CAPACITY.md`).
- The workspace in English, in light and dark schemes, laid out for phones
  too.
- An Installation page with the running version and the upgrade commands.

**Backup**
- Offline encrypted backups, the instance key's recovery code, and restore to
  an empty directory. Restore resets every account's MFA
  (`BACKUP-RESTORE.md`).

**Engineering**
- Signed commits checked in CI, CodeQL, staticcheck, gosec and govulncheck.
- Linux CI that installs, upgrades, rolls back and uninstalls on a real
  systemd runner.
- Browser tests in Chromium.
- Sabotage of security checks in both directions (`ENGINEERING.md`,
  `VERIFICATION.md`).

## Not ready yet

- **Signed, reproducible releases.** There are no tags yet; an upgrade trusts
  the code GitHub serves over HTTPS (KB-10).
- **An independent security audit of an exact release candidate.** CI and the
  maintainer's own review do not count as one.
- **The audit record** for auditors: administrator actions, who connected where
  and when, and a readable log of typed command lines.
- **Shared keys** a user connects with without seeing them.
- **Mail or other notice outside Keybash:** an administrator learns of a renewed
  certificate only at their next sign-in. A certificate renewed with the same key
  is treated like any other: it has not been seen, and each one is checked.
- **Adding RDP to an installation built without it:** `upgrade.sh` keeps the mode
  it finds, so this needs a reinstall.
- **SFTP**, an SSH bastion or jump host, and an RDP domain field.
- **Online or scheduled backups**, a passphrase on the backup file, and instance
  key rotation.
- **Public internet ingress**, measured server sizing, long-session and load
  results.
- **Real Windows acceptance**, and the full browser, keyboard and clipboard
  matrix.
- **A decision on KB-05:** detecting a database record rolled back by someone
  who can write the file.

## Before a production release

Each step is accepted on evidence, not on a date:

1. Real Linux and Windows servers, Chrome, Edge, Firefox and Safari, and the
   operating systems' keyboard and clipboard behaviour. Support claims cover
   only the measured matrix.
2. Load, poor connections, upgrade and restore, and cross-account attack
   tests.
3. Signed tags, a separate reproducible build with published checksums, and
   `verify.md`.
4. An independent audit of the exact candidate commit, with material findings
   resolved before an authorized release.

## Name

The maintainer chose the name Keybash. No well-known product of the same name
turned up in a first search of the field, but legal clearance is not done.
Trademarks and similar names in the target markets must be checked before a
public release.
