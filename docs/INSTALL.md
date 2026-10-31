# Installing Keybash from source

`scripts/build-stage.sh` builds a stage as an ordinary user and
`scripts/install.sh` installs it, as root, on a **fresh** Linux x86-64 host
with systemd and cgroup v2. `scripts/uninstall.sh` removes programs and units
and keeps data. The operator's step-by-step guide is `INSTALL-AZ.md`; the
manual steps these scripts replace remain in `TEST-SETUP-AZ.md`.

This is a source installer for test and small self-hosted use. It is not a
package, an updater or a release; upgrades and signed releases remain gates.

## What the installer does

1. **Checks everything before the first change.** Root, Linux x86-64,
   systemd as PID 1, cgroup v2, `bwrap`, `setpriv`, `prlimit`. The stage holds
   regular executable programs; an RDP runtime, if present, has no symlinks or
   hard links. Nothing of Keybash exists: no program, data or configuration
   directory, sysusers file, unit file or loaded unit, runtime directory,
   account or group. The two service IDs are free (given, or the first free
   pair counting down from 65533; never 65534, never equal). The catalog passes
   `keybash check-targets`, with `--ssh-only` when the stage has no RDP runtime.
   The TLS pair passes `keybash check-tls`: it loads, is valid now, and covers
   the address or `--server-name` browsers use. The limits and listener pass
   the service plan itself. A refusal before this point leaves the host
   untouched and says `install refused: …`.
2. **Installs.** Programs go to `/usr/local/libexec/keybash` (root, 0755),
   each compared by SHA-256 with the stage; the RDP runtime goes to
   `/usr/local/lib/keybash/rdp`, root-owned with no group or world write. The
   unit plan is rendered from the *installed* worker and runtime digests.
   `systemd-sysusers` creates `keybash-gateway` and `keybash-worker`, then the
   IDs are confirmed. `/etc/keybash` is root 0755 with the catalog root 0644;
   `/etc/keybash/keys`, `/etc/keybash/tls` and `/var/lib/keybash` are
   gateway-owned 0700, the TLS pair 0600.
3. **Initializes as the gateway**, through `setpriv` with a clean environment
   and no supplementary groups: `init`, then `key-export`.
4. **Starts** the managers and the gateway after `systemd-analyze verify`, and
   waits until the gateway is active and listening.
5. **Prints once, to the terminal only**, the bootstrap code (15 minutes) and
   the instance key's recovery code (`BACKUP-RESTORE.md`).

It never replaces a file, unit or account. If a step fails after the first
change, it stops, says so, and rolls nothing back; `uninstall.sh` removes
programs and units.

## Options

| Option | Meaning |
|---|---|
| `--stage=/abs/stage` | from `build-stage.sh` (required) |
| `--catalog=/abs/targets.json` | the server catalog (`OPERATOR-CATALOG-LAB.md`, required) |
| `--tls-cert=…`, `--tls-key=…` | the gateway's HTTPS pair (required) |
| `--listen=IP:PORT` | default `127.0.0.1:8443`; another address needs `--allow-from` (`LAN-INGRESS.md`) |
| `--allow-from=NETS`, `--server-name=NAME` | exposed listener only |
| `--cpu-percent`, `--memory-mib`, `--tasks` | aggregate limits, defaults 200, 1024, 512 |
| `--gateway-id`, `--worker-id` | otherwise picked |

The listener settings reach the gateway unit only through
`keybash-service-plan`, which applies the gateway's own rules
(`ingress.Exposure`), so nothing can be injected into a unit line.

## Test HTTPS

`keybash-test-tls --name keybash.lan --output DIR` (or `--address IP`) writes
`ca.pem`, `cert.pem` and `key.pem`. The authority is P-256, at most 397 days,
path length zero, and name-constrained to that one name (every address
excluded) or that one address (names limited to `.invalid`). Its private key
is never written, so it cannot sign anything else. Trusting `ca.pem` on a test
PC, after comparing its printed SHA-256 fingerprint, vouches for this gateway
only. Production uses the organization's own CA or a public one.

## Adding a server later

`keybash server-add --config=/etc/keybash/targets.json --name=… --host=IP
[--port=22] [--fingerprint=SHA256:…]`, as root, adds one SSH server by IP
without hand-written JSON:

- It first checks the name and address against the catalog with a stand-in key.
  Protected networks, loopback, link-local and an address and port already
  listed are refused without any connection.
- It then reads the server's Ed25519 host key over an SSH handshake that
  stops at the key. It offers no other key type and never authenticates.
- It prints the fingerprint and the command to compare it on the server's
  console. It changes nothing until the operator types `yes`, or passes the
  `--fingerprint` they compared.
- The catalog is replaced through `operatorconfig.ReplaceCatalog`:
  - as root;
  - only if its bytes are still those it read;
  - only with a catalog that loads;
  - by writing a root-owned 0644 file beside it and renaming it over.
- The services read the catalog at start, so the command ends by naming the
  restart, which closes open sessions.

## Upgrading

In the checkout on the server, as the usual user, then as root:

```sh
git pull --ff-only
sh scripts/build-stage.sh ~/keybash-stage-$(git rev-parse --short HEAD)    # add --with-rdp for an RDP install
sudo sh scripts/upgrade.sh --stage=$HOME/keybash-stage-$(git rev-parse --short HEAD)
```

`upgrade.sh` replaces the programs (and the RDP runtime) and keeps everything
else: accounts, IDs, listener, networks, server name, limits, catalog, TLS
pair, keys and data. The Installation page in the workspace shows the same
commands with the running version.

- Each build changes every program's digest, since Go stamps the commit into
  it. The units pin the workers' digests, so the upgrade writes a new service
  plan rather than replacing files under the old one.
- The settings are read back from the installed gateway unit. They are used
  only if the installed `keybash-service-plan`, given them and the old
  digests, writes every installed unit and the sysusers file again byte for
  byte. A unit edited by hand is refused.
- Before the first change:
  - the new programs must accept the installed catalog and TLS pair;
  - the new plan must keep the same accounts and pass `systemd-analyze verify`;
  - the stage must keep the mode: an SSH-only install upgrades to SSH only,
    and an RDP install to RDP.
- It copies the old programs, units, runtime and database to
  `/var/backups/keybash/<UTC time>` (root, 0700), stops the services, swaps the
  files and starts them. If they do not come up, it puts the copies back and
  starts the old version.
- Upgrading closes open sessions. One upgrade runs at a time.
- The backup holds the sealed database, not the instance key. Remove it once
  the new version works.

Until Keybash publishes signed releases, an update trusts the code GitHub
serves over HTTPS; signed commits are checked in CI, not on the server.

## Uninstall

`uninstall.sh` stops and disables the units, removes unit files, the sysusers
file, `/usr/local/libexec/keybash` and `/usr/local/lib/keybash`, and reloads
systemd. It keeps `/var/lib/keybash`, `/etc/keybash` and both accounts; a fresh
install needs them removed deliberately, after a backup if the data matters.

## Evidence

`scripts/install-lab.sh` runs in CI on a disposable systemd runner, SSH-only at
the end of `service-lab.sh` and, at the end of `native-rdp-lab.sh`, with the
RDP runtime. It checks 13
refusals that leave the host untouched, a non-root refusal, and a full install:
- units active and enabled;
- `/login` over HTTPS verified through the test authority;
- the printed bootstrap code creating the first account;
- the printed recovery code's format;
- ownership and modes of every installed path.

It then upgrades that install:
- **Refusals that change nothing:** these leave every program, unit, runtime file
  and the database as they were, and the gateway running:
  - not root, an unknown option, a relative stage, a stage missing a program;
  - a stage of the other mode, a second upgrade at once;
  - a gateway unit edited by hand.
- **A real upgrade:** to a stage whose SSH worker differs only in its build ID. The
  new digest must be pinned in both units and match the installed worker. The
  account made at install still signs in, and the backup is root-only and holds
  the old worker.
- **A failed upgrade:** a stage whose gateway passes every check but never
  serves. Programs, units, runtime and database must be byte-identical
  afterwards, and the old version must serve and sign in.
- **Mutations of a copy of the upgrader:** each must fail its intended check:
  - skipping the unit check (an edited unit is upgraded over);
  - skipping the restore (a failed upgrade leaves the host down);
  - pinning the installed worker's digest (a valid upgrade no longer pins
    what it installs).

It then checks that a second install refuses before changing anything, and
that uninstall stops everything while keeping the database and key. Mutations
of a copy of the installer must fail their intended checks in both directions:
- skipping the TLS check;
- skipping `--ssh-only`;
- skipping every fresh-host check;
- never finding a free ID.

Go tests: `TestExposureNeedsNetworksAndASpecificAddress`,
`TestNameIsCanonicalAndNeverAnAddress`,
`TestServicePlanListenerFollowsTheGatewayRule`,
`TestCheckTLSBeforeInstalling`, `TestTestTLSCoversOnlyItsGateway`,
`TestTestTLSAuthorityConstraints` and `TestTestTLSRefusesBadInput`.
