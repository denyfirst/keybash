# Keybash — SSH and RDP on a separate test VM

This path is for a disposable test environment and test accounts only. It is
not a release, a production installer or an audited product. Never test on the
host that runs Porch or Rootwell.

**The short path:** `scripts/build-stage.sh`, `keybash-test-tls` and
`scripts/install.sh` now do the steps "Preparing the source", "A separate HTTPS
test certificate" and "Placing the source services"; see `INSTALL.md`. The
manual steps below stay to explain and check what those scripts do.

## What you need

- A separate **Ubuntu 24.04 x86-64 VM with systemd and cgroup v2** for Keybash.
- As targets, a separate Linux SSH server and a Windows test server with RDP
  and NLA enabled.
- A LAN or VPN path from the Keybash VM to the targets, and stable DNS names or
  IP addresses.
- A VM with a few GiB of RAM for the first trial. The 1 GiB service limit below
  is not a minimum RAM recommendation for the host; no measured hardware
  profile exists yet.
- By default the application listens on `127.0.0.1:8443` and is reached from
  the PC through an SSH tunnel. If you prefer, the "From the local network"
  section below opens it to the LAN or VPN networks you name. Public internet
  access does not exist yet, and a proxy never weakens the Host and Origin
  checks.

Keep only test data on the targets. The RDP clipboard test does not cover
files, images, printers, disks or audio. No particular Windows version or
keyboard matrix has been confirmed on a VM in this repository yet.

## Preparing the source

On the new VM, as an ordinary administrator account, clone the repository on
its own. Check the signed PR merge commit and the `.github/commit-signers`
trust list separately. Do not build as root. Run these in the repository root:

```sh
sudo apt-get update
sudo apt-get install --no-install-recommends git golang-go python3 curl ca-certificates \
  build-essential clang cmake ninja-build pkg-config bubblewrap openssl \
  libssl-dev libcairo2-dev libjpeg-dev libpng-dev libwebp-dev libpango1.0-dev \
  libuuid1 uuid-dev
go version
go mod verify
mkdir -m 700 test-stage
mkdir -m 700 test-stage/bin
CGO_ENABLED=0 go build -trimpath -o test-stage/bin/ ./cmd/...
sh scripts/build-native-runtime.sh "$(pwd)/test-stage/native"
LD_LIBRARY_PATH="$(pwd)/test-stage/native/lib" python3 scripts/build-rdp-runtime.py \
  --prefix "$(pwd)/test-stage/native" --output "$(pwd)/test-stage/runtime"
```

Go has to switch to the exact toolchain in `go.mod`. The build downloads Go
modules and the pinned native source archives. The runtime needs no Node, CDN
or cloud service. The build script never writes over an existing output
directory; after a failed build, choose a new stage name. `--fixtures` is for
CI only.

## The targets' identities

Use the version 1 JSON catalog format in `OPERATOR-CATALOG-LAB.md`. Each server
gets a random 32-character lowercase hex ID, a DNS name, a port, its allowed
IP addresses and its public server identity. These are test examples; adapt
them to your VM network:

```json
{
  "version": 1,
  "capacity": {"total": 2, "per_owner": 1},
  "protected_networks": ["10.90.0.0/24"],
  "targets": [
    {"id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","name":"Linux test","protocol":"ssh",
     "hostname":"linux-test.example.test","port":22,"addresses":["10.91.0.10"],
     "ssh_host_key":"REPLACE_WITH_CANONICAL_ED25519_PUBLIC_HOST_KEY"},
    {"id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","name":"Windows test","protocol":"rdp",
     "hostname":"windows-test.example.test","port":3389,"addresses":["10.91.0.20"],
     "rdp_certificate":"REPLACE_WITH_BASE64_DER_SERVER_CERTIFICATE"}
  ]
}
```

`protected_networks` must cover the networks of the Keybash VM, the vault and
control services, and every other forbidden service. Keeping Keybash and the
targets in separate test subnets makes this choice clear. Every DNS answer
must match the listed addresses. A changed address or fingerprint is never
accepted automatically.

Take the SSH host public key from the Linux VM's console, from
`/etc/ssh/ssh_host_ed25519_key.pub`, drop the comment, and check its SHA256
fingerprint separately. Never trust `ssh-keyscan` output on its own. Make a
separate Ed25519 user key for the test account; never bring a production
private key here. For SSH servers, the Servers page reads the host key itself
and asks you to compare the fingerprint (`INSTALL.md`).

For RDP, keep NLA on. The certificate needs:
- a SHA-256 or stronger signature;
- at least RSA 2048 or ECDSA P-256;
- a DNS SAN, the DigitalSignature key usage and the serverAuth EKU;
- valid dates.

Windows' usual automatic certificate may not meet this profile.
- Choose the certificate on the test Windows console and bind it to the RDP
  listener.
- Export only its public DER from there; the private key or PFX is never given
  to Keybash.
- Give the listener read access to the private key as Microsoft describes.

The Windows configuration follows the
[official listener guide](https://learn.microsoft.com/en-us/troubleshoot/windows-server/remote/remote-desktop-listener-certificate-configurations)
and the
[certificate creation parameters](https://learn.microsoft.com/en-us/powershell/module/pki/new-selfsignedcertificate?view=windowsserver2025-ps).
This Windows step is not yet an actual VM acceptance result.

Give the Windows test user RDP rights to that VM only. In the firewall, accept
3389 from the Keybash test VM only. The username can be a local account name;
there is no separate RDP domain field yet.

## A separate HTTPS test certificate

The gateway's HTTPS certificate is not the Windows RDP certificate.
- The gateway leaf's SAN holds **IP:127.0.0.1**, with serverAuth and a fitting
  key usage. Sign it with a separate test CA.
- The private TLS key stays on the VM.
- Add only the public test CA to the trust store the PC uses for testing, and
  compare its fingerprint separately.
- Never use a certificate bypass or ignore option in the browser.
- Remove this extra trust when the test ends.
- Never use the test CA's private key as an everyday or production CA.

## Placing the source services

These steps are an administrator's job on a **fresh VM** only. Stop if any of
these already exist; never write over an existing Keybash or another product:

- `/usr/local/libexec/keybash`
- `/usr/local/lib/keybash/rdp`
- `/etc/keybash`
- `/var/lib/keybash`
- the `keybash-gateway` and `keybash-worker` accounts, and the UIDs and GIDs
  you choose
- `keybash*.service`, `keybash.slice` and `/run/keybash*-manager`

Copy every `keybash*` Go program from the stage to
`/usr/local/libexec/keybash/`, root-owned with no group or world write, and
the minimal `runtime/` tree the same way to `/usr/local/lib/keybash/rdp/`.
Leave no symlinks or hard links in the runtime: copy it into a new tree with
`cp -R` and give no write permissions.

Choose two separate UIDs and GIDs that belong to no other account. The example
values may be used only if **65533 and 65531 are free**. First check
`getent passwd 65533`, `getent group 65533`, the same for 65531, and the
account names. `0` and `65534` are never used.

Once the programs and runtime are in place, in an ordinary admin shell:

```sh
ssh_digest=$(sha256sum /usr/local/libexec/keybash/keybash-ssh-worker | cut -d ' ' -f 1)
rdp_digest=$(sha256sum /usr/local/libexec/keybash/keybash-rdp-worker | cut -d ' ' -f 1)
runtime_digest=$(/usr/local/libexec/keybash/keybash-rdp-inventory /usr/local/lib/keybash/rdp)
/usr/local/libexec/keybash/keybash-service-plan --gateway-uid=65533 --gateway-gid=65533 \
  --worker-uid=65531 --worker-gid=65531 --worker-digest="$ssh_digest" \
  --rdp-worker-digest="$rdp_digest" --rdp-runtime-digest="$runtime_digest" \
  --cpu-percent=200 --memory-mib=1024 --tasks=512 --output="$(pwd)/test-stage/units"
```

The plan only creates new staging files. Review the five files first.
`keybash.conf` is the sysusers policy: put it at `/etc/sysusers.d/keybash.conf`
and the four units in `/etc/systemd/system/`, root-owned, mode 0644. Create the
accounts with `systemd-sysusers /etc/sysusers.d/keybash.conf`.

`/var/lib/keybash`, `/etc/keybash/keys` and `/etc/keybash/tls` are separate
gateway-owned 0700 directories. The catalog `/etc/keybash/targets.json` is a
root-owned 0644 file, and its parent `/etc/keybash` is root-owned 0755. The
HTTPS certificate and key are gateway-owned 0600 files. The instance key is a
different file from the catalog and the TLS private key.

```sh
sudo /usr/local/libexec/keybash/keybash check-targets --config=/etc/keybash/targets.json
sudo -u keybash-gateway /usr/local/libexec/keybash/keybash init \
  --data=/var/lib/keybash --key-file=/etc/keybash/keys/instance.key
sudo systemd-analyze verify /etc/systemd/system/keybash*.service /etc/systemd/system/keybash.slice
sudo systemctl daemon-reload
sudo systemctl start keybash-gateway.service
```

`init` shows a one-time bootstrap secret. Take it in a private local terminal
only; never put it in a log, a screenshot, a chat or a shell argument. There
is no default password. The services refuse to start when a cgroup controller,
a limit or an identity does not match. Fix the cause; never switch off the
limit check, the namespaces or the syscall filter.

## Opening it from the PC and checking it

On the PC, after confirming the VM's SSH host identity separately:

```sh
ssh -N -L 127.0.0.1:8443:127.0.0.1:8443 vm-admin@KEYBASH_TEST_VM_IP
```

Port 8443 must be free on the PC. Open `https://127.0.0.1:8443` in the browser
with the trusted test HTTPS. Then go through, in order:
1. the bootstrap;
2. a separate sign-in password;
3. MFA and the recovery codes;
4. importing a test SSH key or password;
5. a connection, confirming the server's full fingerprint separately;
6. Connect.

If there is a status or stale-trust error, fix the certificate, the address or
the clock; never grant blanket trust.

### From the local network (no tunnel)

To let everyone in the office or on the VPN connect without a tunnel, open
Keybash on the VM's LAN address. Only the networks in `--allow-from` are
accepted; other connections are closed before TLS. Details: `LAN-INGRESS.md`.

1. The gateway certificate's SAN holds the name (`DNS:keybash.lan`) or address
   (`IP:192.168.1.10`) browsers will use. If the certificate does not cover
   that name, or has expired, the service does not start.
2. Instead of `--listen 127.0.0.1:8443`, give the service:
   ```sh
   --listen 192.168.1.10:8443 --allow-from 192.168.1.0/24 --server-name keybash.lan
   ```
   `0.0.0.0` (every interface) and `0.0.0.0/0` (the whole internet) are
   refused. Several networks are separated by commas (16 at most).
3. Point `keybash.lan` at `192.168.1.10` in the local DNS (or the PCs' hosts
   files) and open `https://keybash.lan:8443` in the browser.

One source may make at most 30 sign-in attempts a minute and hold 64
connections at once. Do not run it behind a reverse proxy: every user would
count as one source.

Check these tasks and write down the expected and the actual result:

1. In SSH: Unicode, Ctrl+C, the arrows, vim and nano, PTY resize, and the
   review of a multi-line paste.
2. On Windows, open Notepad and send non-Latin text, an emoji and a newline in
   both directions. After a remote copy, use Keybash's **Copy** button. The
   local clipboard must not change by itself.
3. Refuse the clipboard permission; copy and paste must still work through the
   text panel. A paste must not add an Enter. Files and HTML must not pass as a
   channel.
4. Check 1280×720 and full screen. If the server does not support display
   updates, the remote size shown does not change until it is confirmed; there
   is no hidden reconnect or password retry.
5. Sign-out, deleting a credential or connection, and stopping a manager cut
   an active session. A new sign-in does not resume the old session by itself.
6. A wrong password, a changed host key or certificate, and another owner's
   resources are refused. Never test these with real credentials.

The source test flow has no lifetime output limit:
- Native output, instructions and pixel work are paced by a per-second budget.
  Going over it slows the session down rather than closing it.
- There are limits of 32 KiB of text and 128 clipboard operations in each
  direction (one returns each second), and 4 resizes a second.
- Session, CPU, RAM and task limits are finite.
- Long daily sessions and a wide browser and Windows matrix have not been
  measured.
- Running out of resources can close an active session too.

After the test, stop the services with
`systemctl stop keybash-gateway keybash-ssh-manager keybash-rdp-manager`, and
keep or delete the disposable VMs as your snapshot policy says. Before
production, restore and upgrade, sizing, public ingress and an independent
audit of an exact candidate must each be completed.
