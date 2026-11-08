# ADR 0003: credential-free RDP boundary experiments

Date: 2026-10-13. Updated: 2026-10-14. Status: accepted for the lab; production native adoption pending.

## Decision

Split RDP investigation into evidence gates. Implement initial negotiation,
TLS identity, bounded text-stream codec and an empty Linux network namespace
experiment before giving a native worker credentials. None is a production
RDP connection or authorization for another connection.

`rdplab.NewIdentity` copies an independently approved leaf certificate DER
(maximum 32 KiB), checks validity and its DNS name, and creates a private trust
pool containing only that leaf. `Probe` binds it to the guarded `NamedTarget`'s
logical name and requires its exact SHA-256 digest. It advertises TLS/HYBRID,
accepts only HYBRID, performs TLS >=1.2 with AEAD/ECDHE TLS 1.2 suites, and closes
the connection. No username, password, cookie, CredSSP, desktop or returned
transport. Its five-second budget includes dial and setup. Standard TLS
certificate/name verification remains enabled, with the imported leaf as its
only trust anchor, plus a mandatory exact pin hook. No system roots, automatic
first-use trust or certificate-ignore option. The pinned leaf must be
current, non-CA, explicitly server-auth/digital-signature capable, have no
unhandled critical extensions, have a matching DNS SAN (CN alone is refused),
and use Ed25519, RSA >=2048 or ECDSA >=256.
Renewal changes DER and needs a new independent approval.

HYBRID selection precedes TLS and is not itself authenticated. The experiment
proves only that the peer subsequently completes TLS with the approved key
and certificate. It does **not** authenticate an account, test CredSSP/channel
binding, or establish that the server actually implements NLA. Never preflight
and trust a later connection: the native worker must enforce its own pin,
including when a changed certificate has a valid CA chain. This small lab is
not a replacement RDP stack.

The private Guacamole wire prototype bounds an instruction to 48 KiB/16 elements,
counts Unicode codepoints and rejects invalid UTF-8/unbounded lengths. Each
clipboard direction admits only clipboard/blob/end, canonical IDs/base64,
text/plain, one active stream and 32 KiB total decoded text. UTF-8 can span blobs;
text appears only at end. Directions/sessions have separate state; refusal
poisons that direction. Close clears its owned buffer and refuses late data.
Returned string copies and OS clipboard history cannot be erased here. There
is no OS clipboard, browser tunnel or remote desktop connected to this codec.

Linux CI creates an unnamed empty network namespace for a fixed test child,
drops UID/GID to 65534, clears groups/capabilities, and sets no-new-privileges.
It verifies a distinct namespace, lone disabled loopback and failed host
loopback/IPv4/IPv6 TCP and DNS UDP attempts. Removing namespace creation must
fail the same child's namespace assertion. This is **network isolation only**:
host filesystem visibility is not sandboxed, guacd is not running, and even
approved destinations are denied. It does not prove a usable approved-only
worker or offline operation of the complete product.

## Update, 2026-11-06: Windows' own certificate at a literal address

The maintainer decided that a Windows server added on the Servers page uses
the certificate Windows makes for itself, checked by its fingerprint.

The rule above (a matching DNS SAN, digital-signature usage) cannot take that
certificate. A real one from Windows Server 2025 is self-signed, names the
computer as its common name, has no alternative names, carries key encipherment
and data encipherment without digital signature, and lasts six months. A small
office network also has no DNS name for it, and giving it one would mean
editing the Keybash host.

So a server at a **literal address** is identified by its exact certificate,
as an SSH server is by its host key:

- **Kept:** the exact DER pin, on the worker's own handshake before CredSSP;
  TLS >=1.2 with ECDHE and an AEAD; HYBRID; the validity period; not a CA and no
  certificate signing; no unhandled critical extension; the serverAuth EKU; the
  key strengths; OpenSSL's auth level 2. No ignore option, and first-use trust
  only as an administrator's explicit, marked choice (see the update below).
- **Dropped for this kind only:** the name check, because there is no name.
- **Changed for this kind only:** the key usage must allow digital signature or
  key encipherment, which is what TLS itself asks of a server certificate.
- **A server with a DNS name keeps every rule above,** name and digital
  signature included. The rules come from the target, never from the
  certificate: `identityFor` and `Identity.boundTo` keep the two kinds apart.

The worker learns the kind from its sealed name file, which then holds exactly
`@exact-leaf`. `@` is in no DNS name, so a missing, empty or cut file refuses and
never relaxes the check.

What this rests on is the comparison, so it cannot be skipped. The administrator
runs a fixed command on the server's own screen and pastes the line it prints;
the gateway reads the certificate again and compares. The API never hands out
the fingerprint of a certificate it read, so no page or script can accept what
the server shows without someone looking at the server. An attacker between the
gateway and the server shows a different certificate, and it does not match.

A renewal changes the pin. On the Windows Server 2025 test machine a certificate
made after removing the old one had a new key, so accepting a renewal because
the key stayed the same was not built: every change takes this comparison. The
real six-month renewal has not been seen yet.

The gateway reads each RDP server's certificate hourly and just before a session
opens. These reads hold no credential and authorize nothing, as the section above
requires: they only tell an administrator and the person connecting, earlier and
more clearly, that the pin no longer matches. A read that fails decides nothing,
and the worker checks its own handshake whatever a read saw.

Each read is a complete TLS handshake, so the server proves it holds the key of
the certificate it shows. Go's TLS library finishes a handshake with a
certificate nobody has trusted yet only with `InsecureSkipVerify`, so
`rdpcert.Read` sets it, and code scanners report it. It is safe there because
nothing is sent over that connection, which never leaves the function; the read
holds no credential; and the certificate it returns is only ever compared with a
pin or with the line an administrator pasted. Taking the certificate from a
failed library check instead would avoid the flag, but the server would no
longer prove it holds the key, so that was not done.

## Update, 2026-11-08: the check is the default, not the only way

The maintainer decided that the comparison above is chosen by default but may
be left out, for an administrator who prefers speed on a network they trust.
The add and **Check identity** sheets carry one box, "Check it on the server's
own screen", ticked when they open:

- **Ticked:** as above; nothing else changes.
- **Unticked:** the page says what it risks, and the gateway pins the
  certificate it reads at that moment, after the same rules, networks, fresh
  factor and limits. The server is marked **Not checked** for administrators
  and for every person who connects to it, until an administrator compares it
  with **Check now**. That takes the console line only and asks nobody to
  accept anything again. Accepting the same certificate without the check
  never undoes a check.
- **What it risks:** whoever is between the gateway and the server at that
  moment is pinned instead of the server, and the Windows passwords people send
  reach them. Every later change is still caught as with any pin: a renewal is
  never accepted by itself, it still raises the alarm, and each person still
  accepts a new pin on their own connection.
- **Only here:** a server from the operator's file, a server with a DNS name
  and an SSH server never carry the mark. The API takes `unchecked` only in an
  RDP server's fingerprint field, where it cannot be taken for a fingerprint.

The worker's own handshake still holds the exact pin either way.

A real Windows Server 2025 also showed that its negotiation answer sets a flag
(0x20) the original rule refused. Flags only say what else a server could do,
and nothing acts on them, so any flags are now taken with HYBRID; anything but
HYBRID is still refused.

## Next adoption gate

guacd/FreeRDP are native candidates, not shipped dependencies. Capture exact
sources/checksums, build/runtime inventory, license/NOTICE, current advisories,
TLS/cipher settings and parser/resource limits before adoption. The fingerprint
option alone is not evidence of the exact native build's behavior. No Java
webapp or hosted service is needed for our design.

A candidate worker has no direct network route. A separately authorized broker
can supply one guarded TCP target stream over narrowly scoped IPC. A local
bridge must preserve end-to-end RDP TLS, never substitute a preflight or
terminate TLS with a proxy certificate. Prove only the intended target can be
reached, including changed DNS, gateway/redirection/UDP attempts and broker
cancellation. No generic proxy, browser-selected args, Docker socket, vault/DB
access or target fallback. Prove filesystem/process/resource isolation,
session ownership and revocation before creating a product entry point.

Then use a fresh-key synthetic NLA server and synthetic accounts to test valid/
invalid password, missing NLA, valid/changed/untrusted/expired cert, native pin
mismatch even with CA validity, Unicode text both ways, resize, keyboard and
cancellation. Browser clipboard needs explicit action, permission fallback and
bounded buffers; the codec alone proves none of that UI. File/image clipboard,
drive/SFTP, gateway, audio, printing, recording and arbitrary channels remain
disabled. Production ownership/vault and independent audit are separate gates.

## Primary references checked

- [Microsoft negotiation request](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/902b090b-9cb3-4efc-92bf-ee13373371e3)
- [Microsoft negotiation response](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/b2975bdc-6d56-49ee-9c57-f2ff3a0b6817)
- [Guacamole wire format](https://guacamole.apache.org/doc/gug/guacamole-protocol.html)
- [Guacamole text streams](https://guacamole.apache.org/doc/gug/protocol-reference.html#clipboard)
- [Guacamole options](https://guacamole.apache.org/doc/gug/configuring-guacamole.html)
- [Guacamole security reports](https://guacamole.apache.org/security/)
- [FreeRDP releases](https://github.com/FreeRDP/FreeRDP/releases)

The original probe/codec uses Go's standard library. The subsequent synthetic
native lab source-builds pinned Guacamole 1.6.0/FreeRDP 3.32.2 and OS libraries
with inventory, license/NOTICE and narrow integration patches. The actual
native TLS hook enforces identity before CredSSP; a one-use guarded broker and
test-only filesystem/network/UID/resource isolation provide the sole transport.
NLA login, image decoding, refusal and callback mutations are required CI gates.
This does not complete the browser/clipboard/keyboard matrix or authorize real
credential use. See [native evidence and limits](../NATIVE-RDP-LAB.md).
The subsequent browser lab adopts locally bundled guacamole-common-js 1.6.0,
with a typed drawing/input adapter and static PNG normalization, while retaining
the owner/Origin/revocation boundary. See [browser evidence](../BROWSER-RDP-LAB.md).
No container or Java webapp is adopted; no Go dependency version is
added. x/sys becomes direct for test-only Unix peer checks. Production worker
launch/authorization, complete sandbox/packaging and independent audit remain.
