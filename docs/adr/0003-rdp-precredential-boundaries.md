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
No container, Java webapp or JS client is adopted; no Go dependency version is
added. x/sys becomes direct for test-only Unix peer checks. Production worker
launch/authorization, complete sandbox/packaging and independent audit remain.
