# Password identity laboratory

Historical scope: this document records the initial memory-only slice. Its
durable account/MFA/custody follow-up is implemented in [CUSTODY-LAB.md](CUSTODY-LAB.md).
The original memory experiment still grants no credential or remote authority.

15 October 2026. The first identity slice is an isolated password-login service
with a browser interface and real password hashing/session checks. It is not a
persistent account system, MFA, vault or remote-access authorization boundary.
No real credentials, installer, public listener, deployment or release.

Porch's login/session sources and Rootwell's login/gate were read as references
only. Neither repository was changed or used as a build/runtime dependency.
Keybash independently implements individual named accounts and its own assets.
The appearance follows the existing Denyfirst dark palette and restrained red.

## Implemented boundary

- `identity.NewLab` accepts only a numeric loopback HTTPS origin and 1..256
  copied, trusted, pre-provisioned accounts. There is no default password,
  public registration, password output/logging or existing-product account import.
- The opaque version-one hash fixes Argon2id at 64 MiB, three passes, four
  lanes, a fresh 16-byte random salt and a 32-byte result. Callers cannot supply
  attacker-controlled KDF cost parameters. Constant-time digest comparison;
  password bytes are preserved exactly, without trimming/normalization.
- New passwords have at least 15 Unicode code points and at most 1024 UTF-8
  bytes. Login inputs are nonempty and at most 1024 bytes. A production password
  blocklist, provisioning, hash persistence/migration and recovery remain gates;
  this is not a claim of NIST compliance or adequate password entropy by length.
- Actual peer loopback, exact Host, HTTPS/TLS >=1.3, no query/escaped paths,
  fixed local assets and a closed route set precede sensitive handling.
  Forwarded headers cannot authorize another peer or origin.
- Mutation endpoints require the exact Origin and a custom request header;
  logout/password change additionally require a per-session CSRF proof derived
  with standard HMAC-SHA256 from a random instance key and the session digest.
  No CORS allowance, arbitrary redirect, URL token or browser storage.
- JSON has a 16 KiB raw ceiling, two exact unique string fields, no unknown or
  duplicate/case-alias fields, no null/coercion/trailing value, <=1024 bytes per
  decoded field and valid UTF-8/scalar escapes. Unpaired surrogates are refused
  before Go's JSON decoder can silently repair them.
- At most two concurrent KDF operations, with no waiting request queue. A
  login takes a KDF slot before its attempt is recorded, then a fixed one-minute
  window permits five checks per supplied name; known and unknown names use the
  same policy and KDF cost. There is no window shared across names or purposes:
  MFA, reauthentication, password change, import, trust and connection opens
  each have their own per-account window, so failed logins cannot lock other
  accounts or a signed-in owner out. At most 8192 counters exist; a full table
  refuses new names rather than evicting another account's counter, and expired
  windows are reclaimed every second. Success does not reset budgets. Repeated
  failures against one name still deny that name for a minute. An exposed
  gateway (`LAN-INGRESS.md`) also allows 30 sign-ins per source per minute.
- Fresh 256-bit opaque session tokens; only SHA-256 token digests are stored.
  `__Host-` Secure/HttpOnly/SameSite=Strict cookie, Path=/, no Domain. Duplicate,
  malformed, forged and revoked cookies cannot select a session. Successful
  sign-in rotates the current browser session; no client-selected session ID.
- At most eight sessions per account and 128 overall; capacity exhaustion
  refuses instead of evicting another browser. Idle expiry is 15 minutes and
  absolute expiry eight hours. Explicit account-page navigation renews idle
  activity; account status/output polling does not. A one-second background
  sweep cancels expired contexts even without another HTTP request.
- Logout cancels only its own session. A password change checks the current
  password and session CSRF, replaces the account hash and cancels all sessions
  of that account, preserving other accounts. Account revision and live-session
  checks after derivation refuse stale/canceled work. Service closure revokes
  every session; pending hashes cannot issue a late session.
- Error messages are fixed and do not echo credentials/remote diagnostics.
  Hash formatting is redacted. Browser forms use POST even without JavaScript,
  clear password inputs before sending and on page hide, and never persist them.
  JS retains sensitive strings transiently; guaranteed RAM erasure is not claimed.
- The account screen verifies the current session before enabling actions.
  Request deadlines cover both headers and bounded response bodies. Failed or
  uncertain logout/password changes never claim success. History restoration
  revalidates through a reload. CSP needs no inline scripts/styles/eval, external
  font/image/CDN, clipboard permission or terminal assets.

## Evidence

Unit tests measure successful Unicode authentication, independent salts and
exact password bytes, wrong/unknown/cross-account refusal, owner isolation,
rotation, cookie/Origin/TLS/CSRF controls, strict/malformed input and quotas,
positive activity renewal, non-renewing status, idle/absolute/background expiry,
password change, stale derivation and close. The JSON fuzz target performs no
KDF; required CI completes two million executions with a hard timeout.

Tagged browser tests use synthetic accounts and an isolated self-signed fixture
only. Edge locally and Chromium in CI exercise denied login, password clearing,
cookie policy, protected navigation, password change, old-password refusal,
logout, malformed account responses, uncertain logout and untouched storage.
Synthetic values enter the browser harness through stdin, never URL, process
arguments, environment or diagnostic output. No listener remains after testing.

## Next identity gates

Durable account IDs and storage, local single-use bootstrap, transactional hash
updates/revision invalidation across restart/processes, password blocklist and
operator recovery precede production use. TOTP enrollment/confirmation, encrypted
seed custody, replay/rate controls and hashed single-use recovery codes remain
planned. Password login here does not claim MFA and cannot open SSH/RDP, reveal
credentials or construct a worker. Wiring those operations requires the completed
MFA/ownership/vault/lifecycle boundary, production isolation and independent
review of an exact candidate. A password-only lab cookie must not become a
shortcut around those gates.

Primary guidance checked on 15 October 2026:
[pinned Argon2 API](https://pkg.go.dev/golang.org/x/crypto@v0.58.0/argon2),
[RFC 9106 parameters](https://www.rfc-editor.org/rfc/rfc9106.html#section-4),
[OWASP password storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html),
[OWASP session management](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html),
[NIST authenticator guidance](https://pages.nist.gov/800-63-4/sp800-63b/authenticators/).
