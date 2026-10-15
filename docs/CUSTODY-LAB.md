# Durable identity and credential custody laboratory

15 October 2026. This extends the memory-only identity experiment. Linux
operator provisioning, encrypted durable accounts, mandatory MFA, single-use
recovery and owner-scoped credential CRUD now exist. The loopback HTTPS lab
has its own bundled interface. It grants no SSH/RDP worker authority. Use
synthetic credentials only until remote authorization, installation, recovery
and independent candidate audit gates pass. There is no production release.

## Trust and cryptography

The local service UID, host administrator, kernel, filesystem and instance-key
holder are trusted. This is server-side encryption, not zero knowledge or
protection against a compromised service/browser. Login password replacement
does not reencrypt the vault with that password. A separate new random 32-byte
instance key is required; Denyfirst signing/release keys are never reused.

`custody.db` is an embedded bbolt transactional file, exclusively locked by one
process, with fsync enabled. Data directory permissions are owned 0700, regular
DB and key files owned 0600. Opened roots/inodes are pinned; final file symlinks
and changed entries are refused. The key's private directory must resolve
outside the data directory. Exported storage/provisioning refuses non-Linux.
Portable tests use private synthetic fixture helpers, not a runtime bypass.

HKDF-SHA256 derives independent wrap/index/check keys with a random instance
ID as salt and version/purpose labels. Each account/credential save generates
a new random 32-byte data key. Standard-library AES-GCM with random nonces
encrypts the record and wraps its data key separately. AAD binds instance,
record kind, immutable owner/record IDs and revision, with separate data/wrap
prefixes. The standard API generates/prefixes the nonce; nil at that API is
required, not a fixed nonce. An authenticated monotonic seal budget stops
before 2^31 wrapping operations. The DB stores keyed username indexes and
encrypted accounts (hash, seed, recovery digests, revision, factor budget)
and credentials. Bootstrap status/expiry, instance ID, record IDs, counts,
sizes and access patterns are visible metadata; its state is HMAC protected.

Wrong keys and changed tags/owner bindings fail closed. Whole-file rollback,
record replay within an old authenticated database snapshot, arbitrary corrupt
bbolt files and offline deletion are not solved by AEAD. In particular an old
backup can resurrect a consumed code: restore must invalidate recovery/factors
before service, in a future tested restore workflow. Filesystem quotas, crash/
power-loss fault injection, key rotation, migration and encrypted export/restore
remain gates. Do not copy a live DB file as a backup. Losing the instance key
loses access; host root or DB plus key can decrypt the records. Go/browser RAM,
swap, core dumps, already delivered bytes and clipboard retention cannot be
guaranteed erased by clearing local buffers or hiding a field.

## Identity and factor state

An operator prints a random single-use 15-minute bootstrap code once. Its
digest is stored; there is no default account or public registration. The
first successful account transaction consumes setup permanently. Offline
renewal works only while uninitialized and replaces the previous code.
Accounts have immutable random 128-bit IDs, case-sensitive restricted names,
encrypted fixed-version Argon2id hashes (64 MiB, three passes, four lanes).
Password creation/change also rejects the bundled 10k common-password list,
explicit long common examples and repeated short patterns. Comparison for
rejection is case-folded/trimmed; hashing preserves exact input bytes. This
offline list is not a complete breach corpus or a NIST compliance claim.

Password authentication issues only a five-minute `enroll` or `challenge`
session. No credential operation is allowed until MFA succeeds and rotates
the cookie. TOTP uses the pinned OTP library, a random 160-bit seed, SHA1,
six digits, 30 seconds, +/- one time step. The greatest consumed counter and
five factor attempts per account/minute (including failures) commit durably.
Ten random 128-bit recovery codes are shown once and only their owner-bound
SHA256 digests persist. Each is atomically removed when used. The password
global/name budgets and KDF two-slot cap remain process-local; a restart
resets those limits but never the durable factor replay/budget state.

Ready sessions expire after 15 idle minutes/eight absolute hours; status reads
do not extend idle. Sessions/CSRF material are memory-only and die on restart.
Live operations recheck durable account identity/revision, and a one-second
sweep cancels changed cached generations. Password/factor/recovery changes
revoke previous sessions. Expired, canceled, corrupted or stale work cannot
grant fresh authority. Sensitive create/reveal/delete, password replacement,
factor replacement and recovery regeneration require password plus a fresh
factor proof no older than two minutes. A previously used TOTP must wait for
the next code; recovery codes can provide immediate fresh proof.

Factor replacement retains the old seed until the new seed/code is confirmed.
Abandoning replacement leaves the old factor working. If the two-minute proof
expires during replacement, sign out and reauthenticate before retrying. Local
offline account recovery changes the password and can explicitly clear a lost
factor, forcing new enrollment. The exclusive DB lock requires stopping the
lab first. No HTTP reset can bypass a factor by supplying only a password.

## Vault and browser boundary

Up to 256 accounts, 256 credentials/owner, 4096 overall, 64 MiB live credential
ciphertext and a 256 MiB DB allocation cap. File growth/IO exhaustion refuse
writes; these limits are not a service-wide CPU/RAM/DoS guarantee.
Credentials are independent of future connections. Password secrets up to
4096 UTF-8 bytes, without NUL, and a single OpenSSH Ed25519 private key up to
64 KiB are supported. Encrypted keys require aes256-ctr/bcrypt, salt 16..64
bytes and 1..64 rounds before invoking the library. Wrong passphrases, legacy
PEM/RSA/multiple keys/trailing data and inconsistent seed/public halves refuse.
Labels/usernames reject controls and formatting characters. RDP domain fields,
other key formats, edit/export and sharing are not implemented in this slice.

The HTTP API accepts no owner selector. Metadata never includes secrets;
explicit fresh-authorized POST reveal does. Even relocated ciphertext cannot
cross owner AAD. Strict bounded scalar JSON rejects duplicate/unknown fields,
null, malformed Unicode and trailing values. Bodies are bounded/read-deadlined
before the session mutex; key parsing/KDF use bounded slots outside it. Secret
responses stop on observed session cancellation, but bytes already delivered
cannot be retracted. The loopback/numeric exact Host, TLS 1.3, exact Origin,
custom request header, CSRF, secure HttpOnly SameSite Strict host cookie,
no-store, self-only CSP and fixed public errors remain enforced.

All assets are local; no CDN, external authentication, telemetry, QR image URL,
browser persistent storage or automatic clipboard read/write. Seeds are manually
entered in the authenticator. Clipboard writes require an explicit copy action;
rejection gives manual selection guidance. Revealed secrets auto-hide after
60 seconds and on background/pagehide. One-time recovery codes survive a tab
switch for saving, but clear on pagehide/logout or acknowledgment. BFCache
restoration clears and reloads state. This cannot erase OS clipboard history.
This slice's copy is vault text, not the still-disabled RDP clipboard feature.

## Operator laboratory

Build from reviewed source with the pinned Go toolchain; no binary release is
published. On Linux create separate owned 0700 directories, e.g. `/srv/keybash-data`
and `/srv/keybash-key`, as the service UID. Run the following with synthetic
data and a locally trusted operator TLS certificate, whose SAN matches the
numeric listener. Do not log/redirect setup-code output into service logs.

```sh
go run ./cmd/keybash init --data /srv/keybash-data --key-file /srv/keybash-key/instance.key
go run ./cmd/keybash serve-lab --data /srv/keybash-data --key-file /srv/keybash-key/instance.key \
  --listen 127.0.0.1:8443 --tls-cert /operator/tls/cert.pem --tls-key /operator/tls/key.pem
```

Visit `https://127.0.0.1:8443/login`, enter the one-time code, create a unique
password, enroll MFA, and save recovery codes separately. There is no TLS trust
bypass or public-listener flag. This is not yet a supported installation guide.
`bootstrap-renew` reissues setup before initialization only. Stop the lab before
`account-add` or `account-recover` (optional `--lost-mfa`). These read exactly two
LF-delimited stdin lines: username, password, with an optional final LF, total
2048 bytes. They emit neither password nor account. Supply stdin through an
operator-controlled private mechanism, never CLI arguments, environment,
shell history or a command containing the password. Passwords containing LF
cannot use this offline two-line protocol. HTTP password input preserves UTF-8.
Provisioning failures retain existing files and require operator inspection;
the tool never deletes/replaces an installation or silently generates a lost key.

## Evidence and remaining work

`TestCustodyHTTPBootstrapMFAAndVault`, `TestCustodyMFAReplayRecoveryAndRestart`,
`TestCustodyFactorFailuresPersistAndReplacementKeepsOldMFA`,
`TestCustodyCiphertextOwnerBindingTamperAndPlaintextAbsence`,
`TestCustodyRandomEnvelopesQuotaAndHTTPIsolation`,
`TestCustodySSHRejectsCostBombAndMismatchedPublic`,
`TestCustodyOfflineRecoveryBootstrapRenewalAndSealLimit`,
`TestCustodyStrictFieldsAndSlowBodyIsolation`, `TestCustodyCancelledReauthentication`
exercise successful/refused/malformed/abusive synthetic flows. Linux CI also
runs `TestCustodyLinuxPrivateProvisioning` and
`TestOperatorLinuxInitBootstrapAndOfflineRecovery`; portable tests do not prove
Linux permission behavior. `TestBrowserDurableCustody` uses Edge locally and
Chromium in required CI, including restart/replay, DOM labels, fresh proof,
failure handling, cookies, and absence of external/secret URL requests/storage.
`FuzzCustodyFields` gets two million executions with a hard timeout in CI.
See `VERIFICATION.md` for deliberate sabotage and adversarial self-review.

Remaining: connect owned credentials to approved target/identity records and
revocable isolated SSH/RDP workers; measured protocol convenience/clipboard;
complete workspace; hardened install/updates, privacy-safe audit, tested backup/
restore/key recovery/rotation, real server/browser/load matrix, independent
review of an exact release candidate and separately authorized signed release.
