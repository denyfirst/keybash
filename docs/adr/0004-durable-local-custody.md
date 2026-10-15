# 0004 — Embedded transactional custody with a separate instance key

Date: 2026-10-15. Status: accepted for the Linux single-process laboratory.

Choose pinned bbolt for fsynced exclusive transactions, including account
revisions, MFA replay/budget and one-time recovery consumption. PostgreSQL was
a candidate in the initial plan; this first self-host slice avoids another
service, public database port and database credentials. This decision does not
promise multi-process/HA deployment. Concurrent operators must stop the service;
network/shared filesystems and concurrent independent services are unsupported.

Use Go standard random-nonce AES-GCM envelope encryption with independent
HKDF purposes and a separate random instance key outside DB backups. Use the
maintained OTP library's bounded HMAC OTP API instead of implementing protocol
cryptography. MFA is mandatory for persistent sessions. Owner IDs come only
from server sessions, never browser-selected owner fields. Code signing and
release keys remain separate from runtime encryption keys.

The server necessarily decrypts active secrets. A compromised service or local
instance-key holder can access custody. Database/key separation protects the
database-only theft case, with explicit metadata/rollback limits. Rotation,
backup/restore, migration, filesystem fault injection and independent candidate
audit must precede production release. `CUSTODY-LAB.md` describes boundaries,
operator behavior, measured evidence and remaining product integration.
