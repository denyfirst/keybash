# Backup, key recovery and restore

Keybash keeps two things that only together open the stored credentials: the
custody database in the data directory, and the 32-byte instance key in its own
directory. A backup copies the first; the key is written down once, separately.

## Step by step on an installed server

The database has one owner at a time, so each command runs as the gateway's
account with the gateway stopped. Sessions close while it is stopped.

**The recovery code.** The installer printed it once. Keep it on paper or in a
password manager, apart from the server and from the backups. To print it
again:

```sh
sudo systemctl stop keybash-gateway
sudo setpriv --reuid=keybash-gateway --regid=keybash-gateway --clear-groups --reset-env -- \
  /usr/local/libexec/keybash/keybash key-export --data=/var/lib/keybash --key-file=/etc/keybash/keys/instance.key
sudo systemctl start keybash-gateway
```

**A backup.** Make a private directory for it once, then:

```sh
sudo install -d -o keybash-gateway -g keybash-gateway -m 0700 /var/backups/keybash-custody
sudo systemctl stop keybash-gateway
sudo setpriv --reuid=keybash-gateway --regid=keybash-gateway --clear-groups --reset-env -- \
  /usr/local/libexec/keybash/keybash backup --data=/var/lib/keybash --key-file=/etc/keybash/keys/instance.key \
  --out=/var/backups/keybash-custody/keybash-$(date -u +%Y%m%dT%H%M%SZ).backup
sudo systemctl start keybash-gateway
```

The file holds no key and no plaintext secret, not even usernames, so it can
be copied to another disk or site. Never keep it with the recovery code.

**A restore.** Restore writes into an empty private directory owned by the
account that runs it, with the key written from the recovery code (read from
standard input, never from an argument):

```sh
mkdir -m 700 restored-data restored-keys
keybash key-import --data=restored-data --key-file=restored-keys/instance.key
keybash restore --data=restored-data --key-file=restored-keys/instance.key --in=keybash-….backup
```

It prints one setup code per account; give each person their own. Every
account sets up its phone again (see "Restore" below). Pointing an installed
service at a restored directory is not scripted yet.

**Check your backups.** From time to time, restore one into a spare empty
directory, check that it opens, then delete that directory. Making backups
alone is not enough.

## Commands

All four are offline operator commands. Like `account-add`, they take the
database's exclusive lock, so the service is stopped while `backup` or
`key-export` runs. Nothing secret is read from arguments or the environment.

| Command | Does |
|---|---|
| `keybash backup --data D --key-file K --out FILE` | writes a sealed backup to a new 0600 file; refuses an existing file and the key's own directory |
| `keybash key-export --data D --key-file K` | prints the instance key's recovery code, only after that key has opened the store |
| `keybash key-import --data D --key-file K` | reads a recovery code on stdin and writes a new 0600 key file; never replaces one |
| `keybash restore --data D --key-file K --in FILE` | restores into a private data directory that has no database, and prints one setup code per account |

## What a backup is

A logical copy of every custody namespace (state, accounts, name index,
credentials, connections, servers, and each account's chosen look), read in
one transaction. Before anything is written, every record is read as the
service would read it: the state's tag, each account, one name-index entry
per account, each credential, connection and look with an existing owner (a
look under its own account's name only), and the write quotas (256 accounts,
256 credentials per owner and 4096 overall, 128 connections per owner and
2048 overall, one look per account). A store holding any other namespace, a nested one, or a record that
does not read is refused rather than backed up in part.

The copy is sealed with AES-256-GCM (random nonce) under a key derived from the
instance key by HKDF for that one file (a random 32-byte salt). The header,
which names the format, the instance ID, the creation time and the salt, is the
associated data, so none of it can change undetected. The records inside are
already the store's own envelopes; the file encryption also hides usernames'
index entries, record counts and sizes. A backup contains no key and no
plaintext secret, and records the program version that wrote it.

## The instance key's recovery code

`KB1-` followed by the key and a four-byte check in base32, in groups of five
(73 characters). Case and separators do not matter on import; a mistyped
character fails the check, and only canonical base32 is accepted. Keep it apart
from the server and from the backups: on paper or in a password manager.

Lose the key and its code, and no backup can ever be opened; there is no
recovery by Keybash or anyone else. Anyone with both a backup and the key can
read every stored credential, as anyone with the server's disk and key could.

## Restore

Restore reads at most `MaxBackupFile` bytes, checks the header, and decrypts
before creating anything: a wrong key, another instance's key or a changed
byte creates no file. Entries must be in canonical order (namespaces in file
order, keys strictly increasing), so nothing can repeat.

The database is created exclusively. Copying the records, the full
verification above and the reset of every account's MFA commit in **one**
transaction. On any refusal the new file is removed; an existing database is
never touched. The restored instance keeps its instance ID, so the same key
opens it.

Every account's TOTP seed and recovery codes are cleared and a fresh one-time
setup code is issued, exactly as `account-recover --lost-mfa` does. An old
backup would otherwise bring back recovery codes used since it was made, or a
factor that was replaced because it leaked. Passwords are kept; enrolling again
needs the password and the setup code together. Users delete the old Keybash
entry from their authenticator app and enroll anew.

## Limits

- A backup is a point in time. Restoring it brings back credentials, passwords
  and connections as they were then: a credential deleted or rotated since, or
  an account password changed since, returns to its old value. Rotate what
  changed for a reason, and use `account-recover` for a user whose password
  changed after the backup.
- Restore replaces an instance, it does not fork one. Running the restored
  instance beside the original with the same key is not supported.
- Backups need a stopped service for now; there is no online or scheduled
  backup, no backup rotation and no off-host transport. Copying a live
  `custody.db` is still not a backup.
- There is no optional passphrase on the backup file itself yet; its secrecy
  rests on the instance key alone.
- Key rotation is not implemented: a key that may have leaked cannot yet be
  replaced while keeping the data.

## Evidence

`TestBackupRestoresEveryRecordAndResetsMFA`,
`TestRestoreRefusesWrongKeyTamperingAndExistingFiles`,
`TestRestoreRefusesMalformedOrInconsistentBodies`,
`TestBackupRefusesWhatItCouldNotRestore`, `TestBackupHoldsTheWriteQuotas`,
`TestInstanceKeyCodeRoundTripAndTypos`, `FuzzBackupFile` and, on Linux, the
whole operator path in `TestOperatorLinuxBackupKeyRecoveryAndRestore`.
