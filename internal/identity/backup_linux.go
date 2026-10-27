//go:build linux

package identity

import (
	"io"
	"os"
	"path/filepath"
	"time"
)

// WriteBackup writes the store's backup to a new file at path. The file must
// not exist, and it may not sit in the instance key's directory: a backup
// kept beside its key protects nothing.
func WriteBackup(s *Store, path, keyPath string, now time.Time) (BackupSummary, error) {
	if s == nil || path == "" || sameDirectory(path, keyPath) {
		return BackupSummary{}, errRefused
	}
	f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600) // #nosec G304 -- operator-chosen output path, created exclusively, never replaced.
	if e != nil {
		return BackupSummary{}, errRefused
	}
	created, se := f.Stat()
	summary, be := s.Backup(f, now)
	ye := f.Sync()
	ce := f.Close()
	if se != nil || be != nil || ye != nil || ce != nil || syncDirectory(filepath.Dir(path)) != nil {
		if current, e := os.Lstat(path); e == nil && se == nil && os.SameFile(created, current) {
			_ = os.Remove(path)
		}
		return BackupSummary{}, errRefused
	}
	return summary, nil
}

func syncDirectory(path string) error {
	d, e := os.Open(path) // #nosec G304 -- the parent of a file this process just created.
	if e != nil {
		return errRefused
	}
	e = d.Sync()
	_ = d.Close()
	if e != nil {
		return errRefused
	}
	return nil
}

// RestoreFiles restores the backup at backupPath into dir, a private data
// directory without a database, using the instance key at keyPath. It
// returns each account's one-time setup code: every factor was reset.
func RestoreFiles(dir, keyPath, backupPath string, now time.Time) ([]SetupCode, BackupSummary, error) {
	if privateDirectory(dir) != nil {
		return nil, BackupSummary{}, errRefused
	}
	root, name, e := keyRoot(dir, keyPath)
	if e != nil {
		return nil, BackupSummary{}, errRefused
	}
	defer root.Close()
	key, e := keyFile(root, name)
	if e != nil {
		return nil, BackupSummary{}, errRefused
	}
	defer clear(key)
	f, e := os.Open(backupPath) // #nosec G304 -- operator-chosen backup, read-only and bounded.
	if e != nil {
		return nil, BackupSummary{}, errRefused
	}
	info, e := f.Stat()
	if e != nil || !info.Mode().IsRegular() || info.Size() > MaxBackupFile {
		_ = f.Close()
		return nil, BackupSummary{}, errRefused
	}
	data, e := io.ReadAll(io.LimitReader(f, MaxBackupFile+1))
	_ = f.Close()
	if e != nil || len(data) > MaxBackupFile {
		return nil, BackupSummary{}, errRefused
	}
	s, codes, summary, e := restoreStore(dir, key, data, now)
	if e != nil {
		return nil, BackupSummary{}, errRefused
	}
	if s.Close() != nil {
		return nil, BackupSummary{}, errRefused
	}
	return codes, summary, nil
}

// ExportKeyFiles returns the recovery code of the instance key at keyPath,
// once that key has opened the store in dir: a wrong key is never exported.
func ExportKeyFiles(dir, keyPath string) (string, error) {
	root, name, e := keyRoot(dir, keyPath)
	if e != nil {
		return "", errRefused
	}
	defer root.Close()
	key, e := keyFile(root, name)
	if e != nil {
		return "", errRefused
	}
	defer clear(key)
	s, e := OpenStore(dir, key)
	if e != nil {
		return "", errRefused
	}
	if s.Close() != nil {
		return "", errRefused
	}
	return instanceKeyCode(key)
}

// ImportKeyFiles writes the instance key from its recovery code to a new key
// file, as init would have; it never replaces one.
func ImportKeyFiles(dir, keyPath, code string) error {
	key, e := parseInstanceKeyCode(code)
	if e != nil {
		return errRefused
	}
	defer clear(key)
	root, name, e := keyRoot(dir, keyPath)
	if e != nil {
		return errRefused
	}
	defer root.Close()
	return writeKeyFile(root, name, key)
}
