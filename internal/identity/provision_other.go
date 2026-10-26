//go:build !linux

package identity

import "time"

func InitializeFiles(string, string) (*Store, string, error) { return nil, "", errRefused }
func OpenFiles(string, string) (*Store, error)               { return nil, errRefused }

func WriteBackup(*Store, string, string, time.Time) (BackupSummary, error) {
	return BackupSummary{}, errRefused
}
func RestoreFiles(string, string, string, time.Time) ([]SetupCode, BackupSummary, error) {
	return nil, BackupSummary{}, errRefused
}
func ExportKeyFiles(string, string) (string, error) { return "", errRefused }
func ImportKeyFiles(string, string, string) error   { return errRefused }
