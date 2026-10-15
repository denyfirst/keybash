//go:build !linux

package identity

func InitializeFiles(string, string) (*Store, string, error) { return nil, "", errRefused }
func OpenFiles(string, string) (*Store, error)               { return nil, errRefused }
