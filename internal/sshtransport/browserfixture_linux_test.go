//go:build browserlab

package sshtransport

import (
	"golang.org/x/crypto/ssh"
	"testing"
)

func browserFixtureOptions(t *testing.T, host, user ssh.Signer) fixtureOptions {
	return linuxShellOptions(t, host, user)
}
