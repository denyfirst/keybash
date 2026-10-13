//go:build browserlab && !linux

package sshtransport

import (
	"golang.org/x/crypto/ssh"
	"io"
	"testing"
)

func browserFixtureOptions(_ *testing.T, host, user ssh.Signer) fixtureOptions {
	return fixtureOptions{host: host, user: user, shellFixture: func(channel ssh.Channel) {
		_, _ = channel.Write([]byte("\x1b[32mKeybash SSH lab\x1b[0m\r\nSintetik sessiya · heç bir əmr icra edilmir.\r\n\r\n"))
		_, _ = io.Copy(channel, channel)
	}}
}
