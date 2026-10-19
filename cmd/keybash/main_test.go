package main

import (
	"bytes"
	"testing"

	"github.com/denyfirst/keybash/internal/identity"
)

func TestOperatorCommandRejectsAmbiguousArguments(t *testing.T) {
	for _, args := range [][]string{nil, {"serve"}, {"init"}, {"serve-lab", "--data", "x"}, {"account-add", "--data", "x", "--key-file", "y", "--password", "secret"}, {"init", "--data", "x", "--key-file", "y", "--lost-mfa"}, {"init", "--data", "x", "--key-file", "y", "extra"}} {
		var output bytes.Buffer
		if run(args, bytes.NewReader(nil), &output) == nil || output.Len() != 0 {
			t.Fatal("invalid operator command succeeded or emitted data")
		}
	}
}

func TestOperatorRemoteFlagsAndProtocolGate(t *testing.T) {
	for _, args := range [][]string{
		{"check-targets"}, {"check-targets", "--config", "missing", "--data", "x"},
		{"serve-ssh-lab", "--data", "x", "--key-file", "y"},
		{"serve-ssh-lab", "--data", "x", "--key-file", "y", "--config", "z", "--ssh-manager", "relative"},
		{"serve-lab", "--data", "x", "--key-file", "y", "--config", "z"},
		{"init", "--data", "x", "--key-file", "y", "--ssh-manager", "z"},
	} {
		var output bytes.Buffer
		if run(args, bytes.NewReader(nil), &output) == nil || output.Len() != 0 {
			t.Fatal("invalid remote CLI flags accepted or emitted data")
		}
	}
	if sshOnly(nil) || sshOnly([]identity.RemoteTarget{{Protocol: "rdp"}}) ||
		sshOnly([]identity.RemoteTarget{{Protocol: "ssh"}, {Protocol: "rdp"}}) {
		t.Fatal("missing or unsupported launcher catalog accepted")
	}
	if !sshOnly([]identity.RemoteTarget{{Protocol: "ssh"}}) {
		t.Fatal("valid SSH-only catalog refused")
	}
}
