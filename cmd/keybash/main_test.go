package main

import (
	"bytes"
	"testing"
)

func TestOperatorCommandRejectsAmbiguousArguments(t *testing.T) {
	for _, args := range [][]string{nil, {"serve"}, {"init"}, {"serve-lab", "--data", "x"}, {"account-add", "--data", "x", "--key-file", "y", "--password", "secret"}, {"init", "--data", "x", "--key-file", "y", "--lost-mfa"}, {"init", "--data", "x", "--key-file", "y", "extra"}} {
		var output bytes.Buffer
		if run(args, bytes.NewReader(nil), &output) == nil || output.Len() != 0 {
			t.Fatal("invalid operator command succeeded or emitted data")
		}
	}
}
