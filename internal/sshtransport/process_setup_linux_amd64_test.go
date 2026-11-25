//go:build linux && amd64

package sshtransport

import (
	"context"
	"os"
	"testing"
	"time"
)

// The gateway's side of the worker pipe tells a refused credential apart from
// every other end of setup, and only by the one empty refused frame.
func TestProcessSetupTellsRefusalApart(t *testing.T) {
	for name, answer := range map[string][]byte{
		"refused":         {frameRefused, 0, 0, 0, 0},
		"failed":          {frameFailed, 0, 0, 0, 0},
		"refused, padded": {frameRefused, 0, 0, 0, 1, 42},
		"closed":          nil,
	} {
		t.Run(name, func(t *testing.T) {
			out, workerOut, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			workerIn, in, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer workerIn.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			s := newProcessStream(ctx, cancel, in, out, make(chan struct{}))
			go func() {
				defer workerOut.Close()
				if writeWorkerFrame(workerOut, frameHello, []byte(workerHello)) != nil {
					return
				}
				if kind, _, err := readWorkerFrame(workerIn); err != nil || kind != frameStart {
					return
				}
				_, _ = workerOut.Write(answer)
			}()
			setup, stop := context.WithTimeout(context.Background(), 5*time.Second)
			defer stop()
			err = finishProcessSetup(s, setup, "ssh.invalid", syntheticSigner(t).PublicKey().Marshal(), "lab-user", methodPassword, []byte(syntheticRemotePassword))
			want := ErrProcess
			if name == "refused" {
				want = ErrRefused
			}
			if err != want {
				t.Fatalf("got %v, want %v", err, want)
			}
			_ = s.Close()
		})
	}
}
