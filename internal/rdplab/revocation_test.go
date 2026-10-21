package rdplab

import (
	"bufio"
	"bytes"
	"context"
	"net"
	"testing"
)

type viewerLeaseConnection struct {
	net.Conn
	lease context.Context
}

func (c viewerLeaseConnection) leaseContext() context.Context { return c.lease }

func TestViewerAndNativeBufferedDataRefuseRevokedLeaseOrOwner(t *testing.T) {
	for _, owner := range []bool{false, true} {
		for _, native := range []bool{false, true} {
			s, _, _ := viewerFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if owner {
				s.native.ctx = ctx
			} else {
				s.native.raw = viewerLeaseConnection{Conn: s.native.raw, lease: ctx}
			}
			var data [128]byte
			if n, e := s.Read(data[:]); n == 0 || e != nil {
				t.Fatal("live owner/lease initial data refused")
			}
			s.ready.Reset(encodedInstruction(t, instruction{"size", "0", "1024", "768"}))
			s.native.reader = bufio.NewReader(bytes.NewReader(encodedInstruction(t, instruction{"size", "0", "1024", "768"})))
			cancel()
			if native {
				if in, e := s.native.next(); in != nil || e == nil {
					t.Fatal("native parser released buffered data after revocation")
				}
			} else if n, e := s.Read(data[:]); n != 0 || e == nil {
				t.Fatal("viewer released buffered data after revocation")
			}
			if _, e := s.Write(encodedInstruction(t, instruction{"nop"})); e == nil {
				t.Fatal("revoked owner/lease accepted input")
			}
		}
	}
}
