package identity

import (
	"context"
	"crypto/x509"
	"time"

	"github.com/denyfirst/keybash/internal/rdpcert"
	"github.com/denyfirst/keybash/internal/targetguard"
)

// An RDP server on the Servers page sits at a literal address and is identified
// by its exact certificate, as an SSH server is by its host key: Windows' own
// RDP certificate names no address and renews itself every six months. The
// worker enforces the pin on its own handshake. What the gateway reads here is
// never trust; it only tells people earlier and more clearly that a pin no
// longer matches, and gives an administrator the certificate to compare with
// the fingerprint they bring from the server's console.

// certificateSoon is how long before its end a pinned certificate shows as
// ending soon.
const certificateSoon = 14 * 24 * time.Hour

// openReadBudget bounds the read just before a session opens.
const openReadBudget = 3 * time.Second

// scanCertificate reads an RDP server's certificate through the guarded target:
// a negotiation that must select HYBRID and a TLS handshake that proves the
// server holds the key it shows, with no credential anywhere. It reads at most
// 64 KiB within 10 seconds.
func scanCertificate(ctx context.Context, target *targetguard.NamedTarget) (*x509.Certificate, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	conn, e := target.DialContext(ctx)
	if e != nil {
		return nil, errRefused
	}
	defer func() { _ = conn.Close() }()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	return rdpcert.Read(ctx, &cappedConn{Conn: conn, left: 64 << 10})
}

// certificatePrint is the fingerprint a read certificate would be pinned under.
func certificatePrint(cert *x509.Certificate) string {
	return identityFingerprint(RemoteTarget{Protocol: "rdp", Identity: cert.Raw})
}

// usableLeaf reports whether a certificate read from target could be pinned for
// it now: the rules for its kind of target, within its validity period.
func usableLeaf(cert *x509.Certificate, target *targetguard.NamedTarget, now time.Time) bool {
	if cert == nil || target == nil || now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
		return false
	}
	if target.Literal() {
		return rdpcert.Check(cert) == nil
	}
	return rdpcert.CheckNamed(cert, target.Hostname()) == nil
}

// WatchCertificates has the gateway read every RDP server's certificate at this
// interval, one server at a time, and just before an RDP session opens, so a
// certificate Windows renewed is seen before someone needs the server. What it
// sees lives in memory only: a restart forgets it and reads again.
func WatchCertificates(every time.Duration) Option {
	return func(l *Lab) error {
		if every <= 0 || l.watchEvery != 0 {
			return errRefused
		}
		l.watchEvery = every
		return nil
	}
}

// certificateWatch reads the certificates until the lab closes.
func (l *Lab) certificateWatch(every time.Duration) {
	defer l.background.Done()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { <-l.stop; cancel() }()
	// The first read comes soon after a start, then at the interval.
	timer := time.NewTimer(min(every, time.Minute))
	defer timer.Stop()
	for {
		select {
		case <-l.stop:
			return
		case <-timer.C:
			l.readCertificates(ctx)
			timer.Reset(every)
		}
	}
}

// readCertificates reads each RDP server once. A server that does not answer
// keeps what was last seen: only a certificate it presents changes that.
func (l *Lab) readCertificates(ctx context.Context) {
	l.mu.Lock()
	var list []RemoteTarget
	for _, t := range l.remote.targets {
		if t.Protocol == "rdp" {
			list = append(list, t)
		}
	}
	scan := l.remote.scanRDP
	l.mu.Unlock()
	for _, t := range list {
		cert, e := scan(ctx, t.Target)
		if ctx.Err() != nil {
			return
		}
		if e == nil && cert != nil {
			l.mu.Lock()
			l.noteCertificateLocked(t.ID, cert)
			l.mu.Unlock()
		}
	}
}

// noteCertificateLocked records what a server showed, if it is still listed.
func (l *Lab) noteCertificateLocked(id string, cert *x509.Certificate) {
	if _, ok := l.remote.targets[id]; ok {
		l.remote.seen[id] = certificatePrint(cert)
	}
}

// certificateChangedLocked reports whether an RDP server last showed another
// certificate than its pin. A server nobody has read yet has not changed.
func (l *Lab) certificateChangedLocked(t RemoteTarget) bool {
	seen, known := l.remote.seen[t.ID]
	return known && t.Protocol == "rdp" && seen != identityFingerprint(t)
}

// certificateStateLocked is what an administrator should know about a listed
// RDP server's pin: "changed", the server last showed another certificate;
// "expired", the pin is past its end; "soon", it ends within certificateSoon;
// otherwise "current". It also returns when the pin ends.
func (l *Lab) certificateStateLocked(w webServer) (string, int64) {
	if w.Protocol != "rdp" {
		return "", 0
	}
	cert, e := x509.ParseCertificate(w.Certificate)
	if e != nil {
		return "", 0
	}
	now := l.now()
	switch {
	case l.certificateChangedLocked(RemoteTarget{ID: w.ID, Protocol: w.Protocol, Identity: w.Certificate}):
		return "changed", cert.NotAfter.Unix()
	case !now.Before(cert.NotAfter):
		return "expired", cert.NotAfter.Unix()
	case cert.NotAfter.Sub(now) <= certificateSoon:
		return "soon", cert.NotAfter.Unix()
	}
	return "current", cert.NotAfter.Unix()
}

// serverShowsAnother reads an RDP server's certificate just before a session
// opens, so a person whose server changed since the last read is told why,
// before any worker exists or a password goes anywhere. Only a certificate that
// differs for certain stops here. Everything else is left to the worker, which
// enforces the pin on its own handshake whatever this read saw.
func (l *Lab) serverShowsAnother(ctx context.Context, target RemoteTarget) bool {
	l.mu.Lock()
	scan, watching := l.remote.scanRDP, l.remote.watching
	l.mu.Unlock()
	if !watching || target.Protocol != "rdp" {
		return false
	}
	read, cancel := context.WithTimeout(ctx, openReadBudget)
	defer cancel()
	cert, e := scan(read, target.Target)
	if e != nil || cert == nil {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.noteCertificateLocked(target.ID, cert)
	return l.certificateChangedLocked(target)
}
