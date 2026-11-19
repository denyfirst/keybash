// Package rdcleanpath reads, strictly, the one RDCleanPath message a browser
// desktop opens with (IronRDP's ironrdp-rdcleanpath, version 3390), and
// writes it again for Keybash's RDP proxy without what only the gateway needs
// (docs/BROWSER-RDP-PAGE.md).
//
// The message is DER: a SEQUENCE of fields under explicit context tags. A
// browser's request carries the version, a destination, the proxy token and
// the X.224 connection request; any other field, a second value, trailing
// bytes or a size over the limits is refused.
package rdcleanpath

import (
	"encoding/asn1"
	"errors"
	"unicode/utf8"
)

// Version is RDCleanPath's version 1, as IronRDP numbers it (3389 + 1).
const Version = 3390

// MaxRequest is the largest first message a desktop page may send.
const MaxRequest = 8 * 1024

const (
	maxDestination = 255
	maxToken       = 512
	maxX224        = 1024
)

// ErrRefused is every refusal: the page learns nothing more.
var ErrRefused = errors.New("rdcleanpath request refused")

// Request is what the gateway takes from a browser's request: its token, and
// the X.224 connection request the proxy will check.
type Request struct {
	Token string
	X224  []byte
}

type wire struct {
	Version       int64         `asn1:"explicit,tag:0"`
	Error         asn1.RawValue `asn1:"optional,explicit,tag:1"`
	Destination   asn1.RawValue `asn1:"optional,explicit,tag:2"`
	ProxyAuth     asn1.RawValue `asn1:"optional,explicit,tag:3"`
	ServerAuth    asn1.RawValue `asn1:"optional,explicit,tag:4"`
	Preconnection asn1.RawValue `asn1:"optional,explicit,tag:5"`
	X224          asn1.RawValue `asn1:"optional,explicit,tag:6"`
	CertChain     asn1.RawValue `asn1:"optional,explicit,tag:7"`
	ServerAddr    asn1.RawValue `asn1:"optional,explicit,tag:9"`
}

func present(v asn1.RawValue) bool { return len(v.FullBytes) != 0 }

// inner is the one element an explicit tag wraps, of the universal type
// want, with nothing after it. A raw field keeps the explicit tag itself.
func inner(v asn1.RawValue, want int) ([]byte, bool) {
	var in asn1.RawValue
	if v.Class != asn1.ClassContextSpecific || !v.IsCompound {
		return nil, false
	}
	rest, err := asn1.Unmarshal(v.Bytes, &in)
	if err != nil || len(rest) != 0 || in.Class != asn1.ClassUniversal || in.Tag != want || in.IsCompound {
		return nil, false
	}
	return in.Bytes, true
}

// text is a present UTF8String of at most most bytes.
func text(v asn1.RawValue, most int) (string, bool) {
	b, ok := inner(v, asn1.TagUTF8String)
	if !ok || len(b) > most || !utf8.Valid(b) {
		return "", false
	}
	return string(b), true
}

// Parse reads a browser's RDCleanPath request.
func Parse(der []byte) (Request, error) {
	var w wire
	if len(der) == 0 || len(der) > MaxRequest {
		return Request{}, ErrRefused
	}
	rest, err := asn1.Unmarshal(der, &w)
	if err != nil || len(rest) != 0 || w.Version != Version {
		return Request{}, ErrRefused
	}
	// What only a proxy sends, and what Keybash never forwards: refused.
	if present(w.Error) || present(w.ServerAuth) || present(w.Preconnection) || present(w.CertChain) || present(w.ServerAddr) {
		return Request{}, ErrRefused
	}
	if !present(w.Destination) || !present(w.ProxyAuth) || !present(w.X224) {
		return Request{}, ErrRefused
	}
	if _, ok := text(w.Destination, maxDestination); !ok {
		return Request{}, ErrRefused
	}
	token, ok := text(w.ProxyAuth, maxToken)
	if !ok {
		return Request{}, ErrRefused
	}
	x224, ok := inner(w.X224, asn1.TagOctetString)
	if !ok || len(x224) == 0 || len(x224) > maxX224 {
		return Request{}, ErrRefused
	}
	return Request{Token: token, X224: append([]byte(nil), x224...)}, nil
}

type forward struct {
	Version     int64  `asn1:"explicit,tag:0"`
	Destination string `asn1:"explicit,tag:2,utf8"`
	ProxyAuth   string `asn1:"explicit,tag:3,utf8"`
	X224        []byte `asn1:"explicit,tag:6"`
}

// Forward writes the request again for the proxy: the same X.224 request,
// with the destination and token empty. IronRDP's parser needs both fields
// present; the proxy ignores them, and the gateway's token never reaches it.
func Forward(x224 []byte) ([]byte, error) {
	if len(x224) == 0 || len(x224) > maxX224 {
		return nil, ErrRefused
	}
	return asn1.Marshal(forward{Version: Version, X224: x224})
}
