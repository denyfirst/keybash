package rdcleanpath

import (
	"bytes"
	"encoding/asn1"
	"encoding/hex"
	"math/rand/v2"
	"strings"
	"testing"
)

// ironRDPRequest is an RDCleanPath request as IronRDP's own encoder writes it
// (the native lab's fixture, internal/rdplab/proxy_native_linux_test.go):
// destination "ignored", token "ignored", and an X.224 request for TLS alone.
const ironRDPRequest = "3033a00402020d3ea2090c0769676e6f726564a3090c0769676e6f726564a6150413030000130ee000000000000100080001000000"

var x224 = []byte{0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// What IronRDP writes is read, and what Keybash writes is IronRDP's own
// encoding: the same fields give the same bytes.
func TestRequestsReadAndWriteAsIronRDPDoes(t *testing.T) {
	r, err := Parse(mustHex(t, ironRDPRequest))
	if err != nil || r.Token != "ignored" || !bytes.Equal(r.X224, x224) {
		t.Fatalf("IronRDP's request read as %+v, %v", r, err)
	}
	same, err := asn1.Marshal(forward{Version: Version, Destination: "ignored", ProxyAuth: "ignored", X224: x224})
	if err != nil || hex.EncodeToString(same) != ironRDPRequest {
		t.Fatalf("Keybash's encoding differs from IronRDP's: %x", same)
	}
	// The proxy's copy carries the X.224 request, and an empty destination
	// and token; it reads back as a request.
	out, err := Forward(x224)
	if err != nil {
		t.Fatal(err)
	}
	var w wire
	if rest, err := asn1.Unmarshal(out, &w); err != nil || len(rest) != 0 || !present(w.Destination) || !present(w.ProxyAuth) ||
		!emptyText(w.Destination) || !emptyText(w.ProxyAuth) || !sameOctets(w.X224, x224) {
		t.Fatalf("the proxy's copy is %x", out)
	}
	if bytes.Contains(out, []byte("ignored")) {
		t.Fatal("the token reached the proxy's copy")
	}
}

func encode(t *testing.T, v any) []byte {
	t.Helper()
	b, err := asn1.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Everything that is not a browser's request, exactly, is refused.
func TestAnythingElseIsRefused(t *testing.T) {
	good := mustHex(t, ironRDPRequest)
	type withField struct {
		Version     int64  `asn1:"explicit,tag:0"`
		Destination string `asn1:"explicit,tag:2,utf8"`
		ProxyAuth   string `asn1:"explicit,tag:3,utf8"`
		Extra       string `asn1:"explicit,tag:5,utf8"`
		X224        []byte `asn1:"explicit,tag:6"`
	}
	type noToken struct {
		Version     int64  `asn1:"explicit,tag:0"`
		Destination string `asn1:"explicit,tag:2,utf8"`
		X224        []byte `asn1:"explicit,tag:6"`
	}
	type noX224 struct {
		Version     int64  `asn1:"explicit,tag:0"`
		Destination string `asn1:"explicit,tag:2,utf8"`
		ProxyAuth   string `asn1:"explicit,tag:3,utf8"`
	}
	type tokenAsOctets struct {
		Version     int64  `asn1:"explicit,tag:0"`
		Destination string `asn1:"explicit,tag:2,utf8"`
		ProxyAuth   []byte `asn1:"explicit,tag:3"`
		X224        []byte `asn1:"explicit,tag:6"`
	}
	cases := map[string][]byte{
		"empty":                  {},
		"trailing bytes":         append(append([]byte(nil), good...), 0),
		"cut short":              good[:len(good)-1],
		"another version":        encode(t, forward{Version: 3389, Destination: "d", ProxyAuth: "t", X224: x224}),
		"a preconnection blob":   encode(t, withField{Version, "d", "t", "blob", x224}),
		"no token":               encode(t, noToken{Version, "d", x224}),
		"no X.224 request":       encode(t, noX224{Version, "d", "t"}),
		"a token as octets":      encode(t, tokenAsOctets{Version, "d", []byte("t"), x224}),
		"a token too long":       encode(t, forward{Version, "d", strings.Repeat("t", maxToken+1), x224}),
		"a destination too long": encode(t, forward{Version, strings.Repeat("d", maxDestination+1), "t", x224}),
		"an X.224 too long":      encode(t, forward{Version, "d", "t", make([]byte, maxX224+1)}),
		"an empty X.224":         encode(t, forward{Version, "d", "t", []byte{}}),
		"a token not UTF-8":      bytes.Replace(encode(t, forward{Version, "d", "tt", x224}), []byte("tt"), []byte{0xff, 0xfe}, 1),
		"over the size limit":    append(encode(t, forward{Version, "d", "t", x224}), make([]byte, MaxRequest)...),
		"a non-minimal length":   append([]byte{0x30, 0x81, 0x33}, good[2:]...),
	}
	for name, der := range cases {
		if r, err := Parse(der); err == nil {
			t.Errorf("%s was read as %+v", name, r)
		}
	}
	if _, err := Forward(nil); err == nil {
		t.Error("an empty X.224 request was written")
	}
	if _, err := Forward(make([]byte, maxX224+1)); err == nil {
		t.Error("an X.224 request over the limit was written")
	}
}

// Mutations of a real request never panic, and whatever is read stays within
// the limits.
func TestMutatedRequestsAreReadSafely(t *testing.T) {
	good := mustHex(t, ironRDPRequest)
	rng := rand.New(rand.NewPCG(1, 2))
	for range 50000 {
		der := append([]byte(nil), good...)
		for range 1 + rng.IntN(3) {
			switch i := rng.IntN(len(der) + 1); rng.IntN(3) {
			case 0:
				if i < len(der) {
					der[i] ^= byte(1 << rng.IntN(8))
				}
			case 1:
				der = append(der[:i], append([]byte{byte(rng.IntN(256))}, der[i:]...)...)
			default:
				der = der[:i]
			}
		}
		if r, err := Parse(der); err == nil && (len(r.Token) > maxToken || len(r.X224) == 0 || len(r.X224) > maxX224) {
			t.Fatalf("%x was read outside the limits: %+v", der, r)
		}
	}
}

func emptyText(v asn1.RawValue) bool {
	b, ok := inner(v, asn1.TagUTF8String)
	return ok && len(b) == 0
}

func sameOctets(v asn1.RawValue, want []byte) bool {
	b, ok := inner(v, asn1.TagOctetString)
	return ok && bytes.Equal(b, want)
}
