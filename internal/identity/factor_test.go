package identity

import (
	"encoding/base32"
	"testing"
	"time"
)

// The published vectors: RFC 4226 appendix D, and RFC 6238 appendix B for
// SHA-1, whose eight-digit codes end in the six-digit ones.
func TestHOTPIsTheRFCAlgorithm(t *testing.T) {
	key := []byte("12345678901234567890")
	for counter, want := range []string{"755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"} {
		if got := hotp(key, uint64(counter)); got != want {
			t.Fatalf("RFC 4226 counter %d: %s, want %s", counter, got, want)
		}
	}
	for _, v := range []struct {
		unix int64
		want string
	}{{59, "287082"}, {1111111109, "081804"}, {1111111111, "050471"}, {1234567890, "005924"}, {2000000000, "279037"}, {20000000000, "353130"}} {
		if got := hotp(key, uint64(v.unix/30)); got != v.want {
			t.Fatalf("RFC 6238 time %d: %s, want %s", v.unix, got, v.want)
		}
	}
}

// One step either side is accepted, two are not; a consumed counter and any
// earlier one are refused; malformed codes and seeds are refused.
func TestFactorCounterWindowAndReplay(t *testing.T) {
	key := []byte("12345678901234567890")
	seed := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(key)
	now := time.Unix(1111111111, 0) // counter 37037037
	for step, accepted := range map[int64]bool{-2: false, -1: true, 0: true, 1: true, 2: false} {
		counter := int64(37037037) + step
		got, ok := factorCounter(seed, hotp(key, uint64(counter)), now, -1)
		if ok != accepted || ok && got != counter {
			t.Fatalf("step %d: accepted %v at %d", step, ok, got)
		}
	}
	code := hotp(key, 37037037)
	if _, ok := factorCounter(seed, code, now, 37037037); ok {
		t.Fatal("a consumed code was accepted again")
	}
	if got, ok := factorCounter(seed, hotp(key, 37037038), now, 37037037); !ok || got != 37037038 {
		t.Fatal("the next code after a consumed one was refused")
	}
	for _, bad := range []string{"", "12345", "1234567", "12345a", " 081804", "０８１８０４"} {
		if _, ok := factorCounter(seed, bad, now, -1); ok {
			t.Fatalf("malformed code %q accepted", bad)
		}
	}
	for _, badSeed := range []string{"", seed[:31], seed + "A", "gezdgnbvgy3tqojqgezdgnbvgy3tqojq"} {
		if _, ok := factorCounter(badSeed, code, now, -1); ok {
			t.Fatalf("malformed seed %q accepted", badSeed)
		}
	}
	if _, ok := factorCounter(seed, hotp(key, 0), time.Unix(29, 0), -1); ok {
		t.Fatal("a time before the first full step was accepted")
	}
}
