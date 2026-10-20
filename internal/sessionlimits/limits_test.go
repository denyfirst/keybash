package sessionlimits

import "testing"

func TestSessionLimitsFiniteBounds(t *testing.T) {
	for _, l := range []Limits{Default(), {1, 1}, {16, 4}, {MaxTotal, MaxTotal}} {
		if !l.Valid() {
			t.Fatal("valid finite capacity refused")
		}
	}
	for _, l := range []Limits{{}, {0, 1}, {1, 0}, {-1, 1}, {1, -1}, {2, 3}, {MaxTotal + 1, 1}} {
		if l.Valid() {
			t.Fatal("invalid or unlimited capacity accepted")
		}
	}
}
