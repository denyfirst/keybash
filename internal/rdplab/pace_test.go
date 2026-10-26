package rdplab

import (
	"testing"
	"time"
)

func TestPacerBurstRateRefillAndRefusal(t *testing.T) {
	start := time.Unix(1000, 0)
	var p pacer
	if wait, ok := p.reserve(100, 100, 10, start); !ok || wait != 0 {
		t.Fatal("zero-value pacer did not start with a full burst")
	}
	if wait, ok := p.reserve(5, 100, 10, start); !ok || wait != 500*time.Millisecond {
		t.Fatal("excess work was not paced at the configured rate")
	}
	// 1.5 s later 15 units have refilled: debt 105-15+15 is again 5 over.
	if wait, ok := p.reserve(15, 100, 10, start.Add(1500*time.Millisecond)); !ok || wait != 500*time.Millisecond {
		t.Fatal("budget did not refill continuously")
	}
	// A clock moving backwards never refills.
	if wait, ok := p.reserve(0, 100, 10, start); !ok || wait != 500*time.Millisecond {
		t.Fatal("a backwards clock refilled the budget")
	}
	for _, cost := range []int{-1, 101} {
		var fresh pacer
		if _, ok := fresh.reserve(cost, 100, 10, start); ok {
			t.Fatal("impossible single cost accepted")
		}
	}
	var transfers pacer
	for i := 0; i < 3; i++ {
		if !transfers.allow(1, 3, 1, start) {
			t.Fatal("allowance refused within its burst")
		}
	}
	if transfers.allow(1, 3, 1, start) || transfers.allow(-1, 3, 1, start) {
		t.Fatal("allowance exceeded its burst")
	}
	if !transfers.allow(1, 3, 1, start.Add(time.Second)) || transfers.allow(1, 3, 1, start.Add(time.Second)) {
		t.Fatal("allowance did not refill exactly one transfer per second")
	}
}

func TestPauseStopsOnRevocation(t *testing.T) {
	var slept time.Duration
	revoked := false
	if !pause(120*time.Millisecond, func() bool { return revoked }, func(d time.Duration) { slept += d }) || slept != 120*time.Millisecond {
		t.Fatal("pause did not wait the requested time")
	}
	calls := 0
	if pause(time.Second, func() bool { return revoked }, func(time.Duration) { calls++; revoked = calls == 2 }) || calls != 2 {
		t.Fatal("pause outlived revocation")
	}
}
