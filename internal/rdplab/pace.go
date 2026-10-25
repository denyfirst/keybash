package rdplab

import "time"

// Continuous work budgets replace the former lifetime totals. A desktop that
// keeps drawing stays usable for its whole session at a bounded rate: work
// beyond the rate pauses the single reader, which backpressures guacd and the
// native peer, instead of ending the session after a fixed amount of output.
// Session idle/absolute lifetime, capacity and the service cgroup still bound
// the aggregate.
const (
	nativeByteBurst, nativeBytesPerSecond            = 32 << 20, 16 << 20  // instruction bytes from guacd
	nativeInstructionBurst, nativeInstructionsPerSec = 32768, 16384        // instructions from guacd
	decodeBurst, decodePerSecond                     = 64 << 20, 32 << 20  // PNG pixels decoded and re-encoded
	renderBurst, renderPerSecond                     = 128 << 20, 64 << 20 // canvas pixels the browser is asked to draw
	clipboardBurst, clipboardPerSecond               = 128, 1              // completed text transfers per direction
)

// pacer is a refilling budget; the zero value starts with a full burst.
type pacer struct {
	debt float64
	last time.Time
}

func (p *pacer) refill(now time.Time, perSecond float64) {
	if !p.last.IsZero() && now.After(p.last) {
		p.debt = max(0, p.debt-now.Sub(p.last).Seconds()*perSecond)
	}
	if p.last.IsZero() || now.After(p.last) {
		p.last = now
	}
}

// reserve spends cost and returns how long the caller must pause before the
// work proceeds. A single cost the burst can never hold is refused.
func (p *pacer) reserve(cost int, burst, perSecond float64, now time.Time) (time.Duration, bool) {
	if cost < 0 || float64(cost) > burst {
		return 0, false
	}
	p.refill(now, perSecond)
	p.debt += float64(cost)
	if p.debt <= burst {
		return 0, true
	}
	return time.Duration((p.debt - burst) / perSecond * float64(time.Second)), true
}

// allow spends cost only when it fits now. Used where excess is abuse rather
// than load, such as clipboard transfers.
func (p *pacer) allow(cost int, burst, perSecond float64, now time.Time) bool {
	p.refill(now, perSecond)
	if cost < 0 || p.debt+float64(cost) > burst {
		return false
	}
	p.debt += float64(cost)
	return true
}

// pause sleeps in short slices so revocation still ends a paced stream
// promptly. It reports false once the stream is revoked.
func pause(wait time.Duration, revoked func() bool, sleep func(time.Duration)) bool {
	for wait > 0 {
		if revoked() {
			return false
		}
		step := min(wait, 50*time.Millisecond)
		sleep(step)
		wait -= step
	}
	return !revoked()
}
