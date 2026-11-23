package terminalweb

// Refusal names, in fixed words, why a desktop ended as "refused": the side
// that sent what Keybash does not accept, and what it was. Both words come
// from fixed lists in Keybash's own code (rdp-proxy/src/refusal.rs and its
// mirror in internal/rdplab); neither carries anything from the session.
type Refusal struct{ Side, What string }

// A RefusingStream names its refusal, when it ended as "refused".
type RefusingStream interface{ Refusal() (Refusal, bool) }

// What the desktop relay itself refuses: a browser message that is not
// binary, or empty.
var browserMessageRefused = Refusal{Side: "browser", What: "desktop message not binary"}

// unknownRefusal is a refusal no one named.
var unknownRefusal = Refusal{Side: "unknown", What: "unknown"}

var refusalSides = map[string]bool{"browser": true, "windows": true, "keybash": true, "unknown": true}

// Line is the journal's one line for a desktop that ended as "refused". It
// holds the two words and nothing else: a side outside the four, or a word of
// anything but letters, digits, spaces and . ' - or longer than 64 bytes, is
// written as "unknown", so no caller can put session text in the journal.
func (r Refusal) Line() string {
	side, what := r.Side, r.What
	if !refusalSides[side] {
		side = "unknown"
	}
	if !plainWord(what) {
		what = "unknown"
	}
	return "desktop refused: side=" + side + " reason=\"" + what + "\"\n"
}

func plainWord(s string) bool {
	if len(s) == 0 || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == ' ' || c == '.' || c == '\'' || c == '-') {
			return false
		}
	}
	return true
}
