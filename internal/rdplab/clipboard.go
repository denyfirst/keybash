package rdplab

import (
	"encoding/base64"
	"errors"
	"strconv"
	"sync"
	"unicode/utf8"
)

var ErrClipboard = errors.New("RDP lab clipboard refused")

// ErrClipboardTooLarge ends a remote copy that was larger than a page takes:
// its text is dropped, the stream stays usable, and the session goes on.
var ErrClipboardTooLarge = errors.New("RDP clipboard text too large")

const (
	maxClipboardBytes = 32 * 1024
	// What a dropped copy may carry before it counts as abuse: guacd 1.6 sends
	// at most 256 KiB (GUAC_COMMON_CLIPBOARD_MAX_LENGTH).
	maxClipboardDiscard = 1024 * 1024
)

// clipboard is a per-session, per-direction text stream accumulator. It does
// not access the OS clipboard. The future UI must explicitly request copy or
// paste; remote end instructions must never automatically change local state.
type clipboard struct {
	mu           sync.Mutex
	closed       bool
	active       bool
	id           string
	data         []byte
	dropOversize bool // the remote's direction: text over the limit is dropped, not fatal
	oversize     bool
	discarded    int
}

// accept owns its state; any malformed instruction poisons this direction.
// Only a completed end returns text. Partial UTF-8 is legal between blobs.
func (c *clipboard) accept(in instruction) (text string, complete bool, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	refuse := func() (string, bool, error) {
		c.clear()
		c.closed = true
		return "", false, ErrClipboard
	}
	if c.closed || len(in) == 0 {
		return refuse()
	}
	switch in[0] {
	case "clipboard":
		if len(in) != 3 || c.active || !streamID(in[1]) || in[2] != "text/plain" {
			return refuse()
		}
		c.id, c.active = in[1], true
	case "blob":
		if len(in) != 3 || !c.active || in[1] != c.id || len(in[2]) == 0 ||
			len(in[2]) > base64.StdEncoding.EncodedLen(maxClipboardBytes) {
			return refuse()
		}
		// Strict canonical base64: no whitespace, stray padding or unused bits.
		decoded, decodeErr := base64.StdEncoding.Strict().DecodeString(in[2])
		if decodeErr != nil || base64.StdEncoding.EncodeToString(decoded) != in[2] {
			return refuse()
		}
		if !c.oversize && len(decoded) > maxClipboardBytes-len(c.data) {
			if !c.dropOversize {
				return refuse()
			}
			c.oversize, c.discarded = true, len(c.data)
			clear(c.data)
			c.data = nil
		}
		if c.oversize {
			if len(decoded) > maxClipboardDiscard-c.discarded {
				return refuse()
			}
			c.discarded += len(decoded)
			break
		}
		c.data = append(c.data, decoded...)
	case "end":
		if len(in) != 2 || !c.active || in[1] != c.id || !c.oversize && !utf8.Valid(c.data) {
			return refuse()
		}
		if c.oversize {
			c.clear()
			return "", true, ErrClipboardTooLarge
		}
		text = string(c.data)
		c.clear()
		return text, true, nil
	default:
		return refuse()
	}
	return "", false, nil
}

func (c *clipboard) close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.clear()
	c.closed = true
}

func (c *clipboard) clear() {
	clear(c.data)
	c.data = nil
	c.id, c.active = "", false
	c.oversize, c.discarded = false, 0
}

func streamID(id string) bool {
	if len(id) == 0 || len(id) > 5 || len(id) > 1 && id[0] == '0' {
		return false
	}
	for _, b := range []byte(id) {
		if b < '0' || b > '9' {
			return false
		}
	}
	n, err := strconv.ParseUint(id, 10, 16)
	return err == nil && n <= 65535
}

func (c *clipboard) matches(id string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return !c.closed && c.active && c.id == id
}
