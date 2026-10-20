package identity

import (
	"errors"
	"net/http"
)

var errRemoteCapacity = errors.New("connection capacity reached")

func markRemoteCapacity(w http.ResponseWriter) {
	w.Header().Set("Retry-After", "5")
	w.Header().Set("X-Keybash-Capacity", "full")
}

func remoteCapacityError(w http.ResponseWriter) {
	markRemoteCapacity(w)
	refuse(w, http.StatusServiceUnavailable)
}

// Caller holds l.mu. Bound pre-proof sockets independently of pending/active
// leases; a socket without a valid first proof must still consume finite space.
func (l *Lab) reserveRemoteSocketLocked(owner string) bool {
	total := 0
	for _, count := range l.remote.sockets {
		total += count
	}
	if l.remote.sockets[owner] >= l.remote.limits.PerOwner || total >= l.remote.limits.Total {
		return false
	}
	l.remote.sockets[owner]++
	return true
}
