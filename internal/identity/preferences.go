package identity

import (
	"encoding/json"

	bolt "go.etcd.io/bbolt"
)

// Optional additive namespace, like connections: an account's first saved
// choice creates it. A preference is how that account's pages look. It is
// not a secret and authorizes nothing, so a missing one means the pages follow
// the system. It is kept here, sealed like every record, because Keybash
// pages store nothing in the browser.
var preferenceBucket = []byte("preferences-v1")

type preferences struct {
	// Theme is "" (follow the system), "light" or "dark".
	Theme string `json:"theme,omitempty"`
	// Menu is "" (the menu shows its names) or "collapsed" (its icons only).
	Menu string `json:"menu,omitempty"`
}

func (p preferences) valid() bool {
	return (p.Theme == "" || p.Theme == "light" || p.Theme == "dark") && (p.Menu == "" || p.Menu == "collapsed")
}

// preferenceInput reads the words a page sends: "system", "light" or "dark",
// and "open" or "collapsed". Nothing else is accepted.
func preferenceInput(theme, menu string) (preferences, bool) {
	var p preferences
	switch theme {
	case "system":
	case "light", "dark":
		p.Theme = theme
	default:
		return preferences{}, false
	}
	switch menu {
	case "open":
	case "collapsed":
		p.Menu = menu
	default:
		return preferences{}, false
	}
	return p, true
}

// preference reads one account's choices. The record is keyed by the account
// under its own name, so deleting what an account owns takes it too.
func (s *Store) preference(tx *bolt.Tx, owner string) (preferences, uint64, error) {
	var p preferences
	if _, e := s.readAccount(tx, owner); e != nil {
		return p, 0, e
	}
	b := tx.Bucket(preferenceBucket)
	if b == nil {
		return p, 0, nil
	}
	data := b.Get(credentialKey(owner, owner))
	if data == nil {
		return p, 0, nil
	}
	plain, revision, e := s.unseal("preference", owner, owner, data)
	if e != nil {
		return preferences{}, 0, e
	}
	defer clear(plain)
	if decodeRecord(plain, &p, 256) != nil || !p.valid() {
		return preferences{}, 0, errRefused
	}
	return p, revision, nil
}

// preferencesOf is what an account's pages are drawn with: the system's look
// whenever there is no record or it cannot be read.
func (s *Store) preferencesOf(owner string) preferences {
	var p preferences
	if s.view(func(tx *bolt.Tx) error { var e error; p, _, e = s.preference(tx, owner); return e }) != nil {
		return preferences{}
	}
	return p
}

// setPreferences saves an account's choices, resealed at the next revision.
// A record that cannot be read is refused rather than written over.
func (s *Store) setPreferences(owner string, p preferences) error {
	if !validID(owner) || !p.valid() {
		return errRefused
	}
	return s.update(func(tx *bolt.Tx) error {
		_, revision, e := s.preference(tx, owner)
		if e != nil {
			return errRefused
		}
		b, e := tx.CreateBucketIfNotExists(preferenceBucket)
		if e != nil {
			return errRefused
		}
		plain, e := json.Marshal(p)
		if e != nil {
			return errRefused
		}
		defer clear(plain)
		sealed, e := s.seal(tx, "preference", owner, owner, revision+1, plain)
		if e != nil {
			return errRefused
		}
		return b.Put(credentialKey(owner, owner), sealed)
	})
}
