package identity

import (
	"regexp"
	"runtime/debug"
	"time"
)

// What the Installation page says about this copy: the build it runs and what
// it serves. It names no path, address, key, account or setting, so every
// signed-in person may read it. How to add a server and how to upgrade are
// fixed text in the page, the same for every installation.
type installationView struct {
	Revision string `json:"revision"`
	Built    string `json:"built"`
	Modified bool   `json:"modified"`
	SSH      bool   `json:"ssh"`
	RDP      bool   `json:"rdp"`
	Servers  int    `json:"servers"`
}

var revisionPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)

// buildStamp reads the commit Go recorded when the program was built from a
// Git checkout, as scripts/build-stage.sh does. A build without one, or with
// a value that is not a full commit, reports nothing rather than a guess.
func buildStamp(info *debug.BuildInfo, ok bool) (revision, built string, modified bool) {
	if !ok || info == nil {
		return "", "", false
	}
	for _, setting := range info.Settings {
		switch setting.Key {
		case "vcs.revision":
			if revisionPattern.MatchString(setting.Value) {
				revision = setting.Value
			}
		case "vcs.time":
			if t, e := time.Parse(time.RFC3339, setting.Value); e == nil {
				built = t.UTC().Format(time.RFC3339)
			}
		case "vcs.modified":
			modified = setting.Value == "true"
		}
	}
	if revision == "" {
		return "", "", false
	}
	return revision, built, modified
}

func (l *Lab) installationLocked() installationView {
	revision, built, modified := buildStamp(debug.ReadBuildInfo())
	view := installationView{Revision: revision, Built: built, Modified: modified}
	if l.remote != nil {
		view.SSH = l.remote.ssh != nil
		view.RDP = l.remote.rdp != nil
		view.Servers = len(l.remote.targets)
	}
	return view
}
