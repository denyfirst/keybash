// Package publication checks what this public repository publishes, rather
// than what the program does. It has no code of its own, only tests.
package publication

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"testing"
)

// A path into a home directory names the person and the machine a file was
// written on. Keybash is public, so its files say "the repository root"
// instead. Git history cannot take one back; this stops the next one.
// Placeholders such as <you>, %USERNAME% or $env:USERNAME do not match.
var homePath = regexp.MustCompile(`[A-Za-z]:\\Users\\[^\\\s<>%$]+\\|/home/[A-Za-z_][A-Za-z0-9_.-]*/|/Users/[A-Za-z][A-Za-z0-9_.-]*/`)

func TestTheHomePathPatternFindsNamesNotPlaceholders(t *testing.T) {
	// Split in two so that this file does not itself hold a match.
	for _, found := range []string{
		`C:\Us` + `ers\someone\projects\keybash`,
		`d:\Us` + `ers\some.one\x`,
		`/ho` + `me/someone/keybash`,
		`/Us` + `ers/someone/keybash`,
	} {
		if !homePath.MatchString(found) {
			t.Errorf("home path not found in %q", found)
		}
	}
	for _, kept := range []string{
		`C:\Users\<you>\keybash`, `C:\Users\%USERNAME%\keybash`, `C:\Users\$env:USERNAME\keybash`,
		`/home/`, `/var/lib/keybash/`, `/run/keybash/approved.pem`, `$HOME/keybash`,
	} {
		if homePath.MatchString(kept) {
			t.Errorf("placeholder or system path refused: %q", kept)
		}
	}
}

func TestTrackedFilesNameNoHomeDirectory(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal("repository root unknown")
	}
	list := exec.Command("git", "ls-files", "-z")
	list.Dir = root
	out, err := list.Output()
	if err != nil {
		t.Skip("not a Git checkout; CI and scripts/check.ps1 run from one")
	}
	names := bytes.Split(bytes.TrimRight(out, "\x00"), []byte{0})
	if len(names) < 100 {
		t.Fatalf("only %d tracked files: not this repository", len(names))
	}
	for _, name := range names {
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(string(name)))) // #nosec G304 -- a file Git tracks in this repository, read only.
		if errors.Is(err, fs.ErrNotExist) {
			continue // deleted in this working tree, so not published from it
		}
		if err != nil {
			t.Fatalf("%s: unreadable", name)
		}
		if bytes.IndexByte(data, 0) >= 0 {
			continue // binary, such as the typeface
		}
		if at := homePath.FindIndex(data); at != nil {
			t.Errorf("%s:%d names a home directory; write the path from the repository root instead",
				name, 1+bytes.Count(data[:at[0]], []byte{'\n'}))
		}
	}
}
