//go:build browserlab

package identity

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/denyfirst/keybash/internal/sessionlimits"
	"github.com/denyfirst/keybash/internal/sshkey"
	"github.com/denyfirst/keybash/internal/targetguard"
	"github.com/denyfirst/keybash/internal/terminalweb"
)

// memoryFolder is a server's account as a Files worker sees it: a few folders
// and files in memory, with the worker's rules (no replacing on rename or a
// new upload, only empty folders deleted).
type memoryFolder struct {
	mu    sync.Mutex
	nodes map[string]*memoryNode
	modes []terminalweb.FilesMode
}
type memoryNode struct {
	dir  bool
	data []byte
	time uint32
}

func newMemoryFolder() *memoryFolder {
	now := uint32(time.Now().Unix())
	return &memoryFolder{nodes: map[string]*memoryNode{
		"/home/deploy":                 {dir: true, time: now},
		"/home/deploy/docs":            {dir: true, time: now},
		"/home/deploy/docs/readme.md":  {data: []byte("# docs\n"), time: now},
		"/home/deploy/notes.txt":       {data: []byte("synthetic notes\n"), time: now},
		"/home/deploy/invoice‮txt.exe": {data: []byte("MZ"), time: now},
		"/home/deploy/\xff\xfe":        {data: []byte("?"), time: now},
	}}
}

func (m *memoryFolder) OpenSSH(ctx context.Context, t *targetguard.NamedTarget, pin []byte, user string, c sshkey.Credential) (terminalweb.Stream, error) {
	return echoSSHWorker{}.OpenSSH(ctx, t, pin, user, c)
}
func (m *memoryFolder) OpenFiles(ctx context.Context, _ *targetguard.NamedTarget, _ []byte, _ string, _ sshkey.Credential, mode terminalweb.FilesMode) (terminalweb.FilesStream, error) {
	m.mu.Lock()
	m.modes = append(m.modes, mode)
	m.mu.Unlock()
	s := &memoryFiles{folder: m, replies: make(chan terminalweb.FileReply, 256)}
	context.AfterFunc(ctx, func() { _ = s.Close() })
	return s, nil
}

func (m *memoryFolder) file(name string) ([]byte, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	node, ok := m.nodes[name]
	if !ok || node.dir {
		return nil, false
	}
	return bytes.Clone(node.data), true
}

type memoryFiles struct {
	folder  *memoryFolder
	mu      sync.Mutex
	closed  bool
	replies chan terminalweb.FileReply
	upload  *terminalweb.FileRequest
	body    bytes.Buffer
}

func (s *memoryFiles) reply(r terminalweb.FileReply) {
	if !s.closed {
		s.replies <- r
	}
}
func (s *memoryFiles) fail(id uint32, why terminalweb.FileFailure) {
	s.reply(terminalweb.FileReply{Kind: terminalweb.ReplyFailed, ID: id, Failure: why})
}
func (s *memoryFiles) done(id uint32, size uint64, where string) {
	s.reply(terminalweb.FileReply{Kind: terminalweb.ReplyDone, ID: id, Size: size, Path: where})
}

func (s *memoryFiles) Send(r terminalweb.FileRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.folder
	m.mu.Lock()
	defer m.mu.Unlock()
	node, exists := m.nodes[r.Path]
	switch r.Op {
	case terminalweb.OpList:
		where := r.Path
		if where == "" {
			where = "/home/deploy"
		}
		if folder, ok := m.nodes[where]; !ok || !folder.dir {
			s.fail(r.ID, terminalweb.FailMissing)
			return nil
		}
		var names []string
		for name := range m.nodes {
			if name != where && path.Dir(name) == where {
				names = append(names, name)
			}
		}
		sort.Strings(names)
		var entries []terminalweb.FileEntry
		for _, name := range names {
			n := m.nodes[name]
			kind := terminalweb.KindFile
			if n.dir {
				kind = terminalweb.KindDir
			}
			entries = append(entries, terminalweb.FileEntry{Name: []byte(path.Base(name)), Kind: kind, Size: uint64(len(n.data)), Time: n.time})
		}
		if len(entries) > 0 {
			s.reply(terminalweb.FileReply{Kind: terminalweb.ReplyEntries, ID: r.ID, Entries: entries})
		}
		s.done(r.ID, 0, where)
	case terminalweb.OpMkdir:
		if exists {
			s.fail(r.ID, terminalweb.FailExists)
			return nil
		}
		m.nodes[r.Path] = &memoryNode{dir: true, time: uint32(time.Now().Unix())}
		s.done(r.ID, 0, "")
	case terminalweb.OpRename:
		if _, taken := m.nodes[r.To]; taken || !exists {
			s.fail(r.ID, terminalweb.FailExists)
			return nil
		}
		m.nodes[r.To] = node
		delete(m.nodes, r.Path)
		s.done(r.ID, 0, "")
	case terminalweb.OpRemove:
		if !exists || node.dir {
			s.fail(r.ID, terminalweb.FailFailed)
			return nil
		}
		delete(m.nodes, r.Path)
		s.done(r.ID, 0, "")
	case terminalweb.OpRmdir:
		for name := range m.nodes {
			if path.Dir(name) == r.Path {
				s.fail(r.ID, terminalweb.FailNotEmpty)
				return nil
			}
		}
		delete(m.nodes, r.Path)
		s.done(r.ID, 0, "")
	case terminalweb.OpGet:
		if !exists || node.dir {
			s.fail(r.ID, terminalweb.FailMissing)
			return nil
		}
		data := bytes.Clone(node.data)
		go func() {
			s.mu.Lock()
			defer s.mu.Unlock()
			s.reply(terminalweb.FileReply{Kind: terminalweb.ReplyAccept, ID: r.ID, Size: uint64(len(data))})
			for rest := data; len(rest) > 0; {
				n := min(len(rest), terminalweb.FileChunk)
				s.reply(terminalweb.FileReply{Kind: terminalweb.ReplyData, Data: rest[:n]})
				rest = rest[n:]
			}
			s.done(r.ID, uint64(len(data)), "")
		}()
	case terminalweb.OpPut, terminalweb.OpReplace:
		if exists && (r.Op == terminalweb.OpPut || node.dir) {
			s.fail(r.ID, terminalweb.FailExists)
			return nil
		}
		if r.Size == 0 {
			m.nodes[r.Path] = &memoryNode{time: uint32(time.Now().Unix())}
			s.done(r.ID, 0, "")
			return nil
		}
		s.upload = &r
		s.body.Reset()
		s.reply(terminalweb.FileReply{Kind: terminalweb.ReplyAccept, ID: r.ID})
	}
	return nil
}

func (s *memoryFiles) Upload(data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.upload == nil {
		return errRefused
	}
	s.body.Write(data)
	if uint64(s.body.Len()) == s.upload.Size {
		s.folder.mu.Lock()
		s.folder.nodes[s.upload.Path] = &memoryNode{data: bytes.Clone(s.body.Bytes()), time: uint32(time.Now().Unix())}
		s.folder.mu.Unlock()
		s.done(s.upload.ID, s.upload.Size, "")
		s.upload = nil
	}
	return nil
}
func (s *memoryFiles) Cancel(id uint32) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.upload != nil && s.upload.ID == id {
		s.upload = nil
		s.fail(id, terminalweb.FailCancelled)
	}
	return nil
}
func (s *memoryFiles) Replies() <-chan terminalweb.FileReply { return s.replies }
func (s *memoryFiles) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.closed {
		s.closed = true
		close(s.replies)
	}
	return nil
}

// TestBrowserFilesPage drives the Files page in a browser through the real
// gateway and relay: the card's Files button, a folder with a hidden
// character and an unreadable name, moving around, a new folder, an upload,
// its download, a replace, a rename, a delete, and the switch going to
// Download only while the page is open.
func TestBrowserFilesPage(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	store, _, _, code := custodyFixture(t)
	server := httptest.NewUnstartedServer(nil)
	origin := "https://" + server.Listener.Addr().String()
	catalog := catalogSSHFixture(t)
	folder := newMemoryFolder()
	l, e := NewRemoteLabWithLimits(origin, store, []RemoteTarget{catalog}, folder, nil, sessionlimits.Default(), TargetNetworks(serverNetworks, serverProtected))
	if e != nil {
		t.Fatal("files browser fixture refused")
	}
	defer l.Close()
	control, e := token()
	if e != nil {
		t.Fatal("fixture control failed")
	}
	var account string
	server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/__fixture/") {
			if r.Method != "POST" || r.Header.Get("X-Fixture-Control") != control {
				w.WriteHeader(403)
				return
			}
			alice, e := store.lookup("alice")
			if e != nil {
				w.WriteHeader(409)
				return
			}
			mode := "download"
			switch r.URL.Path {
			case "/__fixture/account":
				// Alice, now an administrator, on the catalog server's
				// account, which allows upload and download.
				account, mode = accountFixture(t, l, catalog.ID, "deploy", "", alice.ID), "both"
			case "/__fixture/download-only":
			default:
				w.WriteHeader(404)
				return
			}
			if store.setServerFiles(alice.ID, catalog.ID, mode) != nil {
				w.WriteHeader(409)
				return
			}
			l.mu.Lock()
			_ = l.reloadServersLocked()
			l.mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{"account": account})
			return
		}
		l.ServeHTTP(w, r)
	})
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	server.StartTLS()
	defer server.Close()
	config, _ := json.Marshal(struct{ Origin, Code, Password, Control string }{origin, code, alicePassword, control})
	command := exec.CommandContext(ctx, "node", filepath.Join("..", "..", "web", "files-browser-test.mjs")) // #nosec G204 -- fixed synthetic browser driver and stdin-only fixture data.
	command.Stdin = bytes.NewReader(config)
	command.Stdout, command.Stderr = os.Stdout, os.Stderr
	if command.Run() != nil {
		t.Fatal("files page browser checks failed")
	}
	if data, ok := folder.file("/home/deploy/reports/greeting.txt"); ok || data != nil {
		t.Fatal("the deleted file is still on the server")
	}
	if data, ok := folder.file("/home/deploy/reports/hello.txt"); ok || data != nil {
		t.Fatal("the renamed file kept its old name")
	}
	folder.mu.Lock()
	modes := append([]terminalweb.FilesMode(nil), folder.modes...)
	folder.mu.Unlock()
	if len(modes) < 2 || modes[0] != terminalweb.FilesBoth || modes[len(modes)-1] != terminalweb.FilesDownload {
		t.Fatalf("the worker opened %v", modes)
	}
}
