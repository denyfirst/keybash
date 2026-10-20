package identity

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/denyfirst/keybash/internal/sessionlimits"
)

func capacityOwner(t *testing.T, l *Lab, store *Store, name, record string) (*custodyClient, string) {
	t.Helper()
	if store.CreateAccount(name, alicePassword) != nil {
		t.Fatal("capacity account fixture failed")
	}
	enrollFixture(t, store, name, time.Now())
	account, err := store.lookup(name)
	if err != nil {
		t.Fatal("capacity owner missing")
	}
	credential, err := store.putCredential(account.ID, Credential{Name: "fixture", Kind: "password", Username: "synthetic-user", Secret: "Synthetic remote password"})
	if err != nil {
		t.Fatal("capacity credential fixture failed")
	}
	alice, _ := store.lookup("alice")
	row, err := store.readConnection(alice.ID, record)
	if err != nil {
		t.Fatal("capacity connection fixture missing")
	}
	row.ID, row.Revision, row.Credential = "", 0, credential
	connection, err := store.putConnection(account.ID, row)
	if err != nil {
		t.Fatal("capacity connection fixture failed")
	}
	l.mu.Lock()
	if !l.refreshLocked(name) {
		l.mu.Unlock()
		t.Fatal("capacity account refresh failed")
	}
	raw, err := l.issueLocked(name, "")
	if err != nil {
		l.mu.Unlock()
		t.Fatal("capacity session fixture failed")
	}
	id, _ := tokenID(raw)
	l.sessions[id].stage = "ready"
	l.sessions[id].reauthUntil = l.now().Add(2 * time.Minute)
	csrf := l.csrf(id)
	l.mu.Unlock()
	return &custodyClient{t: t, l: l, cookie: sessionCookie(raw, 3600), csrf: csrf}, connection
}

func TestRemoteCapacityConfiguredOwnersGlobalAndReturn(t *testing.T) {
	limits := sessionlimits.Limits{Total: 10, PerOwner: 4}
	l, store, alice, record, worker := remoteFixtureWithLimits(t, "https://127.0.0.1:8443", limits)
	bob, bobRecord := capacityOwner(t, l, store, "bob", record)
	carol, carolRecord := capacityOwner(t, l, store, "carol", record)
	limits.Total, limits.PerOwner = 1, 1 // caller mutation cannot change admitted policy
	var described sessionlimits.Limits
	if json.Unmarshal(alice.expect("GET", "/api/remote/capacity", "", 200).Body.Bytes(), &described) != nil || described != (sessionlimits.Limits{Total: 10, PerOwner: 4}) {
		t.Fatal("configured remote capacity ignored or mutated")
	}
	for i := 0; i < 4; i++ {
		grantFixture(t, alice, record)
	}
	busy := alice.expect("POST", "/api/remote/open", inputJSON(map[string]string{"connection": record}), 503)
	if busy.Header().Get("X-Keybash-Capacity") != "full" || busy.Header().Get("Retry-After") != "5" {
		t.Fatal("capacity refusal lost truthful busy response")
	}
	for i := 0; i < 4; i++ {
		grantFixture(t, bob, bobRecord)
	}
	for i := 0; i < 2; i++ {
		grantFixture(t, carol, carolRecord)
	}
	carol.expect("POST", "/api/remote/open", inputJSON(map[string]string{"connection": carolRecord}), 503)
	l.mu.Lock()
	if len(l.remote.leases) != 10 {
		l.mu.Unlock()
		t.Fatal("global capacity overflowed or valid slots refused")
	}
	l.mu.Unlock()
	alice.expect("DELETE", "/api/session", "{}", 204)
	grantFixture(t, carol, carolRecord)
	if worker.calls.Load() != 0 {
		t.Fatal("capacity admission started a worker")
	}
}

func TestRemoteCapacityConcurrentAdmissionAndExpiry(t *testing.T) {
	l, _, c, record, _ := remoteFixtureWithLimits(t, "https://127.0.0.1:8443", sessionlimits.Limits{Total: 3, PerOwner: 3})
	now := time.Now()
	l.mu.Lock()
	l.now = func() time.Time { return now }
	l.mu.Unlock()
	id, _ := tokenID(c.cookie.Value)
	var wg sync.WaitGroup
	for range 5 {
		wg.Go(func() { l.mu.Lock(); defer l.mu.Unlock(); _, _ = l.grantRemoteLocked(id, record) })
	}
	wg.Wait()
	rate := c.expect("POST", "/api/remote/open", inputJSON(map[string]string{"connection": record}), 429)
	if rate.Header().Get("Retry-After") != "60" || rate.Header().Get("X-Keybash-Capacity") != "" {
		t.Fatal("attempt budget confused with capacity")
	}
	l.mu.Lock()
	if len(l.remote.leases) != 3 {
		l.mu.Unlock()
		t.Fatal("concurrent capacity overbooked or refused valid slots")
	}
	l.mu.Unlock()
	advance(l, &now, 61*time.Second)
	grantFixture(t, c, record)
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.remote.leases) != 1 {
		t.Fatal("expired pending capacity was not returned")
	}
}

func TestRemoteCapacityPreProofSocketsAndLiveLease(t *testing.T) {
	server := httptest.NewUnstartedServer(nil)
	origin := "https://" + server.Listener.Addr().String()
	l, store, alice, record, _ := remoteFixtureWithLimits(t, origin, sessionlimits.Limits{Total: 2, PerOwner: 1})
	bob, _ := capacityOwner(t, l, store, "bob", record)
	carol, _ := capacityOwner(t, l, store, "carol", record)
	server.Config.Handler = l
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	server.StartTLS()
	defer server.Close()
	raw := grantFixture(t, alice, record)
	id, _ := tokenID(alice.cookie.Value)
	l.mu.Lock()
	_, _, _, active, e := l.redeemRemoteLocked(id, raw)
	owner := l.sessions[id].owner
	l.mu.Unlock()
	if e != nil {
		t.Fatal("live capacity lease fixture refused")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	dial := func(c *custodyClient, allow bool) *websocket.Conn {
		t.Helper()
		socket, response, err := websocket.Dial(ctx, strings.Replace(origin, "https:", "wss:", 1)+"/api/remote/socket", &websocket.DialOptions{HTTPClient: server.Client(), HTTPHeader: http.Header{"Origin": []string{origin}, "Cookie": []string{c.cookie.String()}}})
		if response != nil && response.Body != nil {
			defer response.Body.Close()
		}
		if allow {
			if err != nil {
				t.Fatal("valid configured pre-proof socket refused")
			}
			return socket
		}
		if socket != nil {
			socket.CloseNow()
		}
		if err == nil || response == nil || response.StatusCode != 503 || response.Header.Get("X-Keybash-Capacity") != "full" {
			t.Fatal("excess pre-proof socket accepted or busy state lost")
		}
		return nil
	}
	first := dial(alice, true)
	defer first.CloseNow()
	dial(alice, false)
	second := dial(bob, true)
	defer second.CloseNow()
	dial(carol, false)
	select {
	case <-active.Done():
		t.Fatal("capacity refusal canceled a live lease")
	default:
	}
	first.CloseNow()
	for deadline := time.Now().Add(time.Second); ; {
		l.mu.Lock()
		released := l.remote.sockets[owner] == 0
		l.mu.Unlock()
		if released {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("closed socket capacity not returned")
		}
		time.Sleep(time.Millisecond)
	}
	third := dial(carol, true)
	defer third.CloseNow()
}

func TestRemoteCapacityRejectsInvalidConstructorAndBrowserOverrides(t *testing.T) {
	store, _, _ := bootstrapped(t)
	target := remoteTargetFixture(t)
	for _, limits := range []sessionlimits.Limits{{}, {Total: 129, PerOwner: 1}, {Total: 1, PerOwner: 2}} {
		if l, err := NewRemoteLabWithLimits("https://127.0.0.1:8443", store, []RemoteTarget{target}, nil, &fixtureRDPWorker{}, limits); err == nil {
			l.Close()
			t.Fatal("invalid capacity constructor accepted")
		}
	}
	l, _, c, record, _ := remoteFixtureWithLimits(t, "https://127.0.0.1:8443", sessionlimits.Limits{Total: 1, PerOwner: 1})
	c.expect("POST", "/api/remote/open", inputJSON(map[string]string{"connection": record, "total": "100"}), 400)
	c.expect("POST", "/api/remote/capacity", `{"total":100,"per_owner":100}`, 404)
	var result sessionlimits.Limits
	if json.Unmarshal(c.expect("GET", "/api/remote/capacity", "", 200).Body.Bytes(), &result) != nil || result.Total != 1 || l.remote.limits.PerOwner != 1 {
		t.Fatal("browser changed operator capacity")
	}
}
