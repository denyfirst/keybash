package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/denyfirst/keybash/internal/targetguard"
	bolt "go.etcd.io/bbolt"
	"golang.org/x/crypto/ssh"
)

func networkFixture(t *testing.T, host string, port uint16, addresses ...string) *targetguard.NamedTarget {
	t.Helper()
	ips := make([]netip.Addr, len(addresses))
	endpoints := make([]netip.AddrPort, len(addresses))
	for i, s := range addresses {
		ips[i] = netip.MustParseAddr(s)
		endpoints[i] = netip.AddrPortFrom(ips[i], port)
	}
	policy, e := targetguard.New(endpoints, nil)
	if e != nil {
		t.Fatal("network fixture refused")
	}
	target, e := targetguard.NewNamedTarget(policy, host, port, ips)
	if e != nil {
		t.Fatal("named fixture refused")
	}
	return target
}

func TestServerTrustFingerprintFormatsAndNetworkBinding(t *testing.T) {
	target := remoteTargetFixture(t)
	sum := sha256.Sum256(target.Identity)
	if identityFingerprint(target) != "SHA256:"+hex.EncodeToString(sum[:]) {
		t.Fatal("RDP fingerprint differs from certificate DER digest")
	}
	_, private, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal("entropy failed")
	}
	signer, e := ssh.NewSignerFromKey(private)
	if e != nil {
		t.Fatal("signer failed")
	}
	sshTarget := target
	sshTarget.Protocol = "ssh"
	sshTarget.Identity = signer.PublicKey().Marshal()
	if identityFingerprint(sshTarget) != ssh.FingerprintSHA256(signer.PublicKey()) {
		t.Fatal("SSH fingerprint differs from OpenSSH format")
	}
	for _, good := range []string{identityFingerprint(target), identityFingerprint(sshTarget)} {
		if !validFingerprint(good) {
			t.Fatal("valid fingerprint refused")
		}
	}
	for _, bad := range []string{"", "SHA256:", strings.ToLower(identityFingerprint(sshTarget)), identityFingerprint(sshTarget) + "=", identityFingerprint(target) + " ", "SHA256:" + strings.Repeat("!", 43), "SHA256:" + strings.Repeat("A", 64)} {
		if validFingerprint(bad) {
			t.Fatal("malformed fingerprint accepted")
		}
	}
	base := target
	base.Target = networkFixture(t, "rdp.invalid", 3389, "10.34.0.8", "10.34.0.9")
	ordered := base
	ordered.Target = networkFixture(t, "RDP.Invalid.", 3389, "10.34.0.9", "10.34.0.8")
	if approvalFingerprint(base) != approvalFingerprint(ordered) {
		t.Fatal("equivalent network snapshot lost approval")
	}
	for _, change := range []struct {
		host string
		port uint16
		ips  []string
	}{{"other.invalid", 3389, []string{"10.34.0.8", "10.34.0.9"}}, {"rdp.invalid", 3390, []string{"10.34.0.8", "10.34.0.9"}}, {"rdp.invalid", 3389, []string{"10.34.0.8"}}, {"rdp.invalid", 3389, []string{"10.34.0.10", "10.34.0.9"}}} {
		changed := base
		changed.Target = networkFixture(t, change.host, change.port, change.ips...)
		if approvalFingerprint(base) == approvalFingerprint(changed) {
			t.Fatal("network change retained server approval")
		}
	}
}

func trustRow(t *testing.T, l *Lab, store *Store, record string) (connection, RemoteTarget) {
	t.Helper()
	a, e := store.lookup("alice")
	if e != nil {
		t.Fatal("owner missing")
	}
	row, e := store.readConnection(a.ID, record)
	if e != nil {
		t.Fatal("row missing")
	}
	l.mu.Lock()
	target := l.remote.targets[row.Target]
	l.mu.Unlock()
	return row, target
}

func TestServerTrustProofGate(t *testing.T) {
	target := remoteTargetFixture(t)
	now := time.Now()
	fingerprint := identityFingerprint(target)
	approval := approvalFingerprint(target)
	if !acceptTargetProof(target, fingerprint, approval, now) {
		t.Fatal("valid server proof refused")
	}
	if acceptTargetProof(target, "SHA256:"+strings.Repeat("0", 64), approval, now) {
		t.Fatal("wrong fingerprint accepted")
	}
	if acceptTargetProof(target, fingerprint, strings.Repeat("0", 64), now) {
		t.Fatal("stale target snapshot accepted")
	}
	row := connection{Target: target.ID, Approval: approval}
	if connectionTrusted(row, target, now) {
		t.Fatal("missing owner fingerprint retained launch authority")
	}
}

func TestServerTrustReopenAndStaleRevision(t *testing.T) {
	store, key, dir := bootstrapped(t)
	a, _ := store.lookup("alice")
	target := remoteTargetFixture(t)
	credential, e := store.putCredential(a.ID, Credential{Name: "fixture", Kind: "password", Secret: "synthetic"})
	if e != nil {
		t.Fatal("credential failed")
	}
	record, e := store.putConnection(a.ID, connection{Name: "server", Target: target.ID, Credential: credential, Approval: approvalFingerprint(target), Fingerprint: identityFingerprint(target)})
	if e != nil {
		t.Fatal("connection failed")
	}
	next := remoteTargetFixture(t)
	if store.trustConnection(a.ID, record, "1", approvalFingerprint(next), identityFingerprint(next)) != nil {
		t.Fatal("valid stored trust replacement refused")
	}
	if store.trustConnection(a.ID, record, "1", approvalFingerprint(target), identityFingerprint(target)) == nil {
		t.Fatal("stale trust revision accepted")
	}
	_ = store.Close()
	reopened, e := openStore(dir, key, false)
	if e != nil {
		t.Fatal("trust reopen refused")
	}
	defer reopened.Close()
	row, e := reopened.readConnection(a.ID, record)
	if e != nil || row.Revision != 2 || row.Fingerprint != identityFingerprint(next) || row.Approval != approvalFingerprint(next) {
		t.Fatal("trust replacement did not survive reopen")
	}
}
func trustBody(row connection, target RemoteTarget) string {
	return inputJSON(map[string]string{"fingerprint": identityFingerprint(target), "approval": approvalFingerprint(target), "revision": strconv.FormatUint(row.Revision, 10)})
}
func connectionState(t *testing.T, c *custodyClient, want string) {
	t.Helper()
	w := c.expect("GET", "/api/connections", "", 200)
	var rows []connectionView
	if json.Unmarshal(w.Body.Bytes(), &rows) != nil || len(rows) != 1 || rows[0].Trust != want {
		t.Fatal("connection trust state differs")
	}
}

func TestServerTrustProofRefusalAndMetadata(t *testing.T) {
	l, store, c, record, worker := remoteFixture(t, "https://127.0.0.1:8443")
	row, target := trustRow(t, l, store, record)
	w := c.expect("GET", "/api/targets/"+target.ID, "", 200)
	var detail targetView
	if json.Unmarshal(w.Body.Bytes(), &detail) != nil || detail.Hostname != "rdp.invalid" || detail.Port != 3389 || len(detail.Addresses) != 1 || detail.Addresses[0] != "10.34.0.8" || detail.Fingerprint != identityFingerprint(target) || detail.Approval != approvalFingerprint(target) || !detail.Available {
		t.Fatal("server identity metadata differs")
	}
	connectionState(t, c, "verified")
	base := map[string]string{"name": "reviewed", "target": row.Target, "credential": row.Credential, "fingerprint": row.Fingerprint, "approval": row.Approval}
	for _, field := range []string{"fingerprint", "approval"} {
		bad := make(map[string]string)
		for k, v := range base {
			bad[k] = v
		}
		bad[field] = "wrong"
		c.expect("POST", "/api/connections", inputJSON(bad), 409)
		delete(bad, field)
		c.expect("POST", "/api/connections", inputJSON(bad), 400)
	}
	base["host"] = "attacker.invalid"
	c.expect("POST", "/api/connections", inputJSON(base), 400)
	c.expect("POST", "/api/connections/"+record+"/trust", `{"fingerprint":"x","fingerprint":"y","approval":"x","revision":"1"}`, 400)
	c.expect("POST", "/api/connections/"+record+"/trust", `{"fingerprint":"x","approval":"x","revision":1}`, 400)
	c.expect("GET", "/api/targets/"+strings.Repeat("f", 32), "", 404)
	c.expect("POST", "/api/targets", `{}`, 404)
	if worker.calls.Load() != 0 {
		t.Fatal("identity review started a credential worker")
	}
	if rows, e := store.listConnections(l.accounts["alice"].id); e != nil || len(rows) != 1 {
		t.Fatal("refused proof created a connection")
	}
}

func TestServerTrustChangeReapprovalRevokesAndCAS(t *testing.T) {
	l, store, c, record, _ := remoteFixture(t, "https://127.0.0.1:8443")
	row, target := trustRow(t, l, store, record)
	pending := grantFixture(t, c, record)
	active := grantFixture(t, c, record)
	id, _ := tokenID(c.cookie.Value)
	l.mu.Lock()
	_, _, _, activeContext, e := l.redeemRemoteLocked(id, active)
	l.mu.Unlock()
	if e != nil {
		t.Fatal("active review fixture refused")
	}
	changed := target
	changed.Target = networkFixture(t, "rdp.invalid", 3390, "10.34.0.9")
	l.mu.Lock()
	l.remote.targets[row.Target] = changed
	l.mu.Unlock() // test-only restart-equivalent catalog change.
	connectionState(t, c, "changed")
	c.expect("POST", "/api/remote/open", inputJSON(map[string]string{"connection": record}), 401)
	c.expect("GET", "/remote/rdp/"+record, "", 404)
	l.mu.Lock()
	_, _, _, _, e = l.redeemRemoteLocked(id, pending)
	l.mu.Unlock()
	if e == nil {
		t.Fatal("pending grant survived network approval change")
	}
	c.expect("POST", "/api/connections/"+record+"/trust", trustBody(row, target), 409)
	select {
	case <-activeContext.Done():
		t.Fatal("refused review revoked the active connection")
	default:
	}
	body := trustBody(row, changed)
	c.expect("POST", "/api/connections/"+record+"/trust", body, 204)
	select {
	case <-activeContext.Done():
	case <-time.After(time.Second):
		t.Fatal("trust replacement retained active lease")
	}
	l.mu.Lock()
	_, _, _, _, e = l.redeemRemoteLocked(id, pending)
	l.mu.Unlock()
	if e == nil {
		t.Fatal("trust replacement retained pending lease")
	}
	connectionState(t, c, "verified")
	c.expect("POST", "/api/connections/"+record+"/trust", body, 409)
	newRow, _ := trustRow(t, l, store, record)
	if newRow.Revision != row.Revision+1 {
		t.Fatal("trust revision did not advance exactly once")
	}
	_ = grantFixture(t, c, record)
}

func TestServerTrustReplacementKeepsOtherConnection(t *testing.T) {
	l, store, c, record, _ := remoteFixture(t, "https://127.0.0.1:8443")
	row, target := trustRow(t, l, store, record)
	w := c.expect("POST", "/api/connections", inputJSON(map[string]string{"name": "other", "target": row.Target, "credential": row.Credential, "fingerprint": row.Fingerprint, "approval": row.Approval}), 200)
	var other struct{ ID string }
	if json.Unmarshal(w.Body.Bytes(), &other) != nil {
		t.Fatal("other connection fixture failed")
	}
	one, two := grantFixture(t, c, record), grantFixture(t, c, other.ID)
	id := mustSessionID(c)
	l.mu.Lock()
	_, _, _, first, e1 := l.redeemRemoteLocked(id, one)
	_, _, _, second, e2 := l.redeemRemoteLocked(id, two)
	l.mu.Unlock()
	if e1 != nil || e2 != nil {
		t.Fatal("independent lease fixtures failed")
	}
	c.expect("POST", "/api/connections/"+record+"/trust", trustBody(row, target), 204)
	select {
	case <-first.Done():
	case <-time.After(time.Second):
		t.Fatal("review did not revoke its own connection")
	}
	if second.Err() != nil {
		t.Fatal("review revoked an unrelated connection")
	}
}

func TestServerTrustMutationBudget(t *testing.T) {
	l, store, c, record, _ := remoteFixture(t, "https://127.0.0.1:8443")
	now := time.Now()
	l.mu.Lock()
	l.now = func() time.Time { return now }
	l.mu.Unlock()
	for range 4 {
		row, target := trustRow(t, l, store, record)
		c.expect("POST", "/api/connections/"+record+"/trust", trustBody(row, target), 204)
	}
	row, target := trustRow(t, l, store, record)
	raw := grantFixture(t, c, record)
	id := mustSessionID(c)
	l.mu.Lock()
	_, _, _, active, e := l.redeemRemoteLocked(id, raw)
	l.mu.Unlock()
	if e != nil {
		t.Fatal("budget lease fixture failed")
	}
	c.expect("POST", "/api/connections/"+record+"/trust", trustBody(row, target), 429)
	if active.Err() != nil {
		t.Fatal("limited review revoked an active connection")
	}
	unchanged, _ := trustRow(t, l, store, record)
	if unchanged.Revision != row.Revision {
		t.Fatal("limited review changed encrypted state")
	}
	advance(l, &now, 61*time.Second)
	c.expect("POST", "/api/connections/"+record+"/trust", trustBody(row, target), 204)
	select {
	case <-active.Done():
	case <-time.After(time.Second):
		t.Fatal("renewed budget did not permit scoped revocation")
	}
}

func TestServerTrustFreshMFAOwnerAndCSRF(t *testing.T) {
	l, store, c, record, _ := remoteFixture(t, "https://127.0.0.1:8443")
	row, target := trustRow(t, l, store, record)
	body := trustBody(row, target)
	csrf := c.csrf
	c.csrf = "wrong"
	c.expect("POST", "/api/connections/"+record+"/trust", body, 403)
	c.csrf = csrf
	id, _ := tokenID(c.cookie.Value)
	l.mu.Lock()
	fresh := l.sessions[id].reauthUntil
	l.sessions[id].reauthUntil = time.Time{}
	l.mu.Unlock()
	c.expect("GET", "/api/targets/"+row.Target, "", 200)
	c.expect("POST", "/api/connections/"+record+"/trust", body, 403)
	l.mu.Lock()
	l.sessions[id].reauthUntil = fresh
	l.mu.Unlock()
	other := &custodyClient{t: t, l: l}
	other.login()
	other.session("challenge")
	other.expect("GET", "/api/targets/"+row.Target, "", 403)
	other.expect("POST", "/api/connections/"+record+"/trust", body, 403)
	if _, e := store.CreateAccount("bob", alicePassword); e != nil {
		t.Fatal("second account failed")
	}
	_, _, codes := enrollFixture(t, store, "bob", time.Now())
	bob := &custodyClient{t: t, l: l}
	bob.expect("POST", "/api/session", inputJSON(map[string]string{"username": "bob", "password": alicePassword}), 204)
	bob.session("challenge")
	bob.expect("POST", "/api/mfa/verify", inputJSON(map[string]string{"code": codes[0]}), 204)
	bob.session("ready")
	bob.expect("POST", "/api/reauth", inputJSON(map[string]string{"password": alicePassword, "code": codes[1]}), 204)
	bob.expect("POST", "/api/connections/"+record+"/trust", body, 404)
	c.expect("POST", "/api/connections/"+record+"/trust", body, 204)
}

func writeLegacyConnection(t *testing.T, store *Store, owner string, row connection) {
	t.Helper()
	row.Fingerprint = ""
	if store.update(func(tx *bolt.Tx) error {
		plain, e := json.Marshal(row)
		if e != nil {
			return e
		}
		defer clear(plain)
		sealed, e := store.seal(tx, "connection", owner, row.ID, row.Revision+1, plain)
		if e != nil {
			return e
		}
		return tx.Bucket(connectionBucket).Put(credentialKey(owner, row.ID), sealed)
	}) != nil {
		t.Fatal("legacy row fixture failed")
	}
}
func TestServerTrustLegacyRequiresExplicitDecisionAndPersists(t *testing.T) {
	l, store, c, record, _ := remoteFixture(t, "https://127.0.0.1:8443")
	row, target := trustRow(t, l, store, record)
	owner := l.accounts["alice"].id
	writeLegacyConnection(t, store, owner, row)
	connectionState(t, c, "unverified")
	c.expect("POST", "/api/remote/open", inputJSON(map[string]string{"connection": record}), 401)
	row, _ = trustRow(t, l, store, record)
	c.expect("POST", "/api/connections/"+record+"/trust", trustBody(row, target), 204)
	connectionState(t, c, "verified")
	stored, e := store.readConnection(owner, record)
	if e != nil || stored.Fingerprint != identityFingerprint(target) || stored.Revision != row.Revision+1 {
		t.Fatal("explicit legacy decision did not persist")
	}
}

func TestServerTrustExpiredUnavailableAndRevisionBounds(t *testing.T) {
	l, store, c, record, _ := remoteFixture(t, "https://127.0.0.1:8443")
	row, target := trustRow(t, l, store, record)
	for _, rev := range []string{"0", "01", "-1", "2147483648", "18446744073709551616"} {
		body := inputJSON(map[string]string{"fingerprint": row.Fingerprint, "approval": row.Approval, "revision": rev})
		c.expect("POST", "/api/connections/"+record+"/trust", body, 409)
	}
	l.mu.Lock()
	now := l.now().Add(2 * time.Hour)
	l.now = func() time.Time { return now }
	l.sessions[mustSessionID(c)].reauthUntil = now.Add(time.Minute)
	l.sessions[mustSessionID(c)].last = now
	l.mu.Unlock()
	connectionState(t, c, "unavailable")
	c.expect("POST", "/api/connections/"+record+"/trust", trustBody(row, target), 409)
	if acceptTargetProof(target, row.Fingerprint, row.Approval, now) {
		t.Fatal("expired certificate accepted for trust")
	}
	if usableTarget(RemoteTarget{}, time.Now()) || connectionTrusted(row, RemoteTarget{}, time.Now()) {
		t.Fatal("missing target retained trust")
	}
}
func mustSessionID(c *custodyClient) [32]byte { id, _ := tokenID(c.cookie.Value); return id }
