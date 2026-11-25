package identity

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/denyfirst/keybash/internal/sshkey"
	"github.com/denyfirst/keybash/internal/targetguard"
	"github.com/denyfirst/keybash/internal/terminalweb"
	bolt "go.etcd.io/bbolt"
	"golang.org/x/crypto/ssh"
)

// Server accounts (docs/adr/0010-server-accounts.md).

func accountSet(kind, username, secret string, people ...string) string {
	return inputJSON(map[string]string{"kind": kind, "username": username, "secret": secret, "people": strings.Join(people, ",")})
}
func personField(id string) string { return inputJSON(map[string]string{"person": id}) }
func keyPrint(fingerprint string) string {
	return inputJSON(map[string]string{"fingerprint": fingerprint})
}

// accountPath is where an administrator changes a server's accounts.
func accountPath(server string, parts ...string) string {
	path := "/api/servers/" + server + "/accounts"
	for _, part := range parts {
		path += "/" + part
	}
	return path
}

// pemLines are the lines of a private key's PEM body, each of which must
// never appear in anything Keybash answers.
func pemLines(t *testing.T, secret string) []string {
	t.Helper()
	var lines []string
	for _, line := range strings.Split(strings.TrimSpace(secret), "\n") {
		if !strings.HasPrefix(line, "-----") && len(line) >= 16 {
			lines = append(lines, line)
		}
	}
	if len(lines) == 0 {
		t.Fatal("fixture key has no body")
	}
	return lines
}

// accountFixture gives a server an account listing these people, as an
// administrator would on the Servers page, and reloads the lab: a password
// account, or a key made here when secret is empty. It returns its ID.
func accountFixture(t *testing.T, l *Lab, server, username, secret string, people ...string) string {
	t.Helper()
	var admin string
	if l.store.view(func(tx *bolt.Tx) error {
		list, e := l.store.accounts(tx)
		for _, a := range list {
			if activeAdmin(a) && admin == "" {
				admin = a.ID
			}
		}
		return e
	}) != nil || admin == "" {
		t.Fatal("fixture has no administrator")
	}
	kind := "password"
	if secret == "" {
		kind = "ssh-key"
	}
	people = slices.Clone(people)
	slices.Sort(people)
	id, e := l.store.addServerAccount(admin, server, kind, username, secret, people, time.Now())
	if e != nil {
		t.Fatalf("fixture account refused: %v", e)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.reloadServersLocked() != nil {
		t.Fatal("fixture reload failed")
	}
	return id
}

// accountsOf is one server's accounts as c reads them on the Servers page.
func accountsOf(t *testing.T, c *custodyClient, server string) ([]accountView, string) {
	t.Helper()
	answer := c.expect("GET", "/api/servers", "", 200).Body.String()
	var view serversView
	if json.Unmarshal([]byte(answer), &view) != nil {
		t.Fatal("servers unreadable")
	}
	row, ok := serverRow(view, server)
	if !ok {
		t.Fatal("server missing")
	}
	return row.Accounts, answer
}

func TestServerAccountsAreAnAdministratorsAndNeverShown(t *testing.T) {
	f, scans := serversFixture(t)
	keyServer, _ := addServerFixture(t, f.alice, scans, "Web", "10.20.0.7:22")
	passwordServer, _ := addServerFixture(t, f.alice, scans, "Db", "10.20.0.8:22")
	var seen []string
	say := func(c *custodyClient, method, path, body string, status int) string {
		t.Helper()
		answer := c.expect(method, path, body, status).Body.String()
		seen = append(seen, answer)
		return answer
	}
	accounts := func(c *custodyClient, server string) []accountView {
		t.Helper()
		list, answer := accountsOf(t, c, server)
		seen = append(seen, answer)
		return list
	}
	made := func(answer string) string {
		t.Helper()
		var data struct{ ID string }
		if json.Unmarshal([]byte(answer), &data) != nil || !validID(data.ID) {
			t.Fatal("the new account's ID is missing")
		}
		return data.ID
	}

	// Every change needs fresh proof, like adding a server.
	f.advance(freshProof + time.Minute)
	say(f.alice, "POST", accountPath(keyServer), accountSet("ssh-key", "deploy", ""), 428)
	f.alice.expect("POST", "/api/reauth", inputJSON(map[string]string{"code": f.codes[0]}), 204)
	f.advance(61 * time.Second) // a fresh minute of server changes

	// Only an administrator adds one; malformed requests make nothing.
	bob, b := f.person("bob", roleUser)
	dave, d := f.person("dave", roleAuditor)
	say(bob, "POST", accountPath(keyServer), accountSet("ssh-key", "deploy", ""), 403)
	say(dave, "POST", accountPath(keyServer), accountSet("ssh-key", "deploy", ""), 403)
	for _, who := range []durableAccount{b, d} {
		if _, e := f.store.addServerAccount(who.ID, keyServer, "ssh-key", "deploy", "", nil, f.now); e == nil {
			t.Fatal("the store let a user or an auditor add an account")
		}
	}
	for _, bad := range []string{
		accountSet("rsa", "deploy", ""), accountSet("ssh-key", "", ""), accountSet("ssh-key", " deploy", ""), accountSet("ssh-key", "de\x00ploy", ""),
		accountSet("ssh-key", strings.Repeat("u", 129), ""), accountSet("ssh-key", "deploy", "-----BEGIN OPENSSH PRIVATE KEY-----"),
		accountSet("password", "deploy", ""), accountSet("password", "deploy", "pass\x00word"), accountSet("password", "deploy", strings.Repeat("p", 4097)),
		accountSet("ssh-key", "deploy", "", "bob"), accountSet("ssh-key", "deploy", "", b.ID, b.ID), accountSet("ssh-key", "deploy", "", strings.ToUpper(b.ID)),
		accountSet("ssh-key", "deploy", "", b.ID+","), `{"kind":"ssh-key","username":"deploy","secret":""}`,
		`{"kind":"ssh-key","username":"deploy","secret":"","people":"","generated":"true"}`,
	} {
		say(f.alice, "POST", accountPath(keyServer), bad, 400)
	}
	// An auditor is put on no account; someone who does not exist is missing.
	say(f.alice, "POST", accountPath(keyServer), accountSet("ssh-key", "deploy", "", d.ID), 403)
	say(f.alice, "POST", accountPath(keyServer), accountSet("ssh-key", "deploy", "", strings.Repeat("e", 32)), 404)
	if len(accounts(f.alice, keyServer)) != 0 {
		t.Fatal("a refused request made an account")
	}
	say(f.alice, "POST", accountPath(strings.Repeat("e", 32)), accountSet("ssh-key", "deploy", ""), 404)
	f.advance(61 * time.Second)

	// A key is made here; another account on the server needs another name,
	// whatever its case.
	keyAccount := made(say(f.alice, "POST", accountPath(keyServer), accountSet("ssh-key", "deploy", "", b.ID), 200))
	say(f.alice, "POST", accountPath(keyServer), accountSet("ssh-key", "Deploy", ""), 409)
	say(f.alice, "POST", accountPath(keyServer), accountSet("password", "deploy", "Synthetic password"), 409)
	alice := mustLookup(t, f.store, "alice")
	first, e := f.store.readServerAccount(keyServer, keyAccount)
	if e != nil || first.Current.Kind != "ssh-key" || !first.Current.Generated || first.Current.Username != "deploy" || first.Generation != 1 || first.SetBy != alice.ID ||
		first.Next != nil || !slices.Equal(first.People, []string{b.ID}) {
		t.Fatalf("stored account: %v", e)
	}
	list := accounts(f.alice, keyServer)
	want := accountView{ID: keyAccount, Kind: "ssh-key", Username: "deploy", Line: "restrict,pty " + first.Current.Public + " keybash", Fingerprint: first.Current.Fingerprint,
		People: []string{b.ID}, SetBy: alice.ID, Set: f.now.Unix()}
	if len(list) != 1 || !reflect.DeepEqual(list[0], want) {
		t.Fatalf("the administrator's view: %+v", list)
	}
	// An auditor reads the same; a user does not read the page.
	if audited := accounts(dave, keyServer); !reflect.DeepEqual(audited, list) {
		t.Fatal("the auditor's view differs")
	}
	say(bob, "GET", "/api/servers", "", 403)

	// A password is typed once, shown never, and replaced at once.
	const marker = "Synthetic-account-password-7f3a"
	passwordAccount := made(say(f.alice, "POST", accountPath(passwordServer), accountSet("password", "ops", marker), 200))
	if pw := accounts(f.alice, passwordServer); len(pw) != 1 || pw[0].Kind != "password" || pw[0].Username != "ops" || pw[0].Line != "" || pw[0].Fingerprint != "" || pw[0].Next != "" || len(pw[0].People) != 0 {
		t.Fatalf("a password's view: %+v", pw)
	}
	say(bob, "POST", accountPath(passwordServer, passwordAccount, "password"), inputJSON(map[string]string{"secret": marker + "-bob"}), 403)
	say(f.alice, "POST", accountPath(passwordServer, passwordAccount, "password"), inputJSON(map[string]string{"secret": ""}), 400)
	say(f.alice, "POST", accountPath(passwordServer, passwordAccount, "password"), inputJSON(map[string]string{"secret": marker + "-2"}), 204)
	if a, e := f.store.readServerAccount(passwordServer, passwordAccount); e != nil || a.Current.Secret != marker+"-2" || a.Current.Username != "ops" || a.Generation != 2 {
		t.Fatal("the password was not replaced at once")
	}
	// Keys and passwords do not change into each other, and an account is
	// reached only under its own server.
	say(f.alice, "POST", accountPath(keyServer, keyAccount, "password"), inputJSON(map[string]string{"secret": marker}), 403)
	say(f.alice, "POST", accountPath(passwordServer, passwordAccount, "next"), "{}", 403)
	say(f.alice, "POST", accountPath(passwordServer, keyAccount, "next"), "{}", 404)
	say(f.alice, "POST", accountPath(keyServer, "deploy", "next"), "{}", 404)
	say(f.alice, "POST", "/api/servers/"+keyServer+"/account/"+keyAccount+"/next", "{}", 404)
	f.advance(61 * time.Second)

	// A key is replaced in two steps: the current one works until the switch.
	say(bob, "POST", accountPath(keyServer, keyAccount, "next"), "{}", 403)
	say(f.alice, "POST", accountPath(keyServer, keyAccount, "next"), "{}", 204)
	waiting, e := f.store.readServerAccount(keyServer, keyAccount)
	if e != nil || waiting.Next == nil || waiting.Current.Fingerprint != first.Current.Fingerprint || waiting.Current.Secret != first.Current.Secret || waiting.Generation != 1 || waiting.Next.Username != "deploy" {
		t.Fatal("the next key replaced the current one early")
	}
	if list = accounts(f.alice, keyServer); list[0].Fingerprint != first.Current.Fingerprint || list[0].Next != "restrict,pty "+waiting.Next.Public+" keybash" || list[0].NextFingerprint != waiting.Next.Fingerprint {
		t.Fatalf("the view of a waiting key: %+v", list)
	}
	// The switch takes only the key the administrator saw.
	say(f.alice, "POST", accountPath(keyServer, keyAccount, "switch"), keyPrint(first.Current.Fingerprint), 409)
	say(f.alice, "POST", accountPath(keyServer, keyAccount, "switch"), keyPrint("SHA256:nope"), 400)
	say(bob, "POST", accountPath(keyServer, keyAccount, "switch"), keyPrint(waiting.Next.Fingerprint), 403)
	say(f.alice, "POST", accountPath(keyServer, keyAccount, "switch"), keyPrint(waiting.Next.Fingerprint), 204)
	switched, e := f.store.readServerAccount(keyServer, keyAccount)
	if e != nil || switched.Current.Fingerprint != waiting.Next.Fingerprint || switched.Current.Secret != waiting.Next.Secret || switched.Next != nil || switched.Generation != 2 ||
		!slices.Equal(switched.People, []string{b.ID}) {
		t.Fatal("the switch did not make the waiting key the one used, and destroy the old one")
	}
	say(f.alice, "POST", accountPath(keyServer, keyAccount, "switch"), keyPrint(waiting.Next.Fingerprint), 404)
	// A waiting key can be dropped; the current one stays.
	say(f.alice, "POST", accountPath(keyServer, keyAccount, "next"), "{}", 204)
	dropped, _ := f.store.readServerAccount(keyServer, keyAccount)
	say(f.alice, "DELETE", accountPath(keyServer, keyAccount, "next"), "{}", 204)
	say(f.alice, "DELETE", accountPath(keyServer, keyAccount, "next"), "{}", 404)
	if a, e := f.store.readServerAccount(keyServer, keyAccount); e != nil || a.Next != nil || a.Current.Fingerprint != switched.Current.Fingerprint || a.Generation != 2 {
		t.Fatal("dropping the waiting key changed the current one")
	}
	f.advance(61 * time.Second)

	// People are put on and taken off one by one; nobody twice, no auditor.
	say(bob, "POST", accountPath(passwordServer, passwordAccount, "grant"), personField(b.ID), 403)
	say(f.alice, "POST", accountPath(passwordServer, passwordAccount, "grant"), personField("bob"), 400)
	say(f.alice, "POST", accountPath(passwordServer, passwordAccount, "grant"), personField(d.ID), 403)
	say(f.alice, "POST", accountPath(passwordServer, passwordAccount, "grant"), personField(strings.Repeat("e", 32)), 404)
	say(f.alice, "POST", accountPath(passwordServer, passwordAccount, "grant"), personField(b.ID), 204)
	say(f.alice, "POST", accountPath(passwordServer, passwordAccount, "grant"), personField(alice.ID), 204)
	say(f.alice, "POST", accountPath(passwordServer, passwordAccount, "grant"), personField(b.ID), 204)
	people := []string{alice.ID, b.ID}
	slices.Sort(people)
	if a, _ := f.store.readServerAccount(passwordServer, passwordAccount); !slices.Equal(a.People, people) || a.Generation != 2 || a.Current.Secret != marker+"-2" {
		t.Fatal("putting people on changed more than the list")
	}
	say(f.alice, "POST", accountPath(passwordServer, passwordAccount, "revoke"), personField(b.ID), 204)
	say(f.alice, "POST", accountPath(passwordServer, passwordAccount, "revoke"), personField(b.ID), 204)
	if a, _ := f.store.readServerAccount(passwordServer, passwordAccount); !slices.Equal(a.People, []string{alice.ID}) {
		t.Fatal("taking someone off did not")
	}
	f.advance(61 * time.Second)

	// A server holds at most 16 accounts.
	for i := 2; i <= maxServerAccounts; i++ {
		if _, e := f.store.addServerAccount(alice.ID, passwordServer, "password", fmt.Sprintf("user%d", i), "Synthetic password", nil, f.now); e != nil {
			t.Fatalf("account %d refused", i)
		}
	}
	say(f.alice, "POST", accountPath(passwordServer), accountSet("password", "one-too-many", "Synthetic password"), 403)
	if len(accounts(f.alice, passwordServer)) != maxServerAccounts {
		t.Fatal("a server held more accounts than allowed")
	}

	// Removing one destroys it; removing a server takes its accounts along.
	say(bob, "DELETE", accountPath(keyServer, keyAccount), "{}", 403)
	say(f.alice, "DELETE", accountPath(keyServer, keyAccount), "{}", 204)
	say(f.alice, "DELETE", accountPath(keyServer, keyAccount), "{}", 404)
	if _, e := f.store.readServerAccount(keyServer, keyAccount); e != errMissing || len(accounts(f.alice, keyServer)) != 0 {
		t.Fatalf("a removed account remains: %v", e)
	}
	say(f.alice, "DELETE", "/api/servers/"+passwordServer, "{}", 204)
	if f.store.view(func(tx *bolt.Tx) error {
		left := 0
		if b := tx.Bucket(serverAccountBucket); b != nil {
			_ = b.ForEach(func(_, _ []byte) error { left++; return nil })
		}
		if left != 0 {
			return errRefused
		}
		return nil
	}) != nil {
		t.Fatal("a removed server's accounts remain")
	}

	// Nothing Keybash answered carried a secret.
	secrets := []string{marker, "PRIVATE KEY", "Synthetic password"}
	for _, key := range []Credential{first.Current, *waiting.Next, *dropped.Next} {
		secrets = append(secrets, pemLines(t, key.Secret)...)
	}
	for _, answer := range seen {
		for _, secret := range secrets {
			if strings.Contains(answer, secret) {
				t.Fatal("an answer carried an account's secret")
			}
		}
	}
}

func TestServerAccountRecordsAreCheckedOnRead(t *testing.T) {
	f, scans := serversFixture(t)
	one, _ := addServerFixture(t, f.alice, scans, "One", "10.20.0.7:22")
	two, _ := addServerFixture(t, f.alice, scans, "Two", "10.20.0.8:22")
	_, b := f.person("bob", roleUser)
	good := accountFixture(t, f.l, one, "deploy", "", b.ID)
	verify := func() error {
		return f.store.view(func(tx *bolt.Tx) error { _, e := f.store.verifyAll(tx); return e })
	}
	if verify() != nil {
		t.Fatal("a store with an account did not verify")
	}
	base, e := f.store.readServerAccount(one, good)
	if e != nil {
		t.Fatal("fixture account unreadable")
	}
	other, _ := newGeneratedKey("deploy")
	id := strings.Repeat("a", 32)
	write := func(server, key string, a serverAccount) {
		t.Helper()
		if e := f.store.update(func(tx *bolt.Tx) error {
			plain, e := json.Marshal(a)
			if e != nil {
				return e
			}
			sealed, e := f.store.seal(tx, "server-account", server, key, 1, plain)
			if e != nil {
				return e
			}
			return tx.Bucket(serverAccountBucket).Put(accountKey(server, key), sealed)
		}); e != nil {
			t.Fatal(e)
		}
	}
	remove := func(server, key string) {
		t.Helper()
		if f.store.update(func(tx *bolt.Tx) error { return tx.Bucket(serverAccountBucket).Delete(accountKey(server, key)) }) != nil {
			t.Fatal("fixture delete failed")
		}
	}
	base.ID, base.Server = id, two
	if write(two, id, base); verify() != nil {
		t.Fatal("a well-formed record did not verify")
	}
	variants := map[string]func(a *serverAccount){
		"a key brought from elsewhere": func(a *serverAccount) { a.Current.Generated = false },
		"a used password": func(a *serverAccount) {
			a.Current = Credential{Kind: "password", Username: "ops", Secret: "Synthetic password", Used: true}
		},
		"a public half not the key's own":        func(a *serverAccount) { a.Current.Public = other.Public },
		"a name with spaces around it":           func(a *serverAccount) { a.Current.Username = " deploy" },
		"no setter":                              func(a *serverAccount) { a.SetBy = "" },
		"no generation":                          func(a *serverAccount) { a.Generation = 0 },
		"a waiting key for another account":      func(a *serverAccount) { n := other; n.Username = "root"; a.Next = &n },
		"a waiting key equal to the current one": func(a *serverAccount) { n := a.Current; a.Next = &n },
		"a waiting key already used":             func(a *serverAccount) { n := other; n.Used = true; a.Next = &n },
		"another server's record":                func(a *serverAccount) { a.Server = one },
		"another ID":                             func(a *serverAccount) { a.ID = strings.Repeat("b", 32) },
		"people out of order":                    func(a *serverAccount) { a.People = []string{strings.Repeat("f", 32), strings.Repeat("0", 32)} },
		"a person twice":                         func(a *serverAccount) { a.People = []string{b.ID, b.ID} },
		"a person by name":                       func(a *serverAccount) { a.People = []string{"bob"} },
		"too many people": func(a *serverAccount) {
			a.People = nil
			for i := range maxAccountPeople + 1 {
				a.People = append(a.People, fmt.Sprintf("%032x", i))
			}
		},
	}
	for name, change := range variants {
		bad := base
		bad.People = slices.Clone(base.People)
		change(&bad)
		write(two, id, bad)
		if _, e := f.store.readServerAccount(two, id); e == nil {
			t.Fatalf("%s was read", name)
		}
		if verify() == nil {
			t.Fatalf("a store holding %s verified", name)
		}
	}
	// A record that reads but lists someone who does not exist, or an
	// auditor, fails the backup check.
	_, d := f.person("dave", roleAuditor)
	for name, person := range map[string]string{"someone who does not exist": strings.Repeat("e", 32), "an auditor": d.ID} {
		listed := base
		listed.People = []string{person}
		write(two, id, listed)
		if _, e := f.store.readServerAccount(two, id); e != nil || verify() == nil {
			t.Fatalf("a store with %s on an account verified", name)
		}
	}
	// Two accounts on one server under one name, whatever its case, fail it.
	twin := base
	twin.Current = other
	twin.Current.Username = "DEPLOY"
	twin.Server = one
	write(one, id, twin)
	if verify() == nil {
		t.Fatal("two accounts with one name verified")
	}
	remove(one, id)
	write(two, id, base)
	// A key is for SSH alone.
	if accountSecret("rdp", base.Current) || !accountSecret("ssh", base.Current) {
		t.Fatal("a key's protocol was not checked")
	}
	// A record copied under another server's name does not open, and a record
	// for no server fails the backup check.
	move := func(fromServer, toServer string) {
		t.Helper()
		if e := f.store.update(func(tx *bolt.Tx) error {
			bucket := tx.Bucket(serverAccountBucket)
			raw := append([]byte(nil), bucket.Get(accountKey(fromServer, id))...)
			if e := bucket.Delete(accountKey(fromServer, id)); e != nil {
				return e
			}
			return bucket.Put(accountKey(toServer, id), raw)
		}); e != nil {
			t.Fatal(e)
		}
	}
	move(two, one)
	if _, e := f.store.readServerAccount(one, id); e == nil || verify() == nil {
		t.Fatal("a record under another server's name was read")
	}
	move(one, strings.Repeat("e", 32))
	if verify() == nil {
		t.Fatal("an account for no server verified")
	}
}

func TestServerAccountOpensOnlyForPeopleOnIt(t *testing.T) {
	f, scans := serversFixture(t)
	server, _ := addServerFixture(t, f.alice, scans, "Web", "10.20.0.7:22")
	bob, b := f.person("bob", roleUser)
	carol, c := f.person("carol", roleUser)
	dave, _ := f.person("dave", roleAuditor)
	const marker = "Synthetic-ops-password-1c9b"
	var deploy, ops string
	{
		var data struct{ ID string }
		_ = json.Unmarshal(f.alice.expect("POST", accountPath(server), accountSet("ssh-key", "deploy", "", b.ID), 200).Body.Bytes(), &data)
		deploy = data.ID
		_ = json.Unmarshal(f.alice.expect("POST", accountPath(server), accountSet("password", "ops", marker, c.ID), 200).Body.Bytes(), &data)
		ops = data.ID
	}
	open := func(cl *custodyClient, account string, status int) string {
		t.Helper()
		w := cl.expect("POST", "/api/remote/open", inputJSON(map[string]string{"account": account}), status)
		if status != 200 {
			return ""
		}
		var data struct{ Lease string }
		if json.Unmarshal(w.Body.Bytes(), &data) != nil || len(data.Lease) != 43 {
			t.Fatal("lease missing")
		}
		return data.Lease
	}
	listed := func(cl *custodyClient) []accessRow {
		t.Helper()
		answer := cl.expect("GET", "/api/access", "", 200).Body.String()
		if strings.Contains(answer, "PRIVATE") || strings.Contains(answer, "secret") || strings.Contains(answer, marker) {
			t.Fatal("the list carried a secret")
		}
		var rows []accessRow
		if json.Unmarshal([]byte(answer), &rows) != nil {
			t.Fatal("access list unreadable")
		}
		return rows
	}
	redeemAs := func(cl *custodyClient, raw string) (Credential, context.Context, error) {
		t.Helper()
		sid, _ := tokenID(cl.cookie.Value)
		f.l.mu.Lock()
		defer f.l.mu.Unlock()
		_, _, credential, ctx, e := f.l.redeemRemoteLocked(sid, raw)
		return credential, ctx, e
	}
	redeem := func(raw string) (Credential, context.Context, error) { return redeemAs(bob, raw) }
	ended := func(ctx context.Context, what string) {
		t.Helper()
		select {
		case <-ctx.Done():
		case <-time.After(time.Second):
			t.Fatalf("%s did not end the open session", what)
		}
		if context.Cause(ctx) != terminalweb.ReasonAccessChanged {
			t.Fatalf("%s ended the session without saying the access changed: %v", what, context.Cause(ctx))
		}
	}
	// The socket closing, as a page leaving would.
	closeAll := func() {
		f.l.mu.Lock()
		defer f.l.mu.Unlock()
		for key, lease := range f.l.remote.leases {
			if lease.owner == b.ID {
				if lease.cancel != nil {
					lease.cancel(nil)
				}
				delete(f.l.remote.leases, key)
			}
		}
	}
	person := func(account, action, who string) {
		t.Helper()
		f.alice.expect("POST", accountPath(server, account, action), personField(who), 204)
	}

	// Each person sees and opens only the accounts that list them.
	if rows := listed(bob); len(rows) != 1 || rows[0] != (accessRow{Account: deploy, Server: server, Name: "Web", Protocol: "ssh", Username: "deploy", Trust: "verified"}) {
		t.Fatalf("bob's list: %+v", rows)
	}
	if rows := listed(carol); len(rows) != 1 || rows[0].Account != ops || rows[0].Username != "ops" {
		t.Fatalf("carol's list: %+v", rows)
	}
	if len(listed(f.alice)) != 0 {
		t.Fatal("an administrator on no account was listed one")
	}
	open(bob, ops, 401)
	open(carol, deploy, 401)
	open(f.alice, deploy, 401)
	// An auditor reaches nothing; malformed requests open nothing.
	dave.expect("GET", "/api/access", "", 403)
	open(dave, deploy, 403)
	bob.expect("POST", "/api/remote/open", `{"account":"`+deploy+`","server":"`+server+`"}`, 400)
	bob.expect("POST", "/api/remote/open", `{"account":"`+deploy+`","account":"`+deploy+`"}`, 400)
	bob.expect("POST", "/api/remote/open", inputJSON(map[string]string{"connection": deploy}), 400)
	bob.expect("POST", "/api/remote/open", inputJSON(map[string]string{"account": "deploy"}), 401)
	bob.expect("POST", "/api/remote/open", inputJSON(map[string]string{"account": server}), 401)
	bob.expect("POST", "/api/remote/open", inputJSON(map[string]string{"account": strings.Repeat("e", 32)}), 401)
	// The old ways in are gone.
	for _, path := range []string{"/api/remote/open-shared", "/api/connections", "/api/credentials", "/api/credentials/generate"} {
		bob.expect("POST", path, inputJSON(map[string]string{"server": server}), 404)
	}
	for _, path := range []string{"/api/shared", "/api/targets", "/api/connections", "/api/credentials"} {
		bob.expect("GET", path, "", 404)
	}

	// A listed person's lease opens with the account's key, once, and only
	// for them.
	first, _ := f.store.readServerAccount(server, deploy)
	raw := open(bob, deploy, 200)
	if _, _, e := redeemAs(f.alice, raw); e == nil {
		t.Fatal("another person redeemed the lease")
	}
	credential, ctx, e := redeem(raw)
	if e != nil || credential.Fingerprint != first.Current.Fingerprint || credential.Username != "deploy" || !credential.Generated {
		t.Fatal("a listed person's lease did not open with the account's key")
	}
	if _, _, e := redeem(raw); e == nil {
		t.Fatal("a lease was redeemed twice")
	}
	// A new key does not end the open session, but a lease from before the
	// switch is not redeemed; one after it opens with the new key.
	pending := open(bob, deploy, 200)
	f.alice.expect("POST", accountPath(server, deploy, "next"), "{}", 204)
	waiting, _ := f.store.readServerAccount(server, deploy)
	f.alice.expect("POST", accountPath(server, deploy, "switch"), keyPrint(waiting.Next.Fingerprint), 204)
	if _, _, e := redeem(pending); e == nil {
		t.Fatal("a lease from before the switch was redeemed")
	}
	select {
	case <-ctx.Done():
		t.Fatal("a new key ended the open session")
	default:
	}
	closeAll()
	if credential, _, e = redeem(open(bob, deploy, 200)); e != nil || credential.Fingerprint != waiting.Next.Fingerprint {
		t.Fatal("a lease after the switch did not open with the new key")
	}
	closeAll()
	f.advance(61 * time.Second)

	// Putting someone else on, or taking them off, leaves bob's session alone.
	_, ctx, e = redeem(open(bob, deploy, 200))
	if e != nil {
		t.Fatal("lease refused")
	}
	person(deploy, "grant", c.ID)
	person(deploy, "revoke", c.ID)
	select {
	case <-ctx.Done():
		t.Fatal("a change for someone else ended the session")
	default:
	}
	// Taking the person off ends their session and pending lease.
	pending = open(bob, deploy, 200)
	person(deploy, "revoke", b.ID)
	ended(ctx, "taking the person off")
	if _, _, e := redeem(pending); e == nil || len(listed(bob)) != 0 {
		t.Fatal("a person taken off still reaches the account")
	}
	open(bob, deploy, 401)
	f.advance(61 * time.Second)

	// Removing the account ends sessions through it at once.
	person(deploy, "grant", b.ID)
	_, ctx, e = redeem(open(bob, deploy, 200))
	if e != nil {
		t.Fatal("lease refused")
	}
	pending = open(bob, deploy, 200)
	f.alice.expect("DELETE", accountPath(server, deploy), "{}", 204)
	ended(ctx, "removing the account")
	if _, _, e := redeem(pending); e == nil || len(listed(bob)) != 0 {
		t.Fatal("a removed account was still used")
	}
	open(bob, deploy, 401)

	// A new server identity ends them too.
	again := accountFixture(t, f.l, server, "deploy", "", b.ID)
	_, ctx, e = redeem(open(bob, again, 200))
	if e != nil {
		t.Fatal("lease refused")
	}
	renewed := hostKeyFixture(t)
	scans.set("10.20.0.7:22", renewed)
	f.alice.expect("POST", "/api/servers/"+server+"/key", keyPrint(ssh.FingerprintSHA256(renewed)), 204)
	ended(ctx, "a new server identity")
	closeAll()
	f.advance(61 * time.Second)

	// Removing the server ends them too.
	_, ctx, e = redeem(open(bob, again, 200))
	if e != nil {
		t.Fatal("lease refused")
	}
	f.alice.expect("DELETE", "/api/servers/"+server, "{}", 204)
	ended(ctx, "removing the server")
	open(bob, again, 401)
}

// A person made an auditor, or deleted, is taken off every account in the
// same change, and their sessions end.
func TestServerAccountsLoseAuditorsAndDeletedPeople(t *testing.T) {
	f, scans := serversFixture(t)
	server, _ := addServerFixture(t, f.alice, scans, "Web", "10.20.0.7:22")
	bob, b := f.person("bob", roleUser)
	_, c := f.person("carol", roleUser)
	deploy := accountFixture(t, f.l, server, "deploy", "", b.ID, c.ID)
	ops := accountFixture(t, f.l, server, "ops", "Synthetic password", b.ID)
	var lease struct{ Lease string }
	if json.Unmarshal(bob.expect("POST", "/api/remote/open", inputJSON(map[string]string{"account": deploy}), 200).Body.Bytes(), &lease) != nil {
		t.Fatal("lease missing")
	}
	f.alice.expect("POST", "/api/users/"+b.ID+"/role", inputJSON(map[string]string{"role": "auditor"}), 204)
	for _, account := range []string{deploy, ops} {
		if a, e := f.store.readServerAccount(server, account); e != nil || slices.Contains(a.People, b.ID) {
			t.Fatal("a new auditor stayed on an account")
		}
	}
	f.l.mu.Lock()
	_, reached := f.l.mayUseLocked(b.ID, ops)
	f.l.mu.Unlock()
	if reached {
		t.Fatal("the gateway still let a new auditor use an account")
	}
	// Another role change leaves the lists alone.
	f.alice.expect("POST", "/api/users/"+c.ID+"/role", inputJSON(map[string]string{"role": "admin"}), 204)
	if a, _ := f.store.readServerAccount(server, deploy); !slices.Equal(a.People, []string{c.ID}) {
		t.Fatal("making someone an administrator took them off")
	}
	f.alice.expect("DELETE", "/api/users/"+c.ID, "{}", 204)
	if a, _ := f.store.readServerAccount(server, deploy); len(a.People) != 0 {
		t.Fatal("a deleted person stayed on an account")
	}
	if f.store.view(func(tx *bolt.Tx) error { _, e := f.store.verifyAll(tx); return e }) != nil {
		t.Fatal("the store did not verify afterwards")
	}
}

// The page that opens an account is served only to someone who could open it:
// on the account, for the protocol in its path. It is marked with the account.
func TestServerAccountSessionPageOpensOnlyForPeopleOnIt(t *testing.T) {
	f, scans := serversFixture(t)
	server, _ := addServerFixture(t, f.alice, scans, "Web", "10.20.0.7:22")
	bob, b := f.person("bob", roleUser)
	dave, _ := f.person("dave", roleAuditor)
	account := accountFixture(t, f.l, server, "deploy", "", b.ID)
	page := "/remote/ssh/" + account
	w := bob.expect("GET", page, "", 200)
	body := w.Body.String()
	start := strings.Index(body, "<body ")
	if start < 0 || !strings.HasPrefix(body[start:], `<body data-owned-remote="ssh" data-account="`+account+`" `) || strings.Count(body, "data-account") != 1 {
		t.Fatal("the session page is not marked with its account")
	}
	if policy := w.Header().Get("Content-Security-Policy"); !strings.Contains(policy, "; script-src 'self'; ") {
		t.Fatalf("a terminal page may compile WebAssembly: %s", policy)
	}
	// A session page that does not open answers with one closed page, the
	// same for every reason, under the strict policy, leading back to Your
	// servers. It never names the account or the server.
	w = bob.expect("GET", "/remote/ssh/"+strings.Repeat("e", 32), "", 404)
	closed := w.Body.String()
	if !strings.Contains(closed, "This server is not open to you") || !strings.Contains(closed, `<a class="go-back" href="/">Back to your servers</a>`) || strings.Contains(closed, "<script") ||
		w.Header().Get("Content-Type") != "text/html; charset=utf-8" || strings.Contains(w.Header().Get("Content-Security-Policy"), "unsafe") || !strings.Contains(w.Header().Get("Content-Security-Policy"), "default-src 'none'") {
		t.Fatal("a refused session page is not the closed page")
	}
	isClosed := func(who *custodyClient, path string) {
		t.Helper()
		if w := who.expect("GET", path, "", 404); w.Body.String() != closed {
			t.Fatalf("%s did not answer with the closed page", path)
		}
	}
	// Another protocol, the server's ID, or people not on the account: the
	// closed page. Other shapes and the old shared path are no session page.
	isClosed(bob, "/remote/rdp/"+account)
	isClosed(bob, "/remote/ssh/"+server)
	isClosed(f.alice, page)
	isClosed(dave, page)
	for _, path := range []string{"/remote/ssh/" + strings.ToUpper(account), "/remote/" + account, "/remote/ssh/" + account + "/", "/remote/shared/ssh/" + server, "/remote/shared/ssh/" + account} {
		if w := bob.expect("GET", path, "", 404); strings.Contains(w.Body.String(), "data-owned-remote") || w.Body.String() == closed {
			t.Fatalf("%s served a session page", path)
		}
	}
	// Signed out, as from a bookmark: sign in first, like any page.
	if w := (&custodyClient{t: t, l: f.l}).expect("GET", page, "", 303); w.Header().Get("Location") != "/login" || strings.Contains(w.Body.String(), account) {
		t.Fatal("a signed-out session page did not lead to sign-in")
	}
	// Taken off, or the account removed: closed again.
	f.alice.expect("POST", accountPath(server, account, "revoke"), personField(b.ID), 204)
	isClosed(bob, page)
	f.alice.expect("POST", accountPath(server, account, "grant"), personField(b.ID), 204)
	bob.expect("GET", page, "", 200)
	f.alice.expect("DELETE", accountPath(server, account), "{}", 204)
	isClosed(bob, page)
}

// A desktop's account takes a password only, and its card follows its
// server: ready; stopped while Windows shows another certificate than the pin;
// unavailable once the pin ends, and then nothing opens.
func TestServerAccountDesktopFollowsItsCertificate(t *testing.T) {
	f, reads, _ := desktopFixture(t)
	endpoint := "10.20.0.8:3389"
	pin := windowsLeaf(t, func(c *x509.Certificate) { c.NotAfter = f.now.Add(10 * time.Minute) })
	reads.set(endpoint, pin)
	f.alice.expect("POST", "/api/servers/scan", rdpFields("", "10.20.0.8", "3389", ""), 200)
	var made struct{ ID string }
	if json.Unmarshal(f.alice.expect("POST", "/api/servers", rdpFields("Desk", "10.20.0.8", "3389", certificatePrint(pin)), 200).Body.Bytes(), &made) != nil || !validID(made.ID) {
		t.Fatal("desktop was not added")
	}
	id := made.ID
	bob, b := f.person("bob", roleUser)
	f.alice.expect("POST", accountPath(id), accountSet("ssh-key", "kbtest", "", b.ID), 403)
	var account struct{ ID string }
	if json.Unmarshal(f.alice.expect("POST", accountPath(id), accountSet("password", "kbtest", "Synthetic-desk-password-7d2e", b.ID), 200).Body.Bytes(), &account) != nil {
		t.Fatal("desktop account missing")
	}
	trust := func() string {
		t.Helper()
		var rows []accessRow
		if json.Unmarshal(bob.expect("GET", "/api/access", "", 200).Body.Bytes(), &rows) != nil || len(rows) != 1 || rows[0].Server != id || rows[0].Protocol != "rdp" || rows[0].Username != "kbtest" || rows[0].Account != account.ID {
			t.Fatal("desktop account not listed")
		}
		return rows[0].Trust
	}
	read := func() { t.Helper(); f.l.readCertificates(context.Background()) }
	read()
	if trust() != "verified" {
		t.Fatal("a desktop showing its pin is not ready")
	}
	bob.expect("GET", "/remote/rdp/"+account.ID, "", 200)
	reads.set(endpoint, windowsLeaf(t, nil))
	read()
	if trust() != "stopped" {
		t.Fatal("a desktop showing another certificate is not stopped")
	}
	reads.set(endpoint, pin)
	read()
	if trust() != "verified" {
		t.Fatal("a desktop showing its pin again is not ready")
	}
	f.now = f.now.Add(11 * time.Minute)
	if trust() != "unavailable" {
		t.Fatal("a desktop past its pin is not unavailable")
	}
	bob.expect("GET", "/remote/rdp/"+account.ID, "", 404)
	bob.expect("POST", "/api/remote/open", inputJSON(map[string]string{"account": account.ID}), 401)
}

// accountSSHWorker opens an echo terminal and remembers what it was given.
// With refuse set it fails instead, as the SSH worker does.
type accountSSHWorker struct {
	mu       sync.Mutex
	username string
	key      string
	refuse   error
}

func (w *accountSSHWorker) OpenSSH(ctx context.Context, _ *targetguard.NamedTarget, _ []byte, username string, c sshkey.Credential) (terminalweb.Stream, error) {
	w.mu.Lock()
	w.username = username
	if key, ok := c.(*sshkey.Key); ok {
		w.key = ssh.FingerprintSHA256(key.PublicKey())
	}
	refuse := w.refuse
	w.mu.Unlock()
	if refuse != nil {
		return nil, refuse
	}
	left, right := net.Pipe()
	go func() { defer right.Close(); _, _ = io.Copy(right, right) }()
	context.AfterFunc(ctx, func() { _ = left.Close() })
	return fixtureRemoteStream{left}, nil
}

func TestServerAccountKeyReachesTheWorkerAndIsMarkedUsed(t *testing.T) {
	store, _, _ := bootstrapped(t)
	_, _, codes := enrollFixture(t, store, "alice", time.Now())
	_, hostKey, _ := ed25519.GenerateKey(rand.Reader)
	hostSigner, _ := ssh.NewSignerFromKey(hostKey)
	ip := netip.MustParseAddr("10.34.0.9")
	policy, e := targetguard.New([]netip.AddrPort{netip.AddrPortFrom(ip, 22)}, nil)
	if e != nil {
		t.Fatal(e)
	}
	named, e := targetguard.NewNamedTarget(policy, "ssh.invalid", 22, []netip.Addr{ip})
	if e != nil {
		t.Fatal(e)
	}
	target := RemoteTarget{strings.Repeat("c", 32), "Synthetic SSH", "ssh", named, hostSigner.PublicKey().Marshal()}
	worker := &accountSSHWorker{}
	server := httptest.NewUnstartedServer(nil)
	origin := "https://" + server.Listener.Addr().String()
	l, e := NewRemoteLab(origin, store, []RemoteTarget{target}, worker, nil)
	if e != nil {
		t.Fatal("remote constructor refused")
	}
	defer l.Close()
	server.Config.Handler = l
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	server.StartTLS()
	defer server.Close()
	c := &custodyClient{t: t, l: l}
	c.login()
	c.session("challenge")
	c.expect("POST", "/api/mfa/verify", inputJSON(map[string]string{"code": codes[0]}), 204)
	c.session("ready")
	c.expect("POST", "/api/reauth", inputJSON(map[string]string{"code": codes[1]}), 204)
	var made struct{ ID string }
	if json.Unmarshal(c.expect("POST", accountPath(target.ID), accountSet("ssh-key", "deploy", "", mustLookup(t, store, "alice").ID), 200).Body.Bytes(), &made) != nil {
		t.Fatal("account missing")
	}
	first, e := store.readServerAccount(target.ID, made.ID)
	if e != nil {
		t.Fatal("account unreadable")
	}
	used := func() bool {
		t.Helper()
		list, _ := accountsOf(t, c, target.ID)
		if len(list) != 1 {
			t.Fatal("account missing from the view")
		}
		return list[0].Used
	}
	if used() {
		t.Fatal("a new key was marked used")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	open := func() *websocket.Conn {
		t.Helper()
		var lease struct{ Lease string }
		if json.Unmarshal(c.expect("POST", "/api/remote/open", inputJSON(map[string]string{"account": made.ID}), 200).Body.Bytes(), &lease) != nil {
			t.Fatal("lease missing")
		}
		header := http.Header{"Origin": []string{origin}, "Cookie": []string{c.cookie.String()}}
		socket, _, e := websocket.Dial(ctx, strings.Replace(origin, "https:", "wss:", 1)+"/api/remote/socket", &websocket.DialOptions{HTTPClient: server.Client(), HTTPHeader: header})
		if e != nil {
			t.Fatal("valid socket refused")
		}
		if socket.Write(ctx, websocket.MessageText, []byte(inputJSON(map[string]string{"csrf": c.csrf, "lease": lease.Lease}))) != nil {
			t.Fatal("proof write failed")
		}
		return socket
	}
	// The server refusing the key reaches the page as its one word, and the
	// key is not marked used; any other failure says nothing.
	for _, refuse := range []error{terminalweb.ReasonKey, terminalweb.ReasonCredentials, terminalweb.ReasonRefused, errors.New("synthetic worker failure")} {
		worker.mu.Lock()
		worker.refuse = refuse
		worker.mu.Unlock()
		socket := open()
		_, data, e := socket.Read(ctx)
		word, said := refuse.(terminalweb.Reason)
		said = said && (word == terminalweb.ReasonKey || word == terminalweb.ReasonCredentials)
		if said && (e != nil || string(data) != `{"type":"ended","reason":"`+string(word)+`"}`) {
			t.Fatalf("%v: the page was not told why: %q", refuse, data)
		}
		if !said && e == nil {
			t.Fatalf("%v: the page was told %q", refuse, data)
		}
		if said {
			if _, _, e := socket.Read(ctx); e == nil {
				t.Fatal("the socket stayed open after a refusal")
			}
		}
		_ = socket.CloseNow()
		if used() {
			t.Fatal("a refused key was marked used")
		}
	}
	worker.mu.Lock()
	worker.refuse = nil
	worker.mu.Unlock()
	socket := open()
	defer socket.CloseNow()
	if _, data, e := socket.Read(ctx); e != nil || string(data) != `{"type":"ready"}` {
		t.Fatal("the terminal did not open")
	}
	worker.mu.Lock()
	username, key := worker.username, worker.key
	worker.mu.Unlock()
	if username != "deploy" || key != first.Current.Fingerprint {
		t.Fatal("the worker did not get the account's key")
	}
	if !used() {
		t.Fatal("an opened terminal did not mark the key used")
	}
	after, _ := store.readServerAccount(target.ID, made.ID)
	if after.Generation != first.Generation || after.Current.Secret != first.Current.Secret {
		t.Fatal("the used mark changed the key")
	}
}
