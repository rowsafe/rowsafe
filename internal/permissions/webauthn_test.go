package permissions

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

const (
	testRP     = "app.rowsafe.sh"
	testOrigin = "https://app.rowsafe.sh"
	testHost   = "host_01"
)

func init() { trustedUID = os.Getuid() }

func randBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

func TestVerifyRegistration(t *testing.T) {
	for _, alg := range []int{AlgES256, AlgEdDSA, AlgRS256} {
		k := newTestKey(t, alg)
		ch := randBytes(32)
		att, cdj := k.register(testRP, testOrigin, ch)
		c, err := VerifyRegistration(att, cdj, ch, testRP, testOrigin)
		if err != nil {
			t.Fatalf("alg %d: %v", alg, err)
		}
		if !bytes.Equal(c.ID, k.credID) || !bytes.Equal(c.PublicKey, k.cose) || c.Alg != alg {
			t.Fatalf("alg %d: credential %+v", alg, c)
		}
		if c.Fingerprint() != protocol.PermissionFingerprint(k.credID, k.cose) {
			t.Fatal("fingerprint")
		}
	}
}

func TestVerifyRegistrationRefusals(t *testing.T) {
	k := newTestKey(t, AlgES256)
	ch := randBytes(32)
	good := func() (att, cdj []byte) { return k.register(testRP, testOrigin, ch) }
	withAuthData := func(ad []byte) []byte {
		return cborEnc(cmap{{"fmt", "none"}, {"attStmt", cmap{}}, {"authData", ad}})
	}
	cases := map[string]func() (att, cdj []byte, ch []byte, rp, origin string){
		"wrong type": func() ([]byte, []byte, []byte, string, string) {
			att, _ := good()
			return att, clientDataJSON("webauthn.get", ch, testOrigin, nil), ch, testRP, testOrigin
		},
		"wrong challenge": func() ([]byte, []byte, []byte, string, string) {
			att, cdj := good()
			return att, cdj, randBytes(32), testRP, testOrigin
		},
		"wrong origin": func() ([]byte, []byte, []byte, string, string) {
			att, _ := good()
			return att, clientDataJSON("webauthn.create", ch, "https://evil.example", nil), ch, testRP, testOrigin
		},
		"cross origin": func() ([]byte, []byte, []byte, string, string) {
			att, _ := good()
			return att, clientDataJSON("webauthn.create", ch, testOrigin, map[string]any{"crossOrigin": true}), ch, testRP, testOrigin
		},
		"top origin": func() ([]byte, []byte, []byte, string, string) {
			att, _ := good()
			return att, clientDataJSON("webauthn.create", ch, testOrigin, map[string]any{"topOrigin": "https://evil.example"}), ch, testRP, testOrigin
		},
		"wrong rp": func() ([]byte, []byte, []byte, string, string) {
			att, cdj := good()
			return att, cdj, ch, "rowsafe.sh", testOrigin
		},
		"no UV": func() ([]byte, []byte, []byte, string, string) {
			_, cdj := good()
			return withAuthData(authData(testRP, FlagUP|FlagAT, 0, k.attested())), cdj, ch, testRP, testOrigin
		},
		"no UP": func() ([]byte, []byte, []byte, string, string) {
			_, cdj := good()
			return withAuthData(authData(testRP, FlagUV|FlagAT, 0, k.attested())), cdj, ch, testRP, testOrigin
		},
		"no credential": func() ([]byte, []byte, []byte, string, string) {
			_, cdj := good()
			return withAuthData(authData(testRP, FlagUP|FlagUV, 0, nil)), cdj, ch, testRP, testOrigin
		},
		"trailing bytes": func() ([]byte, []byte, []byte, string, string) {
			_, cdj := good()
			return withAuthData(append(authData(testRP, FlagUP|FlagUV|FlagAT, 0, k.attested()), 0)), cdj, ch, testRP, testOrigin
		},
		"unsupported alg": func() ([]byte, []byte, []byte, string, string) {
			_, cdj := good()
			bad := *k
			bad.cose = cborEnc(cmap{{1, 2}, {3, -35}, {-1, 2}, {-2, randBytes(48)}, {-3, randBytes(48)}})
			return withAuthData(authData(testRP, FlagUP|FlagUV|FlagAT, 0, bad.attested())), cdj, ch, testRP, testOrigin
		},
		"point not on curve": func() ([]byte, []byte, []byte, string, string) {
			_, cdj := good()
			bad := *k
			bad.cose = cborEnc(cmap{{1, 2}, {3, AlgES256}, {-1, 1}, {-2, randBytes(32)}, {-3, randBytes(32)}})
			return withAuthData(authData(testRP, FlagUP|FlagUV|FlagAT, 0, bad.attested())), cdj, ch, testRP, testOrigin
		},
		"not CBOR": func() ([]byte, []byte, []byte, string, string) {
			_, cdj := good()
			return []byte{0xbf, 0xff}, cdj, ch, testRP, testOrigin
		},
		"short challenge": func() ([]byte, []byte, []byte, string, string) {
			att, _ := k.register(testRP, testOrigin, ch[:8])
			return att, clientDataJSON("webauthn.create", ch[:8], testOrigin, nil), ch[:8], testRP, testOrigin
		},
	}
	for name, f := range cases {
		att, cdj, ch, rp, origin := f()
		if _, err := VerifyRegistration(att, cdj, ch, rp, origin); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// signer makes signed permission changes like the dashboard.
type signer struct {
	t      *testing.T
	key    *testKey
	rp     string
	origin string
	flags  byte
	cdj    func(challenge []byte) []byte
}

func newChange(now time.Time) protocol.PermissionChange {
	return protocol.PermissionChange{
		Kind: protocol.PermissionChangeKind, HostID: testHost, HostName: "db-1",
		Allow: []string{protocol.PermSecurityUpdates}, Remove: []string{protocol.PermReboot},
		Nonce: base64.RawURLEncoding.EncodeToString(randBytes(16)), IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute),
		RequestedBy: "ana@example.com",
	}
}

func (s *signer) signBytes(change []byte) protocol.SignedPermissionChange {
	ch := protocol.PermissionChallenge(change)
	cdj := clientDataJSON("webauthn.get", ch, s.origin, nil)
	if s.cdj != nil {
		cdj = s.cdj(ch)
	}
	flags := s.flags
	if flags == 0 {
		flags = FlagUP | FlagUV | FlagBE | FlagBS
	}
	ad := authData(s.rp, flags, 0, nil)
	h := sha256Sum(cdj)
	sig := s.key.sign(s.t, append(append([]byte{}, ad...), h...))
	return protocol.SignedPermissionChange{ChangeJSON: change, CredentialID: s.key.credID, AuthenticatorData: ad, ClientDataJSON: cdj, Signature: sig}
}

func (s *signer) sign(c protocol.PermissionChange) protocol.SignedPermissionChange {
	b, err := json.Marshal(c)
	if err != nil {
		s.t.Fatal(err)
	}
	return s.signBytes(b)
}

type memNonces map[string]bool

func (m memNonces) Use(n string, _, _ time.Time) error {
	if m[n] {
		return refuse("this request was applied before; ask again from the dashboard")
	}
	m[n] = true
	return nil
}

func ownerFor(t *testing.T, k *testKey) Owner {
	c := &Credential{ID: k.credID, PublicKey: k.cose, Alg: k.alg}
	return NewOwner(c, "ana@example.com", testRP, testOrigin, testHost, time.Now())
}

func TestVerifyAssertion(t *testing.T) {
	now := time.Now()
	for _, alg := range []int{AlgES256, AlgEdDSA, AlgRS256} {
		k := newTestKey(t, alg)
		other := newTestKey(t, AlgES256)
		owners := []Owner{ownerFor(t, other), ownerFor(t, k)}
		s := &signer{t: t, key: k, rp: testRP, origin: testOrigin}
		c := newChange(now)
		signed := s.sign(c)
		got, owner, err := VerifyAssertion(signed, owners, testHost, now, memNonces{})
		if err != nil {
			t.Fatalf("alg %d: %v", alg, err)
		}
		if owner.Fingerprint != owners[1].Fingerprint || got.Nonce != c.Nonce || got.Allow[0] != protocol.PermSecurityUpdates {
			t.Fatalf("alg %d: %+v %+v", alg, got, owner)
		}
	}
}

func TestVerifyAssertionRefusals(t *testing.T) {
	now := time.Now()
	k := newTestKey(t, AlgES256)
	owners := []Owner{ownerFor(t, k)}
	good := func() *signer { return &signer{t: t, key: k, rp: testRP, origin: testOrigin} }
	type tc struct {
		signed protocol.SignedPermissionChange
		owners []Owner
		host   string
		want   string
	}
	cases := map[string]func() tc{
		"wrong origin": func() tc {
			s := good()
			s.origin = "https://evil.example"
			return tc{signed: s.sign(newChange(now)), want: "used on"}
		},
		"wrong rp": func() tc {
			s := good()
			s.rp = "evil.example"
			return tc{signed: s.sign(newChange(now)), want: "not one for"}
		},
		"wrong challenge": func() tc {
			s := good()
			s.cdj = func([]byte) []byte { return clientDataJSON("webauthn.get", randBytes(32), testOrigin, nil) }
			return tc{signed: s.sign(newChange(now)), want: "different request"}
		},
		"create, not get": func() tc {
			s := good()
			s.cdj = func(ch []byte) []byte { return clientDataJSON("webauthn.create", ch, testOrigin, nil) }
			return tc{signed: s.sign(newChange(now)), want: "webauthn.create"}
		},
		"cross origin": func() tc {
			s := good()
			s.cdj = func(ch []byte) []byte {
				return clientDataJSON("webauthn.get", ch, testOrigin, map[string]any{"crossOrigin": true})
			}
			return tc{signed: s.sign(newChange(now)), want: "frame"}
		},
		"no UV": func() tc {
			s := good()
			s.flags = FlagUP
			return tc{signed: s.sign(newChange(now)), want: "without verifying"}
		},
		"no UP": func() tc {
			s := good()
			s.flags = FlagUV
			return tc{signed: s.sign(newChange(now)), want: "without a person"}
		},
		"bad signature": func() tc {
			signed := good().sign(newChange(now))
			signed.Signature = good().sign(newChange(now)).Signature
			return tc{signed: signed, want: "signature doesn't match"}
		},
		"tampered change bytes": func() tc {
			signed := good().sign(newChange(now))
			signed.ChangeJSON = bytes.Replace(signed.ChangeJSON, []byte("security-updates"), []byte("reboot"), 1)
			return tc{signed: signed, want: "different request"}
		},
		"tampered authenticator data": func() tc {
			signed := good().sign(newChange(now))
			signed.AuthenticatorData[36] ^= 1 // the signature counter
			return tc{signed: signed, want: "signature doesn't match"}
		},
		"expired": func() tc {
			c := newChange(now.Add(-20 * time.Minute))
			return tc{signed: good().sign(c), want: "expired"}
		},
		"lifetime too long": func() tc {
			c := newChange(now)
			c.ExpiresAt = now.Add(time.Hour)
			return tc{signed: good().sign(c), want: "lifetime"}
		},
		"wrong host": func() tc {
			c := newChange(now)
			c.HostID = "host_02"
			return tc{signed: good().sign(c), want: "another server"}
		},
		"owner paired on another host ID": func() tc {
			o := ownerFor(t, k)
			o.HostID = "host_02"
			return tc{signed: good().sign(newChange(now)), owners: []Owner{o}, want: "another Rowsafe server ID"}
		},
		"unknown credential": func() tc {
			s := good()
			s.key = newTestKey(t, AlgES256)
			return tc{signed: s.sign(newChange(now)), want: "isn't one root paired"}
		},
		"owner key swapped in the file": func() tc {
			o := ownerFor(t, k)
			o.PublicKey = base64.RawURLEncoding.EncodeToString(newTestKey(t, AlgES256).cose)
			return tc{signed: good().sign(newChange(now)), owners: []Owner{o}, want: "fingerprint doesn't match"}
		},
		"unknown permission": func() tc {
			c := newChange(now)
			c.Allow = []string{"root-shell"}
			return tc{signed: good().sign(c), want: "unknown permission"}
		},
		"unknown field": func() tc {
			b, _ := json.Marshal(newChange(now))
			b = append(b[:len(b)-1], []byte(`,"also":"x"}`)...)
			return tc{signed: good().signBytes(b), want: "understands"}
		},
		"repeated field": func() tc {
			b, _ := json.Marshal(newChange(now))
			b = append(b[:len(b)-1], []byte(`,"allow":["restart"]}`)...)
			return tc{signed: good().signBytes(b), want: "twice"}
		},
		"trailing data": func() tc {
			b, _ := json.Marshal(newChange(now))
			b = append(b, []byte(` {}`)...)
			return tc{signed: good().signBytes(b), want: "after the change"}
		},
		"another kind": func() tc {
			c := newChange(now)
			c.Kind = "rowsafe.login/v1"
			return tc{signed: good().sign(c), want: "not a permission change"}
		},
		"no host ID known": func() tc {
			return tc{signed: good().sign(newChange(now)), host: "-", want: "Rowsafe ID is unknown"}
		},
	}
	for name, f := range cases {
		c := f()
		if c.owners == nil {
			c.owners = owners
		}
		host := testHost
		if c.host == "-" {
			host = ""
		}
		_, _, err := VerifyAssertion(c.signed, c.owners, host, now, memNonces{})
		var r *Refusal
		if err == nil || !errors.As(err, &r) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want a refusal with %q", name, err, c.want)
		}
	}
}

func TestReplayRefused(t *testing.T) {
	now := time.Now()
	k := newTestKey(t, AlgEdDSA)
	owners := []Owner{ownerFor(t, k)}
	dir := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	store := FileNonceStore{Dir: dir}
	signed := (&signer{t: t, key: k, rp: testRP, origin: testOrigin}).sign(newChange(now))
	if _, _, err := VerifyAssertion(signed, owners, testHost, now, store); err != nil {
		t.Fatal(err)
	}
	_, _, err := VerifyAssertion(signed, owners, testHost, now.Add(time.Minute), store)
	if err == nil || !strings.Contains(err.Error(), "applied before") {
		t.Fatalf("replay: %v", err)
	}
	// A bad signature never uses up a nonce.
	c := newChange(now)
	bad := (&signer{t: t, key: k, rp: testRP, origin: testOrigin}).sign(c)
	bad.Signature[len(bad.Signature)-1] ^= 1
	if _, _, err := VerifyAssertion(bad, owners, testHost, now, store); err == nil {
		t.Fatal("bad signature accepted")
	}
	if _, _, err := VerifyAssertion((&signer{t: t, key: k, rp: testRP, origin: testOrigin}).sign(c), owners, testHost, now, store); err != nil {
		t.Fatalf("the nonce was used up by a refused request: %v", err)
	}
	// Expired nonces are forgotten.
	later := now.Add(30 * time.Minute)
	if err := store.Use("fresh", later.Add(time.Minute), later); err != nil {
		t.Fatal(err)
	}
	var used map[string]time.Time
	data, _ := os.ReadFile(filepath.Join(dir, "used-nonces.json"))
	_ = json.Unmarshal(data, &used)
	if len(used) != 1 {
		t.Fatalf("expired nonces kept: %v", used)
	}
	// A state folder others can read is refused.
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := store.Use("x", later, now); err == nil {
		t.Fatal("open state folder accepted")
	}
}

func TestCBORStrict(t *testing.T) {
	bad := map[string][]byte{
		"indefinite map":   {0xbf, 0x01, 0x02, 0xff},
		"indefinite bytes": {0x5f, 0x41, 0x00, 0xff},
		"tag":              {0xc0, 0x60},
		"float":            {0xf9, 0x00, 0x14},
		"undefined":        {0xf7},
		"duplicate key":    {0xa2, 0x01, 0x01, 0x01, 0x02},
		"truncated bytes":  {0x58, 0x10, 0x00},
		"huge array":       {0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		"huge int":         {0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		"map key is bytes": {0xa1, 0x41, 0x00, 0x01},
		"trailing":         {0x01, 0x01},
		"empty":            {},
	}
	deep := bytes.Repeat([]byte{0x81}, 20)
	bad["too deep"] = append(deep, 0x01)
	for name, b := range bad {
		if _, err := cborDecode(b); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	v, err := cborDecode(cborEnc(cmap{{"a", []any{1, -2, true, nil, []byte{1}}}, {-1, "x"}}))
	if err != nil {
		t.Fatal(err)
	}
	m := v.(map[any]any)
	if m[int64(-1)] != "x" || len(m["a"].([]any)) != 5 {
		t.Fatalf("%#v", v)
	}
}

func TestOwnersFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "owners")
	if owners, err := ReadOwners(path, true); err != nil || owners != nil {
		t.Fatalf("missing file: %v %v", owners, err)
	}
	k := newTestKey(t, AlgES256)
	o := ownerFor(t, k)
	if err := WriteOwners(path, []Owner{o}); err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(path)
	if st.Mode().Perm() != 0o644 {
		t.Fatalf("mode %v", st.Mode())
	}
	got, err := ReadOwners(path, true)
	if err != nil || len(got) != 1 || got[0].Fingerprint != o.Fingerprint || got[0].RPID != testRP {
		t.Fatalf("%v %v", got, err)
	}
	var raw []map[string]any
	data, _ := os.ReadFile(path)
	_ = json.Unmarshal(data, &raw)
	for _, f := range []string{"credential_id", "public_key", "alg", "name", "fingerprint", "rp_id", "origin", "added_at"} {
		if _, ok := raw[0][f]; !ok {
			t.Errorf("owners file has no %q", f)
		}
	}
	if FindOwner(got, strings.ToLower(strings.ReplaceAll(o.Fingerprint, "-", ""))) != 0 || FindOwner(got, "0000-0000-0000-0000") != -1 {
		t.Fatal("FindOwner")
	}
	// Writable by others: refused.
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadOwners(path, true); err == nil {
		t.Fatal("group-writable owners file accepted")
	}
	// A symbolic link: refused.
	_ = os.Chmod(path, 0o644)
	link := filepath.Join(dir, "link")
	_ = os.Symlink(path, link)
	if _, err := ReadOwners(link, true); err == nil {
		t.Fatal("symlinked owners file accepted")
	}
}

func sha256Sum(b []byte) []byte {
	h := sha256.New()
	h.Write(b)
	return h.Sum(nil)
}
