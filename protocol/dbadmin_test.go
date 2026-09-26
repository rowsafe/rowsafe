package protocol

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"flag"
	"os"
	"strings"
	"testing"
)

func TestSealOpen(t *testing.T) {
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := EncodeSealKey(priv.PublicKey())
	msg := []byte(`{"password":"s3cret"}`)
	s, err := Seal(pub, []byte("task_1"), msg)
	if err != nil {
		t.Fatal(err)
	}
	if s.Version != 1 || s.Alg != SealAlg || strings.Contains(s.Ciphertext, "s3cret") {
		t.Fatalf("sealed: %+v", s)
	}
	got, err := Open(priv, []byte("task_1"), s)
	if err != nil || string(got) != string(msg) {
		t.Fatalf("Open = %q, %v", got, err)
	}
	// Another task's ID, another key, or a changed byte: refused.
	if _, err := Open(priv, []byte("task_2"), s); err == nil {
		t.Error("opened with another task's ID")
	}
	other, _ := ecdh.P256().GenerateKey(rand.Reader)
	if _, err := Open(other, []byte("task_1"), s); err == nil {
		t.Error("opened with another key")
	}
	bad := *s
	ct := []byte(bad.Ciphertext)
	if ct[3] == 'A' {
		ct[3] = 'B'
	} else {
		ct[3] = 'A'
	}
	bad.Ciphertext = string(ct)
	if _, err := Open(priv, []byte("task_1"), &bad); err == nil {
		t.Error("opened a changed ciphertext")
	}
	// Each seal uses a fresh key and nonce.
	s2, _ := Seal(pub, []byte("task_1"), msg)
	if s2.EPK == s.EPK || s2.Nonce == s.Nonce || s2.Ciphertext == s.Ciphertext {
		t.Error("seal is not randomized")
	}
}

func TestParseSealKey(t *testing.T) {
	priv, _ := ecdh.P256().GenerateKey(rand.Reader)
	enc := EncodeSealKey(priv.PublicKey())
	if len(enc) != 87 {
		t.Errorf("encoded key length %d", len(enc))
	}
	for _, s := range []string{enc, enc + "="} {
		if _, err := ParseSealKey(s); err != nil {
			t.Errorf("ParseSealKey(%q): %v", s, err)
		}
	}
	x25519, _ := ecdh.X25519().GenerateKey(rand.Reader)
	for _, s := range []string{"", "abc", b64.EncodeToString(x25519.PublicKey().Bytes()),
		b64.EncodeToString(append([]byte{4}, make([]byte, 64)...))} { // not on the curve
		if _, err := ParseSealKey(s); err == nil {
			t.Errorf("ParseSealKey(%q) accepted", s)
		}
	}
}

// sealVector is shared with the dashboard's WebCrypto implementation
// (web/src/lib/dbadmin/seal.ts in the platform repository): each side opens
// what the other sealed, with the same fixed recipient key.
type sealVector struct {
	// RecipientD is the recipient's private scalar (base64url, 32 bytes);
	// RecipientPublic its public key as the browser sends it.
	RecipientD      string        `json:"recipient_d"`
	RecipientPublic string        `json:"recipient_public"`
	AAD             string        `json:"aad"`
	Plaintext       string        `json:"plaintext"`
	SealedByGo      *SealedSecret `json:"sealed_by_go"`
	SealedByWeb     *SealedSecret `json:"sealed_by_webcrypto"`
}

var updateVector = flag.Bool("update-seal-vector", false, "rewrite sealed_by_go in testdata/dbadmin-seal-vector.json")

const sealVectorPath = "testdata/dbadmin-seal-vector.json"

// TestSealVector opens the WebCrypto-sealed secret with Go, and the
// Go-sealed one with the recipient key (the dashboard's test opens it with
// WebCrypto).
func TestSealVector(t *testing.T) {
	data, err := os.ReadFile(sealVectorPath)
	if err != nil {
		t.Fatal(err)
	}
	var v sealVector
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	d, err := b64.DecodeString(v.RecipientD)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := ecdh.P256().NewPrivateKey(d)
	if err != nil {
		t.Fatal(err)
	}
	if EncodeSealKey(priv.PublicKey()) != v.RecipientPublic {
		t.Fatal("recipient_public doesn't match recipient_d")
	}
	if *updateVector {
		if v.SealedByGo, err = Seal(v.RecipientPublic, []byte(v.AAD), []byte(v.Plaintext)); err != nil {
			t.Fatal(err)
		}
		out, _ := json.MarshalIndent(v, "", "  ")
		if err := os.WriteFile(sealVectorPath, append(out, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for name, s := range map[string]*SealedSecret{"go": v.SealedByGo, "webcrypto": v.SealedByWeb} {
		got, err := Open(priv, []byte(v.AAD), s)
		if err != nil {
			t.Errorf("open sealed by %s: %v", name, err)
			continue
		}
		if string(got) != v.Plaintext {
			t.Errorf("sealed by %s: %q", name, got)
		}
	}
}

func TestValidNewName(t *testing.T) {
	for _, ok := range []string{"shop", "app_2", "a", strings.Repeat("a", 63)} {
		if err := ValidNewName("database", ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "Shop", "2shop", "_x", "my-app", "a b", "pg_stuff", "rowsafe", "rowsafe_x",
		"postgres", "template1", "public", "user", strings.Repeat("a", 64), "shop;drop", `x"y`} {
		if err := ValidNewName("database", bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestValidateDBAdmin(t *testing.T) {
	priv, _ := ecdh.P256().GenerateKey(rand.Reader)
	key := EncodeSealKey(priv.PublicKey())
	good := []DBAdminParams{
		{Action: DBAdminList},
		{Action: DBAdminCreateDatabase, Database: "shop", CreateOwner: true, PublicKey: key, Extensions: []string{"pg_trgm", "uuid-ossp"}},
		{Action: DBAdminCreateDatabase, Database: "shop", Owner: "Existing Owner", Template: "template0", Locale: "en_US.UTF-8"},
		{Action: DBAdminCreateUser, User: "reporting", Access: DBAccessReadOnly, Databases: []string{"shop", "Legacy"}, PublicKey: key},
		{Action: DBAdminResetPassword, User: "Legacy User", PublicKey: key},
		{Action: DBAdminDropUser, User: "old", ReassignTo: "shop"},
		{Action: DBAdminEnableExtension, Database: "shop", Extension: "postgis"},
		{Action: DBAdminDisableExtension, Database: "shop", Extension: "postgis"},
		{Action: DBAdminDropDatabase, Database: "shop", Confirm: "shop"},
		{Action: DBAdminCreateUser, User: "x", Access: DBAccessOwner, Databases: []string{"shop"}, PublicKey: key, Host: "10.0.0.5"},
	}
	for _, p := range good {
		if err := ValidateDBAdmin(p); err != nil {
			t.Errorf("%+v: %v", p, err)
		}
	}
	bad := map[string]DBAdminParams{
		"unknown action":         {Action: "sql"},
		"no key":                 {Action: DBAdminCreateDatabase, Database: "shop", CreateOwner: true},
		"bad key":                {Action: DBAdminResetPassword, User: "x", PublicKey: "nope"},
		"bad db name":            {Action: DBAdminCreateDatabase, Database: "Shop", CreateOwner: true, PublicKey: key},
		"bad owner name":         {Action: DBAdminCreateDatabase, Database: "shop", Owner: "Bad", CreateOwner: true, PublicKey: key},
		"no owner":               {Action: DBAdminCreateDatabase, Database: "shop"},
		"bad template":           {Action: DBAdminCreateDatabase, Database: "shop", Owner: "o", Template: "prod"},
		"bad locale":             {Action: DBAdminCreateDatabase, Database: "shop", Owner: "o", Locale: "en'; drop"},
		"untrusted at create":    {Action: DBAdminCreateDatabase, Database: "shop", Owner: "o", Extensions: []string{"plpython3u"}},
		"bad access":             {Action: DBAdminCreateUser, User: "x", Access: "admin", Databases: []string{"shop"}, PublicKey: key},
		"no databases":           {Action: DBAdminCreateUser, User: "x", Access: DBAccessReadOnly, PublicKey: key},
		"reassign to self":       {Action: DBAdminDropUser, User: "x", ReassignTo: "x"},
		"drop plpgsql":           {Action: DBAdminDisableExtension, Database: "shop", Extension: "plpgsql"},
		"bad extension":          {Action: DBAdminEnableExtension, Database: "shop", Extension: "x; drop"},
		"drop postgres":          {Action: DBAdminDropDatabase, Database: "postgres", Confirm: "postgres"},
		"drop without confirm":   {Action: DBAdminDropDatabase, Database: "shop"},
		"drop wrong confirm":     {Action: DBAdminDropDatabase, Database: "shop", Confirm: "shop2"},
		"bad host":               {Action: DBAdminList, Host: "a b"},
		"nul in existing name":   {Action: DBAdminResetPassword, User: "a\x00b", PublicKey: key},
		"too long existing name": {Action: DBAdminResetPassword, User: strings.Repeat("x", 64), PublicKey: key},
	}
	for name, p := range bad {
		if err := ValidateDBAdmin(p); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestDBExtensionUntrusted(t *testing.T) {
	for _, n := range []string{"plpython3u", "plperlu", "pltclu", "file_fdw", "adminpack"} {
		if !DBExtensionUntrusted(n) {
			t.Errorf("%s trusted", n)
		}
	}
	for _, n := range []string{"plpgsql", "plperl", "pg_trgm", "postgis", "uuid-ossp", "plv8"} {
		if DBExtensionUntrusted(n) {
			t.Errorf("%s untrusted", n)
		}
	}
}

func TestConnectionURL(t *testing.T) {
	c := DBConnection{User: "shop", Database: "shop", Host: "10.0.0.5", Port: 5432, SSLMode: "require"}
	if got := ConnectionURL(c, "abcXYZ123"); got != "postgresql://shop:abcXYZ123@10.0.0.5:5432/shop?sslmode=require" {
		t.Error(got)
	}
	c = DBConnection{User: "My User", Database: "a/b", Host: "::1", Port: 6432, SSLMode: "prefer"}
	if got := ConnectionURL(c, "p@ss:w/rd"); got != "postgresql://My%20User:p%40ss%3Aw%2Frd@[::1]:6432/a%2Fb?sslmode=prefer" {
		t.Error(got)
	}
}
