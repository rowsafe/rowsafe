package handoff

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

func TestSealOpen(t *testing.T) {
	primary, _ := Generate()
	standby, _ := Generate()
	other, _ := Generate()
	secret := []byte(`{"cipher_pass":"correct horse battery staple"}`)

	box, err := Seal(primary, standby.PublicKey(), "standby", "standby:db_1:sby_1", secret)
	if err != nil {
		t.Fatal(err)
	}
	if box.SenderKey != primary.PublicKey() || box.RecipientKey != standby.PublicKey() {
		t.Fatalf("keys not recorded: %+v", box)
	}
	for _, s := range []string{box.Ciphertext, box.Nonce} {
		raw, _ := base64.StdEncoding.DecodeString(s)
		if len(raw) == 0 {
			t.Fatal("empty field")
		}
	}
	got, err := Open(standby, box, "standby", "standby:db_1:sby_1", primary.PublicKey())
	if err != nil || string(got) != string(secret) {
		t.Fatalf("open: %q %v", got, err)
	}
	// Without a sender check it still opens.
	if _, err := Open(standby, box, "standby", "standby:db_1:sby_1", ""); err != nil {
		t.Fatal(err)
	}

	// Wrong recipient, context, purpose, sender, or a changed ciphertext.
	if _, err := Open(other, box, "standby", "standby:db_1:sby_1", ""); err == nil {
		t.Fatal("another agent opened it")
	}
	if _, err := Open(standby, box, "standby", "standby:db_1:sby_2", ""); err == nil {
		t.Fatal("opened for another standby")
	}
	if _, err := Open(standby, box, "proof", "standby:db_1:sby_1", ""); err == nil {
		t.Fatal("opened for another purpose")
	}
	if _, err := Open(standby, box, "standby", "standby:db_1:sby_1", other.PublicKey()); err == nil {
		t.Fatal("accepted from the wrong sender")
	}
	tampered := box
	raw, _ := base64.StdEncoding.DecodeString(box.Ciphertext)
	raw[0] ^= 1
	tampered.Ciphertext = base64.StdEncoding.EncodeToString(raw)
	if _, err := Open(standby, tampered, "standby", "standby:db_1:sby_1", ""); err == nil {
		t.Fatal("tampered box opened")
	}
	// A context swapped in the box (the AAD) doesn't open either.
	swapped := box
	swapped.Context = "standby:db_1:sby_2"
	if _, err := Open(standby, swapped, "standby", "standby:db_1:sby_2", ""); err == nil {
		t.Fatal("box with a rewritten context opened")
	}
	// A box claiming another sender (the control plane swapping the sender
	// key) fails: the static DH differs.
	forged := box
	forged.SenderKey = other.PublicKey()
	if _, err := Open(standby, forged, "standby", "standby:db_1:sby_1", other.PublicKey()); err == nil {
		t.Fatal("box with a substituted sender opened")
	}
	if _, err := Seal(primary, primary.PublicKey(), "standby", "x", secret); err == nil {
		t.Fatal("sealed to itself")
	}
	if _, err := Seal(primary, "not a key", "standby", "x", secret); err == nil {
		t.Fatal("sealed to garbage")
	}
}

func TestFingerprint(t *testing.T) {
	k, _ := Generate()
	fp, err := Fingerprint(k.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}$`).MatchString(fp) {
		t.Fatalf("fingerprint %q", fp)
	}
	if !SameFingerprint(fp, "  "+toLowerNoDash(fp)) || SameFingerprint(fp, "") || SameFingerprint(fp[:9], fp[:9]) {
		t.Fatal("SameFingerprint")
	}
	k2, _ := Generate()
	fp2, _ := Fingerprint(k2.PublicKey())
	if SameFingerprint(fp, fp2) {
		t.Fatal("two keys, one fingerprint")
	}
}

func toLowerNoDash(s string) string {
	out := []byte{}
	for _, c := range []byte(s) {
		if c == '-' {
			continue
		}
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		out = append(out, c)
	}
	return string(out)
}

func TestLoadOrCreate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "box.key")
	a, err := LoadOrCreate(path)
	if err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", info.Mode())
	}
	b, err := LoadOrCreate(path)
	if err != nil || b.PublicKey() != a.PublicKey() {
		t.Fatalf("reload: %v", err)
	}
	os.Chmod(path, 0o644)
	if _, err := LoadOrCreate(path); err == nil {
		t.Fatal("accepted a world-readable key")
	}
	os.WriteFile(filepath.Join(dir, "bad.key"), []byte("nope\n"), 0o600)
	if _, err := LoadOrCreate(filepath.Join(dir, "bad.key")); err == nil {
		t.Fatal("accepted garbage")
	}
}
