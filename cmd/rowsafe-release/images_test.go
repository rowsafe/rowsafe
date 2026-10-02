package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rowsafe/rowsafe/release"
)

func TestImagesSignVerify(t *testing.T) {
	dir := t.TempDir()
	digests := filepath.Join(dir, "digests")
	_ = os.Mkdir(digests, 0o755)
	for v, c := range map[string]string{"pg17": "a", "pg17-alpine": "b"} {
		_ = os.WriteFile(filepath.Join(digests, v), []byte("sha256:"+strings.Repeat(c, 64)+"\n"), 0o644)
	}
	var out bytes.Buffer
	if err := imagesCmd([]string{"--version", "v1.2.3", "--digests", digests}, &out); err != nil {
		t.Fatal(err)
	}
	doc := filepath.Join(dir, "images.json")
	_ = os.WriteFile(doc, out.Bytes(), 0o644)
	pub, priv, _ := release.GenerateKey()
	env := func(string) string { return priv }
	if err := signImagesCmd([]string{doc}, env, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	var v bytes.Buffer
	if err := verifyImagesCmd([]string{"--public-key", pub, doc, doc + ".sig"}, &v); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(v.String(), "release 1.2.3") || !strings.Contains(v.String(), "pg17-alpine") {
		t.Fatalf("verify printed %q", v.String())
	}
	// A release manifest isn't signed as an images document, nor the reverse.
	if err := signCmd([]string{doc}, env, &bytes.Buffer{}); err == nil {
		t.Fatal("sign accepted an images document")
	}
	_ = os.WriteFile(filepath.Join(digests, "latest"), []byte("sha256:"+strings.Repeat("c", 64)), 0o644)
	if err := imagesCmd([]string{"--version", "1.2.3", "--digests", digests}, &out); err == nil {
		t.Fatal("a non-variant file was accepted")
	}
}
