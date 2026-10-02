package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/rowsafe/rowsafe/release"
	"github.com/rowsafe/rowsafe/release/agentimages"
)

// The signed list of a release's Docker agent images (release/agentimages):
// written by the release workflow once the images are pushed and verified,
// and checked by rowsafe-docker-control before it updates an agent container.

func imagesCmd(args []string, w io.Writer) error {
	fs := flag.NewFlagSet("images", flag.ContinueOnError)
	version := fs.String("version", "", "release version, MAJOR.MINOR.PATCH")
	dir := fs.String("digests", "", "directory with one file per image variant holding its digest")
	if _, err := parseArgs(fs, args, 0); err != nil {
		return err
	}
	if *version == "" || *dir == "" {
		return errors.New("--version and --digests are required")
	}
	d, err := buildImages(*version, *dir)
	if err != nil {
		return err
	}
	out, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return err
	}
	_, err = w.Write(append(out, '\n'))
	return err
}

func buildImages(version, dir string) (agentimages.Document, error) {
	v, err := release.ParseVersion(version)
	if err != nil {
		return agentimages.Document{}, err
	}
	d := agentimages.Document{Kind: agentimages.Kind, Version: v.String(), Repository: agentimages.Repository, Images: map[string]string{}}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return d, err
	}
	for _, e := range entries {
		if e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		if !agentimages.ValidVariant(e.Name()) {
			return d, fmt.Errorf("%s: not an image variant (want pg17, pg17-alpine, clickhouse26.8...)", e.Name())
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return d, err
		}
		dg := strings.TrimSpace(string(data))
		if !agentimages.ValidDigest(dg) {
			return d, fmt.Errorf("%s: %q is not a digest (sha256:<64 hex>)", e.Name(), dg)
		}
		d.Images[e.Name()] = dg
	}
	return d, d.Validate()
}

func signImagesCmd(args []string, getenv func(string) string, log io.Writer) error {
	fs := flag.NewFlagSet("sign-images", flag.ContinueOnError)
	keyEnv := fs.String("key-env", "ROWSAFE_RELEASE_PRIVATE_KEY", "environment variable holding the base64 private key")
	pos, err := parseArgs(fs, args, 1)
	if err != nil {
		return err
	}
	keyB64 := getenv(*keyEnv)
	if keyB64 == "" {
		return fmt.Errorf("%s is not set", *keyEnv)
	}
	priv, err := release.ParsePrivateKey(keyB64)
	if err != nil {
		return err
	}
	doc, err := os.ReadFile(pos[0])
	if err != nil {
		return err
	}
	sig := release.Sign(priv, doc)
	pub := priv.Public().(ed25519.PublicKey)
	// Refuse to sign anything rowsafe-docker-control would reject.
	d, err := agentimages.Verify(pub, doc, sig)
	if err != nil {
		return fmt.Errorf("not signing an invalid images document: %w", err)
	}
	sigPath := pos[0] + ".sig"
	if err := os.WriteFile(sigPath, []byte(sig+"\n"), 0o644); err != nil {
		return err
	}
	fmt.Fprintf(log, "Signed the images of release %s (%d) -> %s\nPublic key: %s\n", d.Version, len(d.Images), sigPath,
		base64.StdEncoding.EncodeToString(pub))
	return nil
}

func verifyImagesCmd(args []string, w io.Writer) error {
	fs := flag.NewFlagSet("verify-images", flag.ContinueOnError)
	pubB64 := fs.String("public-key", "", "base64 Ed25519 public key")
	pos, err := parseArgs(fs, args, 2)
	if err != nil {
		return err
	}
	if *pubB64 == "" {
		return errors.New("--public-key is required")
	}
	pub, err := agentimages.ParsePublicKey(*pubB64)
	if err != nil {
		return err
	}
	doc, err := os.ReadFile(pos[0])
	if err != nil {
		return err
	}
	sig, err := os.ReadFile(pos[1])
	if err != nil {
		return err
	}
	d, err := agentimages.Verify(pub, doc, string(sig))
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "OK: images of release %s\n", d.Version)
	variants := make([]string, 0, len(d.Images))
	for v := range d.Images {
		variants = append(variants, v)
	}
	sort.Strings(variants)
	for _, v := range variants {
		fmt.Fprintf(w, "  %-12s %s@%s\n", v, d.Repository, d.Images[v])
	}
	return nil
}
