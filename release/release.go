// Package release signs and verifies agent release manifests.
//
// The private key never touches the control plane: releases are signed in CI
// (or on an operator's machine) and the agent verifies them with a public key
// compiled into the binary. A compromised control plane or download host can
// therefore withhold updates, but cannot make an agent run foreign code.
package release

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"runtime"
	"strconv"
	"strings"

	"github.com/rowsafe/rowsafe/protocol"
)

// Version is a strict semantic version: MAJOR.MINOR.PATCH with optional "v".
type Version struct{ Major, Minor, Patch int }

var versionRE = regexp.MustCompile(`^v?(\d{1,6})\.(\d{1,6})\.(\d{1,6})$`)

func ParseVersion(s string) (Version, error) {
	m := versionRE.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return Version{}, fmt.Errorf("invalid version %q: want MAJOR.MINOR.PATCH", s)
	}
	var v Version
	v.Major, _ = strconv.Atoi(m[1])
	v.Minor, _ = strconv.Atoi(m[2])
	v.Patch, _ = strconv.Atoi(m[3])
	return v, nil
}

func (v Version) String() string { return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch) }

// Compare returns -1, 0 or 1.
func (v Version) Compare(o Version) int {
	for _, d := range [][2]int{{v.Major, o.Major}, {v.Minor, o.Minor}, {v.Patch, o.Patch}} {
		if d[0] < d[1] {
			return -1
		}
		if d[0] > d[1] {
			return 1
		}
	}
	return 0
}

// Platform is the artifact key for the running binary, e.g. "linux/amd64".
func Platform() string { return runtime.GOOS + "/" + runtime.GOARCH }

func GenerateKey() (pub, priv string, err error) {
	p, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(p), base64.StdEncoding.EncodeToString(k), nil
}

func ParsePublicKey(b64 string) (ed25519.PublicKey, error) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, errors.New("invalid release public key: want base64 of 32 bytes")
	}
	return ed25519.PublicKey(b), nil
}

func ParsePrivateKey(b64 string) (ed25519.PrivateKey, error) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil || len(b) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid release private key: want base64 of 64 bytes")
	}
	return ed25519.PrivateKey(b), nil
}

// Sign returns a base64 signature over the exact manifest bytes.
func Sign(priv ed25519.PrivateKey, manifest []byte) string {
	return base64.StdEncoding.EncodeToString(ed25519.Sign(priv, manifest))
}

var sha256RE = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Verify checks the signature first and only then parses and validates the
// manifest, so unsigned input is never interpreted.
func Verify(pub ed25519.PublicKey, manifest []byte, signatureB64 string) (protocol.ReleaseManifest, error) {
	var m protocol.ReleaseManifest
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(signatureB64))
	if err != nil || len(sig) != ed25519.SignatureSize {
		return m, errors.New("malformed release signature")
	}
	if !ed25519.Verify(pub, manifest, sig) {
		return m, errors.New("release signature does not match the built-in public key")
	}
	dec := json.NewDecoder(bytes.NewReader(manifest))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return m, fmt.Errorf("parsing signed manifest: %w", err)
	}
	if _, err := ParseVersion(m.Version); err != nil {
		return m, err
	}
	if len(m.Artifacts) == 0 {
		return m, errors.New("manifest lists no artifacts")
	}
	for platform, a := range m.Artifacts {
		u, err := url.Parse(a.URL)
		if err != nil || u.Scheme != "https" || u.Host == "" {
			return m, fmt.Errorf("artifact %s: URL must be https", platform)
		}
		if !sha256RE.MatchString(a.SHA256) {
			return m, fmt.Errorf("artifact %s: sha256 must be 64 lowercase hex characters", platform)
		}
		if a.Size <= 0 || a.Size > 512<<20 {
			return m, fmt.Errorf("artifact %s: implausible size %d", platform, a.Size)
		}
	}
	return m, nil
}

// SHA256Hex is a helper for building manifests.
func SHA256Hex(sum []byte) string { return hex.EncodeToString(sum) }
