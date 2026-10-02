// Package agentimages is the signed list of a release's Docker agent images:
// for each image variant ("pg17", "pg17-alpine"), the digest of
// ghcr.io/rowsafe/agent built for that release.
//
// The release workflow writes it once the images are pushed and cosign
// verifies them as built by the workflow at the release's tag, and signs it
// with the same Ed25519 release key as the agent's manifest. The control
// plane only relays it: rowsafe-docker-control verifies the signature with
// the public key built into it before it pulls anything, so a compromised
// control plane can at most withhold an update, never pick the image.
//
// It imports only the standard library: it is compiled into
// rowsafe-docker-control, which holds the Docker socket.
package agentimages

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Kind tells this document from a release manifest signed with the same key.
const Kind = "rowsafe-agent-images"

// Repository is the only repository the documents name, and the only one
// rowsafe-docker-control ever pulls from.
const Repository = "ghcr.io/rowsafe/agent"

// MaxSize bounds a document (a release has ten images today).
const MaxSize = 16 << 10

// VariantLabel is the image label naming its variant (agent.Dockerfile).
const VariantLabel = "sh.rowsafe.agent.variant"

// Document is the signed list.
type Document struct {
	Kind       string `json:"kind"`
	Version    string `json:"version"`
	Repository string `json:"repository"`
	// Images maps a variant to the digest of its (multi-platform) image,
	// "sha256:<64 hex>".
	Images map[string]string `json:"images"`
}

var (
	versionRE = regexp.MustCompile(`^(\d{1,6})\.(\d{1,6})\.(\d{1,6})$`)
	variantRE = regexp.MustCompile(`^pg([1-9][0-9])(-alpine)?$`)
	digestRE  = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	// tagVariantRE finds the variant at the end of a tag: "pg17",
	// "0.5.0-pg17-alpine".
	tagVariantRE = regexp.MustCompile(`(?:^|-)(pg[1-9][0-9](?:-alpine)?)$`)
)

// ValidVariant reports whether v names an image variant.
func ValidVariant(v string) bool { return variantRE.MatchString(v) }

// ValidDigest reports whether d is "sha256:<64 lowercase hex>".
func ValidDigest(d string) bool { return digestRE.MatchString(d) }

// Variant is the variant for a PostgreSQL major and image flavour.
func Variant(major int, alpine bool) string {
	v := "pg" + strconv.Itoa(major)
	if alpine {
		v += "-alpine"
	}
	return v
}

// VariantOfRef returns the variant an image reference of Repository names in
// its tag ("ghcr.io/rowsafe/agent:0.5.0-pg17-alpine" -> "pg17-alpine"), or
// "" (another repository, a digest, or another tag).
func VariantOfRef(ref string) string {
	tag, ok := strings.CutPrefix(ref, Repository+":")
	if !ok {
		return ""
	}
	if m := tagVariantRE.FindStringSubmatch(tag); m != nil {
		return m[1]
	}
	return ""
}

// ParsePublicKey reads a base64 Ed25519 public key.
func ParsePublicKey(b64 string) (ed25519.PublicKey, error) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, errors.New("invalid release public key: want base64 of 32 bytes")
	}
	return ed25519.PublicKey(b), nil
}

// Verify checks the signature over the exact bytes of doc first, and only
// then parses and validates it, so unsigned input is never interpreted.
func Verify(pub ed25519.PublicKey, doc []byte, signatureB64 string) (Document, error) {
	var d Document
	if len(pub) != ed25519.PublicKeySize {
		return d, errors.New("no release public key to verify the images with")
	}
	if len(doc) == 0 || len(doc) > MaxSize {
		return d, fmt.Errorf("the images document is empty or larger than %d bytes", MaxSize)
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(signatureB64))
	if err != nil || len(sig) != ed25519.SignatureSize {
		return d, errors.New("malformed signature on the images document")
	}
	if !ed25519.Verify(pub, doc, sig) {
		return d, errors.New("the images document's signature does not match Rowsafe's release key")
	}
	dec := json.NewDecoder(bytes.NewReader(doc))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&d); err != nil {
		return d, fmt.Errorf("reading the signed images document: %w", err)
	}
	if dec.More() {
		return d, errors.New("trailing data after the signed images document")
	}
	return d, d.Validate()
}

// Validate checks the document's fields.
func (d Document) Validate() error {
	switch {
	case d.Kind != Kind:
		return fmt.Errorf("not an images document (kind %q)", d.Kind)
	case !versionRE.MatchString(d.Version):
		return fmt.Errorf("invalid version %q in the images document", d.Version)
	case d.Repository != Repository:
		return fmt.Errorf("the images document names repository %q, not %s", d.Repository, Repository)
	case len(d.Images) == 0 || len(d.Images) > 64:
		return fmt.Errorf("the images document lists %d images", len(d.Images))
	}
	for v, dg := range d.Images {
		if !ValidVariant(v) {
			return fmt.Errorf("invalid image variant %q", v)
		}
		if !ValidDigest(dg) {
			return fmt.Errorf("invalid digest %q for %s", dg, v)
		}
	}
	return nil
}

// Ref is the image reference for variant: Repository@digest.
func (d Document) Ref(variant string) (string, bool) {
	dg, ok := d.Images[variant]
	if !ok {
		return "", false
	}
	return Repository + "@" + dg, true
}

// CompareVersions compares two MAJOR.MINOR.PATCH versions (-1, 0, 1); ok is
// false when either doesn't parse.
func CompareVersions(a, b string) (int, bool) {
	ma, mb := versionRE.FindStringSubmatch(strings.TrimPrefix(a, "v")), versionRE.FindStringSubmatch(strings.TrimPrefix(b, "v"))
	if ma == nil || mb == nil {
		return 0, false
	}
	for i := 1; i <= 3; i++ {
		x, _ := strconv.Atoi(ma[i])
		y, _ := strconv.Atoi(mb[i])
		if x != y {
			if x < y {
				return -1, true
			}
			return 1, true
		}
	}
	return 0, true
}
