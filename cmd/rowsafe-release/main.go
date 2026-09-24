// Command rowsafe-release builds, signs and verifies agent release
// manifests. It runs offline (in CI or on a release manager's machine) and
// never talks to the control plane: the private key must never reach it.
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
	"github.com/rowsafe/rowsafe/release"
)

const usage = `rowsafe-release - sign Rowsafe agent releases (offline)

Usage:
  rowsafe-release keygen
      print a new Ed25519 key pair; store the private key in your secret store
  rowsafe-release manifest --version V --base-url URL --dist DIR
      describe DIR/rowsafe-agent-linux-{amd64,arm64} as a release manifest on stdout;
      artifacts are expected at URL/V/rowsafe-agent-linux-ARCH
  rowsafe-release sign [--key-env ROWSAFE_RELEASE_PRIVATE_KEY] MANIFEST
      write MANIFEST.sig; the private key is read from the named environment variable
  rowsafe-release verify --public-key B64 MANIFEST SIG
      check a signature and print the release

Then publish the binaries, and on the control plane run
  rowsafed release add --manifest MANIFEST --signature MANIFEST.sig
`

// archs are the agent builds a release can contain.
var archs = []string{"amd64", "arm64"}

// maxArtifactSize matches what agents accept (see release.Verify).
const maxArtifactSize = 512 << 20

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "keygen":
		err = keygen(os.Stdout)
	case "manifest":
		err = manifestCmd(os.Args[2:], os.Stdout, time.Now)
	case "sign":
		err = signCmd(os.Args[2:], os.Getenv, os.Stderr)
	case "verify":
		err = verifyCmd(os.Args[2:], os.Stdout)
	case "-h", "--help", "help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

// parseArgs accepts flags before and after positional arguments and
// requires exactly want positionals.
func parseArgs(fs *flag.FlagSet, args []string, want int) ([]string, error) {
	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		args = fs.Args()
		if len(args) == 0 {
			break
		}
		positional = append(positional, args[0])
		args = args[1:]
	}
	if len(positional) != want {
		return nil, fmt.Errorf("%s: expected %d argument(s), got %d", fs.Name(), want, len(positional))
	}
	return positional, nil
}

func keygen(w io.Writer) error {
	pub, priv, err := release.GenerateKey()
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(w, "public: %s\nprivate: %s\n", pub, priv)
	return err
}

func manifestCmd(args []string, w io.Writer, now func() time.Time) error {
	fs := flag.NewFlagSet("manifest", flag.ContinueOnError)
	version := fs.String("version", "", "release version, MAJOR.MINOR.PATCH")
	baseURL := fs.String("base-url", "", "https URL the versioned artifacts are published under")
	dist := fs.String("dist", "", "directory containing rowsafe-agent-linux-<arch> binaries")
	if _, err := parseArgs(fs, args, 0); err != nil {
		return err
	}
	if *version == "" || *baseURL == "" || *dist == "" {
		return errors.New("--version, --base-url and --dist are required")
	}
	m, err := buildManifest(*version, *baseURL, *dist, now().UTC())
	if err != nil {
		return err
	}
	out, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	_, err = w.Write(append(out, '\n'))
	return err
}

func buildManifest(version, baseURL, dist string, releasedAt time.Time) (protocol.ReleaseManifest, error) {
	v, err := release.ParseVersion(version)
	if err != nil {
		return protocol.ReleaseManifest{}, err
	}
	u, err := url.Parse(baseURL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return protocol.ReleaseManifest{}, errors.New("--base-url must be an https URL")
	}
	base := strings.TrimRight(baseURL, "/")
	m := protocol.ReleaseManifest{
		Version:    v.String(),
		ReleasedAt: releasedAt.Truncate(time.Second),
		Artifacts:  map[string]protocol.Artifact{},
	}
	for _, arch := range archs {
		name := "rowsafe-agent-linux-" + arch
		a, err := describeArtifact(filepath.Join(dist, name))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return m, err
		}
		a.URL = fmt.Sprintf("%s/%s/%s", base, v, name)
		m.Artifacts["linux/"+arch] = a
	}
	if len(m.Artifacts) == 0 {
		return m, fmt.Errorf("no agent binaries in %s (want rowsafe-agent-linux-amd64 and/or -arm64)", dist)
	}
	return m, nil
}

func describeArtifact(path string) (protocol.Artifact, error) {
	f, err := os.Open(path)
	if err != nil {
		return protocol.Artifact{}, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return protocol.Artifact{}, fmt.Errorf("reading %s: %w", path, err)
	}
	if n == 0 || n > maxArtifactSize {
		return protocol.Artifact{}, fmt.Errorf("%s: implausible size %d bytes", path, n)
	}
	return protocol.Artifact{SHA256: release.SHA256Hex(h.Sum(nil)), Size: n}, nil
}

func signCmd(args []string, getenv func(string) string, log io.Writer) error {
	fs := flag.NewFlagSet("sign", flag.ContinueOnError)
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
	manifest, err := os.ReadFile(pos[0])
	if err != nil {
		return err
	}
	sig := release.Sign(priv, manifest)
	pub := priv.Public().(ed25519.PublicKey)
	// Refuse to sign anything an agent would reject.
	m, err := release.Verify(pub, manifest, sig)
	if err != nil {
		return fmt.Errorf("not signing an invalid manifest: %w", err)
	}
	sigPath := pos[0] + ".sig"
	if err := os.WriteFile(sigPath, []byte(sig+"\n"), 0o644); err != nil {
		return err
	}
	fmt.Fprintf(log, "Signed release %s -> %s\nPublic key: %s\n", m.Version, sigPath, base64.StdEncoding.EncodeToString(pub))
	return nil
}

func verifyCmd(args []string, w io.Writer) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	pubB64 := fs.String("public-key", "", "base64 Ed25519 public key")
	pos, err := parseArgs(fs, args, 2)
	if err != nil {
		return err
	}
	if *pubB64 == "" {
		return errors.New("--public-key is required")
	}
	pub, err := release.ParsePublicKey(*pubB64)
	if err != nil {
		return err
	}
	manifest, err := os.ReadFile(pos[0])
	if err != nil {
		return err
	}
	sig, err := os.ReadFile(pos[1])
	if err != nil {
		return err
	}
	m, err := release.Verify(pub, manifest, string(sig))
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "OK: release %s, released %s\n", m.Version, m.ReleasedAt.UTC().Format(time.RFC3339))
	platforms := make([]string, 0, len(m.Artifacts))
	for p := range m.Artifacts {
		platforms = append(platforms, p)
	}
	sort.Strings(platforms)
	for _, p := range platforms {
		a := m.Artifacts[p]
		fmt.Fprintf(w, "  %-12s %s  %d bytes  %s\n", p, a.SHA256, a.Size, a.URL)
	}
	return nil
}
