package pgbackrest

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"
)

// SFTP repositories (Repo.Type "sftp"): backups go to a directory on a
// server the customer reaches over SSH (a Hetzner Storage Box, a NAS,
// another server). pgBackRest talks to it itself (repo-type=sftp; the host
// key check this package writes needs SFTPMinVersion).
//
// Nothing secret leaves this server: the SSH key is made here by the
// installer (SFTPKeyFile, owned by the agent's user, 0600) and only its
// public half is shown, to be added on the SFTP server; backups are
// encrypted here (repo1-cipher-type) before they go. The server's host key
// is pinned (SFTPHostKey): given by the person, or trusted on first use by
// the installer, which says so. A host key that changes later makes every
// connection fail; nothing ever accepts a new one by itself.

// SFTPMinVersion is the oldest pgBackRest that can back up to an SFTP
// server the way Rowsafe sets it up (repo-sftp-host-key-check-type).
const SFTPMinVersion = "2.48"

// DefaultSFTPPort is SSH's port (Hetzner Storage Boxes use 23).
const DefaultSFTPPort = 22

// SFTPKeyFileName is the SSH key's name in the agent's config directory.
const SFTPKeyFileName = "sftp_ed25519"

// SFTP reports whether the repository is on an SFTP server.
func (r Repo) SFTP() bool { return r.Type == "sftp" }

// sftpPort is the SSH port, DefaultSFTPPort when none is set.
func (r Repo) sftpPort() int {
	if r.SFTPPort == 0 {
		return DefaultSFTPPort
	}
	return r.SFTPPort
}

// SFTPEndpoint is "host:port" of the SFTP server.
func (r Repo) SFTPEndpoint() string {
	return net.JoinHostPort(r.SFTPHost, strconv.Itoa(r.sftpPort()))
}

// sftpRoot is the repository directory, without a trailing slash.
func (r Repo) sftpRoot() string { return strings.TrimRight(r.Path, "/") }

var (
	sftpHostRE = regexp.MustCompile(`^[A-Za-z0-9.:_-]+$`)
	sftpUserRE = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
)

func (r Repo) validateSFTP(prefix string) error {
	var missing []string
	for _, kv := range [][2]string{
		{prefix + "SFTP_HOST", r.SFTPHost}, {prefix + "SFTP_USER", r.SFTPUser},
		{prefix + "SFTP_PATH", r.Path}, {prefix + "SFTP_HOST_KEY", r.SFTPHostKey},
		{prefix + "CIPHER_PASS", r.CipherPass},
	} {
		if strings.TrimSpace(kv[1]) == "" {
			missing = append(missing, kv[0])
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("repository not configured, missing: %s", strings.Join(missing, ", "))
	}
	for _, v := range []string{r.SFTPHost, r.SFTPUser, r.Path, r.SFTPKeyFile, r.SFTPHostKey, r.CipherPass} {
		if strings.ContainsAny(v, "\n\r") {
			return errors.New("repository settings must not contain newlines")
		}
	}
	if strings.Contains(r.SFTPHost, "@") {
		return fmt.Errorf("%sSFTP_HOST is the server's name only: put the user name in %sSFTP_USER", prefix, prefix)
	}
	if !sftpHostRE.MatchString(r.SFTPHost) {
		return fmt.Errorf("%sSFTP_HOST %q is not a server name or address", prefix, r.SFTPHost)
	}
	if !sftpUserRE.MatchString(r.SFTPUser) {
		return fmt.Errorf("%sSFTP_USER %q is not a user name", prefix, r.SFTPUser)
	}
	if r.SFTPPort < 0 || r.SFTPPort > 65535 {
		return fmt.Errorf("%sSFTP_PORT %d is out of range", prefix, r.SFTPPort)
	}
	if !safePathRE.MatchString(r.Path) || strings.Contains(r.Path, "..") || r.sftpRoot() == "" {
		return fmt.Errorf("%sSFTP_PATH must be a directory on the SFTP server, starting with / (e.g. /backups/rowsafe)", prefix)
	}
	if !safePathRE.MatchString(r.SFTPKeyFile) {
		return fmt.Errorf("the SSH key for the SFTP server must be an absolute path, not %q", r.SFTPKeyFile)
	}
	if _, err := ParseHostKey(r.SFTPHostKey, r.SFTPHost, r.sftpPort()); err != nil {
		return fmt.Errorf("%sSFTP_HOST_KEY: %w", prefix, err)
	}
	if len(r.CipherPass) < 20 {
		return fmt.Errorf("%sCIPHER_PASS must be at least 20 characters", prefix)
	}
	return nil
}

// HostKey is a pinned SSH host key: the SHA-256 of the key the SFTP server
// presents.
type HostKey struct {
	Sum  []byte // 32 bytes
	Type string // "ssh-ed25519", ... ("" when given as a fingerprint)
}

// Fingerprint is the key's fingerprint the way OpenSSH prints it
// ("SHA256:..." without padding).
func (k HostKey) Fingerprint() string {
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(k.Sum)
}

// Hex is the fingerprint the way pgBackRest compares it
// (repo-sftp-host-fingerprint with repo-sftp-host-key-hash-type=sha256).
func (k HostKey) Hex() string { return hex.EncodeToString(k.Sum) }

// ParseHostKey reads a pinned host key (ROWSAFE_REPO_SFTP_HOST_KEY) in any
// of the forms people copy one in:
//
//   - an OpenSSH fingerprint, "SHA256:<base64>" (ssh-keygen -lf, the
//     Hetzner Storage Box documentation);
//   - pgBackRest's own form, 64 hex digits (optionally with colons);
//   - a known_hosts line ("host ssh-ed25519 AAAA..."), or a public key
//     ("ssh-ed25519 AAAA...", ssh_host_ed25519_key.pub). A known_hosts line
//     with plain host names must name host (on port, when not 22).
//
// MD5 and SHA-1 fingerprints are refused: SHA-256 only.
func ParseHostKey(s, host string, port int) (HostKey, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return HostKey{}, errors.New("empty")
	}
	if rest, ok := strings.CutPrefix(s, "SHA256:"); ok {
		sum, err := base64.RawStdEncoding.DecodeString(strings.TrimRight(rest, "="))
		if err != nil || len(sum) != sha256.Size {
			return HostKey{}, fmt.Errorf("%q is not a SHA256 fingerprint", s)
		}
		return HostKey{Sum: sum}, nil
	}
	plain := strings.ReplaceAll(s, ":", "")
	if len(plain) == 2*sha256.Size {
		if sum, err := hex.DecodeString(plain); err == nil {
			return HostKey{Sum: sum}, nil
		}
	}
	if strings.HasPrefix(s, "MD5:") || len(plain) == 32 || len(plain) == 40 {
		if _, err := hex.DecodeString(strings.TrimPrefix(plain, "MD5")); err == nil || strings.HasPrefix(s, "MD5:") {
			return HostKey{}, errors.New("an MD5 or SHA-1 fingerprint is not enough: give the SHA256 one (ssh-keygen -lf prints it)")
		}
	}
	if strings.HasPrefix(s, "@") {
		return HostKey{}, errors.New("give the server's own key, not a @cert-authority or @revoked line")
	}
	// A known_hosts line, then a public key on its own (which known_hosts
	// parsing refuses: its key type would be the host name).
	if _, hosts, pub, _, _, err := ssh.ParseKnownHosts([]byte(s)); err == nil {
		if !knownHostsNames(hosts, host, port) {
			return HostKey{}, fmt.Errorf("the known_hosts line is for %s, not %s", strings.Join(hosts, ","), host)
		}
		return hostKeyOf(pub), nil
	}
	if pub, _, opts, _, err := ssh.ParseAuthorizedKey([]byte(s)); err == nil && len(opts) == 0 {
		return hostKeyOf(pub), nil
	}
	return HostKey{}, errors.New("not a SHA256 fingerprint, a known_hosts line or a public key")
}

func hostKeyOf(pub ssh.PublicKey) HostKey {
	sum := sha256.Sum256(pub.Marshal())
	return HostKey{Sum: sum[:], Type: pub.Type()}
}

// knownHostsNames reports whether a known_hosts line's names cover host
// (on port). Hashed names and patterns can't be checked: the key itself is
// what is pinned, so they pass.
func knownHostsNames(hosts []string, host string, port int) bool {
	if host == "" {
		return true
	}
	want := strings.ToLower(host)
	if port != DefaultSFTPPort && port != 0 {
		want = "[" + want + "]:" + strconv.Itoa(port)
	}
	for _, h := range hosts {
		h = strings.ToLower(h)
		if h == want || strings.HasPrefix(h, "|") || strings.ContainsAny(h, "*?!") {
			return true
		}
	}
	return false
}

// sftpOptions are the repo1 options of an SFTP repository, without
// "repo1-", in the order RenderConfig writes them. The host key is always
// checked against the pinned fingerprint.
func (r Repo) sftpOptions() [][2]string {
	hk, _ := ParseHostKey(r.SFTPHostKey, r.SFTPHost, r.sftpPort()) // Validate checked it
	return [][2]string{
		{"sftp-host", r.SFTPHost},
		{"sftp-host-port", strconv.Itoa(r.sftpPort())},
		{"sftp-host-user", r.SFTPUser},
		{"sftp-private-key-file", r.SFTPKeyFile},
		// Optional with libssh2 built on OpenSSL, required otherwise.
		{"sftp-public-key-file", r.SFTPKeyFile + ".pub"},
		{"sftp-host-key-check-type", "fingerprint"},
		{"sftp-host-key-hash-type", "sha256"},
		{"sftp-host-fingerprint", hk.Hex()},
	}
}

// SFTPEnv points pgBackRest at the SFTP repository through its environment
// (PGBACKREST_REPO1_*), with root as repo1-path: the storage test runs it
// with --no-config.
func (r Repo) SFTPEnv(root string) []string {
	env := []string{"PGBACKREST_REPO1_TYPE=sftp"}
	for _, kv := range r.sftpOptions() {
		env = append(env, "PGBACKREST_REPO1_"+strings.ToUpper(strings.ReplaceAll(kv[0], "-", "_"))+"="+kv[1])
	}
	return append(env, "PGBACKREST_REPO1_PATH="+root)
}

// SFTPHostKeyFromError finds the host key fingerprint pgBackRest reports
// when it doesn't match the configured one ("host [<hex>] and configured
// fingerprint ... do not match"): the key the server presented.
func SFTPHostKeyFromError(out []byte) (HostKey, bool) {
	_, rest, ok := bytes.Cut(out, []byte("host ["))
	if !ok {
		return HostKey{}, false
	}
	h, _, ok := bytes.Cut(rest, []byte("]"))
	if !ok || len(h) != 2*sha256.Size {
		return HostKey{}, false
	}
	sum, err := hex.DecodeString(string(h))
	if err != nil {
		return HostKey{}, false
	}
	return HostKey{Sum: sum}, true
}
