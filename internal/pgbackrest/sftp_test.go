package pgbackrest

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/rowsafe/rowsafe/protocol"
)

// testHostKey is an SSH host key and its fingerprints.
func testHostKey(t *testing.T) (pub ssh.PublicKey, line, fp, hexFP string) {
	t.Helper()
	seed := sha256.Sum256([]byte("rowsafe sftp test host key"))
	k, err := ssh.NewPublicKey(ed25519.NewKeyFromSeed(seed[:]).Public())
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(k.Marshal())
	return k, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k))), ssh.FingerprintSHA256(k), hex.EncodeToString(sum[:])
}

func sftpTestRepo(t *testing.T) Repo {
	_, _, fp, _ := testHostKey(t)
	return Repo{
		Type: "sftp", SFTPHost: "u123.your-storagebox.de", SFTPPort: 23, SFTPUser: "u123",
		Path: "/backups/rowsafe/", SFTPKeyFile: "/etc/rowsafe/pgbackrest/sftp_ed25519", SFTPHostKey: fp,
		CipherPass: "correct horse battery staple",
	}
}

func TestRenderConfigSFTP(t *testing.T) {
	r := sftpTestRepo(t)
	_, _, _, hexFP := testHostKey(t)
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	conf := RenderConfig(r, ConfigInput{Stanza: "app", DataDir: "/var/lib/postgresql/18/main", Port: 5432,
		SocketDir: "/var/run/postgresql", User: "postgres", RetentionFull: 2})
	want := "repo1-type=sftp\n" +
		"repo1-sftp-host=u123.your-storagebox.de\n" +
		"repo1-sftp-host-port=23\n" +
		"repo1-sftp-host-user=u123\n" +
		"repo1-sftp-private-key-file=/etc/rowsafe/pgbackrest/sftp_ed25519\n" +
		"repo1-sftp-public-key-file=/etc/rowsafe/pgbackrest/sftp_ed25519.pub\n" +
		"repo1-sftp-host-key-check-type=fingerprint\n" +
		"repo1-sftp-host-key-hash-type=sha256\n" +
		"repo1-sftp-host-fingerprint=" + hexFP + "\n" +
		"repo1-path=/backups/rowsafe/app\n" +
		"repo1-cipher-type=aes-256-cbc\n" +
		"repo1-cipher-pass=correct horse battery staple\n"
	if !strings.Contains(conf, want) {
		t.Errorf("config:\n%s\nwant it to contain:\n%s", conf, want)
	}
	for _, bad := range []string{"repo1-s3", "repo1-storage", "none", "accept-new"} {
		if strings.Contains(conf, bad) {
			t.Errorf("an SFTP config must not have %q:\n%s", bad, conf)
		}
	}

	// Port 22 when none is set; a moved folder.
	r.SFTPPort, r.Folder = 0, "app-2"
	conf = RenderConfig(r, ConfigInput{Stanza: "app", RetentionFull: 1})
	if !strings.Contains(conf, "repo1-sftp-host-port=22\n") || !strings.Contains(conf, "repo1-path=/backups/rowsafe/app-2\n") {
		t.Errorf("config:\n%s", conf)
	}
}

func TestSFTPLocationInfoID(t *testing.T) {
	r := sftpTestRepo(t)
	conf := RenderConfig(r, ConfigInput{Stanza: "app", RetentionFull: 1})
	if got, want := Location(conf), r.Location("app"); got != want || got != "sftp://u123.your-storagebox.de:23/backups/rowsafe/app" {
		t.Errorf("Location(conf) = %q, Repo.Location = %q", got, want)
	}
	if !strings.HasPrefix(Location(conf), r.Root()) {
		t.Errorf("root %q is not a prefix of %q", r.Root(), Location(conf))
	}
	// Never under an S3 repository's root (Rowsafe Storage rotation).
	if strings.HasPrefix(Location(conf), testRepo.Root()) || strings.HasPrefix(testRepo.Location("app"), r.Root()) {
		t.Error("SFTP and S3 locations overlap")
	}
	// A credentials rotation leaves an SFTP config alone.
	if _, ok := SetCredentials(conf, testRepo); ok {
		t.Error("SetCredentials changed an SFTP config")
	}

	info := r.Info(protocol.RepoPrimary)
	if info != (protocol.RepoInfo{Repo: 1, Provider: "sftp", Endpoint: "u123.your-storagebox.de:23", Bucket: "/backups/rowsafe"}) {
		t.Errorf("Info = %+v", info)
	}
	r.SFTPPort = 0
	if got := r.Info(1).Endpoint; got != "u123.your-storagebox.de:22" {
		t.Errorf("endpoint without a port = %q", got)
	}
	if ProviderOf(r) != protocol.ProviderSFTP {
		t.Errorf("provider = %q", ProviderOf(r))
	}

	id := r.ID()
	if len(id) != 12 {
		t.Fatalf("ID = %q", id)
	}
	other := r
	other.Path = "/elsewhere"
	if other.ID() == id {
		t.Error("another folder must have another ID")
	}
	other = r
	other.SFTPHostKey, other.SFTPUser = "SHA256:"+strings.Repeat("A", 43), "someone"
	if other.ID() != id {
		t.Error("the ID is where the backups are, not who reaches them")
	}
	if !r.Configured() {
		t.Error("an SFTP repository is configured")
	}
}

func TestValidateSFTP(t *testing.T) {
	good := sftpTestRepo(t)
	for name, tc := range map[string]struct {
		edit func(*Repo)
		want string
	}{
		"no host":       {func(r *Repo) { r.SFTPHost = "" }, "ROWSAFE_REPO_SFTP_HOST"},
		"no user":       {func(r *Repo) { r.SFTPUser = "" }, "ROWSAFE_REPO_SFTP_USER"},
		"no path":       {func(r *Repo) { r.Path = "" }, "ROWSAFE_REPO_SFTP_PATH"},
		"no host key":   {func(r *Repo) { r.SFTPHostKey = "" }, "ROWSAFE_REPO_SFTP_HOST_KEY"},
		"no passphrase": {func(r *Repo) { r.CipherPass = "" }, "ROWSAFE_REPO_CIPHER_PASS"},
		"short pass":    {func(r *Repo) { r.CipherPass = "short" }, "at least 20"},
		"user@host":     {func(r *Repo) { r.SFTPHost = "u1@host" }, "put the user name in ROWSAFE_REPO_SFTP_USER"},
		"bad host":      {func(r *Repo) { r.SFTPHost = "host;rm" }, "not a server name"},
		"bad user":      {func(r *Repo) { r.SFTPUser = "a b" }, "not a user name"},
		"bad port":      {func(r *Repo) { r.SFTPPort = 70000 }, "out of range"},
		"relative":      {func(r *Repo) { r.Path = "backups" }, "starting with /"},
		"root only":     {func(r *Repo) { r.Path = "/" }, "starting with /"},
		"dotdot":        {func(r *Repo) { r.Path = "/a/../b" }, "starting with /"},
		"newline":       {func(r *Repo) { r.SFTPUser = "u\n[evil]" }, "newlines"},
		"key file":      {func(r *Repo) { r.SFTPKeyFile = "key" }, "absolute path"},
		"md5 host key":  {func(r *Repo) { r.SFTPHostKey = "MD5:16:27:ac:a5:76:28:2d:36:63:1b:56:4d:eb:df:a6:48" }, "SHA256"},
		"bad host key":  {func(r *Repo) { r.SFTPHostKey = "SHA256:nope" }, "not a SHA256 fingerprint"},
		"unknown type":  {func(r *Repo) { r.Type = "ftp" }, "TYPE must be s3 or sftp"},
	} {
		r := good
		tc.edit(&r)
		if err := r.Validate(); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: got %v, want %q", name, err, tc.want)
		}
	}
	if err := good.ValidateAs("ROWSAFE_REPO_"); err != nil {
		t.Error(err)
	}
}

func TestParseHostKey(t *testing.T) {
	pub, line, fp, hexFP := testHostKey(t)
	padded := base64.StdEncoding.EncodeToString(func() []byte { s := sha256.Sum256(pub.Marshal()); return s[:] }())
	for name, in := range map[string]string{
		"openssh fingerprint":      fp,
		"padded fingerprint":       "SHA256:" + padded,
		"surrounding space":        "  " + fp + "\n",
		"pgbackrest hex":           hexFP,
		"hex with colons":          colons(hexFP),
		"public key":               line,
		"public key with comment":  line + " root@sftp",
		"known_hosts default port": "u123.your-storagebox.de " + line,
		"known_hosts on port 23":   "[u123.your-storagebox.de]:23," + "[1.2.3.4]:23 " + line,
		"known_hosts hashed":       "|1|c2FsdA==|aGFzaA== " + line,
	} {
		port := 22
		if strings.Contains(name, "23") {
			port = 23
		}
		k, err := ParseHostKey(in, "u123.your-storagebox.de", port)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if k.Fingerprint() != fp || k.Hex() != hexFP {
			t.Errorf("%s: got %s / %s, want %s / %s", name, k.Fingerprint(), k.Hex(), fp, hexFP)
		}
		if strings.Contains(name, "known") || strings.Contains(name, "public") {
			if k.Type != "ssh-ed25519" {
				t.Errorf("%s: type %q", name, k.Type)
			}
		}
	}
	for name, tc := range map[string]struct{ in, want string }{
		"another host":       {"other.example " + line, "is for other.example"},
		"wrong port":         {"u123.your-storagebox.de " + line, "is for u123.your-storagebox.de"},
		"cert authority":     {"@cert-authority *.example " + line, "@cert-authority"},
		"md5":                {"16:27:ac:a5:76:28:2d:36:63:1b:56:4d:eb:df:a6:48", "MD5 or SHA-1"},
		"sha1 hex":           {strings.Repeat("ab", 20), "MD5 or SHA-1"},
		"short fingerprint":  {"SHA256:abc", "not a SHA256"},
		"garbage":            {"hello world", "not a SHA256 fingerprint, a known_hosts line or a public key"},
		"empty":              {"", "empty"},
		"truncated key blob": {"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI", "not a SHA256"},
	} {
		port := 22
		if name == "wrong port" {
			port = 23
		}
		if _, err := ParseHostKey(tc.in, "u123.your-storagebox.de", port); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: got %v, want %q", name, err, tc.want)
		}
	}
}

func colons(h string) string {
	var parts []string
	for i := 0; i < len(h); i += 2 {
		parts = append(parts, h[i:i+2])
	}
	return strings.Join(parts, ":")
}

func TestSFTPEnv(t *testing.T) {
	r := sftpTestRepo(t)
	_, _, _, hexFP := testHostKey(t)
	env := strings.Join(r.SFTPEnv("/backups/rowsafe"), "\n")
	for _, want := range []string{
		"PGBACKREST_REPO1_TYPE=sftp", "PGBACKREST_REPO1_SFTP_HOST=u123.your-storagebox.de",
		"PGBACKREST_REPO1_SFTP_HOST_PORT=23", "PGBACKREST_REPO1_SFTP_HOST_USER=u123",
		"PGBACKREST_REPO1_SFTP_PRIVATE_KEY_FILE=/etc/rowsafe/pgbackrest/sftp_ed25519",
		"PGBACKREST_REPO1_SFTP_PUBLIC_KEY_FILE=/etc/rowsafe/pgbackrest/sftp_ed25519.pub",
		"PGBACKREST_REPO1_SFTP_HOST_KEY_CHECK_TYPE=fingerprint", "PGBACKREST_REPO1_SFTP_HOST_KEY_HASH_TYPE=sha256",
		"PGBACKREST_REPO1_SFTP_HOST_FINGERPRINT=" + hexFP, "PGBACKREST_REPO1_PATH=/backups/rowsafe",
	} {
		if !strings.Contains(env+"\n", want+"\n") {
			t.Errorf("env missing %q:\n%s", want, env)
		}
	}
	if strings.Contains(env, "CIPHER") || strings.Contains(env, r.CipherPass) {
		t.Error("the storage test env must not carry the passphrase")
	}
}

func TestSFTPHostKeyFromError(t *testing.T) {
	_, _, fp, hexFP := testHostKey(t)
	out := []byte("P00  ERROR: [101]: host [" + hexFP + "] and configured fingerprint (repo-sftp-host-fingerprint) [" +
		strings.Repeat("0", 64) + "] do not match\n")
	k, ok := SFTPHostKeyFromError(out)
	if !ok || k.Fingerprint() != fp {
		t.Errorf("got %v %s", ok, k.Fingerprint())
	}
	if _, ok := SFTPHostKeyFromError([]byte("ERROR: [101]: public key authentication failed")); ok {
		t.Error("no fingerprint there")
	}
}
