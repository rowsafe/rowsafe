package pgbackrest

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// Temporary credentials (Rowsafe Storage) change every day or so, while
// PostgreSQL keeps running `pgbackrest archive-push` with the config file it
// was given. pgBackRest reads its config file on every run, so rewriting the
// file (atomically) is all a rotation takes: the next archive-push uses the
// new credentials, one already running finishes with the old ones, which are
// still valid for days.

// credentialKeys are the repo1 options that hold credentials.
var credentialKeys = []string{"repo1-s3-key", "repo1-s3-key-secret", "repo1-s3-token"}

// SetCredentials returns conf, a config rendered by RenderConfig, with the
// repo1 credentials replaced by repo's (and the session token added or
// removed). Nothing else changes, so the config of a database the agent
// can't inspect right now (PostgreSQL down) can still be rotated. ok is
// false when conf has no repo1 key to replace (not a config of ours).
func SetCredentials(conf string, repo Repo) (out string, ok bool) {
	lines := strings.Split(conf, "\n")
	var b strings.Builder
	found := false
	for i, line := range lines {
		k, _, isKV := strings.Cut(line, "=")
		if isKV && isCredentialKey(k) {
			if k != "repo1-s3-key" {
				continue // written right after repo1-s3-key below
			}
			found = true
			fmt.Fprintf(&b, "repo1-s3-key=%s\n", repo.Key)
			fmt.Fprintf(&b, "repo1-s3-key-secret=%s\n", repo.KeySecret)
			if repo.Token != "" {
				fmt.Fprintf(&b, "repo1-s3-token=%s\n", repo.Token)
			}
			continue
		}
		b.WriteString(line)
		if i < len(lines)-1 {
			b.WriteByte('\n')
		}
	}
	return b.String(), found
}

func isCredentialKey(k string) bool {
	for _, c := range credentialKeys {
		if k == c {
			return true
		}
	}
	return false
}

// Location is where a rendered config's repository is: endpoint, port,
// bucket and path (which ends in the stanza). Two configs with the same
// Location use the same repository, whatever their credentials.
func Location(conf string) string {
	want := map[string]string{"repo1-s3-endpoint": "", "repo1-storage-port": "", "repo1-s3-bucket": "", "repo1-path": ""}
	for _, line := range strings.Split(conf, "\n") {
		k, v, ok := strings.Cut(line, "=")
		if _, known := want[k]; ok && known {
			want[k] = v
		}
	}
	if want["repo1-s3-bucket"] == "" {
		return ""
	}
	return want["repo1-s3-endpoint"] + ":" + want["repo1-storage-port"] + "/" + want["repo1-s3-bucket"] + want["repo1-path"]
}

// ID identifies the repository (endpoint, port, bucket and path prefix)
// without revealing anything: the first 12 hex digits of a SHA-256. It is
// what the agent reports to the control plane, which takes a new full
// backup when it changes.
func (r Repo) ID() string {
	if r.Bucket == "" {
		return ""
	}
	prefix := "/" + strings.Trim(r.PathPrefix, "/")
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s:%d/%s%s", r.Endpoint, r.Port, r.Bucket, prefix)))
	return hex.EncodeToString(sum[:6])
}

// Location is where RenderConfig(r, ...) puts stanza, in the form
// Location(conf) returns.
func (r Repo) Location(stanza string) string {
	port := ""
	if r.Port != 0 {
		port = fmt.Sprint(r.Port)
	}
	return r.Endpoint + ":" + port + "/" + r.Bucket + repoPath(r.PathPrefix, stanza)
}

// repoPath is repo1-path: the path prefix, then the stanza.
func repoPath(pathPrefix, stanza string) string {
	prefix := "/" + strings.Trim(pathPrefix, "/")
	if prefix == "/" {
		prefix = ""
	}
	return prefix + "/" + stanza
}
