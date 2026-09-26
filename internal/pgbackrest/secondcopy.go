package pgbackrest

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/rowsafe/rowsafe/protocol"
)

// The second copy (protocol/secondcopy.go). pgBackRest's own multi-repo
// archiving is not used on purpose: with two repositories, archive-push
// fails while either is unreachable, so an outage of the second storage
// would stop PostgreSQL's archiving, and archive-push-queue-max then drops
// WAL from both repositories, the first one included. Instead the second
// storage has a configuration of its own (<stanza>.copy2.conf, where it is
// repo1) and archive_command, after archiving to the first storage, only
// queues a copy of the file locally; the agent sends queued files on.

// secondCopyMarker ends the second copy's part of archive_command. It
// tells a reader of postgresql.auto.conf what it is for.
const secondCopyMarker = "# rowsafe second copy: the agent sends queued WAL to the second storage"

// SecondCopyGapFile is created in a stanza's queue directory when
// archive_command leaves a WAL file out of the second copy (the queue was
// full, or copying failed): it lists the names of the files left out, one
// per line.
const SecondCopyGapFile = "gap"

// SecondCopyArchiveCommand is the native archive_command with a second
// copy: archive to the first storage exactly like ArchiveCommand, and only
// when that succeeded, queue a copy of the file in queueDir. The queue part
// never fails the command: when the queue already holds
// protocol.SecondCopyQueueMaxFiles entries, or the copy fails (disk full,
// directory missing), the file is left out of the second copy and its name
// is added to the gap file instead. A queued file is complete and durable before it
// gets its name (written to "<file>.tmp", fsynced, renamed), and a file
// already queued (a retry after a crash) is kept.
func SecondCopyArchiveCommand(bin, configPath, stanza, queueDir string) (string, error) {
	push, err := ArchiveCommand(bin, configPath, stanza)
	if err != nil {
		return "", err
	}
	dir := strings.TrimRight(queueDir, "/")
	if !safePathRE.MatchString(dir) || strings.Contains(dir, "..") {
		return "", fmt.Errorf("unsafe second copy queue directory %q", queueDir)
	}
	return fmt.Sprintf(`%s && { d=%s; f=$d/%%f; if test -f "$f"; then :; `+
		`elif test "$(ls -A "$d" 2>/dev/null | wc -l)" -lt %d; then cp %%p "$f.tmp" && sync "$f.tmp" && mv "$f.tmp" "$f" || echo %%f >>"$d/%s"; `+
		`else echo %%f >>"$d/%s"; fi; true; } 2>/dev/null %s`,
		push, dir, protocol.SecondCopyQueueMaxFiles, SecondCopyGapFile, SecondCopyGapFile, secondCopyMarker), nil
}

// IsOwnArchiveCommand reports whether cmd is Rowsafe's native
// archive_command for this stanza and config, with or without a second
// copy part, as this or an earlier agent version wrote it. The agent may
// switch between the two by itself (the second copy is set up or removed on
// the server); it never touches any other archive_command.
func IsOwnArchiveCommand(cmd, bin, configPath, stanza string) bool {
	push, err := ArchiveCommand(bin, configPath, stanza)
	if err != nil {
		return false
	}
	return cmd == push || (strings.HasPrefix(cmd, push+" && {") && strings.HasSuffix(cmd, secondCopyMarker))
}

// SecondCopyConfigPath is the second storage's config next to configPath
// ("/etc/rowsafe/pgbackrest/app.conf" -> ".../app.copy2.conf").
func SecondCopyConfigPath(configPath string) string {
	return strings.TrimSuffix(configPath, ".conf") + ".copy2.conf"
}

// ---- storage use ----

// RepoLs lists everything under the stanza's repository path with sizes.
func (c CLI) RepoLs(ctx context.Context) ([]byte, error) {
	out, err := c.Runner.Run(ctx, c.Bin, "--config="+c.ConfigPath, "--stanza="+c.Stanza,
		"--log-level-console=warn", "--output=json", "--recurse", "repo-ls")
	if err != nil {
		return out, fmt.Errorf("pgbackrest repo-ls: %w: %s", err, errorText(out))
	}
	return out, nil
}

// RepoUsage is what a repository holds for one stanza.
type RepoUsage struct {
	TotalBytes  int64
	WALBytes    int64
	BackupBytes int64
	WALFiles    int
	// ByLabel is the size of each backup's own directory.
	ByLabel map[string]int64
}

// ParseRepoUsage adds up `pgbackrest repo-ls --recurse --output=json` for a
// stanza: {"archive/<stanza>/...": {"type": "file", "size": N}, ...}.
func ParseRepoUsage(data []byte, stanza string) (RepoUsage, error) {
	u := RepoUsage{ByLabel: map[string]int64{}}
	var entries map[string]struct {
		Type string `json:"type"`
		Size int64  `json:"size"`
	}
	if err := json.Unmarshal(jsonPart(data, '{'), &entries); err != nil {
		return u, fmt.Errorf("parsing pgbackrest repo-ls: %w", err)
	}
	backupDir := "backup/" + stanza + "/"
	for path, e := range entries {
		if e.Type != "file" {
			continue
		}
		u.TotalBytes += e.Size
		switch {
		case strings.HasPrefix(path, "archive/"):
			u.WALBytes += e.Size
			name := path[strings.LastIndexByte(path, '/')+1:]
			if len(name) > 25 && name[24] == '-' && IsWALFileName(name[:24]) { // a segment, not archive.info or a .backup file
				u.WALFiles++
			}
		case strings.HasPrefix(path, "backup/"):
			u.BackupBytes += e.Size
			if rest, ok := strings.CutPrefix(path, backupDir); ok {
				if label, _, ok := strings.Cut(rest, "/"); ok && ValidBackupLabel(label) {
					u.ByLabel[label] += e.Size
				}
			}
		}
	}
	return u, nil
}

// RepoBackups lists a stanza's backups, oldest first, with their stored
// size (from ByLabel; info's own figure where repo-ls had none).
func RepoBackups(stanzas []Stanza, name string, u RepoUsage) []protocol.RepoBackup {
	var out []protocol.RepoBackup
	for _, s := range stanzas {
		if s.Name != name {
			continue
		}
		for _, b := range s.Backup {
			if b.Error {
				continue
			}
			size, ok := u.ByLabel[b.Label]
			if !ok {
				size = b.Info.Repository.Delta
			}
			out = append(out, BackupInfoTime(b, size))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].StoppedAt.Before(out[j].StoppedAt) })
	return out
}

// BackupInfoTime is b as a protocol.RepoBackup of the given size.
func BackupInfoTime(b BackupInfo, size int64) protocol.RepoBackup {
	r := b.Result()
	return protocol.RepoBackup{Label: b.Label, Type: b.Type, StoppedAt: r.StoppedAt, StoredBytes: size}
}

// jsonPart skips anything pgBackRest printed before its JSON (warnings go
// to the console too).
func jsonPart(data []byte, open byte) []byte {
	for i, c := range data {
		if c == open {
			return data[i:]
		}
	}
	return data
}

func errorText(out []byte) string {
	s := strings.TrimSpace(string(out))
	if i := strings.Index(s, "ERROR: "); i >= 0 {
		s = s[i:]
	}
	if len(s) > 400 {
		s = s[:400] + "..."
	}
	return s
}

// ---- providers ----

// ProviderOf recognizes the storage provider from an S3 endpoint.
func ProviderOf(r Repo) string {
	if r.Posix() {
		return protocol.ProviderPosix
	}
	h := strings.ToLower(r.Endpoint)
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	switch {
	case strings.HasSuffix(h, ".r2.cloudflarestorage.com"):
		return protocol.ProviderR2
	case h == "s3.amazonaws.com" || strings.HasSuffix(h, ".amazonaws.com"):
		return protocol.ProviderS3
	case strings.HasSuffix(h, ".backblazeb2.com"):
		return protocol.ProviderB2
	case h == "s3.wasabisys.com" || strings.HasSuffix(h, ".wasabisys.com"):
		return protocol.ProviderWasabi
	case strings.HasSuffix(h, ".digitaloceanspaces.com"):
		return protocol.ProviderSpaces
	}
	return protocol.ProviderOther
}

// Info describes where a repository is, without secrets.
func (r Repo) Info(n int) protocol.RepoInfo {
	ri := protocol.RepoInfo{Repo: n, Provider: ProviderOf(r), Bucket: r.Bucket, Region: r.Region}
	if r.Posix() {
		ri.Endpoint = r.Path
		return ri
	}
	ri.Endpoint = r.Endpoint
	if r.Port != 0 && r.Port != 443 {
		ri.Endpoint = net.JoinHostPort(r.Endpoint, fmt.Sprint(r.Port))
	}
	return ri
}
