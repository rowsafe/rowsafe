package pgbackrest

import (
	"context"
	"fmt"
	"regexp"
	"strings"
)

// Docker sidecar mode. The stock postgres images have no pgBackRest, so
// archive_command only hands each WAL file over to a spool directory shared
// with the agent's container, using tools every postgres image has (POSIX
// sh, test, cmp, cp, sync, mv). The agent then pushes spooled files with
// `pgbackrest archive-push` and deletes each one only after pgBackRest has
// stored it in the repository.

// spoolMarker ends every spool archive_command. It tells a reader of
// postgresql.auto.conf what the command is for, lets the planner recognise
// its own command, and contains "pgbackrest": pgBackRest's backup and check
// refuse to run unless archive_command mentions it.
const spoolMarker = "# rowsafe spool: the rowsafe-agent sidecar pushes these files with pgbackrest archive-push"

var stanzaRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)

// SpoolArchiveCommand is the archive_command for sidecar mode. For each WAL
// file (%f, at %p relative to the data directory) it:
//
//   - succeeds without copying when the spool already holds an identical
//     file (Postgres retrying a file it already handed over after a crash or
//     a failed status update), and fails when it holds a different one: it
//     never overwrites a spooled file;
//   - otherwise copies to "<file>.tmp", fsyncs it, renames it into place and
//     fsyncs the directory, so a spooled file is complete and durable before
//     Postgres is told it is archived (and may recycle the segment). The
//     pusher ignores ".tmp" files, and a leftover one is overwritten by the
//     retry;
//   - exits non-zero on any failure, so Postgres keeps the segment and
//     retries.
//
// It is the same for segments, timeline .history files, .backup history
// files and .partial segments.
func SpoolArchiveCommand(spoolRoot, stanza string) (string, error) {
	dir, err := SpoolDir(spoolRoot, stanza)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf(`f=%s/%%f; if test -f "$f"; then cmp -s %%p "$f"; else cp %%p "$f.tmp" && sync "$f.tmp" && mv "$f.tmp" "$f" && sync %s; fi %s`,
		dir, dir, spoolMarker), nil
}

// SpoolDir is the spool directory of one stanza.
func SpoolDir(spoolRoot, stanza string) (string, error) {
	root := strings.TrimRight(spoolRoot, "/")
	if !safePathRE.MatchString(root) || strings.Contains(root, "..") {
		return "", fmt.Errorf("unsafe spool directory %q: use an absolute path of letters, digits, / _ . -", spoolRoot)
	}
	if !stanzaRE.MatchString(stanza) {
		return "", fmt.Errorf("invalid stanza name %q", stanza)
	}
	return root + "/" + stanza, nil
}

var spoolCmdRE = regexp.MustCompile(`^f=(/[A-Za-z0-9/_.-]+)/%f; `)

// ParseSpoolArchiveCommand recognises an archive_command written by
// SpoolArchiveCommand (of this or an earlier agent version) and returns the
// spool directory it writes to.
func ParseSpoolArchiveCommand(cmd string) (dir string, ok bool) {
	if !strings.Contains(cmd, "# rowsafe spool") {
		return "", false
	}
	m := spoolCmdRE.FindStringSubmatch(cmd)
	if m == nil {
		return "", false
	}
	return m[1], true
}

// IsPushArchiveCommand reports whether cmd runs pgBackRest's archive-push
// itself, as the native (non-Docker) archive_command does. Inside a stock
// postgres container such a command cannot work.
func IsPushArchiveCommand(cmd string) bool {
	if _, ok := ParseSpoolArchiveCommand(cmd); ok {
		return false
	}
	return strings.Contains(cmd, "pgbackrest") && strings.Contains(cmd, "archive-push")
}

var (
	walSegmentRE = regexp.MustCompile(`^[0-9A-F]{24}$`)
	// Timeline history, backup history and partial segments.
	walOtherRE = regexp.MustCompile(`^([0-9A-F]{8}\.history|[0-9A-F]{24}\.[0-9A-F]{8}\.backup|[0-9A-F]{24}\.partial)$`)
)

// IsWALFileName reports whether name is something Postgres archives: a WAL
// segment, a timeline history file, a backup history file or a partial
// segment. The pusher leaves anything else (e.g. "*.tmp") alone.
func IsWALFileName(name string) bool {
	return walSegmentRE.MatchString(name) || walOtherRE.MatchString(name)
}

// ArchivePush stores one WAL file in the repository. pgBackRest succeeds
// (with a warning) when the repository already holds an identical file and
// fails when it holds a different one, so a push repeated after a crash is
// safe.
func (c CLI) ArchivePush(ctx context.Context, path string) ([]byte, error) {
	return c.run(ctx, "--log-level-console=warn", "archive-push", path)
}

// ArchiveGet fetches one WAL file from the repository into dest: decrypted,
// decompressed and checksummed. It fails if the repository does not hold it.
func (c CLI) ArchiveGet(ctx context.Context, walFile, dest string) ([]byte, error) {
	if !IsWALFileName(walFile) {
		return nil, fmt.Errorf("invalid WAL file name %q", walFile)
	}
	return c.run(ctx, "--log-level-console=warn", "archive-get", walFile, dest)
}
