package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/internal/engine/sqlite" // registers the SQLite engine
	"github.com/rowsafe/rowsafe/protocol"
)

const sqliteUsage = `rowsafe-agent sqlite - SQLite helpers for the installer, and restores without Rowsafe

  rowsafe-agent sqlite find [--json]
      (root) The SQLite files running programs have open, on this server and
      inside Docker containers, one per line, tab-separated: path size_bytes
      journal(wal|rollback) pid program container container_path uid gid
      suggested_name ("-" when empty). path is where this server reaches
      the file ("-" for a file inside a container's own layer, which the
      agent can't reach). Browsers', desktop and package tools' files are
      left out.

  rowsafe-agent sqlite status --path FILE
      (agent user) key=value lines: path version journal size_bytes
      wal_bytes access(ok|missing|denied|not-sqlite) networkfs owner
      suggested. Exit 0 when the agent can open FILE for reading and
      writing, 1 otherwise.

  rowsafe-agent sqlite restore --stanza STANZA --to FILE [--at TIME | --mark NAME]
      Restore without Rowsafe: with the bucket settings and passphrase in
      the environment (ROWSAFE_REPO_*, as in agent.env), restore a database
      (STANZA is its folder in the bucket) into a new file FILE: the newest
      point, a moment (RFC 3339, e.g. 2026-10-04T09:30:00Z) or a Mark. It
      never touches the live database.
`

func sqliteCmd(ctx context.Context, args []string) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
		fmt.Print(sqliteUsage)
		if len(args) == 0 {
			return 2
		}
		return 0
	}
	fs := flag.NewFlagSet("sqlite "+args[0], flag.ContinueOnError)
	path := fs.String("path", "", "the database file")
	asJSON := fs.Bool("json", false, "print JSON")
	stanza := fs.String("stanza", "", "the database's folder in the bucket")
	to := fs.String("to", "", "the file to restore into")
	at := fs.String("at", "", "the moment to restore (RFC 3339)")
	mark := fs.String("mark", "", "the Mark to restore")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	switch args[0] {
	case "find":
		found := sqlite.FindOpen("")
		if *asJSON {
			_ = json.NewEncoder(os.Stdout).Encode(found)
			return 0
		}
		dash := func(s string) string {
			if s == "" {
				return "-"
			}
			return s
		}
		for _, f := range found {
			fmt.Printf("%s\t%d\t%s\t%d\t%s\t%s\t%s\t%d\t%d\t%s\n", dash(f.Path), f.SizeBytes, f.JournalMode, f.PID, dash(f.Program),
				dash(f.Container), dash(f.ContainerPath), f.UID, f.GID, f.Suggested)
		}
		return 0
	case "status":
		if !protocol.SQLitePath(*path) {
			fmt.Fprintln(os.Stderr, "error: --path must be the database file's absolute path")
			return 2
		}
		st := sqlite.FileStatus(ctx, *path)
		st.WriteTo(os.Stdout)
		if st.Access != "ok" {
			if st.Problem != "" {
				fmt.Fprintln(os.Stderr, st.Problem)
			}
			return 1
		}
		return 0
	case "restore":
		if err := sqliteRestore(ctx, *stanza, *to, *at, *mark); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
		return 0
	}
	fmt.Fprintf(os.Stderr, "unknown sqlite command %q\n\n%s", args[0], sqliteUsage)
	return 2
}

func sqliteRestore(ctx context.Context, stanza, to, at, mark string) error {
	if stanza == "" || to == "" {
		return errors.New("--stanza and --to are required")
	}
	if at != "" && mark != "" {
		return errors.New("pick --at or --mark, not both")
	}
	var t time.Time
	if at != "" {
		var err error
		if t, err = time.Parse(time.RFC3339, at); err != nil {
			return fmt.Errorf("--at: %w (use RFC 3339, e.g. 2026-10-04T09:30:00Z)", err)
		}
	}
	if _, err := os.Lstat(to); err == nil {
		return fmt.Errorf("%s exists: restore into a new file", to)
	}
	cfg, err := agent.ConfigFromEnv()
	if err != nil {
		return err
	}
	if err := cfg.ValidateRepo(); err != nil {
		return err
	}
	abs, err := filepath.Abs(to)
	if err != nil {
		return err
	}
	env := agent.EngineEnvFor(cfg, protocol.EngineSQLite, os.Stderr)
	out, err := sqlite.RestoreWithoutRowsafe(ctx, env, stanza, abs, t, mark)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "restored into %s, as of %s\n", abs, out.Format(time.RFC3339))
	return nil
}
