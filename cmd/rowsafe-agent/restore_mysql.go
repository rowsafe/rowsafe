package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/internal/pgbackrest"
	mysqlengine "github.com/rowsafe/rowsafe/internal/engine/mysql"
)

const restoreMySQLUsage = `rowsafe-agent restore-mysql - restore a MySQL or MariaDB database from your bucket

  rowsafe-agent restore-mysql --engine mysql|mariadb --database NAME --dir DIR [--at TIME | --mark NAME]

Downloads the newest backup before the point you choose from your bucket,
decrypts it with ROWSAFE_REPO_CIPHER_PASS, prepares it and replays the binary
logs up to that second (or Mark; default: the latest change in the bucket).
DIR/data is then a data directory the same server version starts on. Run it
as the mysql user, with /etc/rowsafe/agent.env loaded, on a server with the
same MySQL/MariaDB version and backup tool (the installer sets them up).
Nothing on this server changes except DIR. TIME is UTC, e.g.
2026-09-25T14:04:00Z.
`

type stdoutLog struct{}

func (stdoutLog) Printf(format string, args ...any) {
	fmt.Printf("%s %s\n", time.Now().UTC().Format("15:04:05"), fmt.Sprintf(format, args...))
}

func (l stdoutLog) Output(label string, out []byte) {
	if s := strings.TrimSpace(string(out)); s != "" {
		l.Printf("%s output:\n%s", label, s)
	}
}

func restoreMySQL(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("restore-mysql", flag.ContinueOnError)
	fs.Usage = func() { fmt.Fprint(os.Stderr, restoreMySQLUsage) }
	engine := fs.String("engine", "", "mysql or mariadb")
	database := fs.String("database", "", "the database's name in Rowsafe")
	dir := fs.String("dir", "", "where to restore (empty or missing)")
	at := fs.String("at", "", "restore to this second (UTC, RFC 3339)")
	mark := fs.String("mark", "", "restore to this Mark")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *engine == "" || *database == "" || *dir == "" || !filepath.IsAbs(*dir) {
		fs.Usage()
		return errors.New("--engine, --database and an absolute --dir are required")
	}
	if *at != "" && *mark != "" {
		return errors.New("give --at or --mark, not both")
	}
	cfg, err := agent.ConfigFromEnv()
	if err != nil {
		return err
	}
	o := mysqlengine.RestoreOptions{Engine: *engine, Database: *database, Dir: *dir, Mark: *mark, Log: stdoutLog{},
		Env: agent.EngineEnv{Config: cfg, StateDir: filepath.Join(cfg.StateDir, "engines", *engine), Repo: cfg.Repo,
			Runner: pgbackrest.ExecRunner{}, Log: slog.New(slog.NewTextHandler(os.Stderr, nil)), Notes: io.Discard}}
	if *at != "" {
		t, err := time.Parse(time.RFC3339, *at)
		if err != nil {
			return fmt.Errorf("--at: %w", err)
		}
		o.At = &t
	}
	recovered, err := mysqlengine.RestoreTo(ctx, o)
	if err != nil {
		return err
	}
	fmt.Printf("\nRestored %s into %s: its last change is from %s.\n", *database, filepath.Join(*dir, "data"),
		recovered.UTC().Format(time.RFC3339))
	fmt.Println("Start the server on it (datadir), check your data, then point your application at it.")
	return nil
}
