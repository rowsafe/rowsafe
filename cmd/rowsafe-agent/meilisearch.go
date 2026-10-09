package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/internal/engine/meilisearch" // registers the Meilisearch engine
	"github.com/rowsafe/rowsafe/protocol"
)

const meilisearchUsage = `rowsafe-agent meilisearch - Meilisearch helpers for the installer

  rowsafe-agent meilisearch status --port PORT
      key=value lines: answers (yes/no), tls, version, login (ok, missing
      or refused). Exit 0 when Meilisearch answered, 1 when nothing answers.

  rowsafe-agent meilisearch login --port PORT --binary FILE --snapshot-dir DIR
                                  [--local-port PORT] [--db-path DIR] [--unit UNIT]
                                  [--listen ADDRESSES] [--rowsafe]
                                  [--max-indexing-memory BYTES] [--analytics yes|no]
      As the agent user: make (or make again) Rowsafe's own API key with the
      master key read from stdin (one line, used once and never kept; an
      empty line for an instance without a master key), and save it with
      the facts root found (the program, the snapshot folder...) for the
      agent only. Prints key=value lines: version, tls, key_uid, no_auth.
      Exit 11: a master key is needed; 12: it was refused.

  rowsafe-agent meilisearch tls-front --listen ADDR --to 127.0.0.1:PORT --cert FILE --key FILE
      Rowsafe's TLS front (servers Rowsafe creates; its own systemd service):
      TLS on ADDR, each connection passed to Meilisearch on 127.0.0.1;
      renewed certificate files are served without a restart.

  rowsafe-agent meilisearch download-backup --stanza STANZA [--label LABEL --to FILE]
      Restore without Rowsafe: with the bucket settings and passphrase in the
      environment (ROWSAFE_REPO_*, as in agent.env), list a database's
      snapshots (STANZA is its folder in the bucket), or decrypt snapshot
      LABEL into FILE, which Meilisearch starts from (--import-snapshot FILE).

Rowsafe's key may: read the version, statistics, indexes, settings and
tasks; delete finished tasks (Apply fix); take snapshots (backups); list,
make and delete API keys (Databases & users); make, delete, swap and compact
indexes (Databases & users, rewind in place, Apply fix); read and add
documents (bringing documents back from a Rewind copy).
`

func meilisearchCmd(ctx context.Context, args []string) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
		fmt.Print(meilisearchUsage)
		if len(args) == 0 {
			return 2
		}
		return 0
	}
	if args[0] == "tls-front" {
		return meilisearchFront(ctx, args[1:])
	}
	fs := flag.NewFlagSet("meilisearch "+args[0], flag.ContinueOnError)
	port := fs.Int("port", protocol.MeilisearchPort, "the port apps use")
	localPort := fs.Int("local-port", 0, "Meilisearch itself on 127.0.0.1, behind Rowsafe's TLS front")
	binary := fs.String("binary", "", "the meilisearch program")
	snapDir := fs.String("snapshot-dir", "", "Meilisearch's snapshot folder")
	dbPath := fs.String("db-path", "", "Meilisearch's data folder")
	unit := fs.String("unit", "", "its systemd unit")
	listenAddrs := fs.String("listen", "", "the addresses apps reach it on")
	rowsafe := fs.Bool("rowsafe", false, "installed by Rowsafe's installer")
	maxMem := fs.Int64("max-indexing-memory", 0, "its indexing memory limit (bytes)")
	analytics := fs.String("analytics", "", "yes or no: Meilisearch sends usage data")
	stanza := fs.String("stanza", "", "the database's folder in the bucket")
	label := fs.String("label", "", "the snapshot to download")
	to := fs.String("to", "", "the file to write")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	switch args[0] {
	case "status", "login", "download-backup":
	default:
		fmt.Fprintf(os.Stderr, "unknown meilisearch command %q (see rowsafe-agent meilisearch --help)\n", args[0])
		return 2
	}
	cfg, err := agent.ConfigFromEnv()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	env := agent.EngineEnvFor(cfg, protocol.EngineMeilisearch, os.Stderr)
	if args[0] == "download-backup" {
		return meilisearchDownload(ctx, env, *stanza, *label, *to)
	}
	if os.Geteuid() == 0 {
		fmt.Fprintln(os.Stderr, "run this as the agent user, with /etc/rowsafe/agent.env loaded (the installer does this)")
		return 1
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	if args[0] == "status" {
		st := meilisearch.ServerStatus(ctx, env, *port)
		fmt.Printf("answers=%s\ntls=%s\nversion=%s\nlogin=%s\n", yesNo(st.Answers), yesNo(st.TLS), dash(st.Version), dash(st.Login))
		if !st.Answers {
			return 1
		}
		return 0
	}
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	master := strings.TrimRight(line, "\r\n")
	opts := meilisearch.LoginOptions{Port: *port, LocalPort: *localPort, Binary: *binary, DBPath: *dbPath, SnapshotDir: *snapDir,
		Unit: *unit, Listen: *listenAddrs, Rowsafe: *rowsafe, MaxIndexingMemory: *maxMem}
	switch *analytics {
	case "yes", "no":
		v := *analytics == "yes"
		opts.Analytics = &v
	}
	res, err := meilisearch.Login(ctx, env, opts, master)
	master = ""
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		switch {
		case errors.Is(err, meilisearch.ErrNeedMasterKey):
			return 11
		case strings.Contains(err.Error(), "refused that master key"):
			return 12
		}
		return 1
	}
	fmt.Printf("version=%s\ntls=%s\nkey_uid=%s\nno_auth=%s\n", res.Version, yesNo(res.TLS), dash(res.KeyUID), yesNo(res.NoAuth))
	if len(res.Leftover) > 0 {
		fmt.Printf("leftover_keys=%s\n", strings.Join(res.Leftover, ","))
	}
	return 0
}

// meilisearchFront runs Rowsafe's TLS front.
func meilisearchFront(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("meilisearch tls-front", flag.ContinueOnError)
	listen := fs.String("listen", ":7700", "where to listen")
	to := fs.String("to", "", "Meilisearch's address (127.0.0.1:PORT)")
	cert := fs.String("cert", "", "the certificate file")
	key := fs.String("key", "", "the key file")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *to == "" || *cert == "" || *key == "" {
		fmt.Fprintln(os.Stderr, "usage: rowsafe-agent meilisearch tls-front --listen ADDR --to 127.0.0.1:PORT --cert FILE --key FILE")
		return 2
	}
	err := meilisearch.RunTLSFront(ctx, meilisearch.FrontOptions{Listen: *listen, Backend: *to, CertFile: *cert, KeyFile: *key,
		Log: slog.New(slog.NewTextHandler(os.Stderr, nil))})
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	return 0
}

func meilisearchDownload(ctx context.Context, env agent.EngineEnv, stanza, label, to string) int {
	if stanza == "" || (label == "") != (to == "") {
		fmt.Fprint(os.Stderr, "usage: rowsafe-agent meilisearch download-backup --stanza STANZA [--label LABEL --to FILE]\n")
		return 2
	}
	if label == "" {
		list, err := meilisearch.Backups(ctx, env, stanza)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
		if len(list) == 0 {
			fmt.Println("No finished snapshots in this folder.")
		}
		for _, b := range list {
			fmt.Printf("%-20s %-8s %-9s taken %s  %d indexes, %d documents %s\n", b.Label, b.Version, b.Source, b.TakenAt, b.Indexes, b.Documents, b.Mark)
		}
		return 0
	}
	if err := meilisearch.DownloadBackup(ctx, env, stanza, label, to); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	fmt.Printf("Wrote %s. Start Meilisearch on an empty data folder with --import-snapshot %s (and your master key).\n", to, to)
	return 0
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
