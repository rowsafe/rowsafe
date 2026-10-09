package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/internal/engine/qdrant" // registers the Qdrant engine
	"github.com/rowsafe/rowsafe/protocol"
)

const qdrantUsage = `rowsafe-agent qdrant - Qdrant helpers for the installer

They run as the agent user with agent.env loaded. A key, when asked for, is
read from stdin (one line) and saved for the agent only.

  rowsafe-agent qdrant status --port PORT
      key=value lines: port engine version login tls jwt binary docker
      cluster config unit collections ("-" when empty). login is ok,
      missing, refused or none (the server asks for no key); jwt says
      whether the agent signs tokens rather than sending its key; binary is
      the qdrant program restore tests and copies use. Exit 0 when Qdrant
      answered, 1 when nothing (or something else) answers on PORT.

  rowsafe-agent qdrant login --port PORT [--url URL]
      Save Rowsafe's own key (the server's alternative key, alt_api_key,
      which root set), read from stdin, after checking it manages
      snapshots. With JWT access control on, the agent never sends it: it
      signs a token valid for a few minutes for each request. Exit 12 when
      Qdrant refuses it.

  rowsafe-agent qdrant save-login --port PORT [--url URL]
      The same with a key you give (your api_key: Qdrant has no role that
      can take full snapshots with less).

  rowsafe-agent qdrant download-backup --stanza STANZA [--label LABEL --to FILE]
      Restore without Rowsafe: with the bucket settings and passphrase in the
      environment (ROWSAFE_REPO_*, as in agent.env), list a database's
      snapshots (STANZA is its folder in the bucket), or decrypt snapshot
      LABEL into FILE: a full storage snapshot an empty Qdrant of the same
      or a newer version starts from (qdrant --storage-snapshot FILE).
`

func qdrantCmd(ctx context.Context, args []string) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
		fmt.Print(qdrantUsage)
		if len(args) == 0 {
			return 2
		}
		return 0
	}
	fs := flag.NewFlagSet("qdrant "+args[0], flag.ContinueOnError)
	port := fs.Int("port", 6333, "the server's REST port")
	base := fs.String("url", "", "the server's URL (a Docker sidecar)")
	stanza := fs.String("stanza", "", "the database's folder in the bucket")
	label := fs.String("label", "", "the snapshot to download")
	to := fs.String("to", "", "the file to write")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	cfg, err := agent.ConfigFromEnv()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	env := agent.EngineEnvFor(cfg, protocol.EngineQdrant, os.Stderr)
	if args[0] == "download-backup" {
		return qdrantDownload(ctx, env, *stanza, *label, *to)
	}
	if os.Geteuid() == 0 {
		fmt.Fprintln(os.Stderr, "run this as the agent user, with /etc/rowsafe/agent.env loaded (the installer does this)")
		return 1
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	readSecret := func() string {
		line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		return strings.TrimRight(line, "\r\n")
	}
	switch args[0] {
	case "status":
		st, err := qdrant.ServerStatus(ctx, env, *port)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
		st.Print(os.Stdout)
		return 0
	case "login", "save-login":
		source := "alt"
		if args[0] == "save-login" {
			source = "key"
		}
		res, err := qdrant.SaveLogin(ctx, env, *port, readSecret(), source, *base)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			if strings.Contains(err.Error(), "refused") {
				return exitAdminRefused
			}
			return 1
		}
		how := "the key itself (JSON Web Tokens are off on this server)"
		if res.JWT {
			how = "tokens signed with it, valid for a few minutes (the key itself never goes to Qdrant)"
		}
		fmt.Printf("jwt=%v\n", res.JWT)
		fmt.Fprintf(os.Stderr, "Saved the key for the agent only; it reaches Qdrant with %s.\n", how)
		return 0
	}
	fmt.Fprintf(os.Stderr, "unknown qdrant command %q\n\n%s", args[0], qdrantUsage)
	return 2
}

// qdrantDownload is `rowsafe-agent qdrant download-backup`. It needs no
// server and may run as root (a restore on a new server).
func qdrantDownload(ctx context.Context, env agent.EngineEnv, stanza, label, to string) int {
	if stanza == "" || (label == "") != (to == "") {
		fmt.Fprint(os.Stderr, "usage: rowsafe-agent qdrant download-backup --stanza STANZA [--label LABEL --to FILE]\n")
		return 2
	}
	if label == "" {
		list, err := qdrant.Backups(ctx, env, stanza)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
		if len(list) == 0 {
			fmt.Println("No finished snapshots in this folder.")
		}
		for _, b := range list {
			what := b.Source
			if b.Mark != "" {
				what = "mark " + b.Mark
			}
			fmt.Printf("%-20s qdrant %-8s taken %s  %d collections, %d points  (%s)\n", b.Label, b.Version,
				b.TakenAt.UTC().Format("2006-01-02 15:04:05Z"), b.Collections, b.Points, what)
		}
		return 0
	}
	if err := qdrant.DownloadBackup(ctx, env, stanza, label, to); err != nil {
		if errors.Is(err, os.ErrExist) {
			fmt.Fprintf(os.Stderr, "error: %s exists already\n", to)
			return 1
		}
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	fmt.Printf("Wrote %s. Start an empty Qdrant of the same or a newer version from it: qdrant --storage-snapshot %s\n", to, to)
	return 0
}
